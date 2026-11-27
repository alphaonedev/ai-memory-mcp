//! Crate-internal, test-only environment-isolation helpers shared across the
//! unit-test modules that mutate process-global environment variables.
//!
//! `std::env::set_var`/`remove_var` mutate the single process-wide environment
//! table and are unsound if any other thread accesses the environment
//! concurrently (rust-1.98 UNSAFE-01/03). The libtest harness runs `#[test]`
//! functions on several threads by default, so every in-process test that
//! mutates an env var must:
//!
//! 1. hold the process-wide [`env_lock`] for the whole test body, so no two
//!    such tests run concurrently. This upholds `set_var`'s single-threaded
//!    contract AND prevents one test from observing another's transient value
//!    — the TOCTOU that leaked the at-rest encryption gate and reddened
//!    `Check (macos-fed)` / `Per-Module Coverage Thresholds` (#3301, #2905
//!    test-isolation class); and
//! 2. mutate through an [`EnvGuard`], which snapshots the prior value on
//!    construction and restores it on `Drop`. Because `Drop` also runs during
//!    unwinding, a panic mid-test can never leak the mutation into a sibling
//!    test in the same binary.
//!
//! One guard and ONE lock are reused by every in-process env-mutating unit-test
//! module so the whole in-process test surface is serialised against itself.
//! Since #3523 that lock is literally one `Mutex<()>` crate-wide:
//! [`env_lock`] DELEGATES to [`crate::config::test_env_lock`], which is the
//! same name the `config` / `reranker` / `egress` / `security_profile` /
//! `cli::commands::config` cohort already used. Before #3523 the two were
//! independent `OnceLock<Mutex<()>>` statics over the same process-global
//! writes — a fourth instance of the $HOME per-module-mutex defect
//! (#1998 -> #2115 -> #2127).
//!
//! The shared TLS test PKI is generated under `TMPDIR`. On Unix, its own
//! directory is removed by a process-exit hook. SIGKILL, abort and a crashed
//! harness skip that hook; there is no sweep of inherited paths here. Non-Unix
//! hosts retain the directory after exit because no exit hook is registered.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Process-wide lock serialising every test that mutates an environment
/// variable in-process, so `set_var`'s single-threaded contract holds and no
/// test observes another's transient env state.
///
/// # #3523 — this is a DELEGATE, not a second mutex
///
/// Until #3523 this function declared its OWN
/// `static LOCK: OnceLock<Mutex<()>>`, so the crate held TWO independent
/// mutexes over the SAME process-global environment table: this one (taken by
/// `log_paths`, `encryption`, `daemon_runtime`) and
/// [`crate::config::test_env_lock`] (taken by `config`, `reranker`, `egress`,
/// `security_profile`, `cli::commands::config`, `recover::transcript_paths`,
/// `enterprise_federation_posture`). Holding either excluded only its own
/// users, so a `log_paths` test setting `HOME` and a `config` test reading
/// `~/.config/ai-memory/config.toml` could run at literally the same instant
/// — the identical per-module-mutex defect $HOME already suffered three times
/// (#1998 -> #2115 -> #2127) before `config::test_env_lock` unified the first
/// cohort.
///
/// Both names survive so NO call site had to move; they now resolve to the
/// one [`crate::config::test_env_mutex`]. `tests/env_lock_singleton_gate_3523.rs`
/// pins that structurally, and this module's
/// `tests::the_two_env_lock_paths_are_one_mutex_3523` pins it by OBSERVATION.
///
/// A poisoned lock is recovered rather than propagated: a panic in one
/// env-mutating test must not wedge the others, and the panicking test's
/// [`EnvGuard`] already restored the environment on its way out — the
/// recovery lives in `config::test_env_lock`.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    crate::config::test_env_lock()
}

/// The raw process-env mutex behind [`env_lock`] — the SAME
/// [`crate::config::test_env_mutex`] the `config` cohort acquires (#3523).
///
/// Exposed so the singleton can be proven by OBSERVATION (a probe thread's
/// `try_lock` must fail while a wrapper guard is held) rather than only by
/// reading the source.
pub(crate) fn env_mutex() -> &'static Mutex<()> {
    crate::config::test_env_mutex()
}

/// Snapshot+restore guard for a single process-wide environment variable, so a
/// test never leaks its mutation into a sibling test in the same binary.
///
/// Hold [`env_lock`] for the enclosing test body while this guard is live.
pub(crate) struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    /// Capture `key`'s current value; it is restored on `Drop`.
    pub(crate) fn capture(key: &'static str) -> Self {
        Self {
            key,
            prev: std::env::var_os(key),
        }
    }

    /// Set `key` to `v`. The caller must hold [`env_lock`].
    pub(crate) fn set(&self, v: &str) {
        // SAFETY: the enclosing test holds `env_lock()`, so no other thread is
        // reading or writing the environment concurrently (UNSAFE-01/03).
        unsafe {
            std::env::set_var(self.key, v);
        }
    }

    /// Remove `key`. The caller must hold [`env_lock`].
    pub(crate) fn unset(&self) {
        // SAFETY: same as `set` — serialised by `env_lock()`.
        unsafe {
            std::env::remove_var(self.key);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: same as `set` — serialised by `env_lock()`. Runs during
        // unwinding on panic, so the variable is always restored to its
        // pre-test value.
        unsafe {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

/// #3539 — the ONE window in which a lib test may touch the SQLCipher
/// passphrase channel (the [`crate::storage::ENV_DB_PASSPHRASE`] variable
/// AND the `cfg(test)` process-private passphrase slot behind
/// [`crate::storage::connection::db_passphrase`]).
///
/// # Why this type exists
///
/// `storage::connection::refuse_at_rest_requested_without_sqlcipher()` runs
/// on EVERY sqlite open and refuses when `passphrase_requested()` is true —
/// which consults BOTH the environment variable AND the process-private
/// slot. Under `cfg(test)` that slot is a process-global
/// `RwLock<Option<String>>`, so a test that seeds it makes EVERY concurrent
/// sqlite open in the SAME lib test binary refuse. The pre-#3539
/// `DbPassphraseGuard` only RESET the slot on enter and on drop: it excluded
/// nothing, so `daemon_runtime::tests::test_bootstrap_serve_*` (which took no
/// lock at all) could open sqlite inside a seeding test's live window and hit
/// the sqlcipher refusal — the #3517/#3523 defect class with the passphrase
/// slot as the process-global (CI `macos-fed,sqlite`, 2026-09-08).
///
/// A lock only works when the READERS take it too, so this is the single
/// funnel for both sides:
///
/// * seeders hold it because [`crate::storage::connection::DbPassphraseGuard`]
///   cannot be constructed without a borrow of one (illegal states
///   unrepresentable, ERRORS-09 — not merely a convention a new test can
///   forget); and
/// * readers hold it via [`no_passphrase_guard`], which additionally ASSERTS
///   the slot is empty, so a regression fails loudly instead of flaking.
///
/// Entering clears the environment variable as well as excluding the slot
/// seeders, so a passphrase inherited from the HOST environment cannot reach
/// a plain-sqlite boot either (fail closed; the self-hosted CI legs also blank
/// `AI_MEMORY_DB_PASSPHRASE` / `AI_MEMORY_DB_PASSPHRASE_FILE` before the test
/// step as defence in depth — hygiene, not the fix).
///
/// # Drop order
///
/// Field order IS drop order (OWNERSHIP-24): `_env` restores the variable to
/// its pre-guard value FIRST, and only then does `_lock` release the mutex —
/// so no other test can ever observe the cleared value. `Drop` is infallible
/// (OWNERSHIP-25).
///
/// Not re-entrant: [`env_lock`] is a `std::sync::Mutex`, so a nested
/// `enter()` on one thread self-deadlocks. Take ONE per test body and pass it
/// by reference (`&`) to any inner scope that needs it.
#[must_use = "dropping this guard reopens the passphrase window"]
pub(crate) struct PassphraseEnvIsolation {
    _env: EnvGuard,
    _lock: MutexGuard<'static, ()>,
}

impl PassphraseEnvIsolation {
    /// Acquire the crate-wide env mutex and clear
    /// [`crate::storage::ENV_DB_PASSPHRASE`] for the guard's lifetime.
    pub(crate) fn enter() -> Self {
        let lock = env_lock();
        let env = EnvGuard::capture(crate::storage::ENV_DB_PASSPHRASE);
        env.unset();
        Self {
            _env: env,
            _lock: lock,
        }
    }
}

/// #3539 — reader-side entry to the passphrase window for any lib test that
/// opens a plain (non-sqlcipher) sqlite store or boots a daemon.
///
/// Holds [`PassphraseEnvIsolation`] for the caller's whole body and asserts
/// the process-private passphrase slot is empty. The assertion is sound
/// rather than flaky precisely because the seeders hold the same mutex and
/// clear the slot before releasing it, so once this returns the slot cannot
/// change under the caller.
///
/// # Panics
///
/// If the passphrase slot is non-empty while this lock is held — that would
/// mean a seeder mutated it outside the window, i.e. the #3539 funnel was
/// bypassed.
pub(crate) fn no_passphrase_guard() -> PassphraseEnvIsolation {
    let iso = PassphraseEnvIsolation::enter();
    assert!(
        crate::storage::connection::db_passphrase().is_none(),
        "#3539: the process-private passphrase slot must be empty inside the \
         passphrase window — a seeder mutated it without holding \
         PassphraseEnvIsolation"
    );
    iso
}

// ---------------------------------------------------------------------------
// #3577 — process-global LINEAGE_DAG / CONSOLIDATE_TOMBSTONE_SOURCES funnel
// ---------------------------------------------------------------------------

/// Process-wide lock serialising every test that reads or writes the
/// lineage-DAG atomics (`LINEAGE_DAG`, `CONSOLIDATE_TOMBSTONE_SOURCES`).
///
/// Distinct from [`env_lock`]: these are `AtomicBool`s, not environment
/// variables. Folding into the env mutex would deadlock any test that
/// already holds `env_lock` (std `Mutex` is not reentrant —
/// rust-1.98 CONCURRENCY-04) once #3539 also takes that lock on
/// daemon-boot tests. A poisoned lock is recovered rather than
/// propagated (CONCURRENCY-18): a panic in one seeder must not wedge
/// the readers, and [`LineageDagIsolation`]'s `Drop` already restored
/// the atomics on the way out.
fn lineage_dag_mutex() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn lineage_dag_lock() -> MutexGuard<'static, ()> {
    lineage_dag_mutex()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Snapshot+restore guard for the process-global lineage-DAG flags.
///
/// Hold this for the whole seeder body; [`set_lineage_dag`] /
/// [`set_consolidate_tombstone_sources`] are reachable from `cfg(test)`
/// code only through the methods on this guard (ERRORS-09, enforced by
/// `scripts/check-test-env-lock.sh` arm (f)). `Drop` restores the
/// pre-guard values even on panic (OWNERSHIP-24; Drop is infallible —
/// OWNERSHIP-25).
#[must_use]
pub(crate) struct LineageDagIsolation {
    _lock: MutexGuard<'static, ()>,
    prev_dag: bool,
    prev_tombstone: bool,
}

impl LineageDagIsolation {
    /// Acquire the funnel and snapshot the current flags. Does not
    /// change them — seeders call [`set_lineage_dag`] /
    /// [`set_consolidate_tombstone_sources`] next; readers use
    /// [`no_lineage_dag_guard`] which asserts OFF.
    pub(crate) fn new() -> Self {
        let lock = lineage_dag_lock();
        let (prev_dag, prev_tombstone) = crate::config::lineage_flags_snapshot();
        Self {
            _lock: lock,
            prev_dag,
            prev_tombstone,
        }
    }

    /// Seed the master flag. The caller must hold this guard; the
    /// script gate forbids a bare `config::set_lineage_dag(` outside this
    /// module and `daemon_runtime.rs` (the production boot seed).
    pub(crate) fn set_lineage_dag(&self, enabled: bool) {
        let _held = &self._lock;
        crate::config::set_lineage_dag(enabled);
    }

    /// Seed the tombstone sub-flag. Same funnel as [`Self::set_lineage_dag`].
    pub(crate) fn set_consolidate_tombstone_sources(&self, enabled: bool) {
        let _held = &self._lock;
        crate::config::set_consolidate_tombstone_sources(enabled);
    }

    /// Write the snapshotted flags back. [`Drop`] calls this
    /// (OWNERSHIP-24); tests call it while still holding the funnel so
    /// the assertion cannot race a sibling seeder after lock release
    /// (CONCURRENCY-03). Infallible (OWNERSHIP-25).
    fn restore_flags(&self) {
        let _held = &self._lock;
        crate::config::set_lineage_dag(self.prev_dag);
        crate::config::set_consolidate_tombstone_sources(self.prev_tombstone);
    }
}

/// Pinned RFC3339 stamps for cycle-test fixtures so Pass 0
/// (`lineage_edge_is_forward`) sees a strict newer→older pre-seed even
/// when two inserts would otherwise share one `Utc::now()` tick.
pub(crate) const LINEAGE_FIXTURE_OLDER_AT: &str = "2026-01-01T00:00:00+00:00";
/// Newer sibling of [`LINEAGE_FIXTURE_OLDER_AT`].
pub(crate) const LINEAGE_FIXTURE_NEWER_AT: &str = "2026-03-01T00:00:00+00:00";

/// Seeder funnel that simulates the production boot seed (`lineage_dag`
/// compiled default ON, tombstone sub-flag tracking it). Lib-test
/// `bootstrap_serve` skips the real seed (`#[cfg(not(test))]`); daemon-boot
/// tests must opt in through this helper so a leaked ON restores on drop.
#[must_use]
pub(crate) fn simulate_production_lineage_seed() -> LineageDagIsolation {
    let g = LineageDagIsolation::new();
    g.set_lineage_dag(true);
    g.set_consolidate_tombstone_sources(true);
    g
}

impl Drop for LineageDagIsolation {
    fn drop(&mut self) {
        self.restore_flags();
    }
}

/// Reader-side funnel: hold the lock and assert `LINEAGE_DAG` is OFF.
///
/// Every lib test that writes a lineage relation (`reflects_on` /
/// `derived_from` / `derives_from`) must hold this for the whole body
/// so a concurrent seeder cannot flip the flag mid-write. If a seeder
/// leaked `true` (the pre-#3577 `FLAG_LOCK`-only restore), this
/// asserts loudly instead of failing later inside `create_link` as a
/// flake.
#[must_use]
pub(crate) fn no_lineage_dag_guard() -> LineageDagIsolation {
    let g = LineageDagIsolation::new();
    assert!(
        !crate::config::lineage_dag_enabled(),
        "#3577: LINEAGE_DAG must be OFF for this reader; a seeder leaked \
         the process-global flag (seeders hold LineageDagIsolation and \
         restore on drop)"
    );
    g
}

// ---------------------------------------------------------------------------
// #3705 — "only encrypted data in transit": TLS for in-process tests.
//
// Since the mandate a listener without `--tls-cert`/`--tls-key` is refused
// (`daemon_runtime::tls_bind_guard`), an `http://` federation peer or
// webhook target is refused, and the PostgreSQL DSN needs
// `sslmode=verify-full`. The in-crate tests therefore need two things:
// PATHS that satisfy the bind guard for `bootstrap_serve`-based tests that
// never bind, and a real TLS mock for tests that actually connect.
// ---------------------------------------------------------------------------

/// The checked-in TLS fixture pair (`tests/fixtures/tls`): the leaf carries
/// the SAN `ai-memory-test.local` and a PKCS#8 ECDSA key. Enough for
/// `ServeArgs` in `bootstrap_serve`-based tests, which only need both paths
/// PRESENT to pass the #3705 bind guard and never bind a socket.
pub(crate) fn tls_fixture_paths() -> (PathBuf, PathBuf) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    (dir.join("valid_cert.pem"), dir.join("valid_key_pkcs8.pem"))
}

/// A per-process test PKI for mocks a test CONNECTS to: an ephemeral CA and
/// a leaf it signed whose SANs are the loopback names (`127.0.0.1`, `::1`,
/// `localhost`), so a VERIFYING client accepts the mock exactly the way a
/// production peer would — no `danger_accept_invalid_certs` anywhere.
/// Generated once with rcgen under `TMPDIR`. The static is never dropped;
/// on Unix the directory is created with mode 0700 and an exit hook removes
/// only this PKI's owned directory. See the
/// module documentation for abnormal-exit and non-Unix limitations.
pub(crate) struct TlsTestPki {
    #[cfg(unix)]
    dir: tempfile::TempDir,
    // Non-Unix retains ownership without an exit hook or a field read.
    #[cfg(not(unix))]
    _dir: tempfile::TempDir,
    /// The CA certificate (PEM) a client adds as its root.
    pub(crate) ca_pem: PathBuf,
    /// The leaf certificate (PEM) a mock listener presents.
    pub(crate) leaf_pem: PathBuf,
    /// The leaf's PKCS#8 private key (PEM, created with mode 0600 on Unix).
    pub(crate) leaf_key_pem: PathBuf,
}

static TLS_TEST_PKI: OnceLock<TlsTestPki> = OnceLock::new();

/// The process-wide [`TlsTestPki`] (generated on first use).
pub(crate) fn tls_test_pki() -> &'static TlsTestPki {
    let pki = TLS_TEST_PKI.get_or_init(generate_tls_test_pki);
    register_tls_test_pki_cleanup();
    pki
}

/// Copy `governance::audit::register_exit_drain` without adding a dependency.
fn register_tls_test_pki_cleanup() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        #[cfg(unix)]
        {
            extern "C" fn remove_tls_test_pki_at_exit() {
                use std::io::Write as _;

                // UNSAFE-24: contain all unwinding before returning to the C exit handler.
                if std::panic::catch_unwind(|| {
                    if let Some(pki) = TLS_TEST_PKI.get()
                        && let Err(error) = std::fs::remove_dir_all(pki.dir.path())
                    {
                        // Tracing may already be torn down. Discard only stderr write errors.
                        let _ = writeln!(std::io::stderr(), "test PKI cleanup error (#8651): {error}");
                    }
                })
                .is_err()
                {
                    let _ = writeln!(std::io::stderr(), "test PKI cleanup panicked (#8651)");
                }
            }

            // SAFETY: atexit only records an extern C function pointer. The
            // handler never unwinds (UNSAFE-24) and touches only process-global
            // OnceLock state that outlives main. Registration occurs once.
            let rc = unsafe { libc::atexit(remove_tls_test_pki_at_exit) };
            if rc != 0 {
                // ERRORS-19: failed registration must be visible to the runner.
                tracing::error!(
                    "test PKI cleanup registration returned {rc}; its directory remains at exit (#8651)"
                );
            }
        }
    });
}

/// #8663: create exclusively with private permissions before returning the handle.
fn create_tls_test_private_key(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        const PRIVATE_KEY_MODE: u32 = 0o600;
        options.mode(PRIVATE_KEY_MODE);
    }
    // ERRORS-01: preserve the exact I/O kind, including AlreadyExists.
    options.open(path)
}

fn generate_tls_test_pki() -> TlsTestPki {
    use std::io::Write as _;

    #[cfg(unix)]
    let dir = {
        use std::os::unix::fs::PermissionsExt as _;
        const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
        // #8663: tempfile passes this mode to DirBuilder before mkdir, not chmod.
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .tempdir()
    };
    #[cfg(not(unix))]
    let dir = tempfile::tempdir();
    let dir = dir.expect("TMPDIR tempdir for the #3705 test PKI");
    let ca_key = rcgen::KeyPair::generate().expect("test CA key");
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "ai-memory in-process test CA (#3705)",
    );
    let ca_cert = ca_params.self_signed(&ca_key).expect("test CA certificate");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().expect("test leaf key");
    let leaf_params = rcgen::CertificateParams::new(vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "localhost".to_string(),
        "pin-test.invalid".to_string(),
        "pin-test.invalid.".to_string(),
    ])
    .expect("test leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("test leaf certificate");
    let ca_pem = dir.path().join("test-ca.pem");
    let leaf_pem = dir.path().join("test-leaf.pem");
    let leaf_key_pem = dir.path().join("test-leaf-key.pem");
    std::fs::write(&ca_pem, ca_cert.pem()).expect("write test CA");
    std::fs::write(&leaf_pem, leaf_cert.pem()).expect("write test leaf");
    let mut key_file =
        create_tls_test_private_key(&leaf_key_pem).expect("create private test leaf key");
    key_file
        .write_all(leaf_key.serialize_pem().as_bytes())
        .expect("write test leaf key");
    TlsTestPki {
        #[cfg(unix)]
        dir,
        #[cfg(not(unix))]
        _dir: dir,
        ca_pem,
        leaf_pem,
        leaf_key_pem,
    }
}

/// Serve `app` over TLS (the [`tls_test_pki`] leaf) on a loopback ephemeral
/// port. Returns the `https://127.0.0.1:<port>` base URL. The server task is
/// detached and ends with the runtime, like the plaintext `axum::serve`
/// mocks it replaces.
pub(crate) async fn spawn_tls_mock(app: axum::Router) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tls_test_pki();
    let config = crate::tls::load_rustls_config(&pki.leaf_pem, &pki.leaf_key_pem)
        .await
        .expect("test leaf TLS config");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    // tokio adopts a std listener only in non-blocking mode.
    listener
        .set_nonblocking(true)
        .expect("non-blocking mock listener");
    let addr = listener.local_addr().expect("mock listener address");
    let acceptor = crate::tls::serve_rustls_acceptor(&config);
    tokio::spawn(async move {
        let _ = axum_server::from_tcp(listener)
            .expect("axum_server from_tcp")
            .acceptor(acceptor)
            .serve(app.into_make_service())
            .await;
    });
    format!("https://{addr}")
}

/// A verifying `reqwest` client that trusts the [`tls_test_pki`] CA, so a
/// [`spawn_tls_mock`] listener is accepted the way a production peer is.
pub(crate) fn tls_test_client(timeout: std::time::Duration) -> reqwest::Client {
    let pki = tls_test_pki();
    let ca_pem = std::fs::read(&pki.ca_pem).expect("read the test CA");
    let ca = reqwest::Certificate::from_pem(&ca_pem).expect("parse the test CA");
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .timeout(timeout)
        .build()
        .expect("TLS test client")
}

/// #10122 — wall-clock bound for every re-executed child test process so a
/// spinning or stalled child is killed and surfaces a named failure instead of
/// hanging the suite.
#[cfg(any(test, unix))]
pub(crate) const TEST_CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(any(test, unix))]
const TEST_CHILD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// #10122 — canonical error prefix returned by [`run_command_with_timeout`]
/// when a child exceeds its wall-clock bound.
#[cfg(any(test, unix))]
pub(crate) const TEST_CHILD_TIMEOUT_PREFIX: &str = "test child timed out";

/// #10122 (C-F4, ERRORS-19) — read a child capture file, surfacing any I/O
/// failure verbatim instead of collapsing it into empty output.
#[cfg(any(test, unix))]
fn read_child_capture(
    path: &std::path::Path,
    stream: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("read child {stream} capture for {label}: {e}"))
}

/// #10176 — the directory every child sandbox and run capture is created in.
/// It is fixed at first use (the off-HOME temporary root of `test_key_dir`), so
/// a later change of this process's `TMPDIR` cannot move a sandbox.
pub(crate) fn child_sandbox_base() -> &'static Path {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(crate::identity::test_key_dir::isolated_temp_root)
}

/// A private (0700) directory in [`child_sandbox_base`].
fn private_dir_in_base(prefix: &str) -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(child_sandbox_base())
}

/// Sandbox layout, relative to [`TestSandbox::root`].
const SANDBOX_HOME: &str = "home";
const SANDBOX_CONFIG: &str = "home/.config";
const SANDBOX_DATA: &str = "home/.local/share";
const SANDBOX_STATE: &str = "home/.local/state";
const SANDBOX_CACHE: &str = "home/.cache";
const SANDBOX_RUNTIME: &str = "run";
const SANDBOX_TMP: &str = "tmp";
const SANDBOX_WITNESS: &str = "home/witness-keys";
const SANDBOX_WORK: &str = "work";

/// Directories [`TestSandbox::new`] creates (the witness directory is left to
/// the code that creates it with its own mode).
const SANDBOX_DIRS: &[&str] = &[
    SANDBOX_CONFIG,
    SANDBOX_DATA,
    SANDBOX_STATE,
    SANDBOX_CACHE,
    SANDBOX_RUNTIME,
    SANDBOX_TMP,
    SANDBOX_WORK,
];

/// Every variable a lib-test child gets from its sandbox: `(name, path)`.
const SANDBOX_ENV: &[(&str, &str)] = &[
    ("HOME", SANDBOX_HOME),
    ("USERPROFILE", SANDBOX_HOME),
    ("XDG_CONFIG_HOME", SANDBOX_CONFIG),
    ("XDG_DATA_HOME", SANDBOX_DATA),
    ("XDG_STATE_HOME", SANDBOX_STATE),
    ("XDG_CACHE_HOME", SANDBOX_CACHE),
    ("XDG_RUNTIME_DIR", SANDBOX_RUNTIME),
    ("TMPDIR", SANDBOX_TMP),
    ("TMP", SANDBOX_TMP),
    ("TEMP", SANDBOX_TMP),
    (
        crate::governance::audit::WITNESS_KEY_DIR_ENV,
        SANDBOX_WITNESS,
    ),
];

/// Set to `1` in every child so it never reads an operator config file.
const CHILD_NO_CONFIG_ENV: &str = "AI_MEMORY_NO_CONFIG";

/// The only parent variables a child inherits: the binary search path, the
/// coverage sink, backtrace and stack knobs, the CI marker and the test-tier
/// selectors. None of them names user state.
const CHILD_ENV_PASSTHROUGH: &[&str] = &[
    "PATH",
    "LLVM_PROFILE_FILE",
    "RUST_BACKTRACE",
    "RUST_LIB_BACKTRACE",
    "RUST_MIN_STACK",
    "CI",
    "AI_MEMORY_TEST_POSTGRES_URL",
    "AI_MEMORY_TEST_AGE_URL",
    "AI_MEMORY_TEST_PG_ISOLATE",
    "AI_MEMORY_TEST_PG_LIVE_REQUIRED",
    "AI_MEMORY_TEST_PG_RUN_ID",
    "AI_MEMORY_TEST_PG_TEMPLATE",
    "AI_MEMORY_TEST_TIMING_BUDGET_MULT",
    "AI_MEMORY_TEST_FORCE_SPAWN_EAGAIN",
];

/// Names that point at key, audit or database custody. A child never gets one
/// from a caller; any name holding `KEY_DIR` or ending in `_PUBKEY` is refused
/// the same way.
const CHILD_ENV_CUSTODY: &[&str] = &[
    "AI_MEMORY_DB",
    "AI_MEMORY_AUDIT_DIR",
    crate::identity::keypair::KEY_DIR_ENV,
    "AI_MEMORY_RECORDER_KEY_DIR",
    "AI_MEMORY_JUDGE_KEY_DIR",
    "AI_MEMORY_STOPPER_KEY_DIR",
    "AI_MEMORY_STOPPER_PUBKEY",
];

/// URL schemes a value may carry without being read as a path.
const CHILD_ENV_URL_SCHEMES: &[&str] = &["http://", "https://", "postgres://", "postgresql://"];

/// #10176 — why [`SandboxedTestChild::try_env`] refused a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildEnvRefusal {
    /// Empty, or holds `=` or NUL.
    InvalidName(String),
    /// Set by the sandbox builder (sandbox paths, passthrough, `XDG_*`).
    ReservedName(String),
    /// Key, audit or database custody.
    CustodyName(String),
    /// The value is not UTF-8.
    NonUtf8Value(String),
    /// A path value that is not absolute.
    RelativePath { name: String, value: String },
    /// A path value with a `..` component.
    ParentComponent { name: String, value: String },
    /// A path value outside the sandbox root (lexically or once resolved).
    OutsideSandbox { name: String, value: String },
}

impl std::fmt::Display for ChildEnvRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(name) => {
                write!(f, "child env name {name:?} is empty or holds '=' or NUL")
            }
            Self::ReservedName(name) => write!(
                f,
                "child env {name} is set by the sandbox builder; a caller may not set it"
            ),
            Self::CustodyName(name) => write!(
                f,
                "child env {name} names key, audit or database custody; a lib-test child never receives it"
            ),
            Self::NonUtf8Value(name) => write!(f, "child env {name} value is not UTF-8"),
            Self::RelativePath { name, value } => write!(
                f,
                "child env {name} value {value:?} is a relative path; a path value must be absolute inside the sandbox"
            ),
            Self::ParentComponent { name, value } => {
                write!(f, "child env {name} value {value:?} holds a `..` component")
            }
            Self::OutsideSandbox { name, value } => {
                write!(
                    f,
                    "child env {name} value {value:?} is outside the child sandbox"
                )
            }
        }
    }
}

impl std::error::Error for ChildEnvRefusal {}

fn child_env_name_is_reserved(name: &str) -> bool {
    name == CHILD_NO_CONFIG_ENV
        || name.starts_with("XDG_")
        || SANDBOX_ENV.iter().any(|(n, _)| *n == name)
        || CHILD_ENV_PASSTHROUGH.contains(&name)
}

fn child_env_name_is_custody(name: &str) -> bool {
    CHILD_ENV_CUSTODY.contains(&name) || name.contains("KEY_DIR") || name.ends_with("_PUBKEY")
}

/// #10176 — the value rule of [`SandboxedTestChild::try_env`]. A value with no
/// path separator, or an `http(s)`/`postgres` URL with no whitespace, is
/// accepted. Any other value is a path: it must be absolute, hold no `..`, sit
/// under `root`, and its nearest existing ancestor must still be under `root`
/// once resolved (so a symlink inside the sandbox cannot point out of it).
fn check_child_env(
    root: &Path,
    name: &str,
    value: &std::ffi::OsStr,
) -> Result<(), ChildEnvRefusal> {
    if name.is_empty() || name.contains(['=', '\0']) {
        return Err(ChildEnvRefusal::InvalidName(name.to_string()));
    }
    if child_env_name_is_reserved(name) {
        return Err(ChildEnvRefusal::ReservedName(name.to_string()));
    }
    if child_env_name_is_custody(name) {
        return Err(ChildEnvRefusal::CustodyName(name.to_string()));
    }
    let Some(text) = value.to_str() else {
        return Err(ChildEnvRefusal::NonUtf8Value(name.to_string()));
    };
    if !text.contains(['/', '\\']) {
        return Ok(());
    }
    if CHILD_ENV_URL_SCHEMES.iter().any(|s| text.starts_with(s))
        && !text.chars().any(char::is_whitespace)
    {
        return Ok(());
    }
    let refuse =
        |make: fn(String, String) -> ChildEnvRefusal| Err(make(name.to_string(), text.to_string()));
    let path = Path::new(text);
    if !path.is_absolute() {
        return refuse(|name, value| ChildEnvRefusal::RelativePath { name, value });
    }
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return refuse(|name, value| ChildEnvRefusal::ParentComponent { name, value });
    }
    let outside = |name, value| ChildEnvRefusal::OutsideSandbox { name, value };
    if !path.starts_with(root) {
        return refuse(outside);
    }
    let mut probe = Some(path);
    while let Some(candidate) = probe {
        if candidate.symlink_metadata().is_ok() {
            return match candidate.canonicalize() {
                Ok(resolved) if resolved.starts_with(root) => Ok(()),
                _ => refuse(outside),
            };
        }
        probe = candidate.parent();
    }
    refuse(outside)
}

/// #10176 — a private sandbox for one or more lib-test children: a 0700
/// directory in [`child_sandbox_base`] holding the child's home, XDG
/// directories, runtime and temporary directories, and a `work` directory for
/// the caller's own files (databases, markers, journals). Removed on drop, so
/// keep it alive until every child built on it has exited.
pub(crate) struct TestSandbox {
    dir: tempfile::TempDir,
    root: PathBuf,
}

impl TestSandbox {
    /// # Panics
    /// Panics if the sandbox cannot be allocated (test setup).
    pub(crate) fn new() -> Self {
        let dir = private_dir_in_base(".ai-memory-child-").expect("#10176 allocate child sandbox");
        let root = dir
            .path()
            .canonicalize()
            .expect("#10176 resolve child sandbox root");
        // Every sandbox directory (and each intermediate one) is created 0700
        // whatever the umask, so no other user can rename into it and the
        // deferred-audit spool ancestor check accepts it (#10176).
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        for rel in SANDBOX_DIRS {
            builder
                .create(root.join(rel))
                .expect("#10176 child sandbox directory");
        }
        Self { dir, root }
    }

    /// The sandbox root (resolved); the child's working directory.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The child's `TMPDIR`.
    pub(crate) fn tmp(&self) -> PathBuf {
        self.root.join(SANDBOX_TMP)
    }

    /// A directory for the caller's own files; values under it pass
    /// [`SandboxedTestChild::try_env`].
    pub(crate) fn work(&self) -> PathBuf {
        self.root.join(SANDBOX_WORK)
    }
}

impl std::fmt::Debug for TestSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestSandbox")
            .field("root", &self.root)
            .field("held", &self.dir.path())
            .finish()
    }
}

/// #10176 — the ONLY way a lib test runs this test binary again as a child.
///
/// The child's environment is built from nothing: [`Self::new`] clears it,
/// copies only [`CHILD_ENV_PASSTHROUGH`], points every [`SANDBOX_ENV`] name
/// into the [`TestSandbox`], sets `AI_MEMORY_NO_CONFIG=1` and makes the
/// sandbox root the working directory. The command stays private: a caller
/// adds arguments, stdio and checked variables ([`Self::try_env`], which
/// refuses the sandbox, passthrough and custody names and any path outside the
/// sandbox), then runs it ([`Self::run_bounded`]) or spawns it
/// ([`Self::spawn`]). Nothing can change the environment or the working
/// directory around the sandbox.
///
/// The key directory: a child gets no `AI_MEMORY_KEY_DIR`, and `cfg(test)`
/// arms the #3355 guard in it, so `keypair::resolved_default_key_dir_path`
/// resolves to the child's own `test_key_dir::install` directory, created in
/// its `TMPDIR` — inside the sandbox.
///
/// The spawn goes through the #1937 audited chokepoint; the whole-tree ratchet
/// `tests/test_child_spawner_isolation_10176.rs` fails when any other file
/// under `src/` builds a process outside its exact allowlist.
pub(crate) struct SandboxedTestChild<'s> {
    command: std::process::Command,
    sandbox: &'s TestSandbox,
}

impl<'s> SandboxedTestChild<'s> {
    /// A child that re-runs this test binary in `sandbox`, labelled `caller`
    /// in the spawn audit.
    ///
    /// # Panics
    /// Panics if the test binary's path cannot be resolved.
    #[expect(
        clippy::disallowed_methods,
        reason = "the one #10176 sandboxed test child: re-runs this test binary with an env built from nothing inside a TestSandbox (#10176 gate row)"
    )]
    pub(crate) fn new(caller: &str, sandbox: &'s TestSandbox) -> Self {
        let mut command = crate::spawn_audit::audited_command(
            std::env::current_exe().expect("current_exe for sandboxed test child"),
            caller,
        );
        command.env_clear();
        for name in CHILD_ENV_PASSTHROUGH {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, rel) in SANDBOX_ENV {
            command.env(name, sandbox.root().join(rel));
        }
        command.env(CHILD_NO_CONFIG_ENV, "1");
        command.current_dir(sandbox.root());
        Self { command, sandbox }
    }

    /// Append arguments.
    #[must_use]
    pub(crate) fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command.args(args);
        self
    }

    /// Set a variable after [`check_child_env`].
    ///
    /// # Errors
    /// The exact [`ChildEnvRefusal`] when the name is reserved or custody, or
    /// the value is a path outside the sandbox.
    pub(crate) fn try_env(
        mut self,
        name: &str,
        value: impl AsRef<std::ffi::OsStr>,
    ) -> Result<Self, ChildEnvRefusal> {
        check_child_env(self.sandbox.root(), name, value.as_ref())?;
        self.command.env(name, value);
        Ok(self)
    }

    /// [`Self::try_env`] for a test whose value is fixed.
    ///
    /// # Panics
    /// Panics with the refusal text when [`Self::try_env`] refuses.
    #[must_use]
    pub(crate) fn env(self, name: &str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        self.try_env(name, value)
            .unwrap_or_else(|refusal| panic!("#10176: {refusal}"))
    }

    /// The child's stdout ([`Self::run_bounded`] replaces it with a capture).
    #[must_use]
    pub(crate) fn stdout(mut self, cfg: impl Into<std::process::Stdio>) -> Self {
        self.command.stdout(cfg);
        self
    }

    /// The child's stderr ([`Self::run_bounded`] replaces it with a capture).
    #[must_use]
    pub(crate) fn stderr(mut self, cfg: impl Into<std::process::Stdio>) -> Self {
        self.command.stderr(cfg);
        self
    }

    /// Spawn the child; the handle cannot outlive the sandbox and kills and
    /// reaps the child when dropped unwaited.
    ///
    /// # Errors
    /// The spawn error.
    pub(crate) fn spawn(mut self) -> std::io::Result<SpawnedTestChild<'s>> {
        let child = self.command.spawn()?;
        Ok(SpawnedTestChild {
            child,
            reaped: false,
            _sandbox: std::marker::PhantomData,
        })
    }

    /// Run to completion with file-backed stdout/stderr captures, null stdin
    /// and a hard wall-clock `timeout`. A child still running at the deadline
    /// is killed and reaped (CONCURRENCY-11) and the error starts with
    /// [`TEST_CHILD_TIMEOUT_PREFIX`].
    ///
    /// # Errors
    /// A capture, spawn, poll or reap failure, or the timeout, each naming
    /// `label`.
    pub(crate) fn run_bounded(
        mut self,
        timeout: std::time::Duration,
        label: &str,
    ) -> Result<std::process::Output, String> {
        run_command_bounded(&mut self.command, timeout, label)
    }
}

/// #10176 — a running [`SandboxedTestChild`]. Borrowing the sandbox keeps it
/// alive while the child runs; drop kills and reaps a child nobody waited on.
pub(crate) struct SpawnedTestChild<'s> {
    child: std::process::Child,
    reaped: bool,
    _sandbox: std::marker::PhantomData<&'s TestSandbox>,
}

impl SpawnedTestChild<'_> {
    /// The child's process id.
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    /// Poll without blocking.
    ///
    /// # Errors
    /// The poll error.
    pub(crate) fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let polled = self.child.try_wait();
        if matches!(polled, Ok(Some(_))) {
            self.reaped = true;
        }
        polled
    }

    /// Wait at most `timeout`; a child still running then is killed, reaped
    /// and reported with [`TEST_CHILD_TIMEOUT_PREFIX`].
    ///
    /// # Errors
    /// A poll or reap failure, or the timeout, each naming `label`.
    pub(crate) fn wait_bounded(
        &mut self,
        timeout: std::time::Duration,
        label: &str,
    ) -> Result<std::process::ExitStatus, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(e) => return Err(format!("poll test child {label}: {e}")),
            }
            if std::time::Instant::now() >= deadline {
                let kill_error = self.child.kill().err();
                let reap = self.child.wait();
                self.reaped = reap.is_ok();
                return Err(format!(
                    "{TEST_CHILD_TIMEOUT_PREFIX}: {label} exceeded {}ms (kill_error={kill_error:?}, reap={reap:?})",
                    timeout.as_millis()
                ));
            }
            std::thread::sleep(TEST_CHILD_POLL_INTERVAL);
        }
    }
}

impl Drop for SpawnedTestChild<'_> {
    fn drop(&mut self) {
        if !self.reaped {
            // Best effort in drop (OWNERSHIP-25: never panic here): a child
            // that already exited makes `kill` fail harmlessly; `wait` reaps it.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// #10122 — the bounded run behind [`SandboxedTestChild::run_bounded`]:
/// file-backed captures in a private directory of [`child_sandbox_base`], a
/// poll loop to `timeout`, then kill and reap.
fn run_command_bounded(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
    label: &str,
) -> Result<std::process::Output, String> {
    let scratch = private_dir_in_base(".ai-memory-child-capture-")
        .map_err(|e| format!("create child capture dir for {label}: {e}"))?;
    let stdout_path = scratch.path().join("stdout");
    let stderr_path = scratch.path().join("stderr");
    let stdout_file = std::fs::File::create(&stdout_path)
        .map_err(|e| format!("create child stdout capture for {label}: {e}"))?;
    let stderr_file = std::fs::File::create(&stderr_path)
        .map_err(|e| format!("create child stderr capture for {label}: {e}"))?;
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()
        .map_err(|e| format!("spawn test child {label}: {e}"))?;
    let deadline = std::time::Instant::now() + timeout;
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("poll test child {label}: {e}"));
            }
        }
        if std::time::Instant::now() >= deadline {
            break true;
        }
        std::thread::sleep(TEST_CHILD_POLL_INTERVAL);
    };
    let kill_error = if timed_out { child.kill().err() } else { None };
    let status = child
        .wait()
        .map_err(|e| format!("reap test child {label}: {e}"))?;
    let stdout = read_child_capture(&stdout_path, "stdout", label)?;
    let stderr = read_child_capture(&stderr_path, "stderr", label)?;
    if timed_out {
        return Err(format!(
            "{TEST_CHILD_TIMEOUT_PREFIX}: {label} exceeded {}ms (kill_error={kill_error:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            timeout.as_millis(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        ));
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Internal bounded form of [`spawn_test_child`] so tests can drive a child
/// past a short bound and pin the timeout path (#10122 C-F3).
#[cfg(unix)]
fn spawn_test_child_with_timeout(
    sandbox: &TestSandbox,
    test: &str,
    env: &[(&str, &str)],
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    let mut child = SandboxedTestChild::new("test_support::spawn_test_child", sandbox).args([
        "--exact",
        test,
        "--test-threads=1",
        "--nocapture",
    ]);
    for (key, value) in env {
        child = child
            .try_env(key, value)
            .map_err(|e| format!("#10176: {e}"))?;
    }
    child.run_bounded(timeout, test)
}

/// v1.0.0 #3152 — run THIS test binary again as a child that executes
/// exactly `test` (its full path inside the lib test binary) in `sandbox`
/// with `env` set. The child's environment is built from nothing
/// ([`SandboxedTestChild`], #10176), so no parallel test's environment and no
/// user state reaches it; path values in `env` must live in the sandbox
/// (typically [`TestSandbox::work`]). Waits under [`TEST_CHILD_TIMEOUT`] so a
/// spinning child is killed and reported instead of hanging the suite.
///
/// # Panics
/// Panics with the refusal, spawn or timeout text.
#[cfg(unix)]
pub(crate) fn spawn_test_child(
    sandbox: &TestSandbox,
    test: &str,
    env: &[(&str, &str)],
) -> std::process::Output {
    spawn_test_child_with_timeout(sandbox, test, env, TEST_CHILD_TIMEOUT)
        .unwrap_or_else(|msg| panic!("{msg}"))
}

/// Role env marker for [`run_env_isolated_child_or_spawn`] (#2905).
#[cfg(test)]
pub(crate) const TEST_ENV_ISOLATION_ROLE_ENV: &str = "AI_MEMORY_TEST_ENV_ISOLATION_ROLE";

/// #2905 test-isolation: run an env-MUTATING posture / security-profile
/// test in an ISOLATED CHILD process so its process-global
/// `std::env::set_var`s cannot leak to concurrent handler tests in the
/// same `--lib` binary.
///
/// The class this closes (a `lib-test-blind-spots` process-global
/// interference): `security_profile::enforce_at_boot` writes
/// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (and the rest of the `asi-hard`
/// KNOBS) into the process env, and the HTTP create handler tests read
/// that env WITHOUT taking [`test_env_lock`], so during a posture test's
/// set→remove window a concurrent create test fail-closes with `403`
/// instead of `201`. `enforce_at_boot`'s `set_var` is only safe in the
/// synchronous pre-runtime phase (its own module doc) — never on the
/// parallel libtest harness. Precedent for this fix:
/// `governance::deferred_audit` + `recover::durability` `current_exe()`
/// role-env subprocess isolation.
///
/// The child is a [`SandboxedTestChild`]: its environment is built from
/// nothing (#10176), so it starts from a hermetic baseline whatever the
/// parent's tests set, and it never sees the user's home, config, key or
/// witness directories.
///
/// Returns `true` in the PARENT role — the caller MUST `return` immediately,
/// because the real assertions already ran (and passed) in the spawned
/// child. Returns `false` in the CHILD role — the caller runs its body,
/// alone in a fresh process where its `set_var`s cannot race any other test.
///
/// `exact_path` MUST be the test's full `module::tests::fn_name` path. A
/// mistyped path would run ZERO tests and libtest would STILL exit 0 — a
/// silent false-green (the #2444 shape) — so the parent additionally
/// asserts the child stdout reports `1 passed` and never `0 passed`.
#[cfg(test)]
pub(crate) fn run_env_isolated_child_or_spawn(exact_path: &str) -> bool {
    let _ = crate::identity::test_key_dir::install();
    if std::env::var(TEST_ENV_ISOLATION_ROLE_ENV).as_deref() == Ok("child") {
        return false; // caller runs the real body in this isolated child
    }
    spawn_env_isolated_child(exact_path, &[])
}

/// Internal bounded form of [`spawn_env_isolated_child`] (#10122 C-F3): a
/// fresh [`TestSandbox`], `set` applied through [`SandboxedTestChild::try_env`],
/// and the child wait bounded under `timeout`.
#[cfg(test)]
fn try_spawn_env_isolated_child_with_timeout(
    exact_path: &str,
    set: &[(&str, &str)],
    timeout: std::time::Duration,
) -> Result<bool, String> {
    let sandbox = TestSandbox::new();
    let mut child = SandboxedTestChild::new("config::run_env_isolated_child_or_spawn", &sandbox)
        .args(["--exact", exact_path, "--nocapture", "--test-threads=1"])
        .env(TEST_ENV_ISOLATION_ROLE_ENV, "child");
    for (name, value) in set {
        child = child
            .try_env(name, value)
            .map_err(|e| format!("#10176: {e}"))?;
    }
    let output = child.run_bounded(timeout, exact_path)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "env-isolated child test {exact_path} FAILED:\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    );
    // False-green guard: a mistyped `exact_path` runs zero tests and still
    // exits 0. Require proof exactly one test actually RAN.
    assert!(
        stdout.contains("1 passed") && !stdout.contains("0 passed"),
        "env-isolated child test {exact_path} did NOT run (expected `1 passed`); \
         a mistyped path silently runs zero tests. child stdout:\n{stdout}"
    );
    Ok(true) // caller must `return`
}

/// Spawn `exact_path` alone in a sandboxed child test process with `set`
/// added; panics unless exactly one test ran and passed within
/// [`TEST_CHILD_TIMEOUT`].
#[cfg(test)]
fn spawn_env_isolated_child(exact_path: &str, set: &[(&str, &str)]) -> bool {
    try_spawn_env_isolated_child_with_timeout(exact_path, set, TEST_CHILD_TIMEOUT)
        .unwrap_or_else(|msg| panic!("{msg}"))
}

#[cfg(test)]
mod tests {
    use super::{
        EnvGuard, LineageDagIsolation, env_lock, env_mutex, lineage_dag_mutex,
        no_lineage_dag_guard, simulate_production_lineage_seed,
    };

    /// #8651: a child owns its generated PKI until exit, then leaves no files.
    #[cfg(unix)]
    #[test]
    fn tls_test_pki_is_removed_after_child_exit_8651() {
        const CHILD: &str = "AI_MEMORY_TLS_PKI_CHILD_8651";
        const TEST: &str = concat!(
            module_path!(),
            "::",
            stringify!(tls_test_pki_is_removed_after_child_exit_8651)
        );
        if std::env::var_os(CHILD).is_some() {
            let pki = super::tls_test_pki();
            for path in [&pki.ca_pem, &pki.leaf_pem, &pki.leaf_key_pem] {
                assert!(path.is_file(), "generated PKI file must exist: {path:?}");
            }
            assert!(
                std::ptr::eq(pki, super::tls_test_pki()),
                "all callers must share the process PKI"
            );
            {
                use std::os::unix::fs::PermissionsExt as _;
                const PRIVATE_KEY_MODE: u32 = 0o600;
                const PERMISSION_BITS: u32 = 0o777;
                let mode = std::fs::metadata(&pki.leaf_key_pem)
                    .expect("leaf key metadata")
                    .permissions()
                    .mode();
                assert_eq!(
                    mode & PERMISSION_BITS,
                    PRIVATE_KEY_MODE,
                    "leaf key permissions must stay private"
                );
            }
            return;
        }
        let sandbox = super::TestSandbox::new();
        let tmp = sandbox.tmp();
        let test = TEST.split_once("::").expect("crate-qualified test name").1;
        let child = super::SandboxedTestChild::new(
            "test_support::tls_test_pki_is_removed_after_child_exit_8651",
            &sandbox,
        )
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1");
        let output = run_pki_child_8651(child);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "PKI child: {stdout}\n{stderr}");
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "PKI child must run exactly the selected test: {stdout}"
        );
        assert!(
            std::fs::read_dir(&tmp)
                .expect("read child TMPDIR")
                .next()
                .is_none(),
            "#8651: child exit must remove every generated PKI file and directory"
        );
    }

    /// #8663: a permissive runner umask must not expose the PKI or leaf key.
    #[cfg(unix)]
    #[test]
    fn tls_test_pki_starts_private_under_open_umask_8663() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD: &str = "AI_MEMORY_TLS_PKI_CHILD_8663";
        const TEST: &str = concat!(
            module_path!(),
            "::",
            stringify!(tls_test_pki_starts_private_under_open_umask_8663)
        );
        const PERMISSIVE_UMASK: libc::mode_t = 0;
        const PERMISSION_BITS: u32 = 0o777;
        const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
        const PRIVATE_KEY_MODE: u32 = 0o600;
        if std::env::var_os(CHILD).is_some() {
            // SAFETY: umask takes an integer and has no pointer preconditions.
            // Only this selected test runs in the child; the parent's umask is
            // unchanged, and this child exits after the permission assertions.
            unsafe { libc::umask(PERMISSIVE_UMASK) };
            let pki = super::tls_test_pki();
            let directory = pki.leaf_key_pem.parent().expect("PKI directory");
            for (path, expected, kind) in [
                (directory, PRIVATE_DIRECTORY_MODE, "directory"),
                (pki.leaf_key_pem.as_path(), PRIVATE_KEY_MODE, "private key"),
            ] {
                let actual = std::fs::metadata(path)
                    .expect("PKI permissions")
                    .permissions()
                    .mode()
                    & PERMISSION_BITS;
                assert_eq!(
                    actual, expected,
                    "#8663: {kind} must be private with umask 0"
                );
            }
            return;
        }
        // Keep even the deliberately insecure red fixture behind a private
        // parent: the sandbox root is 0700.
        let sandbox = super::TestSandbox::new();
        let test = TEST.split_once("::").expect("crate-qualified test name").1;
        let child = super::SandboxedTestChild::new(
            "test_support::tls_test_pki_starts_private_under_open_umask_8663",
            &sandbox,
        )
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1");
        let output = run_pki_child_8651(child);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "permission child: {stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "permission child must execute the selected test: {stdout}"
        );
    }

    /// #8663: observe creation permissions before the first write or chmod.
    #[cfg(unix)]
    #[test]
    fn tls_private_key_creation_is_private_8663() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD: &str = "AI_MEMORY_TLS_KEY_CREATION_CHILD_8663";
        const TEST: &str = concat!(
            module_path!(),
            "::",
            stringify!(tls_private_key_creation_is_private_8663)
        );
        const PERMISSIVE_UMASK: libc::mode_t = 0;
        const PERMISSION_BITS: u32 = 0o777;
        const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
        const PRIVATE_KEY_MODE: u32 = 0o600;
        if std::env::var_os(CHILD).is_some() {
            // SAFETY: the integer-only umask call is isolated to this re-executed
            // child, which runs one test and exits; the parent umask is unchanged.
            unsafe { libc::umask(PERMISSIVE_UMASK) };
            let pki = super::tls_test_pki();
            let directory = pki.leaf_key_pem.parent().expect("owned PKI directory");
            let path = directory.join("creation-probe.pem");
            let file = super::create_tls_test_private_key(&path).expect("new private key");
            let metadata = file.metadata().expect("new key handle metadata");
            assert_eq!(
                metadata.permissions().mode() & PERMISSION_BITS,
                PRIVATE_KEY_MODE,
                "#8663: key must be born private before any write or chmod"
            );
            assert_eq!(metadata.len(), 0, "#8663: key has not been written yet");
            assert_eq!(
                std::fs::metadata(directory)
                    .expect("owned PKI directory metadata")
                    .permissions()
                    .mode()
                    & PERMISSION_BITS,
                PRIVATE_DIRECTORY_MODE,
                "#8663: key must be created inside the private PKI directory"
            );
            return;
        }
        let sandbox = super::TestSandbox::new();
        let test = TEST.split_once("::").expect("crate-qualified test name").1;
        let child = super::SandboxedTestChild::new(
            "test_support::tls_private_key_creation_is_private_8663",
            &sandbox,
        )
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1");
        let output = run_pki_child_8651(child);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "creation child: {stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "creation child must execute the selected test: {stdout}"
        );
    }

    /// #8663: exclusive creation must preserve every byte at an existing path.
    #[test]
    fn tls_private_key_existing_path_is_unchanged_8663() {
        const NAMES: [&str; 3] = ["existing.pem", "existing key.pem", "existing-λ.pem"];
        const ORIGINAL: &[u8] = b"existing fixture bytes\x00\xff\n";
        let directory = tempfile::tempdir().expect("existing-key fixture directory");
        for name in NAMES {
            let path = directory.path().join(name);
            std::fs::write(&path, ORIGINAL).expect("seed existing fixture");
            let result = super::create_tls_test_private_key(&path);
            let bytes = std::fs::read(&path).expect("read existing fixture after refusal");
            assert_eq!(
                bytes, ORIGINAL,
                "#8663: existing bytes must survive: {name}"
            );
            let error = result.expect_err("#8663: an existing key must be refused");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists,
                "#8663: existing key error must be exact: {name}"
            );
        }
    }

    /// #10122 (C-F1 / C-F6) / #10176 — route PKI test children through the single
    /// shared sandboxed builder and bounded-timeout runner instead of duplicating
    /// the capture/poll/kill/reap loop. The child's environment is built from
    /// nothing, so no caller variable can replace a sandbox path.
    #[cfg(unix)]
    fn run_pki_child_8651(child: super::SandboxedTestChild<'_>) -> std::process::Output {
        child
            .run_bounded(super::TEST_CHILD_TIMEOUT, "run_pki_child_8651")
            .unwrap_or_else(|msg| panic!("{msg}"))
    }

    /// #3523 — the OBSERVED singleton pin: `test_support::env_lock()` and
    /// `config::test_env_lock()` are ONE mutex, not two.
    ///
    /// A source-walk (`tests/env_lock_singleton_gate_3523.rs`) can be fooled
    /// by a delegate that is spelled correctly but resolves elsewhere; this
    /// asserts the runtime fact. Holding the `test_support` wrapper, a PROBE
    /// THREAD must fail to acquire the `config` path. Two independent mutexes
    /// would let it succeed — which is exactly the pre-#3523 state.
    ///
    /// The probe runs on another thread on purpose: a same-thread `try_lock`
    /// of a mutex this thread already holds also returns `Err`, so it could
    /// not distinguish "one mutex" from "self-conflict"
    /// (`std::sync::Mutex` is not reentrant — rust-1.98 CONCURRENCY-04).
    #[test]
    fn the_two_env_lock_paths_are_one_mutex_3523() {
        let _held = env_lock();
        let probe_acquired =
            std::thread::spawn(|| crate::config::test_env_mutex().try_lock().is_ok())
                .join()
                .expect("probe thread must not panic");
        assert!(
            !probe_acquired,
            "#3523: a probe thread acquired `config::test_env_mutex()` while \
             `test_support::env_lock()` was held — the two paths are TWO \
             independent mutexes again, so a $HOME mutation in one cohort can \
             interleave with the other (the #1998 -> #2115 -> #2127 defect)"
        );
        assert!(
            std::ptr::eq(env_mutex(), crate::config::test_env_mutex()),
            "#3523: `test_support::env_mutex()` and `config::test_env_mutex()` \
             must be the SAME `Mutex<()>` allocation"
        );
    }

    /// The `EnvGuard` RAII contract: the pre-guard value is restored on drop,
    /// including the "was absent" case. Without this the guard could silently
    /// leak a mutation into a sibling test in the same binary — the failure
    /// mode the one lock cannot cover.
    #[test]
    fn env_guard_restores_the_pre_guard_state_3523() {
        const KEY: &str = "AI_MEMORY_TEST_SUPPORT_PROBE_3523";
        let _lock = env_lock();
        assert!(
            std::env::var_os(KEY).is_none(),
            "probe key must start absent"
        );
        {
            let guard = EnvGuard::capture(KEY);
            guard.set("value-a");
            assert_eq!(std::env::var(KEY).ok().as_deref(), Some("value-a"));
            guard.unset();
            assert!(std::env::var_os(KEY).is_none());
            guard.set("value-b");
        }
        assert!(
            std::env::var_os(KEY).is_none(),
            "#3523: `EnvGuard` must restore the ABSENT pre-guard state on drop"
        );
    }

    /// #10122 (C-F1 / C-F2) — shared child-side assertion that a spawned test
    /// child sees isolated `HOME`, `XDG_CONFIG_HOME`, and
    /// `AI_MEMORY_WITNESS_KEY_DIR` VALUES (not merely that variables are set).
    /// The parent passes its own paths hex-encoded ([`parent_path_hex_10122`]),
    /// because a path outside the sandbox is refused as a child value (#10176).
    #[cfg(unix)]
    fn assert_child_sees_isolated_sandbox_values(
        spawner: &str,
        parent_home_env: &str,
        parent_witness_env: &str,
    ) {
        use std::os::unix::ffi::OsStringExt as _;
        let parent_path = |name: &str| {
            std::env::var(name).ok().map(|hex| {
                std::path::PathBuf::from(std::ffi::OsString::from_vec(hex_decode_10176(&hex)))
            })
        };
        let child_home = std::path::PathBuf::from(
            std::env::var_os("HOME")
                .unwrap_or_else(|| panic!("#10122 ({spawner}): child HOME must be set")),
        );
        let child_xdg =
            std::path::PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap_or_else(|| {
                panic!("#10122 ({spawner}): child XDG_CONFIG_HOME must be set")
            }));
        let child_witness = std::path::PathBuf::from(
            std::env::var_os(crate::governance::audit::WITNESS_KEY_DIR_ENV).unwrap_or_else(|| {
                panic!("#10122 ({spawner}): child AI_MEMORY_WITNESS_KEY_DIR must be set")
            }),
        );
        if let Some(parent_home) = parent_path(parent_home_env) {
            assert_ne!(
                child_home, parent_home,
                "#10122 ({spawner}): child HOME must differ from parent HOME"
            );
        }
        if let Some(parent_witness) = parent_path(parent_witness_env) {
            assert_ne!(
                child_witness, parent_witness,
                "#10122 ({spawner}): child AI_MEMORY_WITNESS_KEY_DIR must differ from parent witness dir"
            );
        }
        assert!(
            child_xdg.starts_with(&child_home),
            "#10122 ({spawner}): child XDG_CONFIG_HOME ({child_xdg:?}) must lie inside child HOME ({child_home:?})"
        );
        assert!(
            child_witness.starts_with(&child_home),
            "#10122 ({spawner}): child AI_MEMORY_WITNESS_KEY_DIR ({child_witness:?}) must lie inside child HOME ({child_home:?})"
        );
        let resolved_witness =
            crate::governance::audit::witness_key_dir().expect("resolve child witness_key_dir");
        assert_eq!(
            resolved_witness, child_witness,
            "#10122 ({spawner}): witness_key_dir() must resolve to the isolated child witness dir"
        );
        assert!(
            !child_witness.join("head-anchor.log").exists(),
            "#10122 ({spawner}): isolated child witness dir must not contain a pre-existing head-anchor.log"
        );
    }

    /// #10122 (C-F2) — `spawn_test_child` MUST isolate `HOME`,
    /// `XDG_CONFIG_HOME`, and `AI_MEMORY_WITNESS_KEY_DIR` VALUES to a fresh
    /// private sandbox distinct from the parent's home and witness dir.
    #[cfg(unix)]
    #[test]
    fn spawn_test_child_isolates_home_and_witness_dir_10122() {
        const ROLE_ENV: &str = "AI_MEMORY_TEST_10122_ISOLATION_ROLE";
        const PARENT_HOME_ENV: &str = "AI_MEMORY_TEST_10122_PARENT_HOME";
        const PARENT_WITNESS_ENV: &str = "AI_MEMORY_TEST_10122_PARENT_WITNESS";
        const TEST: &str =
            "test_support::tests::spawn_test_child_isolates_home_and_witness_dir_10122";
        if std::env::var_os(ROLE_ENV).is_some() {
            assert_child_sees_isolated_sandbox_values(
                "spawn_test_child",
                PARENT_HOME_ENV,
                PARENT_WITNESS_ENV,
            );
            return;
        }
        let parent_home = parent_path_hex_10122(std::path::Path::new(
            &std::env::var_os("HOME").unwrap_or_default(),
        ));
        let parent_witness = parent_path_hex_10122(
            &crate::governance::audit::witness_key_dir().expect("resolve parent witness_key_dir"),
        );
        let sandbox = super::TestSandbox::new();
        let out = super::spawn_test_child(
            &sandbox,
            TEST,
            &[
                (ROLE_ENV, "1"),
                (PARENT_HOME_ENV, &parent_home),
                (PARENT_WITNESS_ENV, &parent_witness),
            ],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "#10122 isolation child failed:\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "#10122 isolation child ran zero tests:\n{stdout}"
        );
    }

    /// #10122 (C-F1 / C-F2) — `spawn_env_isolated_child` MUST isolate `HOME`,
    /// `XDG_CONFIG_HOME`, and `AI_MEMORY_WITNESS_KEY_DIR` VALUES to a fresh
    /// private sandbox distinct from the parent's home and witness dir.
    #[cfg(unix)]
    #[test]
    fn spawn_env_isolated_child_isolates_home_config_and_witness_dir_10122() {
        const PARENT_HOME_ENV: &str = "AI_MEMORY_TEST_10122_ENV_ISO_PARENT_HOME";
        const PARENT_WITNESS_ENV: &str = "AI_MEMORY_TEST_10122_ENV_ISO_PARENT_WITNESS";
        const TEST: &str = "test_support::tests::spawn_env_isolated_child_isolates_home_config_and_witness_dir_10122";
        if std::env::var(super::TEST_ENV_ISOLATION_ROLE_ENV).as_deref() == Ok("child") {
            assert_child_sees_isolated_sandbox_values(
                "spawn_env_isolated_child",
                PARENT_HOME_ENV,
                PARENT_WITNESS_ENV,
            );
            return;
        }
        let parent_home = parent_path_hex_10122(std::path::Path::new(
            &std::env::var_os("HOME").unwrap_or_default(),
        ));
        let parent_witness = parent_path_hex_10122(
            &crate::governance::audit::witness_key_dir().expect("resolve parent witness_key_dir"),
        );
        let ran_in_child = super::spawn_env_isolated_child(
            TEST,
            &[
                (PARENT_HOME_ENV, parent_home.as_str()),
                (PARENT_WITNESS_ENV, parent_witness.as_str()),
            ],
        );
        assert!(ran_in_child, "parent branch must spawn child");
    }

    /// #10122 (C-F1 / C-F6) — `run_pki_child_8651` MUST isolate `HOME`,
    /// `XDG_CONFIG_HOME`, and `AI_MEMORY_WITNESS_KEY_DIR` VALUES to a fresh
    /// private sandbox distinct from the parent's home and witness dir.
    #[cfg(unix)]
    #[test]
    fn pki_child_spawner_isolates_home_config_and_witness_dir_10122() {
        const CHILD: &str = "AI_MEMORY_TEST_10122_PKI_ISO_ROLE";
        const PARENT_HOME_ENV: &str = "AI_MEMORY_TEST_10122_PKI_PARENT_HOME";
        const PARENT_WITNESS_ENV: &str = "AI_MEMORY_TEST_10122_PKI_PARENT_WITNESS";
        const TEST: &str =
            "test_support::tests::pki_child_spawner_isolates_home_config_and_witness_dir_10122";
        if std::env::var_os(CHILD).is_some() {
            assert_child_sees_isolated_sandbox_values(
                "run_pki_child_8651",
                PARENT_HOME_ENV,
                PARENT_WITNESS_ENV,
            );
            return;
        }
        let parent_home = parent_path_hex_10122(std::path::Path::new(
            &std::env::var_os("HOME").unwrap_or_default(),
        ));
        let parent_witness = parent_path_hex_10122(
            &crate::governance::audit::witness_key_dir().expect("resolve parent witness_key_dir"),
        );
        let sandbox = super::TestSandbox::new();
        let child = super::SandboxedTestChild::new(
            "test_support::pki_child_spawner_isolates_home_config_and_witness_dir_10122",
            &sandbox,
        )
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env(PARENT_HOME_ENV, &parent_home)
        .env(PARENT_WITNESS_ENV, &parent_witness);
        let out = run_pki_child_8651(child);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "#10122 PKI isolation child failed:\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stdout.contains("1 passed") && !stdout.contains("0 passed"),
            "#10122 PKI isolation child ran zero tests:\n{stdout}"
        );
    }

    /// #10176 — hex form of a parent path, passed to a child as a plain value
    /// (a raw path outside the sandbox is refused as a child value).
    #[cfg(unix)]
    fn parent_path_hex_10122(path: &std::path::Path) -> String {
        use std::os::unix::ffi::OsStrExt as _;
        hex_encode_10176(path.as_os_str().as_bytes())
    }

    /// #10176 — the exhaustive refusal table of `check_child_env`: every
    /// sandbox, passthrough and custody name, every name shape and every value
    /// shape, each with its exact `ChildEnvRefusal` (or acceptance).
    #[cfg(unix)]
    #[test]
    fn child_env_refusals_are_exact_10176() {
        use super::ChildEnvRefusal as R;
        use std::os::unix::ffi::OsStrExt as _;
        let sandbox = super::TestSandbox::new();
        let root = sandbox.root();
        let check = |name: &str, value: &std::ffi::OsStr| super::check_child_env(root, name, value);
        let os = std::ffi::OsStr::new;
        for name in ["", "A=B", "A\0B", "="] {
            assert_eq!(
                check(name, os("1")),
                Err(R::InvalidName(name.to_string())),
                "#10176 name {name:?}"
            );
        }
        let reserved = super::SANDBOX_ENV
            .iter()
            .map(|(name, _)| *name)
            .chain(super::CHILD_ENV_PASSTHROUGH.iter().copied())
            .chain([super::CHILD_NO_CONFIG_ENV, "XDG_SESSION_ID", "XDG_"]);
        for name in reserved {
            assert_eq!(
                check(name, os("1")),
                Err(R::ReservedName(name.to_string())),
                "#10176 reserved {name}"
            );
        }
        for name in super::CHILD_ENV_CUSTODY.iter().copied().chain([
            "AI_MEMORY_OTHER_KEY_DIR",
            "KEY_DIR",
            "AI_MEMORY_OPERATOR_PUBKEY",
            "X_PUBKEY",
        ]) {
            assert_eq!(
                check(name, os("1")),
                Err(R::CustodyName(name.to_string())),
                "#10176 custody {name}"
            );
        }
        let non_utf8 = std::ffi::OsStr::from_bytes(b"\xff/x");
        assert_eq!(
            check("AI_MEMORY_10176_V", non_utf8),
            Err(R::NonUtf8Value("AI_MEMORY_10176_V".to_string()))
        );
        let outside = crate::identity::test_key_dir::private_tempdir();
        let link = sandbox.work().join("escape-link");
        std::os::unix::fs::symlink(outside.path(), &link).expect("plant escape symlink");
        let root_text = root.to_string_lossy().into_owned();
        let work = sandbox.work().to_string_lossy().into_owned();
        let sibling = format!("{root_text}-sibling/work");
        let parent_escape = format!("{work}/../../..");
        let through_link = format!("{}/db.sqlite", link.display());
        let home = crate::identity::test_key_dir::resolved_home()
            .to_string_lossy()
            .into_owned();
        let outside_text = outside.path().to_string_lossy().into_owned();
        let refused: Vec<(&str, R)> = vec![
            (
                "rel/path",
                R::RelativePath {
                    name: "V".into(),
                    value: "rel/path".into(),
                },
            ),
            (
                "./x",
                R::RelativePath {
                    name: "V".into(),
                    value: "./x".into(),
                },
            ),
            (
                "https://a b/c",
                R::RelativePath {
                    name: "V".into(),
                    value: "https://a b/c".into(),
                },
            ),
            (
                "ftp://host/x",
                R::RelativePath {
                    name: "V".into(),
                    value: "ftp://host/x".into(),
                },
            ),
            (
                "a\\b",
                R::RelativePath {
                    name: "V".into(),
                    value: "a\\b".into(),
                },
            ),
            (
                parent_escape.as_str(),
                R::ParentComponent {
                    name: "V".into(),
                    value: parent_escape.clone(),
                },
            ),
            (
                "/etc/passwd",
                R::OutsideSandbox {
                    name: "V".into(),
                    value: "/etc/passwd".into(),
                },
            ),
            (
                "/",
                R::OutsideSandbox {
                    name: "V".into(),
                    value: "/".into(),
                },
            ),
            (
                home.as_str(),
                R::OutsideSandbox {
                    name: "V".into(),
                    value: home.clone(),
                },
            ),
            (
                outside_text.as_str(),
                R::OutsideSandbox {
                    name: "V".into(),
                    value: outside_text.clone(),
                },
            ),
            (
                sibling.as_str(),
                R::OutsideSandbox {
                    name: "V".into(),
                    value: sibling.clone(),
                },
            ),
            (
                through_link.as_str(),
                R::OutsideSandbox {
                    name: "V".into(),
                    value: through_link.clone(),
                },
            ),
        ];
        for (value, expected) in refused {
            assert_eq!(
                check("V", os(value)),
                Err(expected),
                "#10176 value {value:?}"
            );
        }
        let db = format!("{work}/db.sqlite");
        let nested = format!("{work}/not/yet/created");
        for value in [
            "1",
            "child",
            "",
            "abc def",
            "https://example.invalid/x",
            "http://127.0.0.1:1/x",
            "postgres://u@h/d",
            "postgresql://u@h/d",
            root_text.as_str(),
            work.as_str(),
            db.as_str(),
            nested.as_str(),
        ] {
            assert_eq!(
                check("V", os(value)),
                Ok(()),
                "#10176 accepted value {value:?}"
            );
        }
    }

    /// #10176 — the exact refusal texts, and the builder methods route through
    /// the same check: `try_env` returns the refusal and `env` panics with it.
    #[cfg(unix)]
    #[test]
    fn child_env_refusal_texts_and_builder_routing_10176() {
        use super::ChildEnvRefusal as R;
        let rows = [
            (
                R::InvalidName("A=B".into()),
                "child env name \"A=B\" is empty or holds '=' or NUL",
            ),
            (
                R::ReservedName("HOME".into()),
                "child env HOME is set by the sandbox builder; a caller may not set it",
            ),
            (
                R::CustodyName("AI_MEMORY_DB".into()),
                "child env AI_MEMORY_DB names key, audit or database custody; a lib-test child never receives it",
            ),
            (
                R::NonUtf8Value("V".into()),
                "child env V value is not UTF-8",
            ),
            (
                R::RelativePath {
                    name: "V".into(),
                    value: "a/b".into(),
                },
                "child env V value \"a/b\" is a relative path; a path value must be absolute inside the sandbox",
            ),
            (
                R::ParentComponent {
                    name: "V".into(),
                    value: "/x/..".into(),
                },
                "child env V value \"/x/..\" holds a `..` component",
            ),
            (
                R::OutsideSandbox {
                    name: "V".into(),
                    value: "/etc".into(),
                },
                "child env V value \"/etc\" is outside the child sandbox",
            ),
        ];
        for (refusal, text) in rows {
            assert_eq!(refusal.to_string(), text);
        }
        let sandbox = super::TestSandbox::new();
        let refused =
            super::SandboxedTestChild::new("test_support::refusal_routing_10176", &sandbox)
                .try_env("AI_MEMORY_KEY_DIR", sandbox.work())
                .err();
        assert_eq!(refused, Some(R::CustodyName("AI_MEMORY_KEY_DIR".into())));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = super::SandboxedTestChild::new("test_support::refusal_routing_10176", &sandbox)
                .env("HOME", sandbox.work());
        }))
        .expect_err("#10176: env must panic on a reserved name");
        let message = panicked
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            message,
            "#10176: child env HOME is set by the sandbox builder; a caller may not set it"
        );
        let err = super::spawn_test_child_with_timeout(
            &sandbox,
            "test_support::tests::never_runs_10176",
            &[("AI_MEMORY_DB", "x")],
            super::TEST_CHILD_TIMEOUT,
        )
        .expect_err("#10176: spawn_test_child must refuse a custody name");
        assert_eq!(
            err,
            "#10176: child env AI_MEMORY_DB names key, audit or database custody; a lib-test child never receives it"
        );
        let err = super::try_spawn_env_isolated_child_with_timeout(
            "test_support::tests::never_runs_10176",
            &[("XDG_DATA_HOME", "/x")],
            super::TEST_CHILD_TIMEOUT,
        )
        .expect_err("#10176: the env-isolated spawner must refuse a reserved name");
        assert_eq!(
            err,
            "#10176: child env XDG_DATA_HOME is set by the sandbox builder; a caller may not set it"
        );
    }

    /// #10176 — the sandbox layout: a 0700 root inside the off-home base,
    /// holding every directory the child env points at.
    #[cfg(unix)]
    #[test]
    fn test_sandbox_layout_is_private_and_off_home_10176() {
        use std::os::unix::fs::PermissionsExt as _;
        const PRIVATE: u32 = 0o700;
        const BITS: u32 = 0o777;
        let sandbox = super::TestSandbox::new();
        let root = sandbox.root();
        assert!(root.starts_with(super::child_sandbox_base()), "{root:?}");
        if let Ok(home) = crate::identity::test_key_dir::resolved_home().canonicalize() {
            assert!(
                !root.starts_with(&home),
                "#10176 sandbox {root:?} under home {home:?}"
            );
        }
        for rel in [super::SANDBOX_RUNTIME, ""] {
            let mode = std::fs::metadata(root.join(rel))
                .expect("sandbox dir metadata")
                .permissions()
                .mode();
            assert_eq!(mode & BITS, PRIVATE, "#10176 {rel:?} must be 0700");
        }
        for rel in super::SANDBOX_DIRS {
            assert!(root.join(rel).is_dir(), "#10176 sandbox must create {rel}");
        }
        let held = root.to_path_buf();
        drop(sandbox);
        assert!(!held.exists(), "#10176 the sandbox is removed on drop");
    }

    /// #10176 — a spawned child is killed and reaped when its handle drops,
    /// and `wait_bounded` kills a child past its bound.
    #[cfg(unix)]
    #[test]
    fn spawned_test_child_is_bounded_and_reaped_10176() {
        const SLEEP_ROLE_ENV: &str = "AI_MEMORY_TEST_10176_SPAWNED_SLEEP_ROLE";
        const TEST: &str = "test_support::tests::spawned_test_child_is_bounded_and_reaped_10176";
        const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(150);
        const MAX_WALL_ELAPSED: std::time::Duration = std::time::Duration::from_secs(5);
        if std::env::var_os(SLEEP_ROLE_ENV).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        let sandbox = super::TestSandbox::new();
        let spawn = || {
            super::SandboxedTestChild::new("test_support::spawned_10176", &sandbox)
                .args(["--exact", TEST, "--test-threads=1"])
                .env(SLEEP_ROLE_ENV, "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn sleeping child")
        };
        let start = std::time::Instant::now();
        let mut child = spawn();
        let err = child
            .wait_bounded(SHORT_BOUND, TEST)
            .expect_err("sleeping child must time out");
        assert!(err.starts_with(super::TEST_CHILD_TIMEOUT_PREFIX), "{err}");
        assert!(err.contains(TEST), "{err}");
        let dropped = spawn();
        let pid = i32::try_from(dropped.id()).expect("pid fits i32");
        drop(dropped);
        // SAFETY: kill with signal 0 only probes whether the pid exists.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "#10176 a dropped child must be killed and reaped");
        assert!(start.elapsed() < MAX_WALL_ELAPSED, "{:?}", start.elapsed());
    }

    /// #10122 — `run_command_with_timeout` MUST kill a hanging child when the
    /// bound expires and return an `Err` naming `TEST_CHILD_TIMEOUT_PREFIX`.
    #[cfg(unix)]
    #[test]
    fn run_command_with_timeout_kills_and_reports_hanging_child_10122() {
        const SLEEP_ROLE_ENV: &str = "AI_MEMORY_TEST_10122_TIMEOUT_SLEEP_ROLE";
        const TEST: &str =
            "test_support::tests::run_command_with_timeout_kills_and_reports_hanging_child_10122";
        const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(150);
        const MAX_WALL_ELAPSED: std::time::Duration = std::time::Duration::from_secs(5);
        if std::env::var_os(SLEEP_ROLE_ENV).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        let sandbox = super::TestSandbox::new();
        let child = super::SandboxedTestChild::new(
            "test_support::run_command_with_timeout_kills_and_reports_hanging_child_10122",
            &sandbox,
        )
        .args(["--exact", TEST, "--test-threads=1"])
        .env(SLEEP_ROLE_ENV, "1");
        let start = std::time::Instant::now();
        let err = child
            .run_bounded(SHORT_BOUND, TEST)
            .expect_err("sleeping child must time out");
        let elapsed = start.elapsed();
        assert!(
            err.starts_with(super::TEST_CHILD_TIMEOUT_PREFIX),
            "expected timeout prefix, got: {err}"
        );
        assert!(
            err.contains(TEST),
            "timeout message must name the child label: {err}"
        );
        assert!(
            elapsed < MAX_WALL_ELAPSED,
            "timeout kill took too long: {elapsed:?}"
        );
    }

    /// #10122 (C-F3, kills mutant M6) — `spawn_test_child` MUST execute through
    /// the bounded wait so a hanging child is killed and reported with
    /// `TEST_CHILD_TIMEOUT_PREFIX`.
    #[cfg(unix)]
    #[test]
    fn spawn_test_child_enforces_timeout_10122() {
        const SLEEP_ROLE_ENV: &str = "AI_MEMORY_TEST_10122_SPAWN_TEST_TIMEOUT_ROLE";
        const TEST: &str = "test_support::tests::spawn_test_child_enforces_timeout_10122";
        const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(150);
        const MAX_WALL_ELAPSED: std::time::Duration = std::time::Duration::from_secs(5);
        if std::env::var_os(SLEEP_ROLE_ENV).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        let start = std::time::Instant::now();
        let sandbox = super::TestSandbox::new();
        let err = super::spawn_test_child_with_timeout(
            &sandbox,
            TEST,
            &[(SLEEP_ROLE_ENV, "1")],
            SHORT_BOUND,
        )
        .expect_err("sleeping spawn_test_child must time out");
        let elapsed = start.elapsed();
        assert!(
            err.starts_with(super::TEST_CHILD_TIMEOUT_PREFIX),
            "expected timeout prefix, got: {err}"
        );
        assert!(
            err.contains(TEST),
            "timeout message must name the child label: {err}"
        );
        assert!(
            elapsed < MAX_WALL_ELAPSED,
            "spawn_test_child timeout kill took too long: {elapsed:?}"
        );
    }

    /// #10122 (C-F3, kills mutant M5) — `spawn_env_isolated_child` MUST execute
    /// through the bounded wait so a hanging child is killed and reported with
    /// `TEST_CHILD_TIMEOUT_PREFIX`.
    #[cfg(unix)]
    #[test]
    fn spawn_env_isolated_child_enforces_timeout_10122() {
        const TEST: &str = "test_support::tests::spawn_env_isolated_child_enforces_timeout_10122";
        const SHORT_BOUND: std::time::Duration = std::time::Duration::from_millis(150);
        const MAX_WALL_ELAPSED: std::time::Duration = std::time::Duration::from_secs(5);
        if std::env::var(super::TEST_ENV_ISOLATION_ROLE_ENV).as_deref() == Ok("child") {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        let start = std::time::Instant::now();
        let err = super::try_spawn_env_isolated_child_with_timeout(TEST, &[], SHORT_BOUND)
            .expect_err("sleeping spawn_env_isolated_child must time out");
        let elapsed = start.elapsed();
        assert!(
            err.starts_with(super::TEST_CHILD_TIMEOUT_PREFIX),
            "expected timeout prefix, got: {err}"
        );
        assert!(
            err.contains(TEST),
            "timeout message must name the child label: {err}"
        );
        assert!(
            elapsed < MAX_WALL_ELAPSED,
            "spawn_env_isolated_child timeout kill took too long: {elapsed:?}"
        );
    }

    /// #10122 (C-F4, ERRORS-19) — a missing or unreadable child capture file
    /// MUST surface an explicit error naming the stream and label instead of
    /// silently collapsing to empty bytes via `unwrap_or_default()`.
    #[cfg(any(test, unix))]
    #[test]
    fn read_child_capture_surfaces_io_error_10122() {
        let scratch = crate::identity::test_key_dir::private_tempdir();
        let missing = scratch.path().join("missing-stdout-capture");
        let err = super::read_child_capture(&missing, "stdout", "capture-probe-10122")
            .expect_err("missing capture file must error");
        assert!(
            err.contains("read child stdout capture for capture-probe-10122"),
            "expected explicit capture-read error, got: {err}"
        );
    }

    /// #3577 — `LineageDagIsolation` restores BOTH flags on drop,
    /// including the "was false" case a seeder must not leak.
    ///
    /// Snapshot, mutate, and restore MUST all run while this guard
    /// holds the funnel. A process-global read before `new()` or after
    /// `Drop` races sibling seeders: the 20:43Z battery saw
    /// `before=(true,true)` from
    /// `sqlite_finalize_and_disposition_tombstone_disposition` and
    /// `after=(false,false)` from this guard's captured prev. std
    /// `Mutex` is not reentrant (CONCURRENCY-04), so we cannot take
    /// the lock and then construct a second `LineageDagIsolation`.
    /// `restore_flags` is what `Drop` calls; asserting under the same
    /// hold proves the write-back without a lock-release window.
    #[test]
    fn lineage_dag_isolation_restores_pre_guard_state_3577() {
        let g = LineageDagIsolation::new();
        let before = (g.prev_dag, g.prev_tombstone);
        g.set_lineage_dag(!before.0);
        g.set_consolidate_tombstone_sources(!before.1);
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            (!before.0, !before.1)
        );
        g.restore_flags();
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            before,
            "#3577: LineageDagIsolation must restore both flags on drop"
        );
    }

    /// #3577 — the OBSERVED singleton: holding the isolation guard, a
    /// probe thread must fail to acquire the same mutex.
    #[test]
    fn lineage_dag_isolation_serialises_probe_thread_3577() {
        let _held = LineageDagIsolation::new();
        let probe_acquired = std::thread::spawn(|| lineage_dag_mutex().try_lock().is_ok())
            .join()
            .expect("probe thread must not panic");
        assert!(
            !probe_acquired,
            "#3577: a probe thread acquired the lineage-DAG mutex while \
             LineageDagIsolation was held"
        );
    }

    /// #3577 — the reader funnel succeeds when the flag is OFF (the
    /// unseeded atomic default). The loud assert-on-true path is the
    /// same `assert!` the seeder-leak message names; exercising it
    /// here would require leaking `true` without holding the lock,
    /// which is the defect this funnel exists to close.
    #[test]
    fn no_lineage_dag_guard_holds_when_off_3577() {
        let _g = no_lineage_dag_guard();
        assert!(!crate::config::lineage_dag_enabled());
    }

    /// #3577 — production-boot simulation restores BOTH flags on drop
    /// even when it flipped them ON for the seeder body. Same lock-hold
    /// as [`lineage_dag_isolation_restores_pre_guard_state_3577`]: no
    /// unlocked before/after snapshot.
    #[test]
    fn simulate_production_lineage_seed_restores_pre_guard_state_3577() {
        let g = simulate_production_lineage_seed();
        let before = (g.prev_dag, g.prev_tombstone);
        assert!(crate::config::lineage_dag_enabled());
        assert!(crate::config::consolidate_tombstone_sources_enabled());
        g.restore_flags();
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            before,
            "#3577: simulate_production_lineage_seed must restore both flags on drop"
        );
    }

    // ---------------------------------------------------------------------
    // #10176 (MEDIUM 10189 / LOW 10188) — a lib-test child's environment is
    // built from nothing. The driver re-runs itself in an isolated process,
    // plants every sandbox, custody and canary name at a path OUTSIDE any
    // sandbox, moves its own cwd there, then spawns the probe through every
    // spawner. The probe fails naming each variable that arrived.
    // ---------------------------------------------------------------------

    /// What the probe child must see for one variable.
    #[derive(Clone, Copy)]
    enum ChildEnvExpect10176 {
        /// Exactly `<sandbox root>/<rel>`.
        SandboxPath(&'static str),
        /// Unset, or a path inside the sandbox root (the child's own
        /// `test_key_dir::install` may arm one there).
        UnsetOrInsideSandbox,
        /// Never present in the child.
        Unset,
    }

    /// Hand-written expected column (rust-first-pass: never derived from the
    /// code under test).
    const CHILD_ENV_EXPECTED_10176: &[(&str, ChildEnvExpect10176)] = &[
        ("HOME", ChildEnvExpect10176::SandboxPath("home")),
        ("USERPROFILE", ChildEnvExpect10176::SandboxPath("home")),
        (
            "XDG_CONFIG_HOME",
            ChildEnvExpect10176::SandboxPath("home/.config"),
        ),
        (
            "XDG_DATA_HOME",
            ChildEnvExpect10176::SandboxPath("home/.local/share"),
        ),
        (
            "XDG_STATE_HOME",
            ChildEnvExpect10176::SandboxPath("home/.local/state"),
        ),
        (
            "XDG_CACHE_HOME",
            ChildEnvExpect10176::SandboxPath("home/.cache"),
        ),
        ("XDG_RUNTIME_DIR", ChildEnvExpect10176::SandboxPath("run")),
        ("TMPDIR", ChildEnvExpect10176::SandboxPath("tmp")),
        ("TMP", ChildEnvExpect10176::SandboxPath("tmp")),
        ("TEMP", ChildEnvExpect10176::SandboxPath("tmp")),
        (
            "AI_MEMORY_WITNESS_KEY_DIR",
            ChildEnvExpect10176::SandboxPath("home/witness-keys"),
        ),
        (
            "AI_MEMORY_KEY_DIR",
            ChildEnvExpect10176::UnsetOrInsideSandbox,
        ),
        ("AI_MEMORY_DB", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_AUDIT_DIR", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_RECORDER_KEY_DIR", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_JUDGE_KEY_DIR", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_STOPPER_KEY_DIR", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_STOPPER_PUBKEY", ChildEnvExpect10176::Unset),
        ("AI_MEMORY_10176_CANARY", ChildEnvExpect10176::Unset),
    ];

    /// Hex of the planted root; its presence makes the probe run.
    const PROBE_PLANTED_ENV_10176: &str = "AI_MEMORY_TEST_10176_PLANTED_HEX";
    /// Printed by the probe once every check ran, so a probe that never saw
    /// its role cannot count as green.
    const PROBE_RAN_10176: &str = "child-env-probe-10176: checked";
    const PROBE_PATH_10176: &str = "test_support::tests::child_env_probe_10176";
    const DRIVER_PATH_10176: &str = "test_support::tests::child_env_is_built_from_nothing_10176";

    fn hex_encode_10176(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn hex_decode_10176(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("planted hex"))
            .collect()
    }

    /// The probe: a no-op unless the driver handed it the planted root.
    #[cfg(unix)]
    #[test]
    fn child_env_probe_10176() {
        use std::os::unix::ffi::OsStringExt as _;
        let Ok(planted_hex) = std::env::var(PROBE_PLANTED_ENV_10176) else {
            return;
        };
        let planted =
            std::path::PathBuf::from(std::ffi::OsString::from_vec(hex_decode_10176(&planted_hex)));
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        let root = home
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        let mut arrived = Vec::new();
        for (name, expect) in CHILD_ENV_EXPECTED_10176 {
            let got = std::env::var_os(name).map(std::path::PathBuf::from);
            let ok = match (*expect, &got) {
                (ChildEnvExpect10176::SandboxPath(rel), Some(v)) => *v == root.join(rel),
                (ChildEnvExpect10176::UnsetOrInsideSandbox, Some(v)) => {
                    v.starts_with(&root) && !v.starts_with(planted.join(name))
                }
                (ChildEnvExpect10176::UnsetOrInsideSandbox | ChildEnvExpect10176::Unset, None) => {
                    true
                }
                (ChildEnvExpect10176::SandboxPath(_), None)
                | (ChildEnvExpect10176::Unset, Some(_)) => false,
            };
            if !ok {
                arrived.push((*name).to_string());
            }
        }
        if home == planted.join("HOME") {
            arrived.push("HOME (planted value)".to_string());
        }
        match std::env::current_dir() {
            Ok(cwd) if cwd == root => {}
            _ => arrived.push("cwd".to_string()),
        }
        match crate::identity::keypair::resolved_default_key_dir_path() {
            Ok(dir) if dir.starts_with(&root) && !dir.starts_with(&planted) => {}
            _ => arrived.push("resolved key dir".to_string()),
        }
        assert!(
            arrived.is_empty(),
            "#10176: the child environment was not built from nothing; outside-sandbox state arrived for: {arrived:?}"
        );
        println!("{PROBE_RAN_10176}");
    }

    /// Plant every name of [`CHILD_ENV_EXPECTED_10176`] at `<planted>/<NAME>`.
    #[cfg(unix)]
    fn plant_child_env_10176(planted: &std::path::Path) -> Vec<EnvGuard> {
        CHILD_ENV_EXPECTED_10176
            .iter()
            .map(|(name, _)| {
                let dir = planted.join(name);
                std::fs::create_dir_all(&dir).expect("planted dir");
                let guard = EnvGuard::capture(name);
                guard.set(dir.to_str().expect("utf-8 planted dir"));
                guard
            })
            .collect()
    }

    #[cfg(unix)]
    fn probe_outcome_10176(
        spawner: &str,
        out: Result<std::process::Output, String>,
    ) -> Option<String> {
        match out {
            Err(e) => Some(format!("{spawner}: {e}")),
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if out.status.success()
                    && stdout.contains("1 passed")
                    && stdout.contains(PROBE_RAN_10176)
                {
                    None
                } else {
                    Some(format!(
                        "{spawner}: probe failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    ))
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn child_env_is_built_from_nothing_10176() {
        use std::os::unix::ffi::OsStrExt as _;
        if super::run_env_isolated_child_or_spawn(DRIVER_PATH_10176) {
            return;
        }
        // This body runs alone in its own process, so moving the cwd and the
        // environment cannot race another test.
        let _lock = env_lock();
        // The sandbox base is fixed before anything is planted, so a planted
        // TMPDIR cannot move it (the base is a process-wide OnceLock).
        let _ = super::child_sandbox_base();
        let sandbox = super::TestSandbox::new();
        let planted_dir = crate::identity::test_key_dir::private_tempdir();
        let planted = planted_dir.path().to_path_buf();
        let _guards = plant_child_env_10176(&planted);
        std::env::set_current_dir(&planted).expect("cwd to planted root");
        let hex = hex_encode_10176(planted.as_os_str().as_bytes());
        let mut failures = Vec::new();

        let builder = super::SandboxedTestChild::new("test_support::child_env_10176", &sandbox)
            .args([
                "--exact",
                PROBE_PATH_10176,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROBE_PLANTED_ENV_10176, &hex)
            .run_bounded(super::TEST_CHILD_TIMEOUT, "child_env_10176 builder");
        failures.extend(probe_outcome_10176("SandboxedTestChild", builder));

        let spawned = std::panic::catch_unwind(|| {
            super::spawn_test_child(
                &sandbox,
                PROBE_PATH_10176,
                &[(PROBE_PLANTED_ENV_10176, hex.as_str())],
            )
        })
        .map_err(|_| "spawn_test_child panicked".to_string());
        failures.extend(probe_outcome_10176("spawn_test_child", spawned));

        let isolated = std::panic::catch_unwind(|| {
            super::spawn_env_isolated_child(
                PROBE_PATH_10176,
                &[(PROBE_PLANTED_ENV_10176, hex.as_str())],
            )
        });
        if isolated.is_err() {
            failures.push("spawn_env_isolated_child: probe failed (see panic above)".to_string());
        }
        assert!(failures.is_empty(), "#10176: {failures:#?}");
    }
}

/// Captures formatted tracing output (no ANSI, no timestamps).
#[derive(Clone, Default)]
pub(crate) struct CapturedLines(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CapturedLines {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLines {
    type Writer = CapturedLines;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
/// A DEBUG-level capturing subscriber plus the sink it writes to. Shared by
/// the #4310 (forensic writer) and #4318 (flat audit trail) rate-limit cells.
///
/// #4090: the CALLER installs it (`tracing::subscriber::with_default`) inside
/// a test guarded by `run_env_isolated_child_or_spawn`, so the install is
/// visible to the isolation census; the install is deliberately not hidden in
/// this shared helper where no guard can precede it.
pub(crate) fn error_debug_capture() -> (impl tracing::Subscriber + Send + Sync, CapturedLines) {
    let sink = CapturedLines::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(sink.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    (subscriber, sink)
}

/// The (ERROR, DEBUG) line counts a [`error_debug_capture`] sink received.
pub(crate) fn count_error_and_debug_lines(sink: &CapturedLines) -> (usize, usize) {
    let text = String::from_utf8_lossy(
        &sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    let count = |level: &str| text.lines().filter(|l| l.contains(level)).count();
    (count("ERROR"), count("DEBUG"))
}

/// Panics with `expected <expected>, got <label>` for an unexpected
/// [`crate::config::KeySource`]. The label comes from `as_str` (never the
/// `Debug` form, which would carry the key-source payload) per the #8179
/// CodeQL fix; shared by the `config` key-resolution tests (#8179).
#[cold]
#[track_caller]
pub(crate) fn key_panic(expected: &str, got: &crate::config::KeySource) -> ! {
    panic!("expected {expected}, got {}", got.as_str())
}

#[test]
fn key_panic_messages_pinned_8179() {
    use crate::config::KeySource;
    for e in [
        "AliasFallback(XAI_API_KEY)",
        "ConfigEnvVar(MY_CUSTOM_LLM_KEY)",
        "KeySource::Error(lax perms)",
        "AliasFallback(OPENROUTER_API_KEY)",
        "ConfigEnvVar(MY_CUSTOM_EMBED_KEY)",
        "KeySource::Error",
    ] {
        let r = std::panic::catch_unwind(|| key_panic(e, &KeySource::ProcessEnv));
        let m = r.unwrap_err().downcast::<String>().unwrap();
        assert_eq!(
            *m,
            format!("expected {e}, got {}", KeySource::ProcessEnv.as_str())
        );
    }
}
