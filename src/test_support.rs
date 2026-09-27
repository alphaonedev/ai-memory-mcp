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

/// The ONE process-wide lock for the process current directory.
///
/// `std::env::set_current_dir` changes a value every thread in the lib test
/// binary reads. Any test that changes the cwd holds this lock for as long
/// as the cwd differs from its saved value, and so does any test whose
/// assertion depends on the cwd staying put between two reads. Before this
/// lock existed, `cli::helpers` had a private one, while `cli::boot` and
/// `migrate` changed the cwd with no lock at all, so the private lock
/// excluded nobody else.
///
/// A poisoned lock is recovered: the panicking test's restore already ran,
/// or the next holder saves whatever cwd it finds.
pub(crate) fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `<repo>/.local-runs/<tag>`, created if absent. This is the in-tree
/// scratch root the project's no-`/tmp` rule requires.
///
/// The path is anchored on `CARGO_MANIFEST_DIR`, fixed at compile time,
/// and NEVER on `std::env::current_dir()`. A fixture root built from the
/// cwd resolves against whatever directory a concurrent test has switched
/// the process to. That may be `/`, or a tempdir that is deleted by the
/// time the fixture opens its database: four `recover::tests` cells failed
/// that way under a full parallel lib run with `DbOpen("failed to open
/// database")` and zero writes, and each passed alone.
pub(crate) fn local_runs_root(tag: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join(tag);
    std::fs::create_dir_all(&root).expect("create the .local-runs fixture root");
    root
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
/// Generated once with rcgen under `TMPDIR` (the `TempDir` lives for the
/// process; it is dropped with the static, never leaked).
pub(crate) struct TlsTestPki {
    _dir: tempfile::TempDir,
    /// The CA certificate (PEM) a client adds as its root.
    pub(crate) ca_pem: PathBuf,
    /// The leaf certificate (PEM) a mock listener presents.
    pub(crate) leaf_pem: PathBuf,
    /// The leaf's PKCS#8 private key (PEM, mode 0600).
    pub(crate) leaf_key_pem: PathBuf,
}

static TLS_TEST_PKI: OnceLock<TlsTestPki> = OnceLock::new();

/// The process-wide [`TlsTestPki`] (generated on first use).
pub(crate) fn tls_test_pki() -> &'static TlsTestPki {
    TLS_TEST_PKI.get_or_init(generate_tls_test_pki)
}

fn generate_tls_test_pki() -> TlsTestPki {
    let dir = tempfile::tempdir().expect("TMPDIR tempdir for the #3705 test PKI");
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
    std::fs::write(&leaf_key_pem, leaf_key.serialize_pem()).expect("write test leaf key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf_key_pem, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 test leaf key");
    }
    TlsTestPki {
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

#[cfg(test)]
mod tests {
    use super::{
        EnvGuard, LineageDagIsolation, env_lock, env_mutex, lineage_dag_mutex,
        no_lineage_dag_guard, simulate_production_lineage_seed,
    };

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

    fn is_ident_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// #4015/#4016: every source line with comments (`//`, nested `/* */`,
    /// across lines) and the CONTENTS of string, raw-string and char literals
    /// removed, and whitespace dropped except one space between two identifier
    /// characters (so `env as e` survives and `std :: env` does not split).
    /// Neither spacing, a comment nor a literal can hide or fake a cwd access.
    fn cwd_scan_normalise(lines: &[&str]) -> Vec<String> {
        // `None` = code; `Some(None)` = "..." string; `Some(Some(n))` = raw string with n hashes.
        let mut in_str: Option<Option<usize>> = None;
        let mut block_depth = 0usize;
        let mut out_lines = Vec::with_capacity(lines.len());
        for line in lines {
            let cs: Vec<char> = line.chars().collect();
            let at = |k: usize| cs.get(k).copied();
            let mut out = String::new();
            let mut pending_space = false;
            let mut i = 0;
            while i < cs.len() {
                let c = cs[i];
                if block_depth > 0 {
                    if c == '*' && at(i + 1) == Some('/') {
                        block_depth -= 1;
                        i += 2;
                    } else if c == '/' && at(i + 1) == Some('*') {
                        block_depth += 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                match in_str {
                    Some(None) => {
                        if c == '\\' {
                            i += 2;
                            continue;
                        }
                        if c == '"' {
                            in_str = None;
                            out.push('"');
                        }
                        i += 1;
                        continue;
                    }
                    Some(Some(hashes)) => {
                        if c == '"' && (1..=hashes).all(|k| at(i + k) == Some('#')) {
                            in_str = None;
                            out.push('"');
                            i += 1 + hashes;
                        } else {
                            i += 1;
                        }
                        continue;
                    }
                    None => {}
                }
                if c == '/' && at(i + 1) == Some('/') {
                    break;
                }
                if c == '/' && at(i + 1) == Some('*') {
                    block_depth += 1;
                    i += 2;
                    continue;
                }
                let prev_is_ident = i > 0 && is_ident_char(cs[i - 1]);
                if !prev_is_ident && (c == 'r' || (c == 'b' && at(i + 1) == Some('r'))) {
                    let mut j = if c == 'b' { i + 2 } else { i + 1 };
                    let mut hashes = 0;
                    while at(j) == Some('#') {
                        hashes += 1;
                        j += 1;
                    }
                    if at(j) == Some('"') {
                        in_str = Some(Some(hashes));
                        out.push('"');
                        pending_space = false;
                        i = j + 1;
                        continue;
                    }
                }
                if c == '"' {
                    in_str = Some(None);
                    out.push('"');
                    pending_space = false;
                    i += 1;
                    continue;
                }
                if c == '\'' {
                    // A char literal (`'"'`, `'\''`) is skipped whole; a lifetime is kept.
                    if at(i + 1) == Some('\\') {
                        let close = (i + 3..cs.len()).find(|&k| cs[k] == '\'');
                        out.push_str("''");
                        i = close.map_or(cs.len(), |k| k + 1);
                        continue;
                    }
                    if at(i + 2) == Some('\'') {
                        out.push_str("''");
                        i += 3;
                        continue;
                    }
                }
                if c.is_whitespace() {
                    pending_space = true;
                    i += 1;
                    continue;
                }
                if pending_space
                    && is_ident_char(c)
                    && out.chars().last().is_some_and(is_ident_char)
                {
                    out.push(' ');
                }
                pending_space = false;
                out.push(c);
                i += 1;
            }
            out_lines.push(out);
        }
        out_lines
    }

    /// Whether `raw` opens a function item (`pub async fn name(..`).
    fn is_fn_header(raw: &str) -> bool {
        for token in raw.split_whitespace() {
            match token {
                "pub" | "async" | "unsafe" | "const" | "extern" => {}
                t if t.starts_with("pub(") || t.starts_with('"') => {}
                "fn" => return true,
                _ => return false,
            }
        }
        false
    }

    // Split so this file cannot match its own needles.
    const CWD_READ_IDENTS: &[[&str; 2]] = &[["current", "_dir"], ["getc", "wd"]];
    const CWD_WRITE_IDENTS: &[[&str; 2]] = &[["set_current", "_dir"], ["ch", "dir"]];

    /// Whether a normalised line names a process-cwd primitive as an
    /// IDENTIFIER, whatever its path prefix (`std::env::`, a module alias, a
    /// glob import or none). A METHOD call (`.current_dir(` — the
    /// `Command::current_dir` builder, which sets a CHILD's cwd), a struct
    /// field (`current_dir:`) and a definition (`fn current_dir`) are not
    /// process-cwd accesses.
    fn names_a_cwd_primitive(line: &str) -> bool {
        CWD_READ_IDENTS
            .iter()
            .chain(CWD_WRITE_IDENTS)
            .any(|ident| names_ident(line, &ident.concat()))
    }

    /// Whether a normalised line names a primitive that MOVES the process
    /// cwd. A writer must run in a re-exec'd child: a held `cwd_lock()` is not
    /// enough, because an INDIRECT reader (a test calling a production fn that
    /// reads the cwd, the #4016 shape) cannot be seen by this scan and so need
    /// not hold the lock. With no in-process writer, every reader is race-free.
    fn names_a_cwd_writer(line: &str) -> bool {
        CWD_WRITE_IDENTS
            .iter()
            .any(|ident| names_ident(line, &ident.concat()))
    }

    /// Whether `ident` occurs in a normalised line as an identifier token.
    fn names_ident(line: &str, ident: &str) -> bool {
        line.match_indices(ident).any(|(pos, _)| {
            let before = line[..pos].chars().last();
            let after = &line[pos + ident.len()..];
            !before.is_some_and(|b| is_ident_char(b) || b == '.')
                && !after.chars().next().is_some_and(is_ident_char)
                && !(after.starts_with(':') && !after.starts_with("::"))
                && !line[..pos].ends_with("fn ")
        })
    }

    /// Whether a normalised line is a `use` that can bring a cwd primitive
    /// into scope under another name: a glob or alias of the `env` module,
    /// or any `use` naming a cwd primitive.
    fn is_cwd_reaching_use(line: &str) -> bool {
        let rest = line.strip_prefix("pub ").unwrap_or(line);
        let rest = if rest.starts_with("pub(") {
            rest.find(')').map_or(rest, |k| &rest[k + 1..])
        } else {
            rest
        };
        let rest = rest.trim_start();
        rest.starts_with("use ")
            && (names_a_cwd_primitive(rest)
                || rest.contains("env::*")
                || rest.contains("env as ")
                || rest.contains("env::{") && (rest.contains("self") || rest.contains('*')))
    }

    /// The name bound by `let <name>[: T] = …cwd_lock(…)`, if this normalised
    /// line holds the ONE cwd lock in a named binding. `let _ = cwd_lock()`
    /// drops the guard at once and binds nothing, so it is not a hold.
    fn cwd_lock_binding(line: &str) -> Option<(usize, String)> {
        let lock = ["cwd", "_lock("].concat();
        let pos = line.find("let ")?;
        let after_let = &line[pos + 4..];
        let after_let = after_let.strip_prefix("mut ").unwrap_or(after_let);
        let name: String = after_let
            .chars()
            .take_while(|c| is_ident_char(*c))
            .collect();
        let tail = &after_let[name.len()..];
        let value = tail.find('=').map(|k| &tail[k + 1..])?;
        let bound =
            !name.is_empty() && name != "_" && (tail.starts_with('=') || tail.starts_with(':'));
        let lock_at = value.find(lock.as_str())?;
        let lock_called = !value[..lock_at].chars().last().is_some_and(is_ident_char);
        (bound && lock_called).then_some((pos, name))
    }

    /// Apply `text`'s braces to the scope `depth`; a held lock whose block
    /// closes is released.
    fn track_braces(text: &str, depth: &mut i64, held: &mut Vec<(String, i64)>) {
        for ch in text.chars() {
            match ch {
                '{' => *depth += 1,
                '}' => {
                    *depth -= 1;
                    let d = *depth;
                    held.retain(|(_, at)| *at <= d);
                }
                _ => {}
            }
        }
    }

    /// Whether the `if` opened on normalised line `j` has a body that
    /// `return`s. `run_env_isolated_child_or_spawn` answers `true` in the
    /// PARENT after the child has run, so an `if` without a `return` lets the
    /// parent run the rest of the test in-process: that is not isolation.
    fn isolation_block_returns(norm: &[String], j: usize) -> bool {
        let mut depth = 0usize;
        let mut body = String::new();
        for line in &norm[j..] {
            for ch in line.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        if depth == 1 {
                            continue;
                        }
                    }
                    '}' if depth > 0 => {
                        depth -= 1;
                        if depth == 0 {
                            return names_ident(&body, "return");
                        }
                    }
                    _ => {}
                }
                if depth > 0 {
                    body.push(ch);
                }
            }
            if depth > 0 {
                body.push(' ');
            }
        }
        false
    }

    /// #4015/#4016 class rule, as a pure function so its own mutants can be
    /// tested: the 0-based indices of TEST-code lines that reach the process
    /// cwd (`current_dir` / `set_current_dir` / `chdir` / `getcwd`, named as
    /// an identifier under any path, alias or glob) while the enclosing fn
    /// neither HOLDS the ONE cwd lock (a named `let` binding still in scope
    /// and not `drop`ped at the access) nor returns early from
    /// `if …run_env_isolated_child_or_spawn(…)`. A `use` that could bring a
    /// primitive into scope under another name is always a violation. The
    /// process cwd is shared by every test in the lib binary, so an unlocked
    /// read races any writer (tmux-22's R2b retest: 17/20 red) and a fixture
    /// root built from it can resolve under `/` or a deleted tempdir (#4015).
    ///
    /// A WRITER (`set_current_dir` / `chdir`) is satisfied ONLY by the child
    /// isolation, never by a held lock: an indirect reader (a test calling a
    /// production fn that reads the cwd) is invisible here, so the class is
    /// closed by having no in-process writer at all.
    ///
    /// Out of scope, by construction (residuals, named so no one relies on
    /// them): IMPLICIT cwd resolution (a RELATIVE path such as
    /// `Path::new(".")` or `fs::canonicalize(".")`) is not a named access;
    /// a lock held by a CALLER cannot be seen from the callee, so a helper
    /// that reaches the cwd must take the lock (or the isolation) itself; a
    /// `drop(g)` or block close on the SAME line as the access is not seen
    /// (rustfmt splits statements, so `cargo fmt --check` blocks it); a
    /// guard MOVED to another binding (`let h = g; drop(h);`) still reads as
    /// held; and identifiers generated by macros (`paste!`) are not visible
    /// to a source scan.
    fn unguarded_cwd_access(lines: &[&str], is_test: &[bool]) -> Vec<usize> {
        let norm = cwd_scan_normalise(lines);
        let isolate = ["run_env_isolated_child", "_or_spawn("].concat();
        let mut out = Vec::new();
        for (i, line) in norm.iter().enumerate() {
            if !is_test.get(i).copied().unwrap_or(false) {
                continue;
            }
            if is_cwd_reaching_use(line) {
                out.push(i);
                continue;
            }
            if !names_a_cwd_primitive(line) {
                continue;
            }
            let start = (0..=i)
                .rev()
                .find(|&j| !norm[j].is_empty() && is_fn_header(lines[j]));
            let guarded = start.is_some_and(|start| {
                let mut depth: i64 = 0;
                let mut held: Vec<(String, i64)> = Vec::new();
                let mut isolated = false;
                for (j, l) in norm.iter().enumerate().take(i).skip(start) {
                    if l.starts_with("if ")
                        && l.contains(isolate.as_str())
                        && isolation_block_returns(&norm, j)
                    {
                        isolated = true;
                    }
                    held.retain(|(name, _)| !l.contains(&format!("drop({name})")));
                    if let Some((pos, name)) = cwd_lock_binding(l) {
                        track_braces(&l[..pos], &mut depth, &mut held);
                        held.push((name, depth));
                        track_braces(&l[pos..], &mut depth, &mut held);
                    } else {
                        track_braces(l, &mut depth, &mut held);
                    }
                }
                isolated || (!held.is_empty() && !names_a_cwd_writer(line))
            });
            if !guarded {
                out.push(i);
            }
        }
        out
    }

    /// The test-line mask of one source file, from the repo's SSOT
    /// `scripts/lib/production-lines.awk` (which blanks test lines and keeps
    /// the numbering). A file named like `*_tests.rs` is test code throughout,
    /// exactly as `scripts/lib/production-lines.sh` treats it.
    fn test_line_mask(path: &std::path::Path, lines: &[&str]) -> Vec<bool> {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let whole_file_is_test = stem
            .split('_')
            .any(|part| part == "test" || part == "tests");
        if whole_file_is_test {
            return vec![true; lines.len()];
        }
        let awk = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts/lib/production-lines.awk");
        let output = crate::spawn_audit::audited_command("awk", "test_support::test_line_mask")
            .arg("-f")
            .arg(&awk)
            .arg(path)
            .output()
            .expect("run production-lines.awk");
        assert!(
            output.status.success(),
            "production-lines.awk failed on {}",
            path.display()
        );
        let production = String::from_utf8_lossy(&output.stdout).into_owned();
        let production: Vec<&str> = production.lines().collect();
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                !l.trim().is_empty() && production.get(i).is_none_or(|p| p.trim().is_empty())
            })
            .collect()
    }

    /// #4015/#4016 class guard over `src/`: every test-code read or move of
    /// the process cwd holds the ONE cwd lock or runs in an isolated child.
    #[test]
    fn test_code_process_cwd_access_holds_the_cwd_lock_4015_4016() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        assert!(files.len() > 100, "the scan must see the source tree");
        let mut offenders = Vec::new();
        let mut test_lines_seen = 0usize;
        for file in &files {
            let text = std::fs::read_to_string(file).expect("read source file");
            let lines: Vec<&str> = text.lines().collect();
            let mask = test_line_mask(file, &lines);
            test_lines_seen += mask.iter().filter(|t| **t).count();
            for i in unguarded_cwd_access(&lines, &mask) {
                offenders.push(format!("{}:{}", file.display(), i + 1));
            }
        }
        assert!(test_lines_seen > 10_000, "the mask must find the test code");
        assert!(
            offenders.is_empty(),
            "test code reads or moves the process cwd without crate::test_support::cwd_lock() \
             or config::run_env_isolated_child_or_spawn (use test_support::local_runs_root for \
             fixture roots): {offenders:?}"
        );
    }

    /// The class rule catches every evasion the R2b retest (tmux-22) and the
    /// 6ce9eccdf review (f2r) used to slip past earlier guards, and nothing else.
    #[test]
    fn cwd_access_rule_catches_the_r2b_mutants_4015_4016() {
        let flagged = |src: &str| {
            let lines: Vec<&str> = src.lines().collect();
            unguarded_cwd_access(&lines, &vec![true; lines.len()])
        };
        let must_flag: &[(&str, &str, Vec<usize>)] = &[
            (
                "direct",
                "fn r() -> P {\n    std::env::current_dir().unwrap()\n}",
                vec![1],
            ),
            (
                "spaced",
                "fn r() -> P {\n    std :: env :: current_dir ( ).unwrap()\n}",
                vec![1],
            ),
            (
                "split over comments",
                "fn r() -> P {\n    let c = std::env::current_dir().unwrap();\n    // a\n    // b\n    c.join(\"x\")\n}",
                vec![1],
            ),
            (
                "alias import",
                "use std::env::current_dir as cwd;\nfn r() {\n    cwd().ok();\n}",
                vec![0],
            ),
            (
                "unlocked writer",
                "fn t() {\n    std::env::set_current_dir(p).unwrap();\n}",
                vec![1],
            ),
            // f2r @ a805fa46e: a lock does not satisfy a writer; only child isolation does.
            (
                "locked writer",
                "fn t() {\n    let _l = cwd_lock();\n    std::env::set_current_dir(p).unwrap();\n}",
                vec![2],
            ),
            (
                "locked libc chdir",
                "fn t() {\n    let _l = cwd_lock();\n    unsafe { libc::chdir(p) };\n}",
                vec![2],
            ),
            // f2r @ 35d1475cd: the helper answers true in the PARENT, so an `if`
            // that does not `return` is not isolation.
            (
                "isolation without return",
                "fn t() {\n    if run_env_isolated_child_or_spawn(\"x\") {}\n    std::env::set_current_dir(p).unwrap();\n}",
                vec![2],
            ),
            (
                "isolation block without return",
                "fn t() {\n    if run_env_isolated_child_or_spawn(\"x\") {\n        let _n = 1;\n    }\n    std::env::set_current_dir(p).unwrap();\n}",
                vec![4],
            ),
            (
                "lock in another fn",
                "fn t() {\n    let _l = cwd_lock();\n}\nfn helper() -> P {\n    std::env::current_dir().unwrap()\n}",
                vec![4],
            ),
            // f2r @ 6ce9eccdf, row 1: glob import, then a bare call.
            (
                "glob import",
                "use std::env::*;\nfn t() {\n    current_dir().ok();\n}",
                vec![0, 2],
            ),
            // Row 2: module alias.
            (
                "module alias",
                "use std::env as e;\nfn t() {\n    e::current_dir().ok();\n}",
                vec![0, 2],
            ),
            (
                "braced self alias",
                "use std::env::{self as e};\nfn t() {}",
                vec![0],
            ),
            // Row 3: a block comment is not a guard, on one line or across several.
            (
                "block-comment guard",
                "fn t() {\n    /* cwd_lock() */\n    std::env::current_dir().ok();\n}",
                vec![2],
            ),
            (
                "multi-line block-comment guard",
                "fn t() {\n    /*\n    let _l = cwd_lock();\n    */\n    std::env::current_dir().ok();\n}",
                vec![4],
            ),
            // Row 4: a lock released before the access is not held.
            (
                "dropped temporary",
                "fn t() {\n    drop(cwd_lock());\n    std::env::current_dir().ok();\n}",
                vec![2],
            ),
            (
                "let underscore",
                "fn t() {\n    let _ = cwd_lock();\n    std::env::current_dir().ok();\n}",
                vec![2],
            ),
            (
                "dropped binding",
                "fn t() {\n    let g = cwd_lock();\n    drop(g);\n    std::env::current_dir().ok();\n}",
                vec![3],
            ),
            (
                "lock in a closed block",
                "fn t() {\n    {\n        let _l = cwd_lock();\n    }\n    std::env::current_dir().ok();\n}",
                vec![4],
            ),
            // The lexer cannot be desynchronised by a quote in a literal.
            (
                "after a char quote",
                "fn t() {\n    let q = '\"';\n    std::env::current_dir().ok();\n}",
                vec![2],
            ),
            (
                "after a raw string",
                "fn t() {\n    let s = r#\"a\"b\"#;\n    std::env::current_dir().ok();\n}",
                vec![2],
            ),
            (
                "libc chdir",
                "fn t() {\n    unsafe { libc::chdir(p) };\n}",
                vec![1],
            ),
            (
                "fn pointer",
                "fn t() {\n    let f = std::env::current_dir;\n}",
                vec![1],
            ),
        ];
        for (name, src, want) in must_flag {
            assert_eq!(&flagged(src), want, "must flag: {name}");
        }
        let must_pass: &[(&str, &str)] = &[
            (
                "locked",
                "fn t() {\n    let _l = crate::test_support::cwd_lock();\n    std::env::current_dir().ok();\n}",
            ),
            (
                "locked, typed",
                "fn t() {\n    let _l: G = cwd_lock();\n    std::env::current_dir().ok();\n}",
            ),
            (
                "child-isolated",
                "fn t() {\n    if run_env_isolated_child_or_spawn(\"x\") {\n        return;\n    }\n    std::env::current_dir().ok();\n}",
            ),
            (
                "child-isolated writer",
                "fn t() {\n    if run_env_isolated_child_or_spawn(\"x\") {\n        return;\n    }\n    std::env::set_current_dir(p).unwrap();\n}",
            ),
            (
                "lock in the enclosing block",
                "fn t() {\n    let _l = cwd_lock();\n    {\n        std::env::current_dir().ok();\n    }\n}",
            ),
            (
                "Command builder",
                "fn t() {\n    cmd.current_dir(dir);\n    cmd\n        .current_dir(dir);\n}",
            ),
            ("struct field", "fn t() {\n    S { current_dir: p };\n}"),
            (
                "comment mention",
                "fn t() {\n    // std::env::current_dir() is not called\n}",
            ),
            (
                "string mention",
                "fn t() {\n    let s = \"std::env::current_dir()\";\n}",
            ),
            (
                "raw string mention",
                "fn t() {\n    let s = r#\"std::env::current_dir() \"q\" \"#;\n}",
            ),
            ("plain env import", "use std::env;\nfn t() {}"),
        ];
        for (name, src) in must_pass {
            assert!(
                flagged(src).is_empty(),
                "must pass: {name}: {:?}",
                flagged(src)
            );
        }
        let prod = ["std::env::current_dir()"];
        assert!(
            unguarded_cwd_access(&prod, &[false]).is_empty(),
            "production code is out of scope"
        );
    }
}
