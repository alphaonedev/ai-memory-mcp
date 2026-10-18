// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3705 / #3709 — "only encrypted data in transit", anywhere.
//!
//! Real binary boots (env supplied ONLY to the child, `env_clear`) plus the
//! library funnels the daemon shares with the CLI. Every test here FAILS on
//! the #3700 parent commit `4b7ddb963`, where the daemon binds plaintext
//! HTTP by default (loopback exempt), `AI_MEMORY_REQUIRE_TLS` accepts only
//! `1`/`true`, the plaintext downgrade hatches exist, `http://` peers and
//! webhook targets to loopback are accepted, and no local certificate is
//! ever generated.
//!
//! Surfaces pinned: the listener (zero-config TLS on first boot; an
//! ungeneratable certificate REFUSES, never plaintext), the selector grammar,
//! the removed downgrade paths, federation peers, webhook targets, the MCP
//! forward URL and `doctor`'s transit section. Everything that needs NEW
//! library API (the resolver, the bootstrap module, the token resolver)
//! lives in `tests/transit_encryption_3709_lib.rs`, because this file is
//! copied verbatim onto the release head for the fails-on-head proof and
//! must compile there.

use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod common;
use common::free_port;
// Shared `AI_MEMORY_TEST_TIMING_BUDGET_MULT` parse (u64 there, same
// `1..=100` / default-1 contract as `tests/integration.rs`).
#[path = "common/mcp_wait.rs"]
mod mcp_wait;
// The fails-on-head proof copies this file together with tests/common/tls.rs
// onto the release head and declares `pub mod tls;` there, so the one
// `common::tls` path serves both trees (a second by-path declaration is the
// clippy `duplicate_mod` lint).
use common::tls::{
    LOCAL_CA_CERT_FILE, LOCAL_CA_KEY_FILE, LOCAL_TLS_SUBDIR, SERVER_CERT_FILE, SERVER_KEY_FILE,
    TestTls, local_ca_client,
};

/// #7469: `doctor_reports_transit_encryption_section_3705` writes the process
/// environment (the `common::permissive_attestation_for_tests` `Once`) and then
/// opens SQLite, whose first open calls C `getenv`; the tests that build a
/// reqwest client or spawn the daemon read the environment too. All of them
/// run as threads of one test binary, so each of them holds this lock for its
/// whole body (the same file-lock shape as `mcp_driver_text_closed_3761`;
/// nothing here takes the `tests/common` `ENV_LOCK`, so there is one lock order).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The doctor section the #3705 fix adds to the DEFAULT report.
const SECTION_TRANSIT: &str = "Transit encryption (#3705)";

/// The api-key bind guard a `--host 0.0.0.0` boot stops at AFTER the transit
/// floor and the TLS bind guard: reaching it proves those let the boot through.
const BIND_GUARD_MARKER: &str = "without an API key";

/// A valid, EMPTY peer allowlist so the #3582 gate is satisfied.
const EMPTY_ALLOWLIST: &str = "{}";

/// Base boot budget, aligned to the 60 s `tests/integration.rs` ceiling
/// (#3615); [`boot_budget`] scales it on loaded hosts.
const BOOT_DEADLINE: Duration = Duration::from_secs(60);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// Base budget once the listen line is on stderr (#7341), load-scaled like
/// [`BOOT_DEADLINE`]. The daemon logs that line just BEFORE it binds
/// (`src/daemon_runtime.rs:8307`, the bind follows), so this phase still
/// covers bind, first accept, the TLS handshake and the health handler on
/// the loaded host. It equals the old fixed 45 s boot budget: for a line
/// seen at any `t` in `0..=60 s` the total worst case is `t + 45 s >= 45 s`,
/// never shorter than before; with no line the pre-listen 60 s applies.
const POST_LISTEN_BUDGET: Duration = Duration::from_secs(45);
/// The stderr line the daemon logs just before it binds the TLS listener
/// (`src/daemon_runtime.rs:8307`).
const LISTEN_SIGNAL: &str = "ai-memory listening on https://";

fn command(root: &Path) -> Command {
    command_with_config(root, None)
}

/// [`command`] with an optional `config.toml` body written under the
/// sandbox's XDG config dir (and `AI_MEMORY_NO_CONFIG` left unset so the
/// binary reads it) — the way an operator DECLARES a deployment shape.
fn command_with_config(root: &Path, config_body: Option<&str>) -> Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key sandbox");
    }
    let xdg = root.join("home/.config");
    if let Some(body) = config_body {
        let dir = xdg.join("ai-memory");
        std::fs::create_dir_all(&dir).expect("mkdir config dir");
        std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("RUST_LOG", "info");
    if config_body.is_none() {
        cmd.env("AI_MEMORY_NO_CONFIG", "1");
    }
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn key_dir(root: &Path) -> std::path::PathBuf {
    root.join("keys")
}

/// A spawned `serve` whose stderr is captured on a thread.
struct Spawned {
    child: Child,
    stderr: std::sync::Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Spawned {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ai-memory");
        let buf = std::sync::Arc::new(Mutex::new(String::new()));
        let reader = child.stderr.take().map(|err| {
            let sink = std::sync::Arc::clone(&buf);
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    let mut g = sink.lock().unwrap();
                    g.push_str(&line);
                    g.push('\n');
                }
            })
        });
        Self {
            child,
            stderr: buf,
            reader,
        }
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn captured(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    fn finish(mut self) -> String {
        self.reap();
        self.captured()
    }

    /// Kill + wait + join the reader. Idempotent.
    fn reap(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

/// A daemon spawned by a test is reaped when the handle drops — including
/// on the panic path (a failed assertion, a boot deadline). Without this a
/// failing test left `ai-memory serve` running after the test process
/// exited (thirteen orphans from one afternoon of batteries).
impl Drop for Spawned {
    fn drop(&mut self) {
        self.reap();
    }
}

fn health_url(port: u16) -> String {
    format!("{}/api/v1/health", TestTls::base_url(port))
}

/// The two boot-wait budgets (#7341), both load-scaled: `before_listen`
/// bounds the daemon's bring-up (CA and leaf generation, key load);
/// `after_listen` applies once the daemon has logged the listen line (which
/// precedes the bind, `src/daemon_runtime.rs:8307`).
struct BootBudget {
    before_listen: Duration,
    after_listen: Duration,
}

/// Scale `base` by the raw `AI_MEMORY_TEST_TIMING_BUDGET_MULT` value, parsed
/// exactly like `tests/integration.rs::health_probe_attempts` (#3615): a
/// integer in `1..=100`, otherwise 1x (`mcp_wait::budget_mult_from`). The
/// value is a parameter so tests never mutate the process environment shared
/// with parallel tests.
fn scaled_boot_budget(base: Duration, raw_mult: Option<&str>) -> Duration {
    // The clamp is `1..=100`, so the conversion never falls back.
    let mult = u32::try_from(mcp_wait::budget_mult_from(raw_mult)).unwrap_or(1);
    base.saturating_mul(mult)
}

/// [`scaled_boot_budget`] with the one production read of the environment.
fn boot_budget() -> Duration {
    let raw = std::env::var(mcp_wait::ENV_TEST_TIMING_BUDGET_MULT).ok();
    scaled_boot_budget(BOOT_DEADLINE, raw.as_deref())
}

/// Both boot-wait budgets from one read of the environment.
fn boot_budgets() -> BootBudget {
    let raw = std::env::var(mcp_wait::ENV_TEST_TIMING_BUDGET_MULT).ok();
    BootBudget {
        before_listen: scaled_boot_budget(BOOT_DEADLINE, raw.as_deref()),
        after_listen: scaled_boot_budget(POST_LISTEN_BUDGET, raw.as_deref()),
    }
}

/// Wait for the daemon's local CA file and return a client that trusts it.
/// Unlike a bare `local_ca_client` deadline, a daemon that dies first is
/// reported at once with its exit status and stderr (#7341).
fn wait_local_ca_client(
    spawned: &mut Spawned,
    key_dir: &Path,
    budget: Duration,
) -> Result<reqwest::blocking::Client, String> {
    let deadline = Instant::now() + budget;
    loop {
        // A zero deadline makes `local_ca_client` try exactly once.
        if let Some(client) = local_ca_client(key_dir, Duration::ZERO) {
            return Ok(client);
        }
        if let Some(status) = spawned.exited() {
            return Err(format!(
                "serve exited ({status}) before writing its local CA; stderr:\n{}",
                spawned.captured()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no local CA within {budget:?}; stderr:\n{}",
                spawned.captured()
            ));
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// Poll `probe` until it succeeds. Order per iteration: probe, dead-child
/// check (returns the exit status and stderr at once), then the budget. The
/// pre-listen budget applies until the daemon's listen line, logged just before
/// the bind (`src/daemon_runtime.rs:8307`), shows on the captured stderr; from
/// the first sighting only `after_listen` remains.
fn try_wait_healthy(
    spawned: &mut Spawned,
    mut probe: impl FnMut() -> bool,
    budget: &BootBudget,
) -> Result<(), String> {
    let mut deadline = Instant::now() + budget.before_listen;
    let mut listening = false;
    loop {
        if probe() {
            return Ok(());
        }
        if let Some(status) = spawned.exited() {
            return Err(format!(
                "serve exited ({status}) before /health answered over TLS; stderr:\n{}",
                spawned.captured()
            ));
        }
        if !listening && spawned.captured().contains(LISTEN_SIGNAL) {
            listening = true;
            deadline = Instant::now() + budget.after_listen;
        }
        if Instant::now() >= deadline {
            let (phase, waited) = if listening {
                ("after logging its TLS listener", budget.after_listen)
            } else {
                ("before logging its TLS listener", budget.before_listen)
            };
            return Err(format!(
                "serve never answered /health over TLS within {waited:?} {phase}; stderr:\n{}",
                spawned.captured()
            ));
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// Wait until `client` sees a 200 from the TLS health route, or the child
/// exits (returning its stderr as the error).
fn wait_healthy(spawned: &mut Spawned, client: &reqwest::blocking::Client, port: u16) {
    let budget = boot_budgets();
    let url = health_url(port);
    if let Err(why) = try_wait_healthy(
        spawned,
        || {
            client
                .get(&url)
                .send()
                .is_ok_and(|r| r.status().is_success())
        },
        &budget,
    ) {
        panic!("{why}");
    }
}

/// Run a boot that is expected to EXIT on its own; returns (status, stderr).
fn boot_until_exit(cmd: Command) -> (std::process::ExitStatus, String) {
    let mut spawned = Spawned::spawn(cmd);
    let budget = boot_budget();
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = spawned.exited() {
            let err = spawned.finish();
            return (status, err);
        }
        if Instant::now() >= deadline {
            // Reap BEFORE panicking so the daemon never outlives the test.
            let err = spawned.finish();
            panic!("serve did not exit within {budget:?} (a refusal was expected); stderr:\n{err}");
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

/// #3709 item 1 — a FRESH install with no flags and no environment serves
/// TLS: first boot generates a local CA + server certificate into
/// `<key_dir>/tls/` with the right modes, `/health` answers over HTTPS to a
/// client that trusts that CA, and the same port refuses plaintext.
///
/// FAILS ON THE PARENT: the daemon binds plaintext `http://` and never
/// writes `tls/local-ca.pem` (`local_ca_client` returns `None` → the
/// `expect` panics).
#[test]
fn fresh_install_serves_tls_with_zero_config_3709() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut cmd = command(root.path());
    cmd.args(["serve", "--port", &port.to_string()]);
    let mut spawned = Spawned::spawn(cmd);

    let client = wait_local_ca_client(&mut spawned, &key_dir(root.path()), boot_budget())
        .unwrap_or_else(|why| {
            panic!("#3709: first boot must generate tls/local-ca.pem in the key dir: {why}")
        });
    wait_healthy(&mut spawned, &client, port);

    // Material and modes.
    let tls_dir = key_dir(root.path()).join(LOCAL_TLS_SUBDIR);
    for file in [
        LOCAL_CA_CERT_FILE,
        LOCAL_CA_KEY_FILE,
        SERVER_CERT_FILE,
        SERVER_KEY_FILE,
    ] {
        assert!(tls_dir.join(file).is_file(), "{file} must exist");
    }
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&tls_dir), 0o700, "tls/ dir mode");
        for key in [LOCAL_CA_KEY_FILE, SERVER_KEY_FILE] {
            assert_eq!(mode_of(&tls_dir.join(key)), 0o600, "{key} mode");
        }
    }

    // No plaintext on that port: a plain http:// request must not succeed.
    let plain = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{port}/api/v1/health"))
        .send();
    assert!(
        !plain.is_ok_and(|r| r.status().is_success()),
        "#3705: the listener must never answer plaintext http://"
    );

    let err = spawned.finish();
    assert!(
        !err.contains("listening on http://"),
        "no plaintext listener may be announced: {err}"
    );
}

/// #3709 (3x7 audit ruling) — zero-config minting is for the DECLARED
/// SINGLETON shape only: a deployment declaring `[deployment] shape =
/// "team"` (the least demanding non-singleton shape: no hardened floor, so
/// nothing else refuses first) with no `--tls-cert`/`--tls-key` is REFUSED,
/// names the declaration and enterprise PKI as the path, and mints nothing.
///
/// FAILS ON THE PARENT: the daemon boots plaintext and stays up
/// (`boot_until_exit` times out).
#[test]
fn fleet_shape_without_certs_refuses_never_mints_3709() {
    let _env = ENV_LOCK.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut cmd = command_with_config(root.path(), Some("[deployment]\nshape = \"team\"\n"));
    cmd.args(["serve", "--port", &port.to_string()]);
    let (status, err) = boot_until_exit(cmd);
    assert!(!status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(err.contains("enterprise PKI"), "{err}");
    assert!(err.contains("--tls-cert"), "{err}");
    assert!(
        err.contains("shape = \"team\""),
        "the refusal names the operator's declaration: {err}"
    );
    assert!(!err.contains("listening"), "never a listener: {err}");
    assert!(
        !key_dir(root.path()).join(LOCAL_TLS_SUBDIR).exists(),
        "a fleet refusal must mint no local CA"
    );
}

/// #3700 ruling — a node DECLARED (or defaulting to) `singleton` whose
/// signals look like a fleet (federation configured by env) is NOT promoted
/// by what it observed: it still mints the local certificate and serves;
/// the #3700 detector warns instead. Promotion is an operator act.
#[test]
fn observed_fleet_signals_never_promote_out_of_zero_config_3709() {
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut cmd = command(root.path());
    cmd.env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST)
        .args(["serve", "--port", &port.to_string()]);
    let mut spawned = Spawned::spawn(cmd);
    let client = wait_local_ca_client(&mut spawned, &key_dir(root.path()), boot_budget())
        .unwrap_or_else(|why| {
            panic!(
                "#3700 ruling: an observed fleet signal must not stop a declared singleton from \
                 minting its local CA: {why}"
            )
        });
    wait_healthy(&mut spawned, &client, port);
    let err = spawned.captured();
    assert!(
        !err.contains("enterprise PKI"),
        "an observed signal must not promote the node into the enterprise-PKI refusal: {err}"
    );
    assert!(
        err.contains("#3700") && err.contains("[deployment]"),
        "the undeclared promotion is WARNED, naming the config line to declare: {err}"
    );
}

/// Run one ledger-writing CLI verb (`capture-turn`, the verb the #3354 suite
/// uses) against the sandbox while its key dir is still writable. On a tree
/// that carries #3354 this generates the daemon SIGNING key, which #3354's
/// boot check would otherwise refuse to generate into a read-only key dir —
/// BEFORE #3705's certificate generation runs. On this branch's own base
/// nothing is generated and the step is inert. Either way the verb opens no
/// listener, so no TLS material is produced and the certificate stays the
/// one thing left for `serve` to generate. Only the verb's success is
/// asserted; whether a key file appears depends on the tree, not on this cell.
#[cfg(unix)]
fn provision_daemon_signing_key(root: &Path) {
    use std::io::Write as _;
    let params = serde_json::json!({
        "host_session_id": "sess-3705",
        "host_turn_index": 1,
        "role": "assistant",
        "content": "provision the daemon signing key before the key dir is made read-only",
        "host_kind": "claude-code",
    });
    let mut child = command(root)
        .args(["capture-turn", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capture-turn");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(params.to_string().as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("capture-turn output");
    assert!(
        out.status.success(),
        "capture-turn must succeed on a writable key dir: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// #3709 item 5 — when the local certificate cannot be generated (read-only
/// key directory) the boot REFUSES with the remedy and never falls back to
/// plaintext.
///
/// FAILS ON THE PARENT: nothing is generated, so the daemon happily binds
/// plaintext and stays up (the exit wait times out / no `#3705`).
#[cfg(unix)]
#[test]
fn unwritable_key_dir_refuses_never_plaintext_3709() {
    use std::os::unix::fs::PermissionsExt as _;
    let _env = ENV_LOCK.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let port = free_port();
    // #3354 generates the daemon SIGNING key before #3705 generates the TLS
    // material, and refuses first when it cannot write it. Provision the
    // signing key while the key dir is still writable (one ledger-writing
    // verb, no listener, so no TLS material is produced) so that the ONLY
    // thing left to generate at boot is the certificate — the refusal this
    // cell pins.
    provision_daemon_signing_key(root.path());
    let mut cmd = command(root.path());
    // `command` created keys/ as 0700; make it read-only AFTER creation.
    std::fs::set_permissions(key_dir(root.path()), std::fs::Permissions::from_mode(0o500))
        .expect("chmod 0500 key dir");
    cmd.args(["serve", "--port", &port.to_string()]);
    let (status, err) = boot_until_exit(cmd);
    // Restore so the tempdir can be removed.
    let _ = std::fs::set_permissions(key_dir(root.path()), std::fs::Permissions::from_mode(0o700));
    assert!(!status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(
        err.contains("could not generate") || err.contains("unusable"),
        "the refusal must say the certificate could not be produced: {err}"
    );
    assert!(
        err.contains("--tls-cert <fullchain.pem> --tls-key <key.pem>"),
        "{err}"
    );
    // #3709 item 2 — the `ai-memory tls` verbs exist now, so the remedy
    // names one (`tls import`); the inverse pin held while it was fiction.
    assert!(
        err.contains("`ai-memory tls import"),
        "the remedy names the verb that now exists: {err}"
    );
    assert!(!err.contains("listening"), "never a listener: {err}");
    assert!(
        !key_dir(root.path())
            .join(LOCAL_TLS_SUBDIR)
            .join(SERVER_KEY_FILE)
            .exists(),
        "nothing may have been written into a read-only key dir"
    );
}

/// Positive control for the explicit pair: `--tls-cert`/`--tls-key` serves
/// `/health` over HTTPS to a client that trusts exactly that leaf.
///
/// FAILS ON THE PARENT only indirectly (the file does not compile there);
/// kept as the explicit-pair twin of the zero-config test.
#[test]
fn explicit_pair_serves_health_over_https_3705() {
    let _env = ENV_LOCK.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let tls = TestTls::generate(&root.path().join("tls-3705"));
    let port = free_port();
    let mut cmd = command(root.path());
    cmd.args(["serve", "--port", &port.to_string()])
        .args(tls.serve_arg_strs());
    let mut spawned = Spawned::spawn(cmd);
    let client = tls.client();
    wait_healthy(&mut spawned, &client, port);
    let resp = client
        .get(health_url(port))
        .send()
        .expect("health over TLS");
    assert!(resp.status().is_success(), "{}", resp.status());
    let _ = spawned.finish();
}

// ---------------------------------------------------------------------------
// The selector grammar and the removed downgrade paths
// ---------------------------------------------------------------------------

/// Item 2 — ONE truthy grammar: a canonical truthy token (`yes`, which the
/// old grammar ignored) affirms the floor and the boot reaches the next
/// gate; a falsy token is a refused downgrade request; an unrecognised token
/// REFUSES boot (never silently leaves TLS optional). Both refusals name
/// the fix.
///
/// FAILS ON THE PARENT: `=0` and `=maybe` boot on (plaintext, reaching the
/// api-key bind guard) instead of refusing with `#3705`.
#[test]
fn require_tls_falsy_and_unrecognised_refuse_truthy_affirms_3705() {
    // The library-level token matrix lives in tests/transit_encryption_3709_lib.rs
    // (new API); here the BINARY is the witness.
    // A truthy token on a real boot still reaches the next gate.
    let root = tempfile::tempdir().unwrap();
    let tls = TestTls::generate(&root.path().join("tls-3705"));
    let out = command(root.path())
        .env("AI_MEMORY_REQUIRE_TLS", "yes")
        .args(["serve", "--host", "0.0.0.0"])
        .args(tls.serve_arg_strs())
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(err.contains(BIND_GUARD_MARKER), "{err}");
    assert!(!err.contains("#3705"), "{err}");

    // Falsy → refused as a downgrade request, with the fix.
    for token in ["0", "false", "no", "off"] {
        let root = tempfile::tempdir().unwrap();
        let out = command(root.path())
            .env("AI_MEMORY_REQUIRE_TLS", token)
            .args(["serve", "--host", "0.0.0.0"])
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "{token}: {err}");
        assert!(err.contains("#3705"), "{token}: {err}");
        assert!(err.contains("impossible to select"), "{token}: {err}");
        assert!(
            err.contains("unset AI_MEMORY_REQUIRE_TLS"),
            "{token}: {err}"
        );
        assert!(!err.contains(BIND_GUARD_MARKER), "{token}: {err}");
    }
    // Unrecognised → refused, with the fix.
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path())
        .env("AI_MEMORY_REQUIRE_TLS", "maybe")
        .args(["serve", "--host", "0.0.0.0"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(err.contains("not a recognised token"), "{err}");
    assert!(err.contains("unset AI_MEMORY_REQUIRE_TLS"), "{err}");
}

/// Item 4 — the former downgrade paths refuse boot when armed, naming the
/// variable, the reason and the fix; a valid TLS pair does not rescue them.
///
/// FAILS ON THE PARENT: both hatches are honoured (the boot proceeds to the
/// bind guard; no `#3705`).
#[test]
fn removed_downgrade_paths_refuse_boot_3705() {
    for hatch in [
        "AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK",
        "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS",
    ] {
        let root = tempfile::tempdir().unwrap();
        let tls = TestTls::generate(&root.path().join("tls-3705"));
        let out = command(root.path())
            .env(hatch, "1")
            .args(["serve", "--host", "0.0.0.0"])
            .args(tls.serve_arg_strs())
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "{hatch}: {err}");
        assert!(err.contains("#3705"), "{hatch}: {err}");
        assert!(err.contains(hatch), "{hatch}: {err}");
        assert!(err.contains("downgrade path"), "{hatch}: {err}");
        assert!(err.contains(&format!("unset {hatch}")), "{hatch}: {err}");
        assert!(!err.contains(BIND_GUARD_MARKER), "{hatch}: {err}");
    }
}

// ---------------------------------------------------------------------------
// Outbound surfaces
// ---------------------------------------------------------------------------

/// Item 3 — a plaintext federation peer is refused on BOTH doors, loopback
/// included, with the https remedy.
///
/// FAILS ON THE PARENT: `http://127.0.0.1:1` is a loopback peer and exempt;
/// the boots proceed past the peer check (no `#3705`).
#[test]
fn plaintext_federation_peer_refused_loopback_included_3705() {
    let root = tempfile::tempdir().unwrap();
    let tls = TestTls::generate(&root.path().join("tls-3705"));
    let out = command(root.path())
        .env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST)
        .env("AI_MEMORY_SECURITY_PROFILE", "standard")
        .args([
            "serve",
            "--quorum-writes",
            "0",
            "--quorum-peers",
            "http://127.0.0.1:1",
        ])
        .args(tls.serve_arg_strs())
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(err.contains("federation peer"), "{err}");
    assert!(err.contains("change the URL to https://"), "{err}");

    let root = tempfile::tempdir().unwrap();
    let out = command(root.path())
        .env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST)
        .env("AI_MEMORY_SECURITY_PROFILE", "standard")
        .args(["sync-daemon", "--peers", "http://127.0.0.1:1"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(err.contains("federation peer"), "{err}");
    assert!(err.contains("change the URL to https://"), "{err}");
}

/// Item 3 — a plaintext webhook target is refused, loopback included, before
/// the SSRF loopback policy is even consulted; https is accepted.
///
/// FAILS ON THE PARENT: `http://` to loopback was accepted by the scheme
/// check (the loopback SSRF guard fired instead, without `#3705`).
#[test]
fn plaintext_webhook_target_refused_loopback_included_3705() {
    for url in [
        "http://127.0.0.1:9/hook",
        "http://localhost/hook",
        "http://[::1]/hook",
        "http://hooks.example.com/hook",
    ] {
        let err = ai_memory::subscriptions::validate_url(url)
            .expect_err("#3705: every http:// webhook target must be refused")
            .to_string();
        assert!(err.contains("#3705"), "{url}: {err}");
        assert!(err.contains("webhook target"), "{url}: {err}");
        assert!(err.contains("change the URL to https://"), "{url}: {err}");
    }
    assert!(ai_memory::subscriptions::validate_url("https://hooks.example.com/hook").is_ok());
}

/// The MCP → daemon forward URL is a config-carried transit surface: an
/// `http://` value refuses every non-doctor verb at boot, with the remedy.
///
/// FAILS ON THE PARENT: the value is accepted (`stats` runs).
#[test]
fn plaintext_mcp_forward_url_refused_3705() {
    let root = tempfile::tempdir().unwrap();
    let cfg_dir = root.path().join("home/.config/ai-memory");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.toml"),
        "mcp_federation_forward_url = \"http://127.0.0.1:9077\"\n",
    )
    .unwrap();
    let out = command(root.path())
        .env_remove("AI_MEMORY_NO_CONFIG")
        .args(["stats"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("#3705"), "{err}");
    assert!(err.contains("MCP forward URL"), "{err}");
    assert!(err.contains("change the URL to https://"), "{err}");
}

// ---------------------------------------------------------------------------
// The detector and the renewal
// ---------------------------------------------------------------------------

/// Item "detector first" — `doctor`'s DEFAULT report carries the transit
/// section (the facts are pinned by the doctor suite; presence and shape
/// here).
///
/// FAILS ON THE PARENT: the section is absent.
#[test]
fn doctor_reports_transit_encryption_section_3705() {
    let _env = ENV_LOCK.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    common::permissive_attestation_for_tests();
    let _ = ai_memory::db::open(&root.path().join("store.db")).expect("open store");
    let out = command(root.path())
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert!(
        (0..=2).contains(&code),
        "doctor must diagnose, never refuse (exit {code}); stderr:\n{}",
        stderr(&out)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("doctor --json must parse: {e}\n{}", stdout(&out)));
    let sections = report["sections"].as_array().expect("sections array");
    let section = sections
        .iter()
        .find(|s| s["name"] == SECTION_TRANSIT)
        .unwrap_or_else(|| {
            let names: Vec<&str> = sections.iter().filter_map(|s| s["name"].as_str()).collect();
            panic!("doctor section {SECTION_TRANSIT:?} absent (#3705); present: {names:?}")
        });
    assert!(section["facts"].is_array(), "{section}");
}

// ---------------------------------------------------------------------------
// #7341 — the readiness wait is not a fixed wall-clock number
// ---------------------------------------------------------------------------

/// The budget shape mirrors `tests/integration.rs` (#3615): default 1x, a
/// valid multiplier scales, anything outside 1..=100 or unparsable is 1x.
#[test]
fn boot_budget_scales_with_the_timing_multiplier_7341() {
    let base = Duration::from_secs(7);
    assert_eq!(scaled_boot_budget(base, None), base);
    assert_eq!(scaled_boot_budget(base, Some("1")), base);
    assert_eq!(scaled_boot_budget(base, Some("3")), base * 3);
    assert_eq!(scaled_boot_budget(base, Some("100")), base * 100);
    for bad in ["0", "101", "-2", "abc", ""] {
        assert_eq!(scaled_boot_budget(base, Some(bad)), base, "raw {bad:?}");
    }
    // The post-listen budget scales with the same multiplier (the listen
    // line precedes the bind) and is never shorter than the old fixed 45 s.
    assert!(POST_LISTEN_BUDGET >= Duration::from_secs(45));
    assert_eq!(
        scaled_boot_budget(POST_LISTEN_BUDGET, Some("3")),
        POST_LISTEN_BUDGET * 3
    );
    assert_eq!(
        scaled_boot_budget(POST_LISTEN_BUDGET, Some("101")),
        POST_LISTEN_BUDGET
    );
}

/// The CA-file wait reports a daemon that dies before writing its CA at once
/// (status and stderr), not after the boot budget.
#[test]
fn ca_wait_reports_a_dead_child_immediately_7341() {
    let _env = ENV_LOCK.blocking_lock();
    let root = tempfile::tempdir().unwrap();
    let mut cmd = command(root.path());
    cmd.arg("--definitely-not-a-flag-7341");
    let mut spawned = Spawned::spawn(cmd);
    let started = Instant::now();
    let outcome =
        wait_local_ca_client(&mut spawned, &key_dir(root.path()), Duration::from_secs(60));
    let why = outcome.expect_err("a dead child must be an error");
    assert!(why.contains("serve exited"), "{why}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "dead child took {:?}, budget was 60s",
        started.elapsed()
    );
}

/// A child that dies at once is reported at once, with its status and
/// stderr, never after the budget.
#[test]
fn dead_child_is_reported_immediately_7341() {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = command(root.path());
    cmd.arg("--definitely-not-a-flag-7341");
    let mut spawned = Spawned::spawn(cmd);
    let budget = BootBudget {
        before_listen: Duration::from_secs(60),
        after_listen: Duration::from_secs(60),
    };
    let started = Instant::now();
    let outcome = try_wait_healthy(&mut spawned, || false, &budget);
    let elapsed = started.elapsed();
    let why = outcome.expect_err("a dead child must be an error");
    assert!(why.contains("serve exited"), "{why}");
    assert!(
        elapsed < Duration::from_secs(20),
        "dead child took {elapsed:?}, budget was 60s"
    );
}

/// After the listen line the short post-listen budget applies, not the
/// long pre-listen one.
#[cfg(unix)]
#[test]
fn listen_signal_switches_to_the_short_budget_7341() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!(
        "echo '{LISTEN_SIGNAL}127.0.0.1:1' >&2; exec sleep 60"
    ));
    let mut spawned = Spawned::spawn(cmd);
    let budget = BootBudget {
        before_listen: Duration::from_secs(8),
        after_listen: Duration::from_millis(500),
    };
    let started = Instant::now();
    let why = try_wait_healthy(&mut spawned, || false, &budget)
        .expect_err("a listener that never answers must fail");
    assert!(why.contains("listening"), "{why}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "post-listen budget ignored: {:?}",
        started.elapsed()
    );
}

/// #7647: the boot budget comes from ONE named constant, an env override is
/// clamped to a sane range, and the default outlasts a host at load 60 on 14
/// cores (the r5 run that timed out at the old 60 s).
#[test]
fn boot_base_budget_is_one_clamped_constant_7647() {
    let default = Duration::from_secs(BOOT_BASE_SECS_DEFAULT);
    assert_eq!(boot_base_from(None), default);
    assert!(
        default >= Duration::from_secs(120),
        "the default must outlast a loaded host: {default:?}"
    );
    assert_eq!(boot_base_from(Some("240")), Duration::from_secs(240));
    assert_eq!(boot_base_from(Some(" 240 ")), Duration::from_secs(240));
    assert_eq!(
        boot_base_from(Some("1")),
        Duration::from_secs(BOOT_BASE_SECS_MIN)
    );
    assert_eq!(
        boot_base_from(Some("0")),
        Duration::from_secs(BOOT_BASE_SECS_MIN)
    );
    assert_eq!(
        boot_base_from(Some("999999")),
        Duration::from_secs(BOOT_BASE_SECS_MAX)
    );
    for bad in ["", "abc", "-5", "1.5"] {
        assert_eq!(boot_base_from(Some(bad)), default, "raw {bad:?}");
    }
    assert_eq!(
        post_listen_of(Duration::from_secs(60)),
        Duration::from_secs(45)
    );
}
