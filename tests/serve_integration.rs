// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::zombie_processes)]

//! Wave 7 / I7 — HTTP daemon spawn-and-poke regression guards.
//!
//! These tests spawn `ai-memory serve` as a child process and drive it
//! over real HTTP via the production `reqwest` blocking client. They are
//! NOT coverage drivers — subprocess execution doesn't attribute to the
//! parent's `cargo-llvm-cov` run — but they are the only way to catch
//! regressions in the binary's listen-bind-serve-shutdown lifecycle that
//! pure in-process `Router::oneshot` tests can't see.
//!
//! Port allocation: `--port 0` is supported by clap but `serve()` only
//! logs the input address (literal "0") rather than the actual bound
//! port. Until that is fixed (out-of-scope for this lane — would touch
//! `src/`), the tests use a `free_port()` helper that binds a throwaway
//! `TcpListener` on `127.0.0.1:0`, reads the assigned port, and drops
//! the listener so the daemon can re-bind. This has a small TOCTOU race
//! window but is the standard pattern across Rust integration suites.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

mod common;
use common::free_port;

// CI's `Per-Module Coverage Thresholds` job runs the test binary under
// `cargo llvm-cov` instrumentation, which inflates startup time by 3-5x. 60s gives
// enough headroom on every supported CI surface (Linux/macOS/Windows)
// regardless of instrumentation overhead.
const SPAWN_TIMEOUT: Duration = Duration::from_mins(1);

/// Number of times `spawn_serve` re-rolls the ephemeral port when the
/// daemon child loses the `free_port()` TOCTOU race and exits with a
/// bind error before `/health` comes up. The window is tiny but real
/// under full-suite concurrency (many daemon-spawning tests bind
/// ephemeral ports at once), so we re-roll on a collision rather than
/// fail the suite on an environmental flake. A genuine startup crash
/// carries different stderr and is surfaced immediately, never retried.
const SPAWN_BIND_RETRY_ATTEMPTS: usize = 5;

/// Substring the daemon's `bind` error carries on an ephemeral-port
/// collision — `std::io::Error` for `EADDRINUSE` renders as this on both
/// Linux and macOS. Used to tell a retryable port race apart from a real
/// startup failure so retries never mask a genuine crash.
const BIND_IN_USE_MARKER: &str = "Address already in use";

/// Poll interval while waiting for the spawned daemon's `/health` to come
/// up (and for an early-exit child to surface).
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Per-request timeout for the readiness `/health` probe.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Why a single `try_spawn_serve_once` attempt failed. `BindRace` is the
/// only retryable variant; the others are surfaced to the caller with the
/// child's captured stderr for diagnosis.
enum SpawnFailure {
    /// Child exited before readiness and its stderr names an in-use port —
    /// it lost the `free_port()` TOCTOU race. Safe to retry on a new port.
    BindRace { stderr: String },
    /// Child exited before readiness for some other reason — a real
    /// startup failure. Carries exit status + stderr for the panic.
    Crashed {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// Child stayed up but `/health` never returned 200 within
    /// [`SPAWN_TIMEOUT`].
    NeverReady { stderr: String },
}

/// RAII guard for the spawned daemon. Drops kill the child on test
/// exit so leaked test processes don't accumulate on flaky failures.
struct ServeChild {
    child: Option<Child>,
    port: u16,
    /// #3705 — the leaf the daemon serves; every client trusts exactly it.
    tls: common::tls::TestTls,
    /// Everything the daemon has written to stderr so far (#6236 reads the
    /// shutdown log lines from here to pin their order).
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
}

impl ServeChild {
    fn url(&self, path: &str) -> String {
        format!("{}{}", common::tls::TestTls::base_url(self.port), path)
    }
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `ai-memory serve --host 127.0.0.1 --port <p> --db <db>` and wait
/// for `/api/v1/health` to return 200. Returns a guard that kills the
/// child on drop. `extra_args` are appended to the serve subcommand.
/// `extra_envs` lets callers set `HOME` (for config-driven `api_key`
/// scenarios) or other env vars on the child.
///
/// Retries on the `free_port()` TOCTOU bind race (see
/// [`SPAWN_BIND_RETRY_ATTEMPTS`]); a real startup crash is surfaced
/// immediately with the child's captured stderr.
fn spawn_serve(
    db: &std::path::Path,
    extra_args: &[&str],
    extra_envs: &[(&str, &str)],
) -> ServeChild {
    for attempt in 1..=SPAWN_BIND_RETRY_ATTEMPTS {
        match try_spawn_serve_once(db, extra_args, extra_envs) {
            Ok(child) => return child,
            Err(SpawnFailure::BindRace { stderr }) => {
                // Lost the ephemeral-port race to a concurrent binder —
                // re-roll the port. Not a product defect.
                eprintln!(
                    "spawn_serve: ephemeral-port bind race on attempt \
                     {attempt}/{SPAWN_BIND_RETRY_ATTEMPTS}, re-rolling port. \
                     child stderr:\n{stderr}"
                );
            }
            Err(SpawnFailure::Crashed { status, stderr }) => {
                panic!(
                    "serve child exited before /health became ready: {status}\n\
                     --- child stderr ---\n{stderr}"
                );
            }
            Err(SpawnFailure::NeverReady { stderr }) => {
                panic!(
                    "serve daemon did not become ready within {SPAWN_TIMEOUT:?}\n\
                     --- child stderr ---\n{stderr}"
                );
            }
        }
    }
    panic!(
        "serve daemon lost the ephemeral-port bind race \
         {SPAWN_BIND_RETRY_ATTEMPTS} times in a row"
    );
}

/// Single spawn-and-wait attempt backing [`spawn_serve`]. Captures the
/// child's stderr so the outcome can distinguish a retryable port race
/// from a genuine startup crash (and so panics carry real diagnostics).
fn try_spawn_serve_once(
    db: &std::path::Path,
    extra_args: &[&str],
    extra_envs: &[(&str, &str)],
) -> Result<ServeChild, SpawnFailure> {
    let port = free_port();
    let port_s = port.to_string();
    // #3705 — the daemon refuses every plaintext bind; a per-spawn leaf.
    let tls = common::tls::TestTls::generate(
        &db.parent().expect("db lives in a tempdir").join("tls-3705"),
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        // #1751 — permissive attestation opt-out; this suite's unsigned
        // HTTP stores exercise serve wiring, not the attestation gate.
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        // #976 (2026-05-20) — admin allowlist so the post-#946
        // admin-gated routes (stats, archive, forget, …) exercise the
        // happy-path 200 in this test fixture. Negative admin
        // contracts belong in dedicated test files.
        //
        // #1001 (2026-05-21) — pre-#980 this used the `"*"` wildcard
        // sentinel; #980 made `"*"` shape-invalid in
        // `validate_agent_id`, so the env entry got dropped. Tests
        // using `spawn_serve` that hit admin endpoints must thread
        // `X-Agent-Id: ai:serve-test-admin` (matches the env value).
        .env("AI_MEMORY_ADMIN_AGENT_IDS", "ai:serve-test-admin")
        .args([
            "--db",
            db.to_str().unwrap(),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port_s,
        ])
        .args(tls.serve_arg_strs())
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ai-memory serve");

    // Drain stdout to the void; capture stderr into a shared buffer so
    // an early exit can be classified (bind race vs. real crash) and so
    // failures surface the daemon's own error instead of being silent.
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
    }
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_handle = child.stderr.take().map(|stderr| {
        let sink = std::sync::Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut guard = sink.lock().unwrap();
                guard.push_str(&line);
                guard.push('\n');
            }
        })
    });
    // Join the stderr drainer (the pipe EOFs once the child exits, so the
    // thread ends promptly) and return everything it captured.
    let stderr_sink = std::sync::Arc::clone(&stderr_buf);
    let drain_stderr = move || -> String {
        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }
        stderr_buf.lock().unwrap().clone()
    };

    let client = tls.client_with_timeout(READINESS_PROBE_TIMEOUT);
    let url = format!("{}/api/v1/health", common::tls::TestTls::base_url(port));
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
        {
            return Ok(ServeChild {
                child: Some(child),
                port,
                tls,
                stderr: stderr_sink,
            });
        }
        // Bail early if the child crashed — don't burn the full timeout.
        if let Ok(Some(status)) = child.try_wait() {
            let stderr = drain_stderr();
            return Err(if stderr.contains(BIND_IN_USE_MARKER) {
                SpawnFailure::BindRace { stderr }
            } else {
                SpawnFailure::Crashed { status, stderr }
            });
        }
        std::thread::sleep(READINESS_POLL_INTERVAL);
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(SpawnFailure::NeverReady {
        stderr: drain_stderr(),
    })
}

/// #3705 — a client that verifies the spawned daemon's leaf.
fn http_client(serve: &ServeChild) -> reqwest::blocking::Client {
    serve.tls.client_with_timeout(Duration::from_secs(5))
}

/// Bounded retry window for a test's *first* real HTTP request against a
/// freshly-spawned daemon, layered on top of [`try_spawn_serve_once`]'s own
/// `/api/v1/health` readiness gate (#1994).
///
/// `spawn_serve` already blocks until `/health` returns 2xx before handing
/// back a [`ServeChild`], but CI observed an intermittent Windows-only
/// connection-refused panic on the very next request a test issues on a
/// brand-new `reqwest::blocking::Client` (a fresh TCP connection) even
/// though the readiness probe just succeeded moments earlier — a narrow
/// listen-queue/accept race distinct from the `free_port()` TOCTOU bind
/// race `spawn_serve` already retries on (see #1994). [`send_first_request`]
/// closes that residual window by retrying the caller's first request on a
/// connection-level error only; a real HTTP error status or body-content
/// mismatch is never retried and surfaces immediately, so this cannot mask
/// an assertion failure.
const FIRST_REQUEST_RETRY_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends the request `build` constructs, retrying on a connection-level
/// error (not-yet-listening / connection-refused / reset) until
/// [`FIRST_REQUEST_RETRY_TIMEOUT`] elapses. `build` is invoked once per
/// attempt so each retry opens a genuinely fresh TCP connection rather than
/// reusing one that may have raced the daemon's listener. See
/// [`FIRST_REQUEST_RETRY_TIMEOUT`] for why this exists in addition to
/// `spawn_serve`'s own `/health` gate.
fn send_first_request<F>(mut build: F) -> reqwest::blocking::Response
where
    F: FnMut() -> reqwest::blocking::RequestBuilder,
{
    let deadline = Instant::now() + FIRST_REQUEST_RETRY_TIMEOUT;
    loop {
        match build().send() {
            Ok(resp) => return resp,
            Err(e) if e.is_connect() && Instant::now() < deadline => {
                std::thread::sleep(READINESS_POLL_INTERVAL);
            }
            Err(e) => panic!(
                "first request after spawn_serve's readiness gate still failed \
                 (connection-level error, not an assertion failure): {e}"
            ),
        }
    }
}

/// Polls `<base_url>/api/v1/health` until it returns 2xx or `timeout`
/// elapses. Shared readiness-gate helper for spawn paths that cannot reuse
/// `spawn_serve` (e.g. [`serve_api_key_required_when_configured`], which
/// needs a custom `HOME` + must NOT set `AI_MEMORY_NO_CONFIG`) but still
/// need the same bounded retry-until-listening contract (#1994).
fn wait_for_health(client: &reqwest::blocking::Client, base_url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if client
            .get(format!("{base_url}/api/v1/health"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return true;
        }
        std::thread::sleep(READINESS_POLL_INTERVAL);
    }
    false
}

#[test]
fn serve_health_endpoint_returns_200() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let resp = send_first_request(|| http_client(&serve).get(serve.url("/api/v1/health")));
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "ai-memory");
}

#[test]
fn serve_metrics_endpoint_at_root_path() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let resp = send_first_request(|| http_client(&serve).get(serve.url("/metrics")));
    assert!(resp.status().is_success());
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().unwrap();
    assert!(
        ct.starts_with("text/plain"),
        "expected prometheus text content-type, got: {ct}"
    );
    // Prometheus exposition text always has at least one HELP/TYPE line.
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "metrics body lacks prom format markers: {body}"
    );
}

#[test]
fn serve_metrics_endpoint_at_v1_path() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let resp = send_first_request(|| http_client(&serve).get(serve.url("/api/v1/metrics")));
    assert!(resp.status().is_success());
    let body = resp.text().unwrap();
    assert!(body.contains("# HELP") || body.contains("# TYPE"));
}

#[test]
fn serve_create_then_get_memory() {
    // #927/#930 (Track A P4/P9, 2026-05-20) added scope=private +
    // caller-vs-owner gates on the sqlite GET/UPDATE/PROMOTE paths.
    // Set a stable X-Agent-Id on BOTH the write and the read so the
    // round-trip lands on the same principal — without it the write
    // creates a row owned by `anonymous:req-A` and the read tries to
    // load it as `anonymous:req-B`, and the visibility gate 404s.
    const AGENT: &str = "ai:serve-roundtrip";

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let client = http_client(&serve);

    // POST /api/v1/memories
    let create_body = serde_json::json!({
        "tier": "mid",
        "namespace": "test-ns",
        "title": "serve-roundtrip",
        "content": "serve roundtrip body"
    });
    let resp = send_first_request(|| {
        client
            .post(serve.url("/api/v1/memories"))
            .header("X-Agent-Id", AGENT)
            .json(&create_body)
    });
    assert!(
        resp.status().is_success(),
        "create returned {}: {:?}",
        resp.status(),
        resp.text()
    );
    let created: serde_json::Value = resp.json().unwrap();
    let id = created["id"].as_str().expect("id in response").to_string();

    // GET /api/v1/memories/{id}
    let resp = client
        .get(serve.url(&format!("/api/v1/memories/{id}")))
        .header("X-Agent-Id", AGENT)
        .send()
        .unwrap();
    assert!(resp.status().is_success());
    let got: serde_json::Value = resp.json().unwrap();
    // Response wraps the memory in {"memory": …, "links": […]}.
    assert_eq!(got["memory"]["id"], id);
    assert_eq!(got["memory"]["title"], "serve-roundtrip");
}

#[test]
fn serve_api_key_required_when_configured() {
    // The `api_key` field is config-only (loaded from
    // `~/.config/ai-memory/config.toml`), so we synthesize a fake HOME
    // pointing at our tempdir, drop a config.toml in the right place,
    // and DO NOT set `AI_MEMORY_NO_CONFIG=1` for this test alone.
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let xdg_root = tmp.path().join(".config");
    let cfg_dir = xdg_root.join("ai-memory");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let api_key = "test-i7-secret";
    std::fs::write(
        cfg_dir.join("config.toml"),
        format!("api_key = \"{api_key}\"\n"),
    )
    .unwrap();

    // Spawn without AI_MEMORY_NO_CONFIG=1 so the config.toml is honoured.
    // Hosted-ubuntu `Check (ubuntu-latest,sqlite)` has hit a leftover
    // daemon on the ephemeral port (health 200, /stats 403 admin-gate
    // because THAT process had no api_key). Health is api-key-exempt, so
    // `wait_for_health` cannot tell our child from the leftover — retry
    // the whole spawn on a fresh port when /stats is not 401. Same
    // attempt budget as `spawn_serve`'s bind-race loop.
    // #3705 — the daemon refuses every plaintext bind; one leaf for the
    // retry loop, trusted by the probe client.
    let tls = common::tls::TestTls::generate(&tmp.path().join("tls-3705"));
    let client = tls.client_with_timeout(Duration::from_secs(5));
    let mut last_err = String::new();
    for attempt in 1..=SPAWN_BIND_RETRY_ATTEMPTS {
        let port = free_port();
        let port_s = port.to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env_remove("AI_MEMORY_NO_CONFIG")
            .env("AI_MEMORY_NO_CONFIG", "0")
            .env("HOME", tmp.path().to_str().unwrap())
            // #3002 / #3215 — `config_path()` resolves through `dirs::config_dir()`,
            // which honors `XDG_CONFIG_HOME`. Without this pin an ambient host
            // XDG root (or a leftover `config.toml` there) wins, the daemon boots
            // without the test `api_key`, `api_key_auth` becomes a pass-through,
            // and GET `/api/v1/stats` returns the admin-gate 403 instead of the
            // api-key 401 this test is pinning.
            .env("XDG_CONFIG_HOME", &xdg_root)
            .env_remove("AI_MEMORY_DB")
            .env("AI_MEMORY_ADMIN_AGENT_IDS", "ai:serve-test-admin")
            .args([
                "--db",
                db.to_str().unwrap(),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port_s,
            ])
            .args(tls.serve_arg_strs())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
        }
        let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(stderr) = child.stderr.take() {
            let sink = std::sync::Arc::clone(&stderr_buf);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let mut guard = sink.lock().unwrap();
                    guard.push_str(&line);
                    guard.push('\n');
                }
            });
        }

        let url = common::tls::TestTls::base_url(port);
        let ready = wait_for_health(&client, &url, SPAWN_TIMEOUT);
        let guard = ServeChild {
            child: Some(child),
            port,
            tls: tls.clone(),
            stderr: std::sync::Arc::clone(&stderr_buf),
        };
        if !ready {
            last_err = format!(
                "attempt {attempt}: auth-protected daemon never came up; stderr:\n{}",
                stderr_buf.lock().unwrap()
            );
            drop(guard);
            continue;
        }

        let resp = send_first_request(|| client.get(format!("{url}/api/v1/stats")));
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        if status != 401 {
            last_err = format!(
                "attempt {attempt}: missing x-api-key must 401 (got {status}); body={body}; stderr:\n{}",
                stderr_buf.lock().unwrap()
            );
            drop(guard);
            continue;
        }

        let resp = client
            .get(format!("{url}/api/v1/stats"))
            .header("x-api-key", api_key)
            .header("x-agent-id", "ai:serve-test-admin")
            .send()
            .unwrap();
        assert!(
            resp.status().is_success(),
            "auth header rejected: {}; stderr:\n{}",
            resp.status(),
            stderr_buf.lock().unwrap()
        );
        drop(guard);
        return;
    }
    panic!("{last_err}");
}

#[cfg(unix)]
#[test]
fn serve_graceful_shutdown_on_sigterm() {
    use std::os::unix::process::ExitStatusExt;

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let pid = serve.child.as_ref().unwrap().id();

    // SIGTERM: the signal this test is named for and the one `docker stop`
    // sends. `serve` resolves SIGTERM and SIGINT through the same shutdown
    // future (#4072); `serve_sigterm_takes_the_same_graceful_path_as_sigint_4072`
    // pins the two against each other.
    unsafe {
        libc::kill(i32::try_from(pid).expect("pid fits in i32"), libc::SIGTERM);
    }
    // Give the daemon up to 10s to flush the WAL and exit.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut serve_mut = serve;
    let exit_status = loop {
        if Instant::now() > deadline {
            // Force kill so the test reports a real failure rather than
            // hanging the suite.
            let _ = serve_mut.child.as_mut().unwrap().kill();
            panic!("daemon did not exit within 10s of SIGTERM");
        }
        match serve_mut.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };
    // Discard the child handle so Drop doesn't try to wait again.
    serve_mut.child = None;

    // The graceful path ends in a clean exit, never death by signal.
    assert!(
        exit_status.success() && exit_status.signal().is_none(),
        "SIGTERM must end in a clean exit: {exit_status:?}"
    );
}

/// #4072/#6236 — the outcome of one graceful shutdown taken while a request
/// is still in flight.
#[cfg(unix)]
struct DrainOutcome4072 {
    exit: std::process::ExitStatus,
    /// WAL length just before the signal (must be non-zero: the checkpoint
    /// assertion is meaningless on a database that never had a WAL).
    wal_before: u64,
    /// WAL length after exit (0 once the final `wal_checkpoint(TRUNCATE)` ran).
    wal_after: u64,
    /// Status of the request that was in flight when the signal landed.
    inflight_status: reqwest::StatusCode,
    /// The daemon was still running while that request was unfinished.
    alive_during_drain: bool,
    stderr: String,
}

/// A request body that hands over its first half, announces the request is in
/// flight, then blocks until the test releases it.
#[cfg(unix)]
struct GatedBody4072 {
    first: Option<Vec<u8>>,
    rest: Option<Vec<u8>>,
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(unix)]
impl std::io::Read for GatedBody4072 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let chunk = if let Some(first) = self.first.take() {
            let _ = self.started.send(());
            first
        } else if let Some(rest) = self.rest.take() {
            // Held until the test has delivered the signal.
            self.release
                .recv_timeout(Duration::from_secs(30))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))?;
            rest
        } else {
            return Ok(0);
        };
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        if n < chunk.len() {
            // Not reachable for these small bodies; keep the tail rather than
            // silently truncating the request.
            self.rest = Some(chunk[n..].to_vec());
        }
        Ok(n)
    }
}

#[cfg(unix)]
fn drain_outcome_4072(signal: libc::c_int) -> DrainOutcome4072 {
    const AGENT: &str = "ai:drain-4072";
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let mut serve = spawn_serve(&db, &[], &[]);
    let pid = serve.child.as_ref().unwrap().id();
    let client = http_client(&serve);

    // A committed write first, so a WAL exists to be checkpointed.
    let seed = send_first_request(|| {
        client
            .post(serve.url("/api/v1/memories"))
            .header("X-Agent-Id", AGENT)
            .json(&serde_json::json!({
                "tier": "mid", "namespace": "drain-4072",
                "title": "seed", "content": "seed row so the WAL is non-empty"
            }))
    });
    assert!(seed.status().is_success(), "seed write: {}", seed.status());
    let wal_path = tmp.path().join("ai-memory.db-wal");
    let wal_before = std::fs::metadata(&wal_path).map_or(0, |m| m.len());

    // A request that is mid-flight (headers + half the body sent) when the
    // signal lands.
    let body = serde_json::to_vec(&serde_json::json!({
        "tier": "mid", "namespace": "drain-4072",
        "title": "in-flight", "content": "completed during the graceful drain"
    }))
    .unwrap();
    let (head, tail) = body.split_at(body.len() / 2);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let gated = GatedBody4072 {
        first: Some(head.to_vec()),
        rest: Some(tail.to_vec()),
        started: started_tx,
        release: release_rx,
    };
    let url = serve.url("/api/v1/memories");
    let slow_client = serve.tls.client_with_timeout(Duration::from_secs(60));
    let inflight = std::thread::spawn(move || {
        slow_client
            .post(url)
            .header("X-Agent-Id", AGENT)
            .header("Content-Type", "application/json")
            .body(reqwest::blocking::Body::new(gated))
            .send()
            .map(|r| r.status())
    });
    started_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the in-flight request must start");
    std::thread::sleep(Duration::from_millis(500));

    // SAFETY: a plain signal to a pid this test spawned and still owns.
    unsafe {
        libc::kill(i32::try_from(pid).expect("pid fits in i32"), signal);
    }
    std::thread::sleep(Duration::from_millis(1500));
    let alive_during_drain = matches!(serve.child.as_mut().unwrap().try_wait(), Ok(None));
    release_tx.send(()).expect("release the gated body");
    let inflight_status = inflight
        .join()
        .expect("in-flight thread")
        .expect("the in-flight request must complete, not be dropped");

    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if Instant::now() > deadline {
            let _ = serve.child.as_mut().unwrap().kill();
            panic!("daemon did not exit within 30s of signal {signal}");
        }
        match serve.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };
    serve.child = None;
    std::thread::sleep(Duration::from_millis(200));
    let stderr = serve.stderr.lock().unwrap().clone();
    let wal_after = std::fs::metadata(&wal_path).map_or(0, |m| m.len());
    DrainOutcome4072 {
        exit,
        wal_before,
        wal_after,
        inflight_status,
        alive_during_drain,
        stderr,
    }
}

/// #4072/#6236 — SIGTERM (the container image's stop signal; what `docker
/// stop` / Kubernetes send) takes the SAME graceful path as SIGINT, with a
/// request in flight: the request completes, the daemon stays up for it, the
/// shutdown stages run in order (drain, then deferred-audit drain), the exit
/// is a clean success, and the final WAL checkpoint ran on a WAL that existed.
#[cfg(unix)]
#[test]
fn serve_sigterm_takes_the_same_graceful_path_as_sigint_4072() {
    use std::os::unix::process::ExitStatusExt;

    for (name, signal) in [("SIGTERM", libc::SIGTERM), ("SIGINT", libc::SIGINT)] {
        let out = drain_outcome_4072(signal);
        assert!(
            out.exit.success() && out.exit.signal().is_none(),
            "{name}: the daemon must exit success on its own terms: {:?}\n{}",
            out.exit,
            out.stderr
        );
        assert!(
            out.alive_during_drain,
            "{name}: the daemon must stay up while a request is in flight"
        );
        assert!(
            out.inflight_status.is_success(),
            "{name}: the in-flight request must complete with 2xx, got {}",
            out.inflight_status
        );
        assert!(
            out.wal_before > 0,
            "{name}: the test needs a non-empty WAL before the signal"
        );
        assert_eq!(
            out.wal_after, 0,
            "{name}: the final wal_checkpoint(TRUNCATE) must run"
        );
        let drain = out.stderr.find("shutting down");
        let audit = out.stderr.find("deferred-audit queue drained");
        assert!(
            matches!((drain, audit), (Some(d), Some(a)) if d < a),
            "{name}: shutdown stages must log in order (drain, then deferred-audit drain):\n{}",
            out.stderr
        );
    }
}

/// #6236 — the packaging half of #4072: the image stops the daemon with
/// SIGTERM, runs the binary as PID 1 in exec form (so the signal reaches it,
/// not a shell), and the admin guide states the stop budget.
#[test]
fn dockerfile_delivers_sigterm_to_the_binary_and_the_guide_states_the_budget_6236() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");
    let lines: Vec<&str> = dockerfile.lines().map(str::trim).collect();
    assert!(
        lines.contains(&"STOPSIGNAL SIGTERM"),
        "the image must declare STOPSIGNAL SIGTERM"
    );
    let entry = lines
        .iter()
        .find(|l| l.starts_with("ENTRYPOINT"))
        .expect("an ENTRYPOINT");
    assert!(
        entry.starts_with("ENTRYPOINT [") && !entry.contains("sh\"") && !entry.contains("bash"),
        "ENTRYPOINT must be exec form without a shell wrapper so SIGTERM reaches the daemon: {entry}"
    );
    let cmd = lines
        .iter()
        .find(|l| l.starts_with("CMD"))
        .expect("a CMD");
    assert!(
        cmd.starts_with("CMD [") && !cmd.contains("sh\""),
        "CMD must be exec form: {cmd}"
    );
    let guide = std::fs::read_to_string(root.join("docs/ADMIN_GUIDE.md")).expect("read guide");
    assert!(
        guide.contains("at least 90 seconds") && guide.contains("STOPSIGNAL SIGTERM"),
        "ADMIN_GUIDE must state the 90 s stop budget and the image STOPSIGNAL"
    );
}
