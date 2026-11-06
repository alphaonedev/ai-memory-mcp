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

use std::time::{Duration, Instant};

use tempfile::TempDir;

mod common;
use common::tls_serve::{READINESS_POLL_INTERVAL, ServeChild};

/// Apply this suite's arguments and authorization fixture to the shared TLS helper.
fn spawn_serve(
    db: &std::path::Path,
    extra_args: &[&str],
    extra_envs: &[(&str, &str)],
) -> ServeChild {
    common::tls_serve::spawn_serve(db, |cmd| {
        // #1751: unsigned requests test serve wiring, with the #976/#1001 admin fixture.
        cmd.env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .env("AI_MEMORY_ADMIN_AGENT_IDS", "ai:serve-test-admin")
            .args(extra_args);
        for (key, value) in extra_envs {
            cmd.env(key, value);
        }
    })
}

/// #3705 — a client that verifies the spawned daemon's leaf.
fn http_client(serve: &ServeChild) -> reqwest::blocking::Client {
    serve.tls.client_with_timeout(Duration::from_secs(5))
}

/// Bounded retry window for a test's *first* real HTTP request against a
/// freshly-spawned daemon, layered on top of [`common::tls_serve::spawn_serve`]'s own
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

    // #3002/#3215: config_path honors XDG_CONFIG_HOME; pin it on this child.
    // Every startup attempt has a unique trusted leaf, so another listener cannot
    // satisfy readiness. Only bind collisions retry; an auth mismatch is a failure.
    let serve = common::tls_serve::spawn_serve(&db, |cmd| {
        cmd.env("AI_MEMORY_NO_CONFIG", "0")
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", &xdg_root)
            .env_remove("AI_MEMORY_DB")
            .env("AI_MEMORY_ADMIN_AGENT_IDS", "ai:serve-test-admin");
    });
    let client = http_client(&serve);
    let resp = send_first_request(|| client.get(serve.url("/api/v1/stats")));
    assert_eq!(
        resp.status().as_u16(),
        401,
        "missing x-api-key must be rejected; child stderr:\n{}",
        serve.stderr()
    );
    let resp = client
        .get(serve.url("/api/v1/stats"))
        .header("x-api-key", api_key)
        .header("x-agent-id", "ai:serve-test-admin")
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "auth header rejected: {}; child stderr:\n{}",
        resp.status(),
        serve.stderr()
    );
}

#[cfg(unix)]
#[test]
fn serve_graceful_shutdown_on_sigterm() {
    use std::os::unix::process::ExitStatusExt;

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    // #6237: this test sends the signal its name says. The shared shutdown
    // primitive (#8193) gives SIGTERM the same graceful path as SIGINT.
    let (status, stderr) = signal_and_wait(serve, libc::SIGTERM);
    assert_eq!(
        status.signal(),
        None,
        "#6237: SIGTERM must not kill the daemon by signal: {status:?}\n{stderr}"
    );
    assert!(
        status.success(),
        "#6237: SIGTERM must exit 0 like SIGINT: {status:?}\n{stderr}"
    );
}

/// Bound on how long a signalled daemon may take to drain, certify and exit.
#[cfg(unix)]
const SIGNAL_EXIT_DEADLINE: Duration = Duration::from_secs(20);

/// Poll interval while waiting for a signalled daemon to exit.
#[cfg(unix)]
const SIGNAL_EXIT_POLL: Duration = Duration::from_millis(100);

/// Marker the serve shutdown future logs the moment a stop signal arrives.
#[cfg(unix)]
const SHUTDOWN_BEGIN_MARKER: &str = "shutting down";

/// Marker logged once the deferred-audit queue drained, before the final
/// witness and WAL checkpoint.
#[cfg(unix)]
const AUDIT_DRAINED_MARKER: &str = "deferred-audit queue drained";

/// Send `signal` to the daemon and wait for it to exit; returns its exit
/// status and its full stderr. Force-kills (and fails) past the deadline.
#[cfg(unix)]
fn signal_and_wait(mut serve: ServeChild, signal: i32) -> (std::process::ExitStatus, String) {
    let pid = serve.child.as_ref().unwrap().id();
    // SAFETY: `pid` is the id of the child this test spawned and still owns.
    unsafe {
        libc::kill(i32::try_from(pid).expect("pid fits in i32"), signal);
    }
    let deadline = Instant::now() + SIGNAL_EXIT_DEADLINE;
    let status = loop {
        if Instant::now() > deadline {
            let _ = serve.child.as_mut().unwrap().kill();
            panic!("daemon did not exit within {SIGNAL_EXIT_DEADLINE:?} of signal {signal}");
        }
        match serve.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(SIGNAL_EXIT_POLL),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };
    // The child already exited; clearing it lets `stop` only join the pipe readers.
    serve.child = None;
    let _ = serve.stop();
    let stderr = serve.stderr();
    (status, stderr)
}

/// #6236 — for BOTH signals: a WAL exists before the signal, the exit is a
/// success, the shutdown log shows stop then deferred-audit drain, and the
/// WAL is checkpointed to zero length. SIGTERM must equal SIGINT.
#[cfg(unix)]
#[test]
fn serve_stop_signals_drain_in_order_and_exit_success_6236() {
    use std::os::unix::process::ExitStatusExt;

    for (name, signal) in [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)] {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("ai-memory.db");
        let serve = spawn_serve(&db, &[], &[]);
        let client = http_client(&serve);
        let resp = send_first_request(|| {
            client
                .post(serve.url("/api/v1/memories"))
                .header("X-Agent-Id", "ai:serve-6236")
                .json(&serde_json::json!({
                    "tier": "mid",
                    "namespace": "sig-6236",
                    "title": format!("before-{name}"),
                    "content": "written before the stop signal"
                }))
        });
        assert!(
            resp.status().is_success(),
            "{name}: create {}",
            resp.status()
        );
        let wal = tmp.path().join("ai-memory.db-wal");
        assert!(wal.exists(), "{name}: a WAL must exist before the signal");

        let (status, stderr) = signal_and_wait(serve, signal);
        assert_eq!(status.signal(), None, "{name}: died by signal\n{stderr}");
        assert!(status.success(), "{name}: exit {status:?}\n{stderr}");
        let begin = stderr.find(SHUTDOWN_BEGIN_MARKER);
        let drained = stderr.find(AUDIT_DRAINED_MARKER);
        assert!(
            matches!((begin, drained), (Some(b), Some(d)) if b < d),
            "{name}: log must show stop then audit drain: {begin:?} {drained:?}\n{stderr}"
        );
        let wal_len = std::fs::metadata(&wal).map_or(0, |m| m.len());
        assert_eq!(
            wal_len, 0,
            "{name}: WAL must be checkpointed to zero length"
        );
    }
}

/// #6236 — packaging: the image stops with SIGTERM and the admin guide states
/// the stop grace budget.
#[test]
fn dockerfile_stopsignal_and_admin_guide_grace_6236() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).unwrap();
    assert!(
        dockerfile.lines().any(|l| l.trim() == "STOPSIGNAL SIGTERM"),
        "#6236: Dockerfile must declare STOPSIGNAL SIGTERM"
    );
    let guide = std::fs::read_to_string(root.join("docs/ADMIN_GUIDE.md")).unwrap();
    assert!(
        guide.contains("SIGTERM") && guide.contains("--shutdown-grace-secs"),
        "#6236: docs/ADMIN_GUIDE.md must state SIGTERM handling and the grace budget"
    );
}
