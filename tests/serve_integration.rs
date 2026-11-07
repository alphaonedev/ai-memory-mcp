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
#[cfg(unix)]
use ai_memory::stop_signal::DrainOutcome;
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

/// Send `signal` to the daemon (the child this test spawned and still owns).
#[cfg(unix)]
fn send_stop(serve: &ServeChild, signal: i32) {
    let pid = serve.child.as_ref().unwrap().id();
    // SAFETY: `pid` is the id of the child this test spawned and still owns.
    unsafe {
        libc::kill(i32::try_from(pid).expect("pid fits in i32"), signal);
    }
}

/// Wait for a signalled daemon to exit; returns its exit status and its full
/// stderr. Force-kills (and fails) past the deadline.
#[cfg(unix)]
fn reap_after_stop(mut serve: ServeChild, signal: i32) -> (std::process::ExitStatus, String) {
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

/// Send `signal` to the daemon and wait for it to exit.
#[cfg(unix)]
fn signal_and_wait(serve: ServeChild, signal: i32) -> (std::process::ExitStatus, String) {
    send_stop(&serve, signal);
    reap_after_stop(serve, signal)
}

/// Marker logged once the HTTP server stopped and every in-flight request
/// finished, before the deferred-audit drain.
#[cfg(unix)]
const INFLIGHT_DRAINED_MARKER: &str = "in-flight requests drained";

/// Marker logged once the final audit-head witness step ran.
#[cfg(unix)]
const WITNESS_WRITTEN_MARKER: &str = "final witness flushed";

/// Marker logged once the final WAL checkpoint completed.
#[cfg(unix)]
const CHECKPOINT_MARKER: &str = "final WAL checkpoint complete";

/// Grace the grace-expiry case passes to `--shutdown-grace-secs`, the smallest
/// whole-second budget the flag takes.
#[cfg(unix)]
const SHORT_GRACE_SECS: u64 = 1;

/// The drained text does not name the budget, so any value renders it.
#[cfg(unix)]
const SERVE_DEFAULT_GRACE_SECS: u64 = 30;

/// Fragment shared by every grace-expired log text (from the production text:
/// it states the remaining connections were force-closed).
#[cfg(unix)]
const GRACE_EXPIRED_MARKER: &str = "force-closed, not drained";

/// Longest a held request body may stay open before the test gives up.
#[cfg(unix)]
const HELD_BODY_LIMIT: Duration = Duration::from_secs(30);

/// Pause so the held request is certainly received (headers and the first
/// chunk are on the wire) before the stop signal is sent.
#[cfg(unix)]
const INFLIGHT_SETTLE: Duration = Duration::from_millis(1_000);

/// Pause while the signalled daemon must still be waiting on the held request.
#[cfg(unix)]
const DRAIN_WAIT_PROBE: Duration = Duration::from_millis(500);

/// Bound on waiting for the daemon to log that it began shutting down.
#[cfg(unix)]
const SHUTDOWN_LOG_DEADLINE: Duration = Duration::from_secs(10);

/// A request body that yields its first half, then blocks until released:
/// the request is in flight (received, not complete) for as long as the test
/// holds it.
#[cfg(unix)]
struct HeldBody {
    head: Vec<u8>,
    tail: Vec<u8>,
    pos: usize,
    release: std::sync::mpsc::Receiver<()>,
    released: bool,
}

#[cfg(unix)]
impl std::io::Read for HeldBody {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos == self.head.len() && !self.released {
            self.release
                .recv_timeout(HELD_BODY_LIMIT)
                .map_err(std::io::Error::other)?;
            self.released = true;
        }
        let src = if self.pos < self.head.len() {
            &self.head[self.pos..]
        } else {
            &self.tail[self.pos - self.head.len()..]
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        self.pos += n;
        Ok(n)
    }
}

/// #6236 N3 — count the audit-head witness checkpoints the daemon persisted
/// (read-only; the daemon has exited, so the file is quiescent).
#[cfg(unix)]
fn witness_checkpoint_count(db: &std::path::Path) -> i64 {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the daemon db read-only");
    conn.query_row(
        "SELECT COUNT(*) FROM checkpoints WHERE namespace = ?1",
        [ai_memory::governance::audit::WITNESS_CHECKPOINT_NAMESPACE],
        |r| r.get(0),
    )
    .expect("count witness checkpoints")
}

/// #6236 — for BOTH signals, with a request still in flight when the signal
/// arrives: the in-flight request completes successfully, the exit is a
/// success, and the shutdown log shows, in order: stop, in-flight drained,
/// deferred-audit drained, final witness, WAL checkpoint. The WAL is
/// checkpointed to zero length. SIGTERM must equal SIGINT.
#[cfg(unix)]
#[test]
fn serve_stop_signals_drain_in_order_and_exit_success_6236() {
    use std::os::unix::process::ExitStatusExt;

    for (name, signal) in [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)] {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("ai-memory.db");
        // #6236 N3: enrol a witness key (custody dir + out-of-band pubkey pin)
        // so the shutdown flush really signs and persists a witness row.
        // A memory write does not append to the signed-event chain, and the
        // shutdown flush is a no-op at chain head 0, so seed one event.
        {
            let conn = ai_memory::db::open(&db).expect("init the daemon db");
            let event = ai_memory::signed_events::SignedEvent {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: "ai:serve-6236".to_string(),
                event_type: "memory_link.created".to_string(),
                payload_hash: ai_memory::signed_events::payload_hash(b"serve-6236-seed"),
                signature: None,
                attest_level: "unsigned".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                ..ai_memory::signed_events::SignedEvent::default()
            };
            ai_memory::signed_events::append_signed_event(&conn, &event)
                .expect("seed the signed-event chain");
        }
        let witness_dir = tmp.path().join("witness-keys");
        let witness_key =
            ai_memory::identity::keypair::generate(ai_memory::governance::audit::WITNESS_KEY_LABEL)
                .expect("generate the witness key");
        ai_memory::identity::keypair::save(&witness_key, &witness_dir)
            .expect("save the witness key");
        let witness_dir_arg = witness_dir.to_str().expect("utf-8 witness dir");
        let witness_pub = witness_key.public_base64();
        let serve = spawn_serve(
            &db,
            &[],
            &[
                (
                    ai_memory::governance::audit::WITNESS_KEY_DIR_ENV,
                    witness_dir_arg,
                ),
                (
                    ai_memory::governance::audit::WITNESS_PUBKEY_ENV,
                    witness_pub.as_str(),
                ),
            ],
        );
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

        // A request that is in flight when the signal arrives: its body is
        // held half-sent until the test releases it.
        let payload = serde_json::to_vec(&serde_json::json!({
            "tier": "mid",
            "namespace": "sig-6236",
            "title": format!("in-flight-{name}"),
            "content": "completes while the daemon drains"
        }))
        .unwrap();
        let (head, tail) = payload.split_at(payload.len() / 2);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let body = reqwest::blocking::Body::new(HeldBody {
            head: head.to_vec(),
            tail: tail.to_vec(),
            pos: 0,
            release: release_rx,
            released: false,
        });
        let slow_client = serve.tls.client_with_timeout(HELD_BODY_LIMIT);
        let slow_request = serve.url("/api/v1/memories");
        let in_flight = std::thread::spawn(move || {
            slow_client
                .post(slow_request)
                .header("X-Agent-Id", "ai:serve-6236")
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .map(|r| r.status())
        });
        std::thread::sleep(INFLIGHT_SETTLE);

        send_stop(&serve, signal);
        let begun = Instant::now();
        while !serve.stderr().contains(SHUTDOWN_BEGIN_MARKER) {
            assert!(
                begun.elapsed() < SHUTDOWN_LOG_DEADLINE,
                "{name}: the daemon never logged that it began shutting down\n{}",
                serve.stderr()
            );
            std::thread::sleep(SIGNAL_EXIT_POLL);
        }
        std::thread::sleep(DRAIN_WAIT_PROBE);
        assert!(
            !serve.stderr().contains(INFLIGHT_DRAINED_MARKER),
            "{name}: the daemon must wait for the in-flight request\n{}",
            serve.stderr()
        );
        release_tx.send(()).unwrap();
        let in_flight_status = in_flight
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("{name}: the in-flight request failed: {e}"));
        assert!(
            in_flight_status.is_success(),
            "{name}: the in-flight request must complete: {in_flight_status}"
        );

        let (status, stderr) = reap_after_stop(serve, signal);
        assert_eq!(status.signal(), None, "{name}: died by signal\n{stderr}");
        assert!(status.success(), "{name}: exit {status:?}\n{stderr}");
        let order: Vec<Option<usize>> = [
            SHUTDOWN_BEGIN_MARKER,
            INFLIGHT_DRAINED_MARKER,
            AUDIT_DRAINED_MARKER,
            WITNESS_WRITTEN_MARKER,
            CHECKPOINT_MARKER,
        ]
        .iter()
        .map(|marker| stderr.find(marker))
        .collect();
        assert!(
            order.iter().all(Option::is_some) && order.windows(2).all(|w| w[0] < w[1]),
            "{name}: log must show stop, in-flight drained, audit drained, witness, checkpoint in that order: {order:?}\n{stderr}"
        );
        // #8193 R5: a real drain logs the drained text, taken from the
        // production text source, and never the grace-expired text.
        assert!(
            stderr.contains(&DrainOutcome::Drained.log_text(SERVE_DEFAULT_GRACE_SECS)),
            "{name}: a drained shutdown must log the drained text\n{stderr}"
        );
        assert!(
            !stderr.contains(GRACE_EXPIRED_MARKER),
            "{name}: a drained shutdown must not log the grace-expired text\n{stderr}"
        );
        let wal_len = std::fs::metadata(&wal).map_or(0, |m| m.len());
        assert_eq!(
            wal_len, 0,
            "{name}: WAL must be checkpointed to zero length"
        );
        let witnesses = witness_checkpoint_count(&db);
        assert!(
            witnesses >= 1,
            "{name}: the final witness must be persisted for the enrolled key, found {witnesses} rows"
        );
    }
}

/// #8193 R5 (code r4 M1) - the serve grace-expiry decision. With a held
/// request outliving a 1 s `--shutdown-grace-secs`, the daemon cuts the
/// request at the budget and must log the grace-expired text, never the
/// drained text. Catches the mutation that drops the `signalled_at` `.set(..)`
/// in the shutdown future (elapsed stays zero, every stop logs "drained").
#[cfg(unix)]
#[test]
fn serve_sigterm_past_grace_logs_grace_expired_not_drained_8193() {
    use std::os::unix::process::ExitStatusExt;

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let grace_arg = SHORT_GRACE_SECS.to_string();
    let serve = spawn_serve(&db, &["--shutdown-grace-secs", grace_arg.as_str()], &[]);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let body = reqwest::blocking::Body::new(HeldBody {
        head: br#"{"tier":"mid","#.to_vec(),
        tail: br#""namespace":"sig-8193"}"#.to_vec(),
        pos: 0,
        release: release_rx,
        released: false,
    });
    let slow_client = serve.tls.client_with_timeout(HELD_BODY_LIMIT);
    let slow_request = serve.url("/api/v1/memories");
    let in_flight = std::thread::spawn(move || {
        slow_client
            .post(slow_request)
            .header("X-Agent-Id", "ai:serve-8193")
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map(|r| r.status())
    });
    std::thread::sleep(INFLIGHT_SETTLE);

    let (status, stderr) = signal_and_wait(serve, libc::SIGTERM);
    // The held request was cut at the budget; release the body thread.
    let _ = release_tx.send(());
    let _ = in_flight.join();
    assert_eq!(status.signal(), None, "died by signal\n{stderr}");
    assert!(status.success(), "exit {status:?}\n{stderr}");
    assert!(
        stderr.contains(&DrainOutcome::GraceExpired.log_text(SHORT_GRACE_SECS)),
        "a stop past the grace budget must log the grace-expired text\n{stderr}"
    );
    assert!(
        !stderr.contains(&DrainOutcome::Drained.log_text(SHORT_GRACE_SECS)),
        "a stop past the grace budget must not claim a drain\n{stderr}"
    );
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
    // The ONE stop budget (seconds): systemd `TimeoutStopSec`, `docker stop -t`
    // and compose `stop_grace_period` all carry it, so a supervisor never
    // SIGKILLs the daemon inside its drain (r1 L3/F4).
    let budget = STOP_BUDGET_SECS;
    for needle in [
        format!("TimeoutStopSec={budget}"),
        format!("docker stop -t {budget}"),
        format!("stop_grace_period: {budget}s"),
    ] {
        assert!(
            guide.contains(&needle),
            "#6236: docs/ADMIN_GUIDE.md must state the container stop timeout: missing {needle:?}"
        );
    }
}

/// The documented stop budget in seconds: the HTTP grace plus the bounded
/// drain, witness and checkpoint phases (systemd `TimeoutStopSec`).
const STOP_BUDGET_SECS: u32 = 90;
