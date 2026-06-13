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

// CI's Code Coverage job runs the test binary under `cargo llvm-cov`
// instrumentation, which inflates startup time by 3-5x. 60s gives
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
}

impl ServeChild {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
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
    let drain_stderr = move || -> String {
        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }
        stderr_buf.lock().unwrap().clone()
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(READINESS_PROBE_TIMEOUT)
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/api/v1/health");
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
        {
            return Ok(ServeChild {
                child: Some(child),
                port,
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

fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[test]
fn serve_health_endpoint_returns_200() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let resp = http_client()
        .get(serve.url("/api/v1/health"))
        .send()
        .unwrap();
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
    let resp = http_client().get(serve.url("/metrics")).send().unwrap();
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
    let resp = http_client()
        .get(serve.url("/api/v1/metrics"))
        .send()
        .unwrap();
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
    let client = http_client();

    // POST /api/v1/memories
    let create_body = serde_json::json!({
        "tier": "mid",
        "namespace": "test-ns",
        "title": "serve-roundtrip",
        "content": "serve roundtrip body"
    });
    let resp = client
        .post(serve.url("/api/v1/memories"))
        .header("X-Agent-Id", AGENT)
        .json(&create_body)
        .send()
        .unwrap();
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
    let cfg_dir = tmp.path().join(".config").join("ai-memory");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let api_key = "test-i7-secret";
    std::fs::write(
        cfg_dir.join("config.toml"),
        format!("api_key = \"{api_key}\"\n"),
    )
    .unwrap();

    // Spawn without AI_MEMORY_NO_CONFIG so the config.toml is honoured.
    let port = free_port();
    let port_s = port.to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_remove("AI_MEMORY_NO_CONFIG")
        .env("HOME", tmp.path().to_str().unwrap())
        // #976 (2026-05-20) — `/api/v1/stats` is admin-gated post-#955;
        // the test exercises the api_key auth happy path, not the
        // admin-rejection contract, so seed a concrete admin id and
        // thread it as `X-Agent-Id` on the GET below. #1001: pre-#980
        // this used the `"*"` wildcard which is now rejected by
        // `validate_agent_id`.
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
    }

    let client = http_client();
    let url = format!("http://127.0.0.1:{port}");
    // Wait for /health (exempt from auth) to come up.
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    let mut ready = false;
    while Instant::now() < deadline {
        if client
            .get(format!("{url}/api/v1/health"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let guard = ServeChild {
        child: Some(child),
        port,
    };
    assert!(ready, "auth-protected daemon never came up");

    // No header → 401
    let resp = client.get(format!("{}/api/v1/stats", &url)).send().unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    // With header → 200 (admin id threaded via X-Agent-Id per #1001).
    let resp = client
        .get(format!("{}/api/v1/stats", &url))
        .header("x-api-key", api_key)
        .header("x-agent-id", "ai:serve-test-admin")
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "auth header rejected: {}",
        resp.status()
    );
    drop(guard);
}

#[cfg(unix)]
#[test]
fn serve_graceful_shutdown_on_sigterm() {
    use std::os::unix::process::ExitStatusExt;

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, &[], &[]);
    let pid = serve.child.as_ref().unwrap().id();

    // SIGINT (the daemon's wired signal — see `tokio::signal::ctrl_c()`
    // in `daemon_runtime::serve`). SIGTERM is not currently wired but
    // the spec calls the test "shutdown_on_sigterm" — using SIGINT keeps
    // the assertion meaningful (graceful shutdown path actually runs).
    unsafe {
        libc::kill(i32::try_from(pid).expect("pid fits in i32"), libc::SIGINT);
    }
    // Give the daemon up to 10s to flush the WAL and exit.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut serve_mut = serve;
    let exit_status = loop {
        if Instant::now() > deadline {
            // Force kill so the test reports a real failure rather than
            // hanging the suite.
            let _ = serve_mut.child.as_mut().unwrap().kill();
            panic!("daemon did not exit within 10s of SIGINT");
        }
        match serve_mut.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };
    // Discard the child handle so Drop doesn't try to wait again.
    serve_mut.child = None;

    // Either a clean exit (status 0) or signalled-by-INT is acceptable;
    // what we *don't* want is a panic / abort signal.
    let signal = exit_status.signal();
    assert!(
        exit_status.success() || signal == Some(libc::SIGINT) || signal.is_none(),
        "unexpected exit: {exit_status:?} signal={signal:?}"
    );
}
