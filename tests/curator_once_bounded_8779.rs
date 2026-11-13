// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8779: `curator --once` terminates within a bounded wall clock with
//! tracing enabled.
//!
//! The dispatch arm held the process stderr lock while it awaited the
//! `spawn_blocking` sweep. The console subscriber writes to stderr, so the
//! first tracing event on the worker thread blocked on that lock and the
//! command never returned. A sweep only emits on the worker thread when it
//! has eligible rows and a reachable LLM, so the test seeds rows and serves
//! a loopback stub LLM, runs the real binary with the most verbose filter,
//! and kills it at the ceiling, so a regression fails here instead of
//! hanging CI.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Wall-clock ceiling for one `curator --once` sweep over the seeded store.
/// A healthy run takes a few seconds; the ceiling only absorbs a loaded CI
/// host. The deadlock never finishes, so any finite ceiling separates the
/// two.
const ONCE_CEILING: Duration = Duration::from_secs(90);

/// Poll interval while waiting for the child to exit.
const EXIT_POLL: Duration = Duration::from_millis(100);

/// The most verbose filter: every tracing event on every thread is written to
/// stderr, which is the condition that deadlocked.
const TRACE_EVERYTHING: &str = "trace";

/// Model name the stub LLM advertises and the curator is pointed at.
const STUB_MODEL: &str = "stub-8779";

/// Rows seeded so the sweep has eligible candidates (each over the curator's
/// minimum content length, none carrying `auto_tags`).
const SEEDED_ROWS: usize = 3;

/// Namespace of the seeded rows.
const SEED_NAMESPACE: &str = "curator-8779";

/// Environment switch that turns the SQLite consolidation (compaction) pass
/// on for one run. The audit reproduced #8779 through this pass as well: its
/// nested store and runtime emit tracing on the blocking worker after the
/// write-ahead row lands.
const COMPACTION_ON: (&str, &str) = ("AI_MEMORY_COMPACTION_ENABLED", "1");

/// Upper bound on one stub request's header block, so a malformed client can
/// never make the stub read without end.
const STUB_MAX_HEADER_LINES: usize = 128;

/// Upper bound on one stub request body.
const STUB_MAX_BODY: usize = 1 << 20;

/// Reply for the Ollama model listing (`GET /api/tags`) and health probe.
fn stub_tags_body() -> String {
    format!(r#"{{"models":[{{"name":"{STUB_MODEL}"}},{{"name":"{STUB_MODEL}:latest"}}]}}"#)
}

/// Reply for an Ollama chat call (`POST /api/chat`): a short tag list, so the
/// sweep reaches its persist and trace paths.
const STUB_CHAT_BODY: &str = r#"{"model":"stub-8779","message":{"role":"assistant","content":"deploy, rollout, canary"},"done":true}"#;

/// Answer one HTTP/1.1 request on `stream` and close it.
fn serve_one(stream: TcpStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut content_length = 0_usize;
    for _ in 0..STUB_MAX_HEADER_LINES {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0).min(STUB_MAX_BODY);
        }
    }
    let mut body = vec![0_u8; content_length];
    let _ = reader.read_exact(&mut body);
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let reply = if path.starts_with("/api/tags") {
        stub_tags_body()
    } else if path.starts_with("/api/chat") {
        STUB_CHAT_BODY.to_string()
    } else {
        r#"{"status":"success"}"#.to_string()
    };
    let mut out = stream;
    let _ = write!(
        out,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = out.flush();
}

/// Start the loopback stub LLM on an ephemeral port and return its base URL.
/// The accept thread is detached; it ends with the test process.
fn start_stub_llm() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub LLM");
    let addr = listener.local_addr().expect("stub LLM addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_one(stream));
        }
    });
    format!("http://{addr}")
}

/// Seed `SEEDED_ROWS` eligible mid-tier rows through the real `store` verb.
fn seed_rows(db: &Path, home: &Path) {
    for n in 0..SEEDED_ROWS {
        let status = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .arg("--db")
            .arg(db)
            .args(["store", "--tier", "mid", "--namespace", SEED_NAMESPACE])
            .arg("--title")
            .arg(format!("canary rollout note {n}"))
            .arg("--content")
            .arg(format!(
                "canary rollout of the kubernetes deploy pipeline, step {n}, with a staged \
                 traffic shift and an automatic rollback on error budget burn"
            ))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", "ai:curator-8779")
            .env("HOME", home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn ai-memory store");
        assert!(
            status.success(),
            "#8779: seeding row {n} failed: {status:?}"
        );
    }
}

/// Run `curator --once` with `extra` args against a seeded store and the stub
/// LLM, and return `(exit status, stdout, elapsed)`, killing the child (this
/// test's own) at the ceiling.
fn run_once_bounded(
    extra: &[&str],
    envs: &[(&str, &str)],
) -> (std::process::ExitStatus, String, Duration) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db = tmp.path().join("curator-once-8779.db");
    let keys = tmp.path().join("keys");
    seed_rows(&db, tmp.path());
    let llm_url = start_stub_llm();
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("--db")
        .arg(&db)
        .arg("curator")
        .arg("--once")
        .args(extra)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", "ai:curator-8779")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_LLM_BACKEND", "ollama")
        .env("AI_MEMORY_LLM_BASE_URL", &llm_url)
        .env("AI_MEMORY_LLM_MODEL", STUB_MODEL)
        .env("HOME", tmp.path())
        .env("RUST_LOG", TRACE_EVERYTHING)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // stderr is discarded rather than piped so a full pipe can never be
        // the reason the child stops.
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ai-memory curator --once");
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if started.elapsed() > ONCE_CEILING {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "#8779: `curator --once` did not exit within {ONCE_CEILING:?} with \
                 RUST_LOG={TRACE_EVERYTHING} (stdio lock held across the blocking sweep)"
            );
        }
        std::thread::sleep(EXIT_POLL);
    };
    let elapsed = started.elapsed();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    (status, stdout, elapsed)
}

#[test]
fn curator_once_exits_within_ceiling_with_trace_logging_8779() {
    let (status, stdout, elapsed) = run_once_bounded(&[], &[]);
    assert!(
        status.success(),
        "#8779: curator --once exit {status:?}; stdout:\n{stdout}"
    );
    assert!(elapsed < ONCE_CEILING, "#8779: took {elapsed:?}");
}

#[test]
fn curator_once_json_report_is_written_after_traced_sweep_8779() {
    let (status, stdout, _) = run_once_bounded(&["--json"], &[]);
    assert!(
        status.success(),
        "#8779: curator --once --json exit {status:?}; stdout:\n{stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("#8779: --json stdout is not one JSON report ({e}):\n{stdout}"));
    let scanned = report
        .get("memories_scanned")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("#8779: report has no memories_scanned: {report}"));
    assert_eq!(
        scanned,
        u64::try_from(SEEDED_ROWS).expect("seeded rows fit u64"),
        "#8779: the sweep scanned the seeded rows: {report}"
    );
}

#[test]
fn curator_once_with_compaction_exits_within_ceiling_8779() {
    let (status, stdout, elapsed) = run_once_bounded(&["--json"], &[COMPACTION_ON]);
    assert!(
        status.success(),
        "#8779: curator --once (compaction on) exit {status:?}; stdout:\n{stdout}"
    );
    assert!(
        elapsed < ONCE_CEILING,
        "#8779: compaction run took {elapsed:?}"
    );
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("#8779: compaction --json stdout is not one JSON report ({e}):\n{stdout}")
    });
    assert!(
        report.get("memories_scanned").is_some(),
        "#8779: the compaction sweep wrote its report: {report}"
    );
}
