// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1955 (R45) — end-to-end coverage for the `ai-memory stop` CLI dispatch
//! ARM in `src/daemon_runtime.rs` (`Command::Stop`), driven through the real
//! binary (`CARGO_BIN_EXE_ai-memory`) so the dispatch glue (stdio locks +
//! async SAL-store build + exit-code routing) is exercised — it is otherwise
//! integration-only (see `coverage/policy.md` for the `daemon_runtime.rs`
//! exception). The
//! actuator's storage-layer behavior is unit/integration-tested separately in
//! `tests/record_stop_r45_1955.rs`; this pins the CLI seam.
//!
//! `sal`-gated: the `stop` verb builds the SAL `MemoryStore`.
#![cfg(feature = "sal")]

use std::path::Path;
use std::process::Output;

/// Run `ai-memory --db <db> stop <args...>` against a throwaway DB with the
/// process env pinned to `AI_MEMORY_NO_CONFIG=1` so no developer config
/// leaks in. Returns the captured `Output`.
fn run_stop(db_path: &Path, args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("--db").arg(db_path).arg("stop");
    for a in args {
        cmd.arg(a);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd.output().expect("spawn ai-memory stop")
}

/// A fresh temp DB path under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_db(label: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1955-cli-dispatch");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let db = dir.path().join("ai-memory.db");
    (dir, db)
}

#[test]
fn stop_status_on_fresh_db_reports_not_stopped_exit_zero() {
    let (_dir, db) = fresh_db("status");
    let out = run_stop(&db, &["--status", "--json"]);
    assert!(
        out.status.success(),
        "status exit: {:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status --json parses");
    // A never-stopped substrate reports stopped=false.
    assert_eq!(v["stopped"], serde_json::Value::Bool(false), "got: {v}");
}

#[test]
fn stop_then_status_then_resume_round_trips_through_the_dispatch_arm() {
    let (_dir, db) = fresh_db("roundtrip");

    // Engage the record-stop.
    let engaged = run_stop(&db, &["--json"]);
    assert!(
        engaged.status.success(),
        "stop exit: {:?} stderr={}",
        engaged.status.code(),
        String::from_utf8_lossy(&engaged.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&engaged.stdout).expect("stop --json");
    assert_eq!(v["action"], "stopped", "got: {v}");
    assert_eq!(v["changed"], serde_json::Value::Bool(true), "got: {v}");

    // Status now reflects the stop (persisted across process invocations).
    let status = run_stop(&db, &["--status", "--json"]);
    assert!(status.status.success());
    let v: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status --json");
    assert_eq!(v["stopped"], serde_json::Value::Bool(true), "got: {v}");

    // Resume releases it.
    let resumed = run_stop(&db, &["--resume", "--json"]);
    assert!(resumed.status.success());
    let v: serde_json::Value = serde_json::from_slice(&resumed.stdout).expect("resume --json");
    assert_eq!(v["action"], "resumed", "got: {v}");
    assert_eq!(v["changed"], serde_json::Value::Bool(true), "got: {v}");

    // Final status: back to not-stopped.
    let status2 = run_stop(&db, &["--status", "--json"]);
    assert!(status2.status.success());
    let v: serde_json::Value = serde_json::from_slice(&status2.stdout).expect("status --json");
    assert_eq!(v["stopped"], serde_json::Value::Bool(false), "got: {v}");
}
