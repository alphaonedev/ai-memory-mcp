// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Process-isolated regression coverage for escalation frame diagnostics.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use ai_memory::models::GovernedAction;
use ai_memory::storage::connection::WriteTxn;
use ai_memory::storage::escalation_deferral::{DeferredEscalation, defer_to_open_txn};
use rusqlite::Connection;

const CHILD_ROLE: &str = "AI_MEMORY_TEST_ESCALATION_8184_CHILD";
const OPEN_REPORT: &str = "#4116: a WriteTxn opened";
const EXIT_REPORT: &str = "ERROR #4116: thread exited";

fn child_stderr(name: &str, action: impl FnOnce() + Send + 'static) -> Option<String> {
    if std::env::var(CHILD_ROLE).as_deref() == Ok(name) {
        std::thread::spawn(action).join().expect("child thread");
        return None;
    }
    let output = ai_memory::spawn_audit::audited_command(
        std::env::current_exe().expect("test executable"),
        "escalation_frame_reporting_8184::child",
    )
    .args(["--exact", name, "--nocapture", "--test-threads=1"])
    .env(CHILD_ROLE, name)
    .output()
    .expect("run child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "child failed: {stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "child did not run: {stdout}");
    Some(stderr)
}

fn intent(id: &str) -> DeferredEscalation {
    DeferredEscalation {
        pending_id: id.to_owned(),
        action: GovernedAction::Store,
        namespace: "gov8184/leak".to_owned(),
        memory_id: None,
        requested_by: "ai:worker".to_owned(),
        rule_id: "R-leak".to_owned(),
        payload: serde_json::json!({}),
    }
}

fn leak(path: &Path, ids: &[&str]) {
    let conn = Connection::open(path).expect("open leaked connection");
    let txn = WriteTxn::begin(&conn).expect("begin leaked transaction");
    for id in ids {
        assert!(defer_to_open_txn(conn.path(), intent(id)).is_ok());
    }
    // Deliberate leak: dropping the connection releases SQLite's lock while
    // retaining its unsettled thread-local frame (OWNERSHIP-25).
    std::mem::forget(txn);
}

fn reopen(path: &Path) {
    let conn = Connection::open(path).expect("open next connection");
    let result = catch_unwind(AssertUnwindSafe(|| {
        drop(WriteTxn::begin(&conn).expect("begin next transaction"));
    }));
    assert_eq!(result.is_err(), cfg!(debug_assertions));
}

#[test]
fn issue_6132_stale_frame_reported_once_across_repeated_opens_and_exit() {
    let name = "issue_6132_stale_frame_reported_once_across_repeated_opens_and_exit";
    let Some(stderr) = child_stderr(name, || {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .without_time()
            .try_init()
            .expect("install subscriber");
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["lost"]);
        reopen(&path);
        reopen(&path);
    }) else {
        return;
    };
    assert_eq!(
        stderr.matches(OPEN_REPORT).count() + stderr.matches(EXIT_REPORT).count(),
        1,
        "one lost intent must produce one report: {stderr}"
    );
}

#[test]
fn issue_6449_thread_exit_labels_intents_and_frames_separately() {
    let name = "issue_6449_thread_exit_labels_intents_and_frames_separately";
    let Some(stderr) = child_stderr(name, || {
        let dir = tempfile::tempdir().expect("test directory");
        leak(&dir.path().join("leak.db"), &["first", "second"]);
    }) else {
        return;
    };
    assert!(
        stderr.contains("2 unreported deferred escalation(s) in 1 unsettled escalation frame(s)"),
        "one frame holding two intents must report both units: {stderr}"
    );
}

#[test]
fn issue_6541_stale_frame_unwind_rolls_back_both_begin_modes() {
    let name = "issue_6541_stale_frame_unwind_rolls_back_both_begin_modes";
    child_stderr(name, || {
        for exclusive in [false, true] {
            let dir = tempfile::tempdir().expect("test directory");
            let path = dir.path().join("leak.db");
            leak(&path, &["lost"]);
            let conn = Connection::open(&path).expect("open next connection");
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let txn = if exclusive {
                    WriteTxn::begin_exclusive(&conn)
                } else {
                    WriteTxn::begin(&conn)
                }
                .expect("begin next transaction");
                drop(txn);
            }));
            assert_eq!(outcome.is_err(), cfg!(debug_assertions));
            assert!(conn.is_autocommit(), "frame registration must not leak BEGIN");
            conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK")
                .expect("connection must remain usable after frame registration");
        }
    });
}
