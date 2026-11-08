// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Process-isolated regression coverage for escalation frame diagnostics.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use crate::models::GovernedAction;
use crate::storage::connection::WriteTxn;
use crate::storage::escalation_deferral::{DeferredEscalation, defer_to_open_txn};
use rusqlite::Connection;

const CHILD_ROLE: &str = "AI_MEMORY_TEST_ESCALATION_8184_CHILD";
const RAW_REPORT_PREFIX: &str = "ERROR #4116:";
const OPEN_REPORT: &str = "ERROR #4116: a WriteTxn opened";
const EXIT_REPORT: &str = "ERROR #4116: thread exited";

fn child_stderr(name: &str, action: impl FnOnce() + Send + 'static) -> Option<String> {
    if std::env::var(CHILD_ROLE).as_deref() == Ok(name) {
        std::thread::spawn(action).join().expect("child thread");
        return None;
    }
    let (_, module) = module_path!().split_once("::").expect("crate module path");
    let test_path = format!("{module}::{name}");
    let output = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("test executable"),
        "escalation_frame_reporting_8184::child",
    )
    .args(["--exact", &test_path, "--nocapture", "--test-threads=1"])
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

/// Only raw lines beginning `ERROR #4116:` are authoritative lost-write
/// reports. Structured tracing diagnostics have a target prefix and do not
/// count, even when the subscriber also writes to stderr (ruling #8184).
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
        stderr
            .lines()
            .filter(|line| line.starts_with(RAW_REPORT_PREFIX))
            .count(),
        1,
        "one lost intent must produce one report: {stderr}"
    );
    assert!(stderr.lines().any(|line| line.starts_with(OPEN_REPORT)));
    assert!(!stderr.lines().any(|line| line.starts_with(EXIT_REPORT)));
}

#[test]
fn issue_6132_no_subscriber_reports_at_open_and_not_again_at_exit() {
    let name = "issue_6132_no_subscriber_reports_at_open_and_not_again_at_exit";
    let Some(stderr) = child_stderr(name, || {
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["lost"]);
        reopen(&path);
    }) else {
        return;
    };
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(OPEN_REPORT))
            .count(),
        1,
        "no subscriber must still receive the open-time raw report: {stderr}"
    );
    assert!(
        !stderr.lines().any(|line| line.starts_with(EXIT_REPORT)),
        "a delivered open-time report must not repeat at exit: {stderr}"
    );
}

#[test]
fn issue_6132_later_intent_on_reported_frame_remains_reportable() {
    let name = "issue_6132_later_intent_on_reported_frame_remains_reportable";
    let Some(stderr) = child_stderr(name, || {
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["first"]);
        reopen(&path);
        let conn = Connection::open(&path).expect("open connection for later intent");
        assert!(defer_to_open_txn(conn.path(), intent("later")).is_ok());
    }) else {
        return;
    };
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(OPEN_REPORT))
            .count(),
        1
    );
    assert!(
        stderr.contains("thread exited with 1 unreported deferred escalation(s) in 1 unsettled escalation frame(s)"),
        "only the later intent remains uncredited: {stderr}"
    );
}

#[test]
fn issue_6132_open_on_other_database_does_not_credit_stale_frame() {
    let name = "issue_6132_open_on_other_database_does_not_credit_stale_frame";
    let Some(stderr) = child_stderr(name, || {
        let dir = tempfile::tempdir().expect("test directory");
        leak(&dir.path().join("leak.db"), &["lost"]);
        let other = Connection::open(dir.path().join("other.db")).expect("open other database");
        drop(WriteTxn::begin(&other).expect("begin on other database"));
    }) else {
        return;
    };
    assert!(!stderr.lines().any(|line| line.starts_with(OPEN_REPORT)));
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(EXIT_REPORT))
            .count(),
        1
    );
}

#[test]
fn issue_6540_no_subscriber_never_silences_a_lost_intent() {
    let name = "issue_6540_no_subscriber_never_silences_a_lost_intent";
    let Some(stderr) = child_stderr(name, || {
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["lost"]);
        reopen(&path);
    }) else {
        return;
    };
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(RAW_REPORT_PREFIX))
            .count(),
        1,
        "a missing tracing subscriber must not erase the raw loss report: {stderr}"
    );
}

#[test]
fn issue_6540_filtered_tracing_never_silences_a_lost_intent() {
    let name = "issue_6540_filtered_tracing_never_silences_a_lost_intent";
    let Some(stderr) = child_stderr(name, || {
        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::OFF)
            .try_init()
            .expect("install disabled subscriber");
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["lost"]);
        reopen(&path);
    }) else {
        return;
    };
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(RAW_REPORT_PREFIX))
            .count(),
        1,
        "a disabled tracing module must not erase the raw loss report: {stderr}"
    );
}

#[test]
fn issue_6540_failed_raw_receipt_leaves_every_intent_for_exit() {
    let name = "issue_6540_failed_raw_receipt_leaves_every_intent_for_exit";
    let Some(stderr) = child_stderr(name, || {
        super::FORCE_REPORT_WRITE_FAILURE.with(|failure| failure.set(true));
        let dir = tempfile::tempdir().expect("test directory");
        let path = dir.path().join("leak.db");
        leak(&path, &["first", "second"]);
        reopen(&path);
        reopen(&path);
    }) else {
        return;
    };
    assert!(!stderr.lines().any(|line| line.starts_with(OPEN_REPORT)));
    assert!(
        stderr.contains("thread exited with 2 unreported deferred escalation(s) in 1 unsettled escalation frame(s)"),
        "failed receipts must leave both intents pending for exit: {stderr}"
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
            assert!(
                conn.is_autocommit(),
                "frame registration must not leak BEGIN"
            );
            conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK")
                .expect("connection must remain usable after frame registration");
        }
    });
}

// Debug assertion contract; the release twin below verifies its reporting path.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "stale escalation frame")]
fn issue_7287_leaked_frame_with_intents_is_detected_on_next_open() {
    let dir = tempfile::tempdir().expect("test directory");
    let path = dir.path().join("leak.db");
    leak(&path, &["lost"]);
    let conn = Connection::open(&path).expect("open next connection");
    let _txn = WriteTxn::begin(&conn).expect("begin next transaction");
}

#[cfg(not(debug_assertions))]
#[test]
fn issue_7287_release_open_reports_without_panicking() {
    let name = "issue_7287_release_open_reports_without_panicking";
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
        // This helper asserts that release begins and drops the next
        // transaction without unwinding. The parent verifies the diagnostic.
        reopen(&path);
    }) else {
        return;
    };
    assert!(
        stderr.contains(OPEN_REPORT),
        "release must retain stale-frame reporting: {stderr}"
    );
}
