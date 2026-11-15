// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8662 — no deferred work may land in a LEAKED `WriteTxn` frame.
//!
//! Invariant: every intent handed to a frame is either settled by that
//! frame's live transaction or surfaces a typed error; a frame whose
//! transaction has provably ended (its connection dropped, its transaction
//! ended underneath it, or a later `BEGIN IMMEDIATE` on the same database
//! succeeded) never accepts new work. Two sites hand work to frames:
//! escalation intents (`route_escalation_to_approval_gate`) and signed-event
//! audit anchors (`defer_audit_anchor`). Each is driven over every leak shape.
//!
//! Backend parity: the frame stack exists on SQLite only. Postgres has no
//! thread-local transaction frames (its sqlx transactions are explicit
//! values) and no escalation deferral, so there is no Postgres cell.

use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use super::TXN_FRAMES;
use crate::approvals::signed::route_escalation_to_approval_gate;
use crate::models::GovernedAction;
use crate::storage::connection::WriteTxn;
use crate::storage::escalation_deferral::{DeferredEscalation, defer_audit_anchor, is_deferred};

/// `busy_timeout` that `crate::db::open` applies (`apply_writer_pragmas`).
const WRITER_BUSY_TIMEOUT_MS: i64 = 5_000;
/// A routing that waited out the writer lock would take the whole
/// `busy_timeout`; a correct one returns well inside this ceiling.
const ROUTE_CEILING: Duration = Duration::from_millis(1_000);
const NAMESPACE: &str = "gov8662/leak";
const REQUESTER: &str = "ai:worker-8662";
const RULE_ID: &str = "R-8662";
const REASON: &str = "leaked frame regression";
/// Head 0 is never due for a watermark, so emitting it writes nothing.
const INERT_HEAD_SEQUENCE: i64 = 0;

/// How the leaked frame came to be, and which connection routes afterwards.
#[derive(Debug, Clone, Copy)]
enum LeakShape {
    /// Forgotten `WriteTxn`, connection dropped, a later `WriteTxn` opened
    /// and closed on the database; the route runs on a third connection.
    DroppedThenReopened,
    /// Forgotten `WriteTxn` that had already deferred an intent, connection
    /// dropped, a later open reported it; route on a third connection.
    DroppedWithIntentThenReopened,
    /// Forgotten `WriteTxn`, connection dropped, NO later open; the route
    /// runs on another connection to the same database.
    DroppedNoReopen,
    /// Forgotten `WriteTxn` whose transaction was then ended with a raw
    /// ROLLBACK on the same, still-open connection, which routes next.
    EndedUnderneathSameConnection,
}

const LEAK_SHAPES: &[LeakShape] = &[
    LeakShape::DroppedThenReopened,
    LeakShape::DroppedWithIntentThenReopened,
    LeakShape::DroppedNoReopen,
    LeakShape::EndedUnderneathSameConnection,
];

fn intent(id: &str) -> DeferredEscalation {
    DeferredEscalation {
        pending_id: id.to_owned(),
        action: GovernedAction::Store,
        namespace: NAMESPACE.to_owned(),
        memory_id: None,
        requested_by: REQUESTER.to_owned(),
        rule_id: RULE_ID.to_owned(),
        payload: serde_json::json!({}),
    }
}

fn open(path: &Path) -> Connection {
    crate::db::open(path).expect("open migrated database")
}

fn pending_rows(path: &Path, id: &str) -> i64 {
    let conn = Connection::open(path).expect("open probe connection");
    conn.query_row(
        "SELECT COUNT(*) FROM pending_actions WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .expect("count pending rows")
}

fn busy_timeout(conn: &Connection) -> i64 {
    conn.pragma_query_value(None, "busy_timeout", |r| r.get(0))
        .expect("read busy_timeout")
}

fn route(conn: &Connection) -> String {
    route_escalation_to_approval_gate(
        conn,
        GovernedAction::Store,
        NAMESPACE,
        None,
        REQUESTER,
        &serde_json::json!({ "content": "escalated" }),
        RULE_ID,
        REASON,
    )
    .expect("route escalation")
}

/// Open a `WriteTxn` on a later connection and close it. A leaked frame
/// holding intents makes the open report (and, in debug builds, assert).
fn reopen(path: &Path) {
    let conn = open(path);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(WriteTxn::begin(&conn).expect("begin later transaction"));
    }));
    if let Err(payload) = result {
        let text = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(
            text.contains("stale escalation frame"),
            "only the leak assertion may fire: {text}"
        );
    }
}

/// Build `shape` on `path`, then run `act` on the connection that routes
/// next. Runs on a fresh thread so the leaked frame cannot reach other tests.
fn with_leak<T: Send + 'static>(
    shape: LeakShape,
    path: &Path,
    act: impl FnOnce(&Connection) -> T + Send + 'static,
) -> T {
    let path = path.to_path_buf();
    std::thread::spawn(move || {
        // Every connection is opened (and migrated) BEFORE the leak, so no
        // migration transaction observes the leaked frame.
        let leaker = open(&path);
        let router = open(&path);
        let txn = WriteTxn::begin(&leaker).expect("begin leaked transaction");
        if matches!(shape, LeakShape::DroppedWithIntentThenReopened) {
            assert!(super::defer_to_open_txn(leaker.path(), intent("leaked-first")).is_ok());
        }
        std::mem::forget(txn);
        match shape {
            LeakShape::DroppedThenReopened | LeakShape::DroppedWithIntentThenReopened => {
                drop(leaker);
                reopen(&path);
                act(&router)
            }
            LeakShape::DroppedNoReopen => {
                drop(leaker);
                act(&router)
            }
            LeakShape::EndedUnderneathSameConnection => {
                leaker
                    .execute_batch(super::super::connection::SQL_ROLLBACK)
                    .expect("end the leaked transaction underneath its guard");
                act(&leaker)
            }
        }
    })
    .join()
    .expect("leak thread")
}

/// Site 1 — an escalation routed after a leak is QUEUED NOW: the returned
/// pending id names a row that exists, it is not parked in the dead frame,
/// and the connection's busy_timeout is left as it was.
#[test]
fn issue_8662_escalation_after_leak_is_queued_not_parked_in_dead_frame() {
    for &shape in LEAK_SHAPES {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leak.db");
        let (id, deferred, timeout, elapsed) = with_leak(shape, &path, |conn| {
            let start = Instant::now();
            let id = route(conn);
            (
                id.clone(),
                is_deferred(&id),
                busy_timeout(conn),
                start.elapsed(),
            )
        });
        assert!(
            !deferred,
            "{shape:?}: pending {id} parked in a leaked frame"
        );
        assert_eq!(
            pending_rows(&path, &id),
            1,
            "{shape:?}: caller was handed pending id {id} with no row"
        );
        assert_eq!(
            timeout, WRITER_BUSY_TIMEOUT_MS,
            "{shape:?}: busy_timeout changed"
        );
        assert!(elapsed < ROUTE_CEILING, "{shape:?}: route took {elapsed:?}");
    }
}

/// Control (#4116 must not regress) — with a LIVE frame on the database the
/// escalation is still deferred to it, without waiting out the writer lock,
/// and lands when that transaction ends.
#[test]
fn issue_8662_live_frame_still_defers_and_lands_on_commit() {
    for same_connection in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("live.db");
        let path_for_thread = path.clone();
        let (id, deferred, rows_before, timeout, elapsed) = std::thread::spawn(move || {
            let owner = open(&path_for_thread);
            let other = open(&path_for_thread);
            let txn = WriteTxn::begin(&owner).expect("begin live transaction");
            let router = if same_connection { &owner } else { &other };
            let start = Instant::now();
            let id = route(router);
            let elapsed = start.elapsed();
            let deferred = is_deferred(&id);
            let timeout = busy_timeout(router);
            let rows_before = pending_rows(&path_for_thread, &id);
            txn.commit().expect("commit live transaction");
            (id, deferred, rows_before, timeout, elapsed)
        })
        .join()
        .expect("live thread");
        assert!(
            deferred,
            "same={same_connection}: live frame must take the intent"
        );
        assert_eq!(rows_before, 0, "same={same_connection}: row before settle");
        assert_eq!(
            pending_rows(&path, &id),
            1,
            "same={same_connection}: row after commit"
        );
        assert_eq!(
            timeout, WRITER_BUSY_TIMEOUT_MS,
            "same={same_connection}: busy_timeout"
        );
        assert!(
            elapsed < ROUTE_CEILING,
            "same={same_connection}: route took {elapsed:?}"
        );
    }
}

/// Site 2 — a signed-event audit anchor handed over on a connection whose
/// frame leaked is never absorbed into that dead frame (it would never be
/// emitted): the connection is in autocommit, so the append committed.
#[test]
fn issue_8662_audit_anchor_is_never_absorbed_by_a_dead_frame() {
    for reopen_same_connection in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("anchor.db");
        let absorbed = std::thread::spawn(move || {
            let conn = open(&path);
            std::mem::forget(WriteTxn::begin(&conn).expect("begin leaked transaction"));
            conn.execute_batch(super::super::connection::SQL_ROLLBACK)
                .expect("end the leaked transaction underneath its guard");
            if reopen_same_connection {
                WriteTxn::begin(&conn)
                    .expect("begin later transaction")
                    .commit()
                    .expect("commit later transaction");
            }
            let addr = std::ptr::from_ref(&conn).addr();
            defer_audit_anchor(
                &conn,
                crate::governance::audit::PendingAuditAnchor::watermark(
                    INERT_HEAD_SEQUENCE,
                    "head-8662",
                    "db-8662",
                ),
            );
            TXN_FRAMES.with(|frames| {
                frames
                    .borrow()
                    .0
                    .iter()
                    .any(|f| f.conn_addr == addr && !f.anchor.is_empty())
            })
        })
        .join()
        .expect("anchor thread");
        assert!(
            !absorbed,
            "reopen={reopen_same_connection}: anchor absorbed by a leaked frame"
        );
    }
}

// ---------------------------------------------------------------------------
// #8707 review round 1: the probe transaction and the remaining windows.
// ---------------------------------------------------------------------------

/// Env var naming the cell a re-executed child process runs.
const CHILD_ROLE: &str = "AI_MEMORY_TEST_LEAKED_FRAME_8707_CHILD";
/// Label for the audited re-exec of this test binary.
const CHILD_SPAWN_LABEL: &str = "escalation_leaked_frame_8707::child";
/// The thread-exit report of a frame left holding exactly one intent.
const EXIT_REPORT_ONE_INTENT: &str = "ERROR #4116: thread exited with 1 unreported deferred \
     escalation(s) in 1 unsettled escalation frame(s)";
/// Prefix of every thread-exit lost-write report.
const EXIT_REPORT_PREFIX: &str = "ERROR #4116: thread exited";
/// Ceiling for a hand-off between the router and the lock-holder thread.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);
/// Pending id the probe-insert failure cells write.
const PROBE_FAILURE_ID: &str = "probe-failure-8707";
/// Message of the trigger that refuses every `pending_actions` INSERT.
const REFUSING_TRIGGER_MSG: &str = "forced pending insert refusal 8707";
/// SQLite's text for the duplicate primary key the duplicate cell provokes.
const DUPLICATE_ID_MSG: &str = "UNIQUE constraint failed: pending_actions.id";

/// Rows for `NAMESPACE`, whatever their id.
fn namespace_rows(path: &Path) -> i64 {
    let conn = Connection::open(path).expect("open probe connection");
    conn.query_row(
        "SELECT COUNT(*) FROM pending_actions WHERE namespace = ?1",
        [NAMESPACE],
        |r| r.get(0),
    )
    .expect("count namespace rows")
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default()
}

/// Run `action` in a child process (a fresh test binary run of `name`) and
/// return its stderr; inside that child, run `action` and return `None`.
fn child_stderr(name: &str, action: impl FnOnce() + Send + 'static) -> Option<String> {
    if std::env::var(CHILD_ROLE).as_deref() == Ok(name) {
        std::thread::spawn(action).join().expect("child thread");
        return None;
    }
    let (_, module) = module_path!().split_once("::").expect("crate module path");
    let test_path = format!("{module}::{name}");
    let output = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("test executable"),
        CHILD_SPAWN_LABEL,
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

/// Code F1 (#8707) - a panic after the probe's `BEGIN IMMEDIATE` and before
/// its COMMIT must not leave the routing connection inside a write
/// transaction (it would hold the database write lock) and must leave the
/// connection's busy_timeout as it was.
#[test]
fn issue_8707_panic_inside_probe_txn_rolls_back_and_restores_busy_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("probe-panic.db");
    let (text, autocommit, timeout) = with_leak(LeakShape::DroppedNoReopen, &path, |conn| {
        super::force_probe_panic_for_test(true);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| route(conn)));
        super::force_probe_panic_for_test(false);
        let text = match outcome {
            Ok(id) => format!("no panic, routed {id}"),
            Err(payload) => panic_text(payload.as_ref()),
        };
        (text, conn.is_autocommit(), busy_timeout(conn))
    });
    assert_eq!(text, super::MSG_FORCED_PROBE_PANIC, "the seam must fire");
    assert!(
        autocommit,
        "the probe transaction survived the unwind and still holds the write lock"
    );
    assert_eq!(timeout, WRITER_BUSY_TIMEOUT_MS, "busy_timeout not restored");
    assert_eq!(namespace_rows(&path), 0, "a panicked probe wrote a row");
}

/// A route into a dead frame that the probe cannot rule out (#8707 code F2,
/// F3; security F1, F2). Both defer the intent and fail CLOSED.
#[derive(Debug, Clone, Copy)]
enum ResidualWindow {
    /// Another connection (here another thread of this process) holds the
    /// write lock at the probe instant, so the zero-timeout probe is BUSY.
    ForeignWriterHoldsLock,
    /// The router is inside a transaction of its own (no frame), so the
    /// probe would nest and is not run: the `(false, false)` arm.
    RouterInOwnTransaction,
}

const RESIDUAL_WINDOWS: &[ResidualWindow] = &[
    ResidualWindow::ForeignWriterHoldsLock,
    ResidualWindow::RouterInOwnTransaction,
];

/// What one residual-window route observed.
struct ResidualOutcome {
    id: String,
    deferred: bool,
    refusal: String,
    rows_at_return: i64,
}

fn route_in_residual_window(
    window: ResidualWindow,
    path: &Path,
    conn: &Connection,
) -> ResidualOutcome {
    let observe = |conn: &Connection| {
        let id = route(conn);
        ResidualOutcome {
            deferred: is_deferred(&id),
            refusal: crate::storage::escalation_deferral::escalation_refusal_text(&id, REASON),
            rows_at_return: pending_rows(path, &id),
            id,
        }
    };
    match window {
        ResidualWindow::ForeignWriterHoldsLock => {
            let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let holder_path = path.to_path_buf();
            let holder = std::thread::spawn(move || {
                let holder_conn = open(&holder_path);
                let txn = WriteTxn::begin(&holder_conn).expect("holder takes the write lock");
                held_tx.send(()).expect("signal held");
                release_rx
                    .recv_timeout(HANDOFF_TIMEOUT)
                    .expect("router releases the holder");
                txn.rollback();
            });
            held_rx
                .recv_timeout(HANDOFF_TIMEOUT)
                .expect("holder holds the lock");
            let outcome = observe(conn);
            release_tx.send(()).expect("release holder");
            holder.join().expect("holder thread");
            outcome
        }
        ResidualWindow::RouterInOwnTransaction => {
            let txn = conn
                .unchecked_transaction()
                .expect("router's own transaction");
            let outcome = observe(conn);
            txn.rollback().expect("roll back router's own transaction");
            outcome
        }
    }
}

/// Code F2/F3, security F1/F2 (#8707) - every remaining route into a dead
/// frame fails CLOSED: the caller gets an id that is deferred, the DEFERRED
/// refusal text (which tells it how to detect the failed queue write), no row
/// exists, and the lost intent is reported exactly once at thread exit.
#[test]
fn issue_8707_residual_windows_defer_fail_closed_and_report_once_at_exit() {
    let name = "issue_8707_residual_windows_defer_fail_closed_and_report_once_at_exit";
    let Some(stderr) = child_stderr(name, || {
        for &window in RESIDUAL_WINDOWS {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("residual.db");
            let thread_path = path.clone();
            let outcome = with_leak(LeakShape::DroppedNoReopen, &path, move |conn| {
                route_in_residual_window(window, &thread_path, conn)
            });
            assert!(outcome.deferred, "{window:?}: {} not deferred", outcome.id);
            assert_eq!(
                outcome.refusal,
                crate::storage::escalation_deferral::deferred_refusal_text(&outcome.id, REASON),
                "{window:?}: refusal text"
            );
            assert_eq!(outcome.rows_at_return, 0, "{window:?}: row at return");
            assert_eq!(
                pending_rows(&path, &outcome.id),
                0,
                "{window:?}: row after exit"
            );
        }
    }) else {
        return;
    };
    assert_eq!(
        stderr.matches(EXIT_REPORT_PREFIX).count(),
        RESIDUAL_WINDOWS.len(),
        "one exit report per residual window: {stderr}"
    );
    assert_eq!(
        stderr.matches(EXIT_REPORT_ONE_INTENT).count(),
        RESIDUAL_WINDOWS.len(),
        "each exit report counts exactly 1 intent: {stderr}"
    );
}

/// How the INSERT inside the probe transaction is made to fail.
#[derive(Debug, Clone, Copy)]
enum ProbeInsertFailure {
    /// A row with the intent's pending id already exists.
    DuplicatePendingId,
    /// A trigger refuses every `pending_actions` INSERT.
    RefusingTrigger,
}

const PROBE_INSERT_FAILURES: &[(ProbeInsertFailure, &str, i64)] = &[
    (ProbeInsertFailure::DuplicatePendingId, DUPLICATE_ID_MSG, 1),
    (ProbeInsertFailure::RefusingTrigger, REFUSING_TRIGGER_MSG, 0),
];

/// SQLite's own message carried by the `rusqlite` error in `error`'s chain,
/// or the whole chain when there is none (so a mismatch shows what came back).
fn sqlite_message(error: &anyhow::Error) -> String {
    error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::SqliteFailure(_, Some(message))) => Some(message.clone()),
            _ => None,
        })
        .unwrap_or_else(|| format!("{error:#}"))
}

/// Code F4 (#8707) - a failed INSERT inside the probe transaction returns
/// its error, writes nothing, leaves the connection in autocommit (the probe
/// was rolled back) and restores busy_timeout. `rows` is the count of rows
/// with the pending id afterwards: the seeded row only, or none.
#[test]
fn issue_8707_failed_insert_inside_probe_txn_rolls_back() {
    for &(failure, message, rows) in PROBE_INSERT_FAILURES {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("probe-insert.db");
        {
            let seed = open(&path);
            match failure {
                ProbeInsertFailure::DuplicatePendingId => {
                    crate::storage::escalation_deferral::insert_pending_action_row(
                        &seed,
                        PROBE_FAILURE_ID,
                        GovernedAction::Store,
                        NAMESPACE,
                        None,
                        REQUESTER,
                        &serde_json::json!({ "seed": true }),
                    )
                    .expect("seed the duplicate row");
                }
                ProbeInsertFailure::RefusingTrigger => seed
                    .execute_batch(&format!(
                        "CREATE TRIGGER refuse_pending_8707 BEFORE INSERT ON pending_actions \
                         BEGIN SELECT RAISE(ABORT, '{REFUSING_TRIGGER_MSG}'); END;"
                    ))
                    .expect("install refusing trigger"),
            }
        }
        let (error, autocommit, timeout, deferred) =
            with_leak(LeakShape::DroppedNoReopen, &path, |conn| {
                let error = crate::storage::escalation_deferral::defer_or_queue(
                    conn,
                    intent(PROBE_FAILURE_ID),
                )
                .map_or_else(|e| sqlite_message(&e), |()| "Ok".to_owned());
                (
                    error,
                    conn.is_autocommit(),
                    busy_timeout(conn),
                    is_deferred(PROBE_FAILURE_ID),
                )
            });
        assert_eq!(error, message, "{failure:?}: SQLite message of the error");
        assert!(autocommit, "{failure:?}: probe transaction left open");
        assert_eq!(timeout, WRITER_BUSY_TIMEOUT_MS, "{failure:?}: busy_timeout");
        assert!(!deferred, "{failure:?}: intent parked in a dead frame");
        assert_eq!(
            pending_rows(&path, PROBE_FAILURE_ID),
            rows,
            "{failure:?}: rows with the pending id"
        );
    }
}
