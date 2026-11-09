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
            (id.clone(), is_deferred(&id), busy_timeout(conn), start.elapsed())
        });
        assert!(!deferred, "{shape:?}: pending {id} parked in a leaked frame");
        assert_eq!(
            pending_rows(&path, &id),
            1,
            "{shape:?}: caller was handed pending id {id} with no row"
        );
        assert_eq!(timeout, WRITER_BUSY_TIMEOUT_MS, "{shape:?}: busy_timeout changed");
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
        assert!(deferred, "same={same_connection}: live frame must take the intent");
        assert_eq!(rows_before, 0, "same={same_connection}: row before settle");
        assert_eq!(pending_rows(&path, &id), 1, "same={same_connection}: row after commit");
        assert_eq!(timeout, WRITER_BUSY_TIMEOUT_MS, "same={same_connection}: busy_timeout");
        assert!(elapsed < ROUTE_CEILING, "same={same_connection}: route took {elapsed:?}");
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
