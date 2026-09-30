// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4116 — signed-approval escalations deferred to the write transaction the
//! calling thread holds.
//!
//! The L1-6 governance pre-write hook consults (and routes `Escalate`
//! verdicts) on its OWN connection, because it fires synchronously from inside
//! a write funnel. When that funnel holds `BEGIN IMMEDIATE` on the same
//! database, a pending INSERT on the hook's connection waited out the whole
//! `busy_timeout` behind this thread's own writer lock and failed
//! `SQLITE_BUSY`: the escalated write was refused WITHOUT being queued for
//! approval, and the lock was held the whole time.
//!
//! Every [`super::connection::WriteTxn`] therefore registers a per-thread
//! frame recording its database. [`defer_to_open_txn`] hands an escalation to
//! the innermost frame on the same database, and the transaction writes it on
//! ITS OWN connection the moment it ends (commit or rollback, lock released).
//! Governance evaluation still runs inside the held lock; only the queue write
//! moves. Kept out of `storage/mod.rs` (QUAL-10: no ceiling bump).

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, params};

use crate::models::GovernedAction;

/// One escalation routing deferred to the caller's open write transaction.
#[derive(Debug, Clone)]
pub struct DeferredEscalation {
    /// The pending id already reported to the caller.
    pub pending_id: String,
    /// The governed action the pending replays.
    pub action: GovernedAction,
    /// The escalated write's namespace.
    pub namespace: String,
    /// The memory the action targets, when any.
    pub memory_id: Option<String>,
    /// The escalated write's author.
    pub requested_by: String,
    /// The escalating rule (logs only).
    pub rule_id: String,
    /// The ENRICHED pending payload (`requires_signed_approval` + escalation
    /// provenance), byte-identical to an immediate route.
    pub payload: serde_json::Value,
}

/// One open [`super::connection::WriteTxn`] on this thread.
struct TxnFrame {
    id: u64,
    /// `Connection::path()` of the transaction's connection (`None` for an
    /// in-memory / temp database, which no other connection can share).
    db_path: Option<String>,
    deferred: Vec<DeferredEscalation>,
}

thread_local! {
    /// The write transactions open on this thread, innermost last. `WriteTxn`
    /// borrows a `!Sync` `Connection`, so it is `!Send`: a frame is pushed and
    /// popped on the same thread.
    static TXN_FRAMES: RefCell<Vec<TxnFrame>> = const { RefCell::new(Vec::new()) };
}

static NEXT_FRAME_ID: AtomicU64 = AtomicU64::new(1);

/// Register a frame for a write transaction just opened on `conn`.
pub(super) fn open_frame(conn: &Connection) -> u64 {
    let id = NEXT_FRAME_ID.fetch_add(1, Ordering::Relaxed);
    let db_path = conn.path().filter(|p| !p.is_empty()).map(str::to_string);
    TXN_FRAMES.with(|frames| {
        frames.borrow_mut().push(TxnFrame {
            id,
            db_path,
            deferred: Vec::new(),
        });
    });
    id
}

/// Pop frame `frame_id` and queue its deferred escalations on `conn`, whose
/// transaction has just ENDED. Infallible (it runs from `WriteTxn`'s
/// terminator, which may be `Drop`): every deferred write was already REFUSED
/// to its caller, so a failure loses only the pending (ERROR log) and never
/// admits the write. Nothing is queued during a panic unwind or while `conn`
/// is still inside a transaction (a failed ROLLBACK): never write into a
/// foreign transaction.
pub(super) fn settle_frame(conn: &Connection, frame_id: u64) {
    let deferred = TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        frames
            .iter()
            .rposition(|f| f.id == frame_id)
            .map(|at| frames.remove(at).deferred)
            .unwrap_or_default()
    });
    if deferred.is_empty() {
        return;
    }
    if std::thread::panicking() || !conn.is_autocommit() {
        tracing::error!(
            count = deferred.len(),
            "#4116: dropping deferred escalation(s) — the write transaction ended by \
             panic or its connection is still inside a transaction; the escalated \
             write(s) stay REFUSED but are NOT queued for approval"
        );
        return;
    }
    for intent in deferred {
        match insert_pending_action_row(
            conn,
            &intent.pending_id,
            intent.action,
            &intent.namespace,
            intent.memory_id.as_deref(),
            &intent.requested_by,
            &intent.payload,
        ) {
            Ok(()) => tracing::info!(
                "L1-6 escalation namespace={:?} rule_id={} — queued signed-approval \
                 pending_id={} on the funnel connection after its write transaction \
                 ended (#4116)",
                intent.namespace,
                intent.rule_id,
                intent.pending_id
            ),
            Err(e) => tracing::error!(
                "L1-6 escalation: deferred routing FAILED namespace={:?} rule_id={} \
                 pending_id={} err={e:#}; the escalated write stays REFUSED \
                 (fail-closed) but no pending was queued",
                intent.namespace,
                intent.rule_id,
                intent.pending_id
            ),
        }
    }
}

/// Hand `intent` to the innermost write transaction open on THIS thread
/// against `db_path`, to be queued on that transaction's connection when it
/// ends.
///
/// # Errors
///
/// Returns `intent` unchanged when no such transaction is open (the caller
/// then queues it itself, immediately).
pub fn defer_to_open_txn(
    db_path: Option<&str>,
    intent: DeferredEscalation,
) -> std::result::Result<(), DeferredEscalation> {
    let Some(db_path) = db_path.filter(|p| !p.is_empty()) else {
        return Err(intent);
    };
    TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        match frames
            .iter_mut()
            .rev()
            .find(|f| f.db_path.as_deref() == Some(db_path))
        {
            Some(frame) => {
                frame.deferred.push(intent);
                Ok(())
            }
            None => Err(intent),
        }
    })
}

/// Insert a `pending_actions` row under a caller-minted `id` (the body of
/// [`super::queue_pending_action`]).
///
/// # Errors
///
/// Propagates the record-stop gate and SQLite errors (a duplicate `id` is a
/// primary-key violation, never an overwrite).
pub fn insert_pending_action_row(
    conn: &Connection,
    id: &str,
    action: GovernedAction,
    namespace: &str,
    memory_id: Option<&str>,
    requested_by: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    // Wave-2 B7 — sibling of gated `upsert_pending_action` (ERRORS-09).
    super::record_stop::gate_storage_conn(conn)?;
    let now = Utc::now().to_rfc3339();
    let payload_json = serde_json::to_string(payload)?;
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
        params![
            id,
            action.as_str(),
            memory_id,
            namespace,
            payload_json,
            requested_by,
            now,
        ],
    )?;
    Ok(())
}
