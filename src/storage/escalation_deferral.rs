// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4116 — signed-approval escalations deferred to the write transaction the
//! calling thread holds (5-agent vote 4d3ea1c5, verdict D amended).
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
//!
//! # What the caller is told (never a phantom pending id)
//!
//! - **Funnel-owned transaction** (restore, caller-scoped restore,
//!   consolidate, merge_inbound): the funnel ends its transaction with
//!   [`super::connection::WriteTxn::rollback_resolving`], which settles the
//!   frame FIRST and then rewrites the refusal to the REAL outcome: the
//!   queued text naming `pending_id=<id>` (the row exists), or
//!   `escalation NOT queued: <err>`.
//! - **Caller-owned transaction** (e.g. `SqliteStore::update` wrapping an
//!   inner funnel): the refusal leaves the funnel before the enclosing
//!   transaction ends, so it carries the distinguishable DEFERRED text
//!   ([`deferred_refusal_text`]), which tells the caller how to detect a
//!   failed queue write.
//!
//! # Frame lifetime and `.await`
//!
//! A frame lives exactly as long as its `WriteTxn`: pushed by `begin*`,
//! removed BY ID (never by position) when the transaction ends. `WriteTxn`
//! borrows a `!Sync` `rusqlite::Connection`, so it is `!Send`: it cannot be
//! held across an `.await` in a `Send` future, and every storage funnel that
//! opens one is synchronous code. The frame therefore never outlives, or
//! migrates away from, the thread that opened it.
//!
//! # Leak detection
//!
//! A frame that still holds deferred intents when a later `WriteTxn` opens on
//! the same thread and database, a settle of an unknown frame, and frames
//! still holding intents when the thread exits (a `mem::forget`-ed
//! `WriteTxn`) are all reported at ERROR. The first two go through `tracing`
//! and also trip a `debug_assert!`; the thread-exit case is written directly
//! to stderr (an `ERROR #4116: ...` line), because the `tracing` fmt layer's
//! own thread-local buffer may already be destroyed at thread exit and
//! logging through it would abort the process.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, params};

use crate::models::GovernedAction;

/// One escalation routing deferred to the caller's open write transaction.
#[derive(Debug, Clone)]
pub struct DeferredEscalation {
    /// The pending id the queue write will use.
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

/// Why one deferred queue write did NOT land (the row does not exist).
///
/// Typed per ERRORS-10/13 (never a bare `String` error): `Display` is the
/// lowercase phrase the funnel splices into `escalation NOT queued: <err>`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueWriteError {
    /// A panic unwind, or the connection is still inside a transaction (a
    /// failed ROLLBACK): nothing is written into a foreign transaction.
    TxnNotEnded,
    /// The `cfg(test)` failure seam was armed (vote item 4).
    Forced,
    /// The `pending_actions` INSERT failed (record-stop gate, PK, BUSY, disk);
    /// carries the rendered `anyhow` chain.
    Insert(String),
}

impl std::fmt::Display for QueueWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxnNotEnded => {
                f.write_str("the write transaction did not end cleanly (panic or failed ROLLBACK)")
            }
            Self::Forced => f.write_str("forced deferred queue failure (test seam)"),
            Self::Insert(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for QueueWriteError {}

/// The real outcome of one deferred queue write: `Ok` = the row exists.
pub type SettledEscalation = (String, std::result::Result<(), QueueWriteError>);

/// One open [`super::connection::WriteTxn`] on this thread.
struct TxnFrame {
    id: u64,
    /// `Connection::path()` of the transaction's connection (`None` for an
    /// in-memory / temp database, which no other connection can share).
    db_path: Option<String>,
    deferred: Vec<DeferredEscalation>,
}

/// The per-thread frame stack. Its destructor (thread exit) reports frames
/// that were never settled: a `mem::forget`-ed `WriteTxn`.
struct Frames(Vec<TxnFrame>);

impl Drop for Frames {
    fn drop(&mut self) {
        let lost: usize = self.0.iter().map(|f| f.deferred.len()).sum();
        if lost > 0 {
            // No debug_assert here: a panic in a TLS destructor aborts. This
            // runs at thread exit, in thread-local destructor order (reverse
            // of registration). `tracing::error!` is NOT usable here: the
            // product's `tracing-subscriber` fmt layer keeps a thread-local
            // formatting buffer (`BUF.with`, `fmt_layer.rs`) that is already
            // destroyed when it was registered after this stack, and its
            // access panics ("cannot access a Thread Local Storage value
            // during or after destruction"), which aborts the process
            // ("thread local panicked on drop"). Catching that panic keeps the
            // process alive but loses the diagnostic. Write the ERROR line
            // straight to stderr instead: no thread-local is touched, so it
            // can neither panic nor be lost, and a failed write is discarded
            // on purpose (nothing left to report to; ERRORS-19).
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!(
                    "ERROR #4116: thread exited with {lost} unsettled escalation frame(s) \
                     (a leaked WriteTxn); those escalated writes stay REFUSED but were NOT queued\n"
                ),
            );
        }
    }
}

thread_local! {
    /// The write transactions open on this thread, innermost last.
    static TXN_FRAMES: RefCell<Frames> = const { RefCell::new(Frames(Vec::new())) };
    /// Test seam: fail the deferred queue writes on this thread.
    #[cfg(test)]
    static FORCE_QUEUE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

static NEXT_FRAME_ID: AtomicU64 = AtomicU64::new(1);

/// Test seam (vote item 4): make the NEXT deferred queue writes on this
/// thread fail, so a cell can assert what the caller is told.
#[cfg(test)]
pub(crate) fn force_deferred_queue_failure_for_test(on: bool) {
    FORCE_QUEUE_FAILURE.with(|f| f.set(on));
}

#[cfg(test)]
fn forced_failure() -> bool {
    FORCE_QUEUE_FAILURE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn forced_failure() -> bool {
    false
}

/// Register a frame for a write transaction just opened on `conn`.
pub(super) fn open_frame(conn: &Connection) -> u64 {
    let id = NEXT_FRAME_ID.fetch_add(1, Ordering::Relaxed);
    let db_path = conn.path().filter(|p| !p.is_empty()).map(str::to_string);
    TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        let stale = frames
            .0
            .iter()
            .any(|f| f.db_path == db_path && db_path.is_some() && !f.deferred.is_empty());
        if stale {
            tracing::error!(
                "#4116: a WriteTxn opened while an older frame on the same database still \
                 holds deferred escalations (leaked or unsettled transaction)"
            );
            debug_assert!(false, "#4116: stale escalation frame on this database");
        }
        frames.0.push(TxnFrame {
            id,
            db_path,
            deferred: Vec::new(),
        });
    });
    id
}

/// Pop frame `frame_id` and queue its deferred escalations on `conn`, whose
/// transaction has just ENDED; return each queue write's REAL outcome.
///
/// Infallible (it may run from `WriteTxn`'s `Drop`): every deferred write was
/// already REFUSED to its caller, so a failure loses only the pending (ERROR
/// log) and never admits the write. Nothing is queued during a panic unwind or
/// while `conn` is still inside a transaction (a failed ROLLBACK) — never write
/// into a foreign transaction; those intents report `Err`.
pub(super) fn settle_frame(conn: &Connection, frame_id: u64) -> Vec<SettledEscalation> {
    let frame = TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        frames
            .0
            .iter()
            .rposition(|f| f.id == frame_id)
            .map(|at| frames.0.remove(at))
    });
    let Some(frame) = frame else {
        tracing::error!(frame_id, "#4116: settle of an unknown escalation frame");
        debug_assert!(false, "#4116: settle of an unknown escalation frame");
        return Vec::new();
    };
    let mut outcomes = Vec::with_capacity(frame.deferred.len());
    let blocked = std::thread::panicking() || !conn.is_autocommit();
    for intent in frame.deferred {
        let result = if blocked {
            Err(QueueWriteError::TxnNotEnded)
        } else if forced_failure() {
            Err(QueueWriteError::Forced)
        } else {
            insert_pending_action_row(
                conn,
                &intent.pending_id,
                intent.action,
                &intent.namespace,
                intent.memory_id.as_deref(),
                &intent.requested_by,
                &intent.payload,
            )
            .map_err(|e| QueueWriteError::Insert(format!("{e:#}")))
        };
        match &result {
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
                 pending_id={} err={e}; the escalated write stays REFUSED (fail-closed) \
                 but no pending was queued",
                intent.namespace,
                intent.rule_id,
                intent.pending_id
            ),
        }
        outcomes.push((intent.pending_id, result));
    }
    outcomes
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
            .0
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

/// `true` when `pending_id` is deferred in a frame still open on this thread.
#[must_use]
pub fn is_deferred(pending_id: &str) -> bool {
    TXN_FRAMES.with(|frames| {
        frames
            .borrow()
            .0
            .iter()
            .any(|f| f.deferred.iter().any(|d| d.pending_id == pending_id))
    })
}

/// The immediate (row already written) refusal text.
#[must_use]
pub fn queued_refusal_text(pending_id: &str, reason: &str) -> String {
    format!("action escalated for signed approval (pending_id={pending_id}): {reason}")
}

/// Vote item 3 — the DEFERRED refusal text, distinguishable from the queued
/// text: the row lands only when the enclosing transaction ends.
#[must_use]
pub fn deferred_refusal_text(pending_id: &str, reason: &str) -> String {
    format!(
        "escalation deferred: pending_id={pending_id} will be queued when the enclosing \
         transaction ends; if memory_pending_approve {pending_id} returns not-found, the queue \
         write failed - re-submit ({reason})"
    )
}

/// The refusal text the escalate producer returns for `pending_id`.
#[must_use]
pub fn escalation_refusal_text(pending_id: &str, reason: &str) -> String {
    if is_deferred(pending_id) {
        deferred_refusal_text(pending_id, reason)
    } else {
        queued_refusal_text(pending_id, reason)
    }
}

/// Vote item 2 — rewrite a funnel's refusal to the REAL outcome of the queue
/// writes its own transaction just settled: the deferred text becomes the
/// queued text (row exists) or `escalation NOT queued: <err>`.
pub(super) fn resolve_refusal(err: &mut anyhow::Error, outcomes: &[SettledEscalation]) {
    if outcomes.is_empty() {
        return;
    }
    let Some(refusal) = err.downcast_mut::<super::GovernanceRefusal>() else {
        return;
    };
    for (pending_id, result) in outcomes {
        let head = format!("escalation deferred: pending_id={pending_id} ");
        let Some(rest) = refusal.reason.strip_prefix(&head) else {
            continue;
        };
        let reason = rest
            .rsplit_once(" - re-submit (")
            .and_then(|(_, r)| r.strip_suffix(')'))
            .unwrap_or(rest)
            .to_string();
        refusal.reason = match result {
            Ok(()) => queued_refusal_text(pending_id, &reason),
            Err(e) => format!("escalation NOT queued: {e}: {reason}"),
        };
        return;
    }
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

#[cfg(test)]
mod tests {
    /// Vote item 5(a) — a leaked `WriteTxn` whose frame still holds a deferred
    /// escalation is detected when the next transaction opens on the database.
    #[test]
    #[should_panic(expected = "stale escalation frame")]
    fn leaked_frame_with_intents_is_detected_on_next_open() {
        let dir = tempfile::Builder::new()
            .prefix("issue-4116-leak-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("ai-memory.db");
        let a = crate::db::open(&path).expect("open a");
        let b = crate::db::open(&path).expect("open b");
        let leaked = super::super::connection::WriteTxn::begin(&a).expect("begin a");
        let intent = super::DeferredEscalation {
            pending_id: "leak-4116".to_string(),
            action: crate::models::GovernedAction::Store,
            namespace: "gov4116/leak".to_string(),
            memory_id: None,
            requested_by: "ai:worker".to_string(),
            rule_id: "R-leak".to_string(),
            payload: serde_json::json!({}),
        };
        assert!(super::defer_to_open_txn(a.path(), intent).is_ok());
        std::mem::forget(leaked);
        // BEGIN IMMEDIATE holds the write lock; release connection `a` so `b` can
        // open. The leaked frame stays in the thread-local frame stack (matched
        // by db path), so the expected panic still fires.
        drop(a);
        let _next = super::super::connection::WriteTxn::begin(&b).expect("begin b");
    }

    /// #4116 F1 — the thread-exit leak report is an ERROR line on stderr and
    /// never aborts the process. The child leaks a frame on a thread that then
    /// logs through the product's global fmt subscriber (registering the fmt
    /// layer's thread-local buffer AFTER the frame stack, so it is destroyed
    /// first); `tracing::error!` from `Frames::drop` used to panic there and
    /// abort (SIGABRT, "thread local panicked on drop").
    #[test]
    fn issue_4116_thread_exit_leak_is_reported_on_stderr_and_does_not_abort() {
        const ROLE: &str = "AI_MEMORY_TEST_4116_THREAD_EXIT_LEAK";
        const PATH: &str = "storage::escalation_deferral::tests::issue_4116_thread_exit_leak_is_reported_on_stderr_and_does_not_abort";
        if std::env::var(ROLE).as_deref() != Ok("child") {
            let out = crate::spawn_audit::audited_command(
                std::env::current_exe().expect("current_exe"),
                "escalation_deferral::issue_4116_thread_exit_leak",
            )
            .args(["--exact", PATH, "--nocapture", "--test-threads=1"])
            .env(ROLE, "child")
            .output()
            .expect("spawn child");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success(),
                "child must exit 0, got {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                out.status
            );
            assert!(
                stdout.contains("1 passed") && !stdout.contains("0 passed"),
                "child did not run:\n{stdout}"
            );
            assert!(
                stderr.contains("ERROR #4116: thread exited with 1 unsettled escalation frame(s)"),
                "the leak ERROR line must be on stderr:\n{stderr}"
            );
            assert!(
                !stderr.contains("fatal runtime error"),
                "must not abort:\n{stderr}"
            );
            return;
        }
        crate::logging::init_console_tracing(&[]);
        std::thread::spawn(|| {
            let dir = tempfile::Builder::new()
                .prefix("issue-4116-exit-")
                .tempdir()
                .expect("tempdir");
            let conn = crate::db::open(&dir.path().join("ai-memory.db")).expect("open");
            let leaked = super::super::connection::WriteTxn::begin(&conn).expect("begin");
            let intent = super::DeferredEscalation {
                pending_id: "exit-4116".to_string(),
                action: crate::models::GovernedAction::Store,
                namespace: "gov4116/exit".to_string(),
                memory_id: None,
                requested_by: "ai:worker".to_string(),
                rule_id: "R-exit".to_string(),
                payload: serde_json::json!({}),
            };
            assert!(super::defer_to_open_txn(conn.path(), intent).is_ok());
            std::mem::forget(leaked);
            // Registers the fmt layer's thread-local buffer after the frames.
            tracing::error!("issue 4116 probe: log after the leak");
        })
        .join()
        .expect("leaking thread must not abort or panic");
    }

    /// #6132 — one leaked intent is reported ONCE. The child leaks a frame
    /// holding one deferred escalation, opens another `WriteTxn` on the same
    /// database on the same thread (`open_frame` reports the stale frame),
    /// then lets the thread exit (`Frames::drop`). Across both detection
    /// points the child's stderr must carry exactly one `#4116` ERROR report,
    /// not one from each.
    #[test]
    fn issue_4116_stale_frame_reported_once() {
        const ROLE: &str = "AI_MEMORY_TEST_6132_STALE_FRAME_REPORTED_ONCE";
        const PATH: &str =
            "storage::escalation_deferral::tests::issue_4116_stale_frame_reported_once";
        if std::env::var(ROLE).as_deref() != Ok("child") {
            let out = crate::spawn_audit::audited_command(
                std::env::current_exe().expect("current_exe"),
                "escalation_deferral::issue_4116_stale_frame_reported_once",
            )
            .args(["--exact", PATH, "--nocapture", "--test-threads=1"])
            .env(ROLE, "child")
            .output()
            .expect("spawn child");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success(),
                "child must exit 0, got {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                out.status
            );
            assert!(
                stdout.contains("1 passed") && !stdout.contains("0 passed"),
                "child did not run:\n{stdout}"
            );
            let reports = stderr
                .lines()
                .filter(|l| l.contains("ERROR") && l.contains("#4116"))
                .count();
            assert_eq!(
                reports, 1,
                "one leaked intent must be reported exactly once across open_frame + \
                 thread exit:\n{stderr}"
            );
            return;
        }
        crate::logging::init_console_tracing(&[]);
        std::thread::spawn(|| {
            let dir = tempfile::Builder::new()
                .prefix("issue-6132-once-")
                .tempdir()
                .expect("tempdir");
            let path = dir.path().join("ai-memory.db");
            let a = crate::db::open(&path).expect("open a");
            let b = crate::db::open(&path).expect("open b");
            let leaked = super::super::connection::WriteTxn::begin(&a).expect("begin a");
            let intent = super::DeferredEscalation {
                pending_id: "once-6132".to_string(),
                action: crate::models::GovernedAction::Store,
                namespace: "gov6132/once".to_string(),
                memory_id: None,
                requested_by: "ai:worker".to_string(),
                rule_id: "R-once".to_string(),
                payload: serde_json::json!({}),
            };
            assert!(super::defer_to_open_txn(a.path(), intent).is_ok());
            std::mem::forget(leaked);
            // Release `a`'s write lock so `b` can BEGIN IMMEDIATE; the leaked
            // frame stays on this thread's stack (matched by db path).
            drop(a);
            // Debug builds trip the stale-frame `debug_assert!` inside
            // `open_frame` (after its report); release builds return a guard.
            let next = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::super::connection::WriteTxn::begin(&b)
            }));
            drop(next);
        })
        .join()
        .expect("leaking thread must not abort or panic");
    }
}
