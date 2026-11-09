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
//!
//! # Leaked frames accept no new work (#8662)
//!
//! A leaked frame stays on the stack until thread exit, but its transaction
//! is over. Work handed to it would never be settled, and the caller would be
//! holding a pending id that has no row. So a frame is marked `stale` as soon
//! as its end is PROVEN, and a stale frame takes no new escalation or audit
//! anchor:
//!
//! - a later `BEGIN IMMEDIATE` / `BEGIN EXCLUSIVE` succeeds on the same
//!   database (a live frame would hold the write lock) or on the same
//!   connection (a live frame would make it a nested BEGIN);
//! - the routing connection IS the frame's connection and is in autocommit;
//! - [`defer_or_queue`] finds a frame on another connection and its
//!   non-blocking `BEGIN IMMEDIATE` probe gets the write lock, so nothing
//!   holds it. The pending row is then written inside that probe
//!   transaction.
//!
//! Remaining windows. In two routes a dead, not-yet-stale frame still takes
//! the intent:
//!
//! | Route | When | Pinned by |
//! |---|---|---|
//! | probe finds the lock held | ANY other connection holds the write lock at the probe instant: another process, or another thread or connection of this process (the probe never waits, `busy_timeout` is 0) | `issue_8707_residual_windows_defer_fail_closed_and_report_once_at_exit` (`ForeignWriterHoldsLock`) |
//! | router in its own transaction | the routing connection is not in autocommit, so liveness cannot be probed without nesting (#8710 tracks closing it) | the same test (`RouterInOwnTransaction`) |
//!
//! Both fail closed: no row is written, the caller gets the DEFERRED text,
//! which tells it how to detect a failed write, and the dead frame reports
//! the lost intent at the next open or at thread exit.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, params};

use super::connection::NoWaitWriteTxn;
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
    /// #7241 - the address of the transaction's own connection. Audit
    /// anchors are deferred to the transaction of the SAME connection (the
    /// one their append wrote into), never to a sibling connection on the
    /// same file. The `WriteTxn` borrows the connection, so the address is
    /// stable and unique for the frame's whole life.
    conn_addr: usize,
    deferred: Vec<DeferredEscalation>,
    /// #8662 - the transaction has provably ended without settling this
    /// frame (a leaked `WriteTxn`). A stale frame takes no new escalation or
    /// audit anchor; [`settle_frame`] still settles what it already holds.
    stale: bool,
    /// Intents included in a successfully written raw lost-write report.
    /// A count keeps subsequently deferred intents reportable (#6132/#6540).
    reported: usize,
    /// #7241 - the off-table audit anchors of signed-event appends made by
    /// nested funnels inside this transaction: emitted when it COMMITS,
    /// dropped unrecorded when it rolls back.
    anchor: crate::governance::audit::PendingAuditAnchor,
}

impl TxnFrame {
    fn unreported(&self) -> usize {
        self.deferred.len().saturating_sub(self.reported)
    }
}

/// The per-thread frame stack. Its destructor (thread exit) reports frames
/// that were never settled: a `mem::forget`-ed `WriteTxn`.
struct Frames(Vec<TxnFrame>);

/// Diagnostic units stay distinct: one frame can hold several intents.
const UNREPORTED_ESCALATIONS_LABEL: &str = "unreported deferred escalation(s)";
const UNSETTLED_FRAMES_LABEL: &str = "unsettled escalation frame(s)";

impl Drop for Frames {
    fn drop(&mut self) {
        let lost: usize = self.0.iter().map(TxnFrame::unreported).sum();
        if lost > 0 {
            let unsettled = self.0.iter().filter(|frame| frame.unreported() > 0).count();
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
            // straight to stderr instead to avoid that thread-local teardown
            // hazard. Delivery remains best effort; a failed write is discarded
            // on purpose (nothing left to report to; ERRORS-19).
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!(
                    "ERROR #4116: thread exited with {lost} {UNREPORTED_ESCALATIONS_LABEL} \
                     in {unsettled} {UNSETTLED_FRAMES_LABEL} \
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
    /// Test seam: fail open-time raw report writes without touching stderr.
    #[cfg(test)]
    static FORCE_REPORT_WRITE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test seam (#8707): panic inside the #8662 probe transaction, after its
    /// `BEGIN IMMEDIATE` succeeded and before the pending row is written.
    #[cfg(test)]
    static FORCE_PROBE_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The panic message of the [`FORCE_PROBE_PANIC`] seam.
#[cfg(test)]
pub(crate) const MSG_FORCED_PROBE_PANIC: &str = "#8707: forced panic inside the probe transaction";

/// Test seam (#8707): make the next probe transactions on this thread panic
/// after their BEGIN, so a cell can prove the unwind rolls them back.
#[cfg(test)]
pub(crate) fn force_probe_panic_for_test(on: bool) {
    FORCE_PROBE_PANIC.with(|f| f.set(on));
}

#[cfg(test)]
fn panic_if_probe_panic_forced() {
    assert!(
        !FORCE_PROBE_PANIC.with(std::cell::Cell::get),
        "{MSG_FORCED_PROBE_PANIC}"
    );
}

#[cfg(not(test))]
fn panic_if_probe_panic_forced() {}

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

#[cfg(test)]
const MSG_FORCED_REPORT_WRITE_FAILURE: &str = "forced open-time escalation report write failure";

/// Write the report through stderr, without relying on tracing enablement.
/// On Unix, write through an owned duplicate of the live stderr descriptor:
/// `Stderr` itself treats EBADF from a closed or read-only descriptor as a
/// successful no-op. Failed duplication or writing leaves report credit unchanged.
/// A successful write means the OS accepted the bytes, not that a downstream
/// reader retained them. Hold stderr's lock through the entire raw write to
/// exclude other stderr-lock writers; release it before the caller traces.
fn write_open_report(frame: &TxnFrame) -> std::io::Result<()> {
    #[cfg(test)]
    if FORCE_REPORT_WRITE_FAILURE.with(std::cell::Cell::get) {
        return Err(std::io::Error::other(MSG_FORCED_REPORT_WRITE_FAILURE));
    }
    let stderr = std::io::stderr();
    // Keep the serialization provided by Stderr::write_fmt at thread exit.
    // The duplicate prevents descriptor closure between checking and writing
    // from becoming a falsely successful receipt (ERRORS-02, ERRORS-19).
    let stderr_lock = stderr.lock();
    #[cfg(unix)]
    let mut writer = {
        use std::os::fd::AsFd;
        std::fs::File::from(stderr.as_fd().try_clone_to_owned()?)
    };
    #[cfg(not(unix))]
    let mut writer = stderr_lock;
    #[cfg(test)]
    let mut writer = reporting_tests::ObserveWrite(&mut writer);
    let unreported = frame.unreported();
    let result = std::io::Write::write_fmt(
        &mut writer,
        format_args!(
            "ERROR #4116: a WriteTxn opened while an older frame on the same database still \
             holds {unreported} {UNREPORTED_ESCALATIONS_LABEL} (leaked transaction); \
             those escalated writes stay REFUSED but were NOT queued\n"
        ),
    );
    #[cfg(unix)]
    drop(stderr_lock);
    result
}

/// Register a frame for a write transaction just opened on `conn`.
///
/// #8662 - `BEGIN IMMEDIATE` / `BEGIN EXCLUSIVE` has just SUCCEEDED on
/// `conn`. A live older frame on the same database would still hold the
/// write lock, so that BEGIN would have failed `SQLITE_BUSY`. A live older
/// frame on this same connection would have made it a refused nested BEGIN.
/// Every such frame is therefore leaked, and it is marked stale.
pub(super) fn open_frame(conn: &Connection) -> u64 {
    let id = NEXT_FRAME_ID.fetch_add(1, Ordering::Relaxed);
    let db_path = conn.path().filter(|p| !p.is_empty()).map(str::to_string);
    let conn_addr = std::ptr::from_ref(conn).addr();
    TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        let mut leaked_with_intents = false;
        for frame in &mut frames.0 {
            let same_db = db_path.is_some() && frame.db_path == db_path;
            if same_db || frame.conn_addr == conn_addr {
                frame.stale = true;
            }
            if !same_db || frame.deferred.is_empty() {
                continue;
            }
            leaked_with_intents = true;
            let intent_count = frame.unreported();
            if intent_count == 0 {
                continue;
            }
            // Credit only a completed raw write, before any debug assertion
            // or subscriber can unwind. Failure leaves all intents pending
            // for a later open or thread exit (ERRORS-19, OWNERSHIP-25).
            if write_open_report(frame).is_ok() {
                frame.reported = frame.deferred.len();
            }
            tracing::error!(
                frame_id = frame.id,
                db_path = ?frame.db_path,
                intent_count,
                "#4116: a WriteTxn opened while an older frame on the same database still \
                 holds deferred escalations (leaked or unsettled transaction)"
            );
        }
        if leaked_with_intents {
            debug_assert!(false, "#4116: stale escalation frame on this database");
        }
        frames.0.push(TxnFrame {
            id,
            db_path,
            conn_addr,
            deferred: Vec::new(),
            stale: false,
            reported: 0,
            anchor: crate::governance::audit::PendingAuditAnchor::none(),
        });
    });
    id
}

/// Pop frame `frame_id` and queue its deferred escalations on `conn`, whose
/// transaction has just ENDED; return each queue write's REAL outcome.
///
/// #7241 - `committed` is `true` only when the transaction's COMMIT
/// succeeded: the frame's deferred audit anchors are then emitted; on every
/// other end (rollback, failed commit, unwind) they are dropped unrecorded.
///
/// Infallible (it may run from `WriteTxn`'s `Drop`): every deferred write was
/// already REFUSED to its caller, so a failure loses only the pending (ERROR
/// log) and never admits the write. Nothing is queued during a panic unwind or
/// while `conn` is still inside a transaction (a failed ROLLBACK) — never write
/// into a foreign transaction; those intents report `Err`.
pub(super) fn settle_frame(
    conn: &Connection,
    frame_id: u64,
    committed: bool,
) -> Vec<SettledEscalation> {
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
    if committed {
        frame.anchor.emit_after_commit();
    } else {
        frame.anchor.discard();
    }
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

/// Test primitive: hand `intent` to the innermost write transaction open on
/// THIS thread against `db_path`. Production code routes through
/// [`defer_or_queue`], which also proves that the frame is live.
///
/// # Errors
///
/// Returns `intent` unchanged when no such transaction is open or when the
/// innermost one is stale (#8662).
#[cfg(test)]
pub(crate) fn defer_to_open_txn(
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
            Some(frame) if !frame.stale => {
                frame.deferred.push(intent);
                Ok(())
            }
            _ => Err(intent),
        }
    })
}

/// Where an escalation routed on a connection goes (#8662).
enum Route {
    /// No usable frame: write the pending row now on the routing connection.
    QueueNow,
    /// Hand it to the live frame with this id.
    Defer(u64),
    /// A frame on ANOTHER connection is open on this database and the routing
    /// connection is in autocommit: probe the write lock to see whether that
    /// frame is still live.
    Probe(u64),
}

fn classify_route(conn: &Connection) -> Route {
    let Some(db_path) = conn.path().filter(|p| !p.is_empty()) else {
        return Route::QueueNow;
    };
    let conn_addr = std::ptr::from_ref(conn).addr();
    TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        let Some(frame) = frames
            .0
            .iter_mut()
            .rev()
            .find(|f| f.db_path.as_deref() == Some(db_path))
        else {
            return Route::QueueNow;
        };
        if frame.stale {
            // Every older frame on this database is dead too: a live one
            // would have refused the BEGIN that this newer frame recorded.
            return Route::QueueNow;
        }
        match (frame.conn_addr == conn_addr, conn.is_autocommit()) {
            // The frame's own connection has no transaction open: the frame
            // ended without being settled.
            (true, true) => {
                frame.stale = true;
                Route::QueueNow
            }
            (true, false) => Route::Defer(frame.id),
            (false, true) => Route::Probe(frame.id),
            // The router is inside a transaction of its own; liveness cannot
            // be probed without nesting, so the #4116 deferral stands. This
            // is the second remaining window of the module doc (#8710).
            (false, false) => Route::Defer(frame.id),
        }
    })
}

fn insert_intent(conn: &Connection, intent: &DeferredEscalation) -> Result<()> {
    insert_pending_action_row(
        conn,
        &intent.pending_id,
        intent.action,
        &intent.namespace,
        intent.memory_id.as_deref(),
        &intent.requested_by,
        &intent.payload,
    )
}

/// Write `intent` inside the probe transaction `probe` holds on `conn`, then
/// COMMIT. The row either exists when this returns `Ok`, or the error is
/// returned and the probe transaction is rolled back: by the guard's `Drop`
/// on an early `?`, a failed COMMIT, or a panic unwind (#8707).
fn insert_in_probe_txn(
    probe: NoWaitWriteTxn<'_>,
    conn: &Connection,
    intent: &DeferredEscalation,
) -> Result<()> {
    panic_if_probe_panic_forced();
    insert_intent(conn, intent)?;
    probe.commit()?;
    Ok(())
}

fn mark_db_frames_stale(db_path: Option<&str>) {
    TXN_FRAMES.with(|frames| {
        for frame in &mut frames.borrow_mut().0 {
            if frame.db_path.as_deref() == db_path {
                frame.stale = true;
            }
        }
    });
}

/// Push `intent` into frame `frame_id`, or give it back when that frame is
/// gone or has gone stale.
fn push_to_frame(
    frame_id: u64,
    intent: DeferredEscalation,
) -> std::result::Result<(), DeferredEscalation> {
    TXN_FRAMES.with(|frames| {
        match frames
            .borrow_mut()
            .0
            .iter_mut()
            .find(|f| f.id == frame_id && !f.stale)
        {
            Some(frame) => {
                frame.deferred.push(intent);
                Ok(())
            }
            None => Err(intent),
        }
    })
}

/// #4116 / #8662 - route an escalation `intent` raised on `conn`. When THIS
/// thread holds a LIVE write transaction on the same database, the intent is
/// deferred to it and lands on that transaction's connection when it ends.
/// Otherwise the pending row is written now. A frame left behind by a leaked
/// `WriteTxn` takes the intent only in the two remaining windows of the
/// module doc ("Leaked frames"): the write lock is held by another connection
/// at the probe instant, or the routing connection is inside a transaction of
/// its own. The intent is then held by that dead frame, the caller gets the
/// DEFERRED text, and the frame's exit report counts it.
///
/// `Ok` means the row exists, or the intent is held by a frame that will
/// settle it ([`is_deferred`] tells which).
///
/// # Errors
///
/// The queue write or the liveness probe failed: no row exists and no frame
/// holds the intent.
pub fn defer_or_queue(conn: &Connection, intent: DeferredEscalation) -> Result<()> {
    let intent = match classify_route(conn) {
        Route::QueueNow => intent,
        Route::Defer(frame_id) => match push_to_frame(frame_id, intent) {
            Ok(()) => return Ok(()),
            Err(intent) => intent,
        },
        Route::Probe(frame_id) => match NoWaitWriteTxn::try_begin(conn)? {
            Some(probe) => {
                // Nothing holds the write lock, so every frame on this
                // database on this thread is dead.
                mark_db_frames_stale(conn.path().filter(|p| !p.is_empty()));
                return insert_in_probe_txn(probe, conn, &intent);
            }
            None => match push_to_frame(frame_id, intent) {
                Ok(()) => return Ok(()),
                Err(intent) => intent,
            },
        },
    };
    insert_intent(conn, &intent)
}

/// #7241 - hand a signed-event append's pending audit anchor to the owner of
/// the transaction it was appended in, for a funnel that runs INSIDE a
/// transaction it does not own (so it cannot commit, and must not record an
/// anchor of a head the owner may still roll back).
///
/// - `conn` is inside a [`super::connection::WriteTxn`] on this thread: the
///   anchor joins that transaction's frame and is emitted after its COMMIT
///   (dropped on rollback).
/// - `conn` is in autocommit: the append already committed, so the anchor is
///   emitted now.
/// - `conn` is inside a transaction this thread has no frame for (a raw
///   `rusqlite::Transaction` owner): the anchor is dropped unrecorded. That is
///   under-emission only, never a false verdict: the watermark throttle was
///   not claimed, so the next due append anchors the head again.
pub fn defer_audit_anchor(conn: &Connection, anchor: crate::governance::audit::PendingAuditAnchor) {
    if anchor.is_empty() {
        anchor.discard();
        return;
    }
    let conn_addr = std::ptr::from_ref(conn).addr();
    let conn_path = conn.path().filter(|p| !p.is_empty());
    let unowned = TXN_FRAMES.with(|frames| {
        let mut frames = frames.borrow_mut();
        match frames.0.iter_mut().rev().find(|f| f.conn_addr == conn_addr) {
            Some(frame)
                if !frame.stale
                    && !conn.is_autocommit()
                    && frame.db_path.as_deref() == conn_path =>
            {
                frame.anchor = std::mem::take(&mut frame.anchor).merge(anchor);
                None
            }
            // #8662 - a frame at this address whose connection is in
            // autocommit, or that is on another database (a dropped
            // connection's address reused), is leaked. The anchor never
            // joins it, because a dead frame never emits.
            Some(frame) => {
                frame.stale = true;
                Some(anchor)
            }
            None => Some(anchor),
        }
    });
    let Some(anchor) = unowned else {
        return;
    };
    if conn.is_autocommit() {
        anchor.emit_after_commit();
    } else {
        // Count first so the drop is recorded even when the debug assertion
        // below unwinds (#7281, ERRORS-19).
        FRAMELESS_ANCHOR_DROPS.fetch_add(FRAMELESS_DROP_INCREMENT, Ordering::Relaxed);
        crate::metrics::inc_audit_anchor_frameless_drop();
        // A new raw-transaction caller of a deferring funnel would under-anchor
        // silently: fail loudly in debug and test builds, warn in release.
        debug_assert!(
            false,
            "#7241: audit anchor dropped: its append ran in a transaction with no WriteTxn frame"
        );
        tracing::warn!(
            "#7241: audit anchor dropped: its append ran in a transaction with no WriteTxn \
             frame on this thread; the next due append re-anchors the head"
        );
        anchor.discard();
    }
}

/// Step of the monotonic frameless-drop counter.
const FRAMELESS_DROP_INCREMENT: u64 = 1;

/// #7281 - audit anchors dropped unrecorded because their append ran in a raw
/// transaction with no `WriteTxn` frame (monotonic, process-wide).
static FRAMELESS_ANCHOR_DROPS: AtomicU64 = AtomicU64::new(0);

/// #7281 - how many audit anchors the frameless-drop branch has discarded.
/// Mirrored to `ai_memory_audit_anchor_frameless_drop_total`.
#[must_use]
pub fn frameless_anchor_drop_count() -> u64 {
    FRAMELESS_ANCHOR_DROPS.load(Ordering::Relaxed)
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
#[path = "escalation_frame_reporting_8184_tests.rs"]
mod reporting_tests;

#[cfg(test)]
#[path = "escalation_leaked_frame_8662_tests.rs"]
mod leaked_frame_8662_tests;

#[cfg(test)]
mod tests {
    /// #7241 L1 - an anchor handed to a funnel that runs in a raw transaction
    /// with no `WriteTxn` frame is dropped; a debug or test build must trip a
    /// `debug_assert!` so a new raw-transaction caller cannot under-anchor
    /// silently (ERRORS-19).
    #[test]
    fn frameless_raw_transaction_anchor_drop_trips_debug_assert_7241() {
        /// Head sequence of the pending watermark the funnel hands over.
        const HEAD_SEQUENCE: i64 = 64;
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch("BEGIN").expect("raw transaction");
        let anchor = crate::governance::audit::PendingAuditAnchor::watermark(
            HEAD_SEQUENCE,
            "head-hash",
            "db-id",
        );
        let before = super::frameless_anchor_drop_count();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::defer_audit_anchor(&conn, anchor);
        }));
        if cfg!(debug_assertions) {
            let payload = outcome.expect_err("debug build must trip the assertion");
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            assert!(
                message.contains("no WriteTxn frame"),
                "panic text: {message}"
            );
        } else {
            assert!(outcome.is_ok(), "release build must not panic");
        }
        assert_eq!(
            super::frameless_anchor_drop_count(),
            before + 1,
            "the frameless drop must be counted (#7281)"
        );
    }

    /// Vote item 5(a) — a leaked `WriteTxn` whose frame still holds a deferred
    /// escalation is detected when the next transaction opens on the database.
    #[cfg(debug_assertions)]
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
                stderr.contains("ERROR #4116: thread exited with 1 unreported deferred escalation(s) in 1 unsettled escalation frame(s)"),
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
}
