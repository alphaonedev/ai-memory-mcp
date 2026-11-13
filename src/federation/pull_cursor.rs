// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8743 — the federation receiver's pull cursor, bounded by the RECEIVER's
//! own clock.
//!
//! Every `/sync/since` puller (the `serve` catch-up loops in
//! [`crate::federation::receive`] and the sync-daemon's
//! [`crate::daemon_runtime::sync_cycle_once`]) persists a per-peer cursor in
//! `sync_state` through a monotonic (refuse-to-regress) upsert, and the peer
//! answers the next pull with `updated_at > cursor`. Before #8743 the cursor
//! was taken from a value the PEER controls: the applied row's `updated_at`
//! (catch-up) or the peer's `next_since`. One row dated in the future
//! therefore moved the cursor ahead of every row the peer wrote afterwards,
//! and those rows were never pulled while every pull logged `ok`.
//!
//! The invariant this module enforces for every sequence of peer answers:
//!
//! * the cursor is never ahead of the receiver's clock ([`PullCursorTracker::resolve`]
//!   refuses any candidate past `now`, chronologically AND lexically, because
//!   `sync_state` and the peer's SQL compare the strings lexically);
//! * a row stamped more than [`PULL_CURSOR_FUTURE_SKEW_SECS`] ahead of the
//!   receiver's clock is not applied: it is DEFERRED with the named outcome
//!   [`OUTCOME_DEFERRED_FUTURE_SKEW`], counted and logged, and the cursor is
//!   held strictly below it so it is re-offered (and applied once the clocks
//!   agree, or once the peer rewrites it with a sane stamp);
//! * #8788 / #8789 — a delivered row the receiver will not apply for a
//!   reason a re-pull cannot change (an unparseable timestamp or body, a
//!   failed field validation, a refused namespace, a refused attestation) is
//!   REFUSED with a [`RefusalReason`]: one WARN line, the
//!   `ai_memory_federation_pull_rows_refused_total{reason}` counter and a
//!   [`RefusedRow`] in the window's [`PullOutcome`]. A refused row is settled:
//!   the cursor may pass it, so one refused row never stops the rows after it,
//!   and no row is dropped without that record;
//! * a row that was delivered but not durably applied for a TRANSIENT reason
//!   (a probe or apply error) is DEFERRED and holds the cursor strictly below
//!   its timestamp, so no later row can carry the cursor past it (#2714). A
//!   row deferred in [`PULL_HOLD_STALL_PASSES`] windows that each applied
//!   other rows (so the store is healthy and the failure is the row's own) is
//!   refused as [`RefusalReason::HoldStalled`] with an ERROR line, so no row
//!   blocks the loop forever; a window that applied nothing (an outage) never
//!   counts toward the stall;
//! * a full page that cannot advance (one tie group larger than the page) is
//!   reported as `held`, and any pull that left rows behind is reported as
//!   incomplete instead of `ok`.
//!
//! Re-pulling a row the receiver already holds is harmless: every apply path
//! is an idempotent `insert_if_newer` / `apply_remote_memory` upsert.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, Utc};

/// v1.0.0 #2718 / CB-14 (B-5) — the maximum a peer timestamp may LEAD the
/// receiver's wall-clock before it is treated as out of bound. It absorbs real
/// NTP drift. #8743: a ROW stamped beyond it is deferred (not applied); a
/// CURSOR candidate is bounded tighter still, by the receiver's clock itself.
pub(crate) const PULL_CURSOR_FUTURE_SKEW_SECS: i64 = 300;

/// The page size the peer's `/sync/since` handler uses when the request names
/// no `limit` (the `serve` catch-up loops send none). One constant for the
/// server default and the receiver's page-full test.
pub(crate) const SYNC_SINCE_DEFAULT_LIMIT: usize = 500;

/// #8743 — the logged, counted outcome for a delivered row whose
/// `updated_at` leads the receiver's clock by more than
/// [`PULL_CURSOR_FUTURE_SKEW_SECS`]: not applied, cursor held below it.
pub const OUTCOME_DEFERRED_FUTURE_SKEW: &str = "deferred_future_skew";

/// #8788 — windows (each of which applied at least one other row) a
/// transiently deferred row may hold the cursor before it is refused as
/// [`RefusalReason::HoldStalled`].
pub const PULL_HOLD_STALL_PASSES: u32 = 10;

/// #8788 — the most (peer, row) pairs the stall ledger tracks at once. A pair
/// past the cap is still deferred (fail closed: it holds), it is only not
/// counted toward [`PULL_HOLD_STALL_PASSES`] until room frees up.
const PULL_HOLD_STALL_TRACKED_MAX: usize = 10_000;

/// #8788 — consecutive healthy windows each (peer, memory id) was deferred in.
static HOLD_STALLS: Mutex<Option<HashMap<(String, String), u32>>> = Mutex::new(None);

/// #8788 / #8789 — why a delivered row was refused (closed set; the label is
/// the `reason` of the log line and of the refused-rows counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalReason {
    /// `updated_at` missing or not RFC 3339.
    UnparseableTs,
    /// The row JSON does not decode into a memory.
    UnparseableBody,
    /// The decoded memory fails `validate_memory` (#8789).
    InvalidMemory,
    /// The peer is not allowed to write the row's namespace (#3233).
    NamespaceScope,
    /// The row's write attestation is forged or unverifiable (#2715).
    Attestation,
    /// A transient failure held the cursor for [`PULL_HOLD_STALL_PASSES`]
    /// healthy windows (#8788).
    HoldStalled,
}

impl RefusalReason {
    /// The closed-set label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnparseableTs => "unparseable_ts",
            Self::UnparseableBody => "unparseable_body",
            Self::InvalidMemory => "invalid_memory",
            Self::NamespaceScope => "namespace_scope",
            Self::Attestation => "content_attestation",
            Self::HoldStalled => "hold_stalled",
        }
    }
}

/// #8788 / #8789 — one refused row of a pull window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRow {
    /// The row's id as the peer sent it (`<missing>` when absent).
    pub memory_id: String,
    /// Why it was refused.
    pub reason: RefusalReason,
}

/// v1.0.0 #2718 / CB-14 — validate a peer-advertised pull-cursor candidate
/// against the current wall clock. See [`validate_pull_cursor_at`]. The
/// production loops resolve through [`PullCursorTracker`]; this wrapper keeps
/// the #2718 unit pins.
#[cfg(test)]
pub(crate) fn validate_pull_cursor(
    candidate: &str,
    current_since: Option<&str>,
) -> Result<(), &'static str> {
    validate_pull_cursor_at(candidate, current_since, Utc::now())
}

/// v1.0.0 #2718 / CB-14 — `Ok(())` only when `candidate` is RFC 3339, does
/// not lead `now` by more than [`PULL_CURSOR_FUTURE_SKEW_SECS`], and is
/// LEXICALLY strictly greater than the current cursor (the same compare the
/// `sync_state` upsert and the peer's `updated_at > since` SQL use).
pub(crate) fn validate_pull_cursor_at(
    candidate: &str,
    current_since: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    let Some(candidate_dt) = parse_ts(candidate) else {
        return Err("not RFC3339");
    };
    if candidate_dt > now + chrono::Duration::seconds(PULL_CURSOR_FUTURE_SKEW_SECS) {
        return Err("exceeds now + skew (far-future cursor poison)");
    }
    if let Some(cur) = current_since
        && candidate <= cur
    {
        return Err("not strictly greater than current cursor");
    }
    Ok(())
}

fn parse_ts(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// #8743 — what to do with one delivered row, decided from its raw
/// `updated_at` before it is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowAdmission {
    /// Within bound: run the normal gates and apply it.
    Admit,
    /// Beyond `now + skew`: skip it; the cursor is held below it.
    FutureSkew,
    /// Missing or unparseable timestamp: skip it.
    Rejected,
}

/// #8743 — the per-peer result of one pull window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullOutcome {
    /// Rows the peer returned in this window.
    pub returned: usize,
    /// Rows durably applied.
    pub applied: usize,
    /// Rows delivered but not applied for a recoverable reason (namespace or
    /// attestation refusal, a probe or apply error); the cursor holds below.
    pub deferred: usize,
    /// Rows deferred as [`OUTCOME_DEFERRED_FUTURE_SKEW`].
    pub future_skew: usize,
    /// #8788 / #8789 — rows refused and recorded; the cursor may pass them.
    pub refused: Vec<RefusedRow>,
    /// A full page whose cursor could not advance (one tie group larger than
    /// the page): the rows past the page are not reachable this cycle.
    pub held: bool,
    /// The cursor written to `sync_state`, when it moved.
    pub advanced_to: Option<String>,
    /// #9082 — rows stamped beyond the skew bound that a sequence-mode
    /// window APPLIED (the sequence cursor never reads a row's timestamp, so
    /// such a row cannot move it; it is logged and counted, not deferred).
    pub future_skew_applied: usize,
    /// #9082 — the sequence cursor persisted for a sequence-mode window.
    pub advanced_seq: Option<i64>,
}

impl PullOutcome {
    /// `true` only when every row the peer delivered was applied and the
    /// cursor was not held on a full page. Only a complete pull logs `ok`.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.deferred == 0 && self.future_skew == 0 && self.refused.is_empty() && !self.held
    }
}

/// #8743 — tracks one pull window and resolves the cursor from the receiver's
/// clock and the rows it actually applied.
pub(crate) struct PullCursorTracker {
    current: Option<String>,
    page_limit: usize,
    now: DateTime<Utc>,
    /// `now` rendered the way rows are stamped, for the lexical bound.
    cursor_ceiling: String,
    admit_ceiling: DateTime<Utc>,
    admit_ceiling_str: String,
    /// Timestamps of rows applied or refused: the cursor may pass them.
    settled_ts: Vec<String>,
    /// Ids applied or refused in this window (cleared from the stall ledger).
    settled_ids: Vec<String>,
    /// Transiently deferred rows `(memory id, updated_at)`.
    pending: Vec<(String, String)>,
    max_delivered: Option<String>,
    min_blocker: Option<String>,
    /// #9082 — the peer answered on its serving-assigned sequence: the
    /// timestamp cursor rules (ceiling, tie groups, future-skew deferral) do
    /// not apply, see [`Self::resolve_seq`].
    seq_mode: bool,
    outcome: PullOutcome,
}

impl PullCursorTracker {
    /// A tracker for a window pulled with cursor `current` and a page of at
    /// most `page_limit` rows, judged against the wall clock.
    pub(crate) fn new(current: Option<String>, page_limit: usize) -> Self {
        Self::new_at(current, page_limit, Utc::now())
    }

    /// As [`Self::new`], judged against `now` (unit tests pin the clock).
    pub(crate) fn new_at(current: Option<String>, page_limit: usize, now: DateTime<Utc>) -> Self {
        let admit_ceiling = now + chrono::Duration::seconds(PULL_CURSOR_FUTURE_SKEW_SECS);
        Self {
            current,
            page_limit,
            now,
            cursor_ceiling: now.to_rfc3339(),
            admit_ceiling,
            admit_ceiling_str: admit_ceiling.to_rfc3339(),
            settled_ts: Vec::new(),
            settled_ids: Vec::new(),
            pending: Vec::new(),
            max_delivered: None,
            min_blocker: None,
            seq_mode: false,
            outcome: PullOutcome::default(),
        }
    }

    /// #9082 — a tracker for a window the peer answered on its sequence
    /// (`next_seq` present), with a page of at most `page_limit` rows.
    pub(crate) fn new_seq(page_limit: usize) -> Self {
        Self::new_seq_at(page_limit, Utc::now())
    }

    /// As [`Self::new_seq`], judged against `now` (unit tests pin the clock).
    pub(crate) fn new_seq_at(page_limit: usize, now: DateTime<Utc>) -> Self {
        Self {
            seq_mode: true,
            ..Self::new_at(None, page_limit, now)
        }
    }

    /// Decide one delivered row from its raw `updated_at`. A `FutureSkew` or
    /// `Rejected` answer is already counted and logged; the caller skips it.
    pub(crate) fn admit(&mut self, ts: Option<&str>, peer: &str, memory_id: &str) -> RowAdmission {
        let Some(dt) = ts.and_then(parse_ts) else {
            self.refused(peer, memory_id, ts, RefusalReason::UnparseableTs);
            return RowAdmission::Rejected;
        };
        let Some(ts) = ts else {
            return RowAdmission::Rejected;
        };
        if self.max_delivered.as_deref().is_none_or(|m| ts > m) {
            self.max_delivered = Some(ts.to_string());
        }
        if dt > self.admit_ceiling || ts > self.admit_ceiling_str.as_str() {
            if self.seq_mode {
                // decision: apply over defer because the sequence cursor never
                // reads a row timestamp, so the row cannot poison it, and a
                // deferral would hold the whole page behind it. The receiver
                // mirrors the origin's state (the row wins last-writer-wins
                // here exactly as it does there).
                self.outcome.future_skew_applied += 1;
                tracing::warn!(
                    target: crate::federation::SCOPE_TRACE_TARGET,
                    peer = %peer,
                    memory_id = ?memory_id,
                    updated_at = ?ts,
                    bound = %self.admit_ceiling_str,
                    "pull: row timestamp leads this node's clock by more than {PULL_CURSOR_FUTURE_SKEW_SECS}s; \
                     applied on the sequence walk, the cursor does not read it (#9082)"
                );
                return RowAdmission::Admit;
            }
            self.outcome.future_skew += 1;
            self.block(ts);
            tracing::warn!(
                target: crate::federation::SCOPE_TRACE_TARGET,
                peer = %peer,
                memory_id = ?memory_id,
                updated_at = ?ts,
                bound = %self.admit_ceiling_str,
                outcome = OUTCOME_DEFERRED_FUTURE_SKEW,
                "pull: row timestamp leads this node's clock by more than {PULL_CURSOR_FUTURE_SKEW_SECS}s; \
                 not applied, cursor held below it (#8743)"
            );
            return RowAdmission::FutureSkew;
        }
        RowAdmission::Admit
    }

    /// #8788 / #8789 — the delivered row was refused for `reason`: logged,
    /// counted, recorded in the outcome and settled, so the cursor may pass
    /// it (a row whose timestamp does not parse settles nothing).
    ///
    /// Recording is at least once: a refused row that is the newest row of a
    /// full page is re-delivered by the next window (the tie-safe cursor stays
    /// strictly below it) and recorded a second time, then passed.
    pub(crate) fn refused(
        &mut self,
        peer: &str,
        memory_id: &str,
        ts: Option<&str>,
        reason: RefusalReason,
    ) {
        if reason == RefusalReason::HoldStalled {
            tracing::error!(
                target: crate::federation::SCOPE_TRACE_TARGET,
                peer = %peer,
                memory_id = ?memory_id,
                updated_at = ?ts,
                reason = reason.label(),
                "pull: row failed to apply in {PULL_HOLD_STALL_PASSES} windows that applied other rows; \
                 refused and recorded, the cursor passes it (#8788)"
            );
        } else {
            tracing::warn!(
                target: crate::federation::SCOPE_TRACE_TARGET,
                peer = %peer,
                memory_id = ?memory_id,
                updated_at = ?ts,
                reason = reason.label(),
                "pull: row refused and recorded; not applied, the cursor passes it (#8788/#8789)"
            );
        }
        crate::metrics::registry()
            .federation_pull_rows_refused_total
            .with_label_values(&[reason.label()])
            .inc();
        self.outcome.refused.push(RefusedRow {
            memory_id: memory_id.to_string(),
            reason,
        });
        self.settled_ids.push(memory_id.to_string());
        if let Some(ts) = ts.filter(|t| parse_ts(t).is_some()) {
            self.settled_ts.push(ts.to_string());
        }
    }

    fn block(&mut self, ts: &str) {
        if self.min_blocker.as_deref().is_none_or(|b| ts < b) {
            self.min_blocker = Some(ts.to_string());
        }
    }

    /// The row `memory_id` with timestamp `ts` was durably applied.
    pub(crate) fn applied(&mut self, ts: &str, memory_id: &str) {
        self.outcome.applied += 1;
        self.settled_ts.push(ts.to_string());
        self.settled_ids.push(memory_id.to_string());
    }

    /// The admitted row was delivered but not applied for a TRANSIENT reason
    /// (a probe or apply error): the cursor stays strictly below `ts`, until
    /// the row stalls (see [`PULL_HOLD_STALL_PASSES`]).
    pub(crate) fn deferred(&mut self, ts: &str, memory_id: &str) {
        self.outcome.deferred += 1;
        self.pending.push((memory_id.to_string(), ts.to_string()));
    }

    /// #8788 — settle this window's rows in the stall ledger: applied and
    /// refused rows leave it; each deferred row counts one more healthy
    /// window (only when this window applied something) and, at
    /// [`PULL_HOLD_STALL_PASSES`], is refused as `HoldStalled`. Every other
    /// deferred row blocks the cursor.
    fn settle_stalls(&mut self, peer: &str) {
        let healthy = self.outcome.applied > 0;
        let mut stalled = Vec::new();
        {
            let mut guard = HOLD_STALLS.lock().unwrap_or_else(PoisonError::into_inner);
            let ledger = guard.get_or_insert_with(HashMap::new);
            for id in &self.settled_ids {
                ledger.remove(&(peer.to_string(), id.clone()));
            }
            for (id, ts) in &self.pending {
                let key = (peer.to_string(), id.clone());
                let count = if !healthy {
                    0
                } else if let Some(n) = ledger.get_mut(&key) {
                    *n = n.saturating_add(1);
                    *n
                } else if ledger.len() < PULL_HOLD_STALL_TRACKED_MAX {
                    ledger.insert(key.clone(), 1);
                    1
                } else {
                    0
                };
                if count >= PULL_HOLD_STALL_PASSES {
                    ledger.remove(&key);
                    stalled.push((id.clone(), ts.clone()));
                }
            }
        }
        for (id, ts) in std::mem::take(&mut self.pending) {
            if stalled.iter().any(|(sid, sts)| *sid == id && *sts == ts) {
                self.outcome.deferred = self.outcome.deferred.saturating_sub(1);
                self.refused(peer, &id, Some(&ts), RefusalReason::HoldStalled);
            } else {
                self.block(&ts);
            }
        }
    }

    fn accept(&self, candidate: &str) -> Result<(), &'static str> {
        validate_pull_cursor_at(candidate, self.current.as_deref(), self.now)?;
        if parse_ts(candidate).is_none_or(|dt| dt > self.now)
            || candidate > self.cursor_ceiling.as_str()
        {
            return Err("ahead of this node's clock (#8743 cursor ceiling)");
        }
        if let Some(blocker) = self.min_blocker.as_deref()
            && candidate >= blocker
        {
            return Err("at or past a delivered row that was not applied (#8743)");
        }
        Ok(())
    }

    /// Resolve the cursor to persist after the window: the peer's
    /// `next_since` when it passes every bound, else the newest applied row
    /// that does (strictly below the newest delivered row when the page was
    /// full, so a tie group cut by the page is re-pulled), else no advance.
    pub(crate) fn resolve(
        &mut self,
        next_since: Option<&str>,
        returned: usize,
        peer: &str,
    ) -> Option<String> {
        self.outcome.returned = returned;
        self.settle_stalls(peer);
        let page_full = returned > 0 && returned >= self.page_limit;
        let mut advance = None;
        if let Some(candidate) = next_since {
            // A full page may have cut a tie group: the peer's `next_since`
            // (its newest examined row) is then the newest delivered row, and
            // honouring it would leap the rest of that group (`> since` SQL).
            let page_cut = page_full
                && self
                    .max_delivered
                    .as_deref()
                    .is_some_and(|m| candidate >= m);
            match self.accept(candidate).and_then(|()| {
                if page_cut {
                    Err("full page: at or past the newest delivered row (tie group may continue)")
                } else {
                    Ok(())
                }
            }) {
                Ok(()) => advance = Some(candidate.to_string()),
                Err(reason) => tracing::warn!(
                    target: crate::federation::SCOPE_TRACE_TARGET,
                    peer = %peer,
                    candidate = ?candidate,
                    reason,
                    "pull: refusing peer-advertised next_since cursor (#2718/#8743)"
                ),
            }
        }
        if advance.is_none() {
            advance = self
                .settled_ts
                .iter()
                .filter(|ts| {
                    !page_full
                        || self
                            .max_delivered
                            .as_deref()
                            .is_some_and(|m| ts.as_str() < m)
                })
                .filter(|ts| self.accept(ts).is_ok())
                .max()
                .cloned();
        }
        self.outcome.held = advance.is_none() && page_full;
        self.outcome.advanced_to.clone_from(&advance);
        advance
    }

    /// #9082 — resolve the sequence cursor after a sequence-mode window.
    ///
    /// `effective_after` is the `after_seq` the peer says it walked from (the
    /// requested value, or 0 after its reset); `next_seq` is the highest
    /// sequence it examined. The answer is `next_seq` when every delivered
    /// row was applied or refused, else `effective_after`: a transiently
    /// deferred row holds the whole window (the puller does not learn each
    /// row's sequence), until it stalls into [`RefusalReason::HoldStalled`].
    /// A `next_seq` below `effective_after` is a broken peer: refused, held.
    /// `rewalk` (the stored cursor belongs to another epoch of the peer)
    /// answers 0, so the next window walks the new numbering from the start.
    pub(crate) fn resolve_seq(
        &mut self,
        effective_after: i64,
        next_seq: i64,
        returned: usize,
        rewalk: bool,
        peer: &str,
    ) -> i64 {
        self.outcome.returned = returned;
        self.settle_stalls(peer);
        let advance = if rewalk {
            0
        } else if next_seq < effective_after {
            tracing::warn!(
                target: crate::federation::SCOPE_TRACE_TARGET,
                peer = %peer,
                next_seq,
                effective_after,
                "pull: refusing a next_seq below the walked after_seq (#9082)"
            );
            effective_after
        } else if self.min_blocker.is_some() {
            effective_after
        } else {
            next_seq
        };
        self.outcome.advanced_seq = Some(advance);
        advance
    }

    /// The window's outcome (call after [`Self::resolve`]).
    pub(crate) fn outcome(&self) -> PullOutcome {
        self.outcome.clone()
    }
}

/// #8743 — the one log line for a finished pull window: the canonical
/// `pull: <peer> ok` only when the window is complete, else a WARN that
/// names every count.
pub(crate) fn log_pull_outcome(label: &str, peer: &str, outcome: &PullOutcome) {
    if outcome.is_complete() {
        tracing::info!(
            peer_id = %peer,
            rows = outcome.returned,
            "{label}: pull: {peer} ok ({} row(s) returned)",
            outcome.returned
        );
    } else {
        tracing::warn!(
            target: crate::federation::SCOPE_TRACE_TARGET,
            peer_id = %peer,
            returned = outcome.returned,
            applied = outcome.applied,
            deferred = outcome.deferred,
            future_skew = outcome.future_skew,
            refused = outcome.refused.len(),
            held = outcome.held,
            "{label}: pull: {peer} incomplete ({} returned, {} applied, {} deferred, {} {OUTCOME_DEFERRED_FUTURE_SKEW}, \
             {} refused, held={}) (#8743/#8788)",
            outcome.returned,
            outcome.applied,
            outcome.deferred,
            outcome.future_skew,
            outcome.refused.len(),
            outcome.held
        );
    }
}

/// #8743 — the sync-daemon's apply loop for one `/sync/since` window (lifted
/// out of `sync_cycle_once`). Admits each row against the receiver's clock,
/// runs the #2715 attestation gate, applies durably, and records every row in
/// `tracker`.
pub(crate) fn apply_sync_cycle_window(
    conn: &rusqlite::Connection,
    memories: &[crate::models::Memory],
    tracker: &mut PullCursorTracker,
    peer_key: &str,
) {
    for mem in memories {
        if tracker.admit(Some(mem.updated_at.as_str()), peer_key, &mem.id) != RowAdmission::Admit {
            continue;
        }
        if let Err(e) = crate::validate::RequestValidator::validate_memory(mem) {
            log_invalid_memory(peer_key, &mem.id, &e);
            tracker.refused(
                peer_key,
                &mem.id,
                Some(&mem.updated_at),
                RefusalReason::InvalidMemory,
            );
            continue;
        }
        // #2715 (CB-11 / B-4) — per-write content attestation, the pull
        // sibling of the `/sync/push` gate. #8788 — a refusal is recorded and
        // settled (the cursor passes it) instead of halting every later row.
        let mut to_insert = mem.clone();
        crate::handlers::federation_receive::sanitize_inbound_pull_memory(&mut to_insert);
        let author_bound_key =
            crate::identity::attest::presented_attestation_author_needing_bound_key(
                &to_insert, None,
            )
            .and_then(|author| {
                crate::handlers::federation_receive::historical_author_key_or_warn(
                    crate::db::agent_pubkey_for_attestation_at(conn, author, &to_insert.created_at),
                    author,
                )
            });
        if !crate::handlers::federation_receive::attest_inbound_pull_memory(
            &mut to_insert,
            author_bound_key.as_ref(),
        ) {
            tracker.refused(
                peer_key,
                &mem.id,
                Some(&mem.updated_at),
                RefusalReason::Attestation,
            );
            continue;
        }
        // #2714 (CB-10) — a non-durable apply holds the cursor below the row.
        match crate::db::insert_if_newer(conn, &to_insert) {
            Ok(_) => tracker.applied(&mem.updated_at, &mem.id),
            Err(e) => {
                tracker.deferred(&mem.updated_at, &mem.id);
                tracing::warn!(
                    target: crate::federation::SCOPE_TRACE_TARGET,
                    peer = %peer_key,
                    memory_id = %to_insert.id,
                    error = %e,
                    "sync-daemon: non-durable apply — holding the cursor so the \
                     un-applied row is re-pulled next cycle (#2714 row-loss guard)"
                );
            }
        }
    }
}

/// #8789 — the field-validation failure behind a
/// [`RefusalReason::InvalidMemory`] refusal (the error names the field, never
/// the content).
pub(crate) fn log_invalid_memory(peer: &str, memory_id: &str, e: &impl std::fmt::Display) {
    tracing::warn!(
        target: crate::federation::SCOPE_TRACE_TARGET,
        peer = %peer,
        memory_id = ?memory_id,
        error = %e,
        "pull: row failed field validation (#8789)"
    );
}

#[cfg(test)]
mod tests {
    //! #8743 — the tracker against a pinned clock.
    use super::*;

    const NOW: &str = "2026-11-10T12:00:00+00:00";
    const PEER: &str = "peer-8743-unit";

    fn now() -> DateTime<Utc> {
        parse_ts(NOW).expect("NOW parses")
    }

    fn at(offset_secs: i64) -> String {
        (now() + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    }

    fn apply_all(t: &mut PullCursorTracker, rows: &[String]) {
        for (i, ts) in rows.iter().enumerate() {
            let id = format!("m{i}");
            if t.admit(Some(ts), PEER, &id) == RowAdmission::Admit {
                t.applied(ts, &id);
            }
        }
    }

    #[test]
    fn audit_case_future_row_last_cursor_stays_below_now_8743() {
        let rows = [at(-20), at(-10), at(24 * 3600)];
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        apply_all(&mut t, &rows);
        let adv = t.resolve(Some(&rows[2]), rows.len(), PEER);
        assert_eq!(adv.as_deref(), Some(rows[1].as_str()));
        let o = t.outcome();
        assert_eq!((o.applied, o.future_skew, o.held), (2, 1, false));
        assert!(!o.is_complete());
    }

    #[test]
    fn within_skew_row_applied_but_cursor_held_at_now_8743() {
        let rows = [at(-10), at(PULL_CURSOR_FUTURE_SKEW_SECS / 2)];
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        apply_all(&mut t, &rows);
        let adv = t.resolve(Some(&rows[1]), rows.len(), PEER);
        assert_eq!(adv.as_deref(), Some(rows[0].as_str()));
        assert!(t.outcome().is_complete());
    }

    #[test]
    fn deferred_row_blocks_later_rows_8743() {
        let rows = [at(-30), at(-20), at(-10)];
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        assert_eq!(t.admit(Some(&rows[0]), PEER, "a"), RowAdmission::Admit);
        t.applied(&rows[0], "a");
        assert_eq!(t.admit(Some(&rows[1]), PEER, "b"), RowAdmission::Admit);
        t.deferred(&rows[1], "b");
        assert_eq!(t.admit(Some(&rows[2]), PEER, "c"), RowAdmission::Admit);
        t.applied(&rows[2], "c");
        let adv = t.resolve(Some(&rows[2]), rows.len(), PEER);
        assert_eq!(adv.as_deref(), Some(rows[0].as_str()));
        assert_eq!(t.outcome().deferred, 1);
    }

    #[test]
    fn full_page_single_tie_group_is_held_8743() {
        let ts = at(-60);
        let rows = vec![ts.clone(); 3];
        let mut t = PullCursorTracker::new_at(None, 3, now());
        apply_all(&mut t, &rows);
        assert_eq!(t.resolve(None, rows.len(), PEER), None);
        let o = t.outcome();
        assert!(o.held);
        assert!(!o.is_complete());
    }

    #[test]
    fn full_page_falls_back_strictly_below_newest_delivered_8743() {
        let rows = [at(-60), at(-50), at(-50)];
        let mut t = PullCursorTracker::new_at(None, 3, now());
        apply_all(&mut t, &rows);
        assert_eq!(
            t.resolve(None, rows.len(), PEER).as_deref(),
            Some(rows[0].as_str())
        );
    }

    #[test]
    fn full_page_refuses_peer_next_since_at_newest_delivered_8743() {
        // Page of 3 cut a tie group at -40: the peer advertises -40 (its
        // newest examined row); honouring it would leap the rest of the group.
        let rows = [at(-50), at(-40), at(-40)];
        let mut t = PullCursorTracker::new_at(None, 3, now());
        apply_all(&mut t, &rows);
        assert_eq!(
            t.resolve(Some(&rows[2]), rows.len(), PEER).as_deref(),
            Some(rows[0].as_str())
        );
        // The same next_since on a short page is the end of the data: taken.
        let mut short = PullCursorTracker::new_at(None, 4, now());
        apply_all(&mut short, &rows);
        assert_eq!(
            short.resolve(Some(&rows[2]), rows.len(), PEER).as_deref(),
            Some(rows[2].as_str())
        );
    }

    #[test]
    fn unparseable_and_missing_timestamps_are_rejected_8743() {
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        assert_eq!(
            t.admit(Some("yesterday"), PEER, "a"),
            RowAdmission::Rejected
        );
        assert_eq!(t.admit(None, PEER, "b"), RowAdmission::Rejected);
        assert_eq!(t.resolve(None, 2, PEER), None);
        let reasons: Vec<RefusalReason> = t.outcome().refused.iter().map(|r| r.reason).collect();
        assert_eq!(reasons, [RefusalReason::UnparseableTs; 2]);
    }

    #[test]
    fn offset_format_cannot_pass_the_lexical_ceiling_8743() {
        // Chronologically one second in the past, lexically ahead of NOW.
        let shifted = "2026-11-10T16:59:59+05:00";
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        assert_eq!(t.resolve(Some(shifted), 0, PEER), None);
    }

    #[test]
    fn validate_pull_cursor_at_keeps_the_2718_rules() {
        assert_eq!(
            validate_pull_cursor_at("9999-12-31T23:59:59+00:00", None, now()),
            Err("exceeds now + skew (far-future cursor poison)")
        );
        assert_eq!(
            validate_pull_cursor_at("nope", None, now()),
            Err("not RFC3339")
        );
        assert_eq!(
            validate_pull_cursor_at(NOW, Some(NOW), now()),
            Err("not strictly greater than current cursor")
        );
        assert_eq!(validate_pull_cursor_at(&at(-1), None, now()), Ok(()));
    }

    /// One window: `good` applied (at -60 s) and the row `stuck` (at -30 s)
    /// deferred; returns the advanced cursor and the window's outcome.
    fn stuck_window(peer: &str, good: bool) -> (Option<String>, PullOutcome) {
        let (good_ts, stuck_ts) = (at(-60), at(-30));
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        if good {
            assert_eq!(t.admit(Some(&good_ts), peer, "good"), RowAdmission::Admit);
            t.applied(&good_ts, "good");
        }
        assert_eq!(t.admit(Some(&stuck_ts), peer, "stuck"), RowAdmission::Admit);
        t.deferred(&stuck_ts, "stuck");
        let adv = t.resolve(Some(&stuck_ts), 2, peer);
        (adv, t.outcome())
    }

    #[test]
    fn transient_hold_converts_to_hold_stalled_after_healthy_passes_8788() {
        const STALL_PEER: &str = "peer-8788-stall";
        for pass in 1..PULL_HOLD_STALL_PASSES {
            let (adv, o) = stuck_window(STALL_PEER, true);
            assert_eq!(
                adv.as_deref(),
                Some(at(-60).as_str()),
                "pass {pass} holds below the row"
            );
            assert_eq!((o.deferred, o.refused.len()), (1, 0), "pass {pass}");
        }
        let (adv, o) = stuck_window(STALL_PEER, true);
        assert_eq!(
            adv.as_deref(),
            Some(at(-30).as_str()),
            "the stalled row is passed"
        );
        assert_eq!(o.deferred, 0);
        assert_eq!(
            o.refused,
            [RefusedRow {
                memory_id: "stuck".to_string(),
                reason: RefusalReason::HoldStalled
            }]
        );
        assert!(!o.is_complete());
        // The ledger entry is gone: the next deferral starts a new count.
        let (_, o) = stuck_window(STALL_PEER, true);
        assert_eq!((o.deferred, o.refused.len()), (1, 0));
    }

    #[test]
    fn outage_windows_never_count_toward_the_stall_8788() {
        const OUTAGE_PEER: &str = "peer-8788-outage";
        for pass in 0..PULL_HOLD_STALL_PASSES * 3 {
            let (adv, o) = stuck_window(OUTAGE_PEER, false);
            assert_eq!(adv, None, "pass {pass}: nothing applied, nothing passed");
            assert_eq!((o.deferred, o.refused.len()), (1, 0), "pass {pass}");
        }
    }

    #[test]
    fn refused_row_settles_and_later_rows_advance_8788() {
        let rows = [at(-30), at(-20), at(-10)];
        let mut t = PullCursorTracker::new_at(None, SYNC_SINCE_DEFAULT_LIMIT, now());
        assert_eq!(t.admit(Some(&rows[0]), PEER, "r0"), RowAdmission::Admit);
        t.refused(PEER, "r0", Some(&rows[0]), RefusalReason::Attestation);
        assert_eq!(t.admit(Some(&rows[1]), PEER, "r1"), RowAdmission::Admit);
        t.applied(&rows[1], "r1");
        assert_eq!(t.admit(Some(&rows[2]), PEER, "r2"), RowAdmission::Admit);
        t.refused(PEER, "r2", Some(&rows[2]), RefusalReason::InvalidMemory);
        assert_eq!(
            t.resolve(Some(&rows[2]), 3, PEER).as_deref(),
            Some(rows[2].as_str())
        );
        let reasons: Vec<&str> = t
            .outcome()
            .refused
            .iter()
            .map(|r| r.reason.label())
            .collect();
        assert_eq!(
            reasons,
            [
                RefusalReason::Attestation.label(),
                RefusalReason::InvalidMemory.label()
            ]
        );
    }

    // ---- #9082: the sequence walk ----

    #[test]
    fn seq_walk_applies_far_future_row_and_advances_9082() {
        let peer = "peer-9082-future";
        let rows = [at(-10), "9999-12-31T23:59:59+00:00".to_string()];
        let mut t = PullCursorTracker::new_seq_at(SYNC_SINCE_DEFAULT_LIMIT, now());
        for (i, ts) in rows.iter().enumerate() {
            let id = format!("f{i}");
            assert_eq!(t.admit(Some(ts), peer, &id), RowAdmission::Admit);
            t.applied(ts, &id);
        }
        assert_eq!(t.resolve_seq(5, 9, rows.len(), false, peer), 9);
        let o = t.outcome();
        assert_eq!(
            (
                o.applied,
                o.future_skew,
                o.future_skew_applied,
                o.advanced_seq
            ),
            (2, 0, 1, Some(9))
        );
    }

    #[test]
    fn seq_walk_table_9082() {
        // (case, row action, effective_after, next_seq, rewalk, want)
        #[derive(Clone, Copy)]
        enum Row {
            Applied,
            Deferred,
            Refused,
            Unparseable,
        }
        let cases: &[(&str, Row, i64, i64, bool, i64)] = &[
            ("clean", Row::Applied, 5, 9, false, 9),
            ("empty-page echo", Row::Applied, 5, 5, false, 5),
            ("transient hold", Row::Deferred, 5, 9, false, 5),
            ("refused passes", Row::Refused, 5, 9, false, 9),
            ("unparseable passes", Row::Unparseable, 5, 9, false, 9),
            ("next below after", Row::Applied, 5, 3, false, 5),
            ("foreign epoch", Row::Applied, 5, 9, true, 0),
            ("foreign epoch while held", Row::Deferred, 5, 9, true, 0),
            ("peer reset", Row::Applied, 0, 4, false, 4),
        ];
        for (i, &(case, row, after, next, rewalk, want)) in cases.iter().enumerate() {
            let peer = format!("peer-9082-table-{i}");
            let mut t = PullCursorTracker::new_seq_at(SYNC_SINCE_DEFAULT_LIMIT, now());
            let ts = at(-5);
            match row {
                Row::Applied => {
                    assert_eq!(t.admit(Some(&ts), &peer, "r"), RowAdmission::Admit);
                    t.applied(&ts, "r");
                }
                Row::Deferred => {
                    assert_eq!(t.admit(Some(&ts), &peer, "r"), RowAdmission::Admit);
                    t.deferred(&ts, "r");
                }
                Row::Refused => {
                    assert_eq!(t.admit(Some(&ts), &peer, "r"), RowAdmission::Admit);
                    t.refused(&peer, "r", Some(&ts), RefusalReason::InvalidMemory);
                }
                Row::Unparseable => {
                    assert_eq!(
                        t.admit(Some("not-a-time"), &peer, "r"),
                        RowAdmission::Rejected
                    );
                }
            }
            assert_eq!(
                t.resolve_seq(after, next, 1, rewalk, &peer),
                want,
                "case {case}"
            );
        }
    }

    #[test]
    fn seq_walk_stalled_row_releases_the_window_8788_9082() {
        let peer = "peer-9082-stall";
        let mut last = None;
        for pass in 0..=PULL_HOLD_STALL_PASSES {
            let mut t = PullCursorTracker::new_seq_at(SYNC_SINCE_DEFAULT_LIMIT, now());
            let (good, bad) = (at(-20), at(-10));
            assert_eq!(t.admit(Some(&good), peer, "good"), RowAdmission::Admit);
            t.applied(&good, "good");
            assert_eq!(t.admit(Some(&bad), peer, "bad"), RowAdmission::Admit);
            t.deferred(&bad, "bad");
            let got = t.resolve_seq(5, 9, 2, false, peer);
            last = Some((pass, got, t.outcome()));
            if got == 9 {
                break;
            }
            assert_eq!(got, 5, "pass {pass} holds the window");
        }
        let (pass, got, o) = last.expect("at least one pass");
        assert_eq!((pass, got), (PULL_HOLD_STALL_PASSES - 1, 9));
        assert_eq!(o.refused.len(), 1);
        assert_eq!(o.refused[0].memory_id, "bad");
        assert_eq!(o.refused[0].reason, RefusalReason::HoldStalled);
    }
}
