// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4025 — federated pending-action APPROVAL whose decision becomes durable
//! only AFTER its effect landed.
//!
//! Pre-#4025 the federation receive funnels (sqlite and postgres) ran
//! [`super::approve_with_approver_type`] — which COMMITS `status = 'approved'`
//! — and then [`super::execute_pending_action`] as a separate step. A failed
//! execution (or a process stop in between) left an `approved` row whose
//! store/delete/promote/reflect effect never happened, and every later
//! redelivery of the same decision was refused as "already decided", so the
//! effect could never be completed.
//!
//! This funnel inverts the order: eligibility (and consensus bookkeeping) is
//! evaluated first, the effect is run against the row AS-IF approved, and the
//! approval (with its final consensus vote) is committed only once the effect
//! succeeded, by a compare-and-set on `status = 'pending'`. Consequently:
//!
//! * a failed effect commits NOTHING — the row stays `pending`, so the
//!   redelivered decision re-runs the whole approve-then-effect unit;
//! * an `approved` row reached through this funnel always has its effect, so
//!   a redelivery (e.g. a lost response) is acknowledged as a converged no-op
//!   ([`FederatedApproveOutcome::AlreadyApproved`]);
//! * a conflicting decision (`rejected` / `expired`) stays refused.
//!
//! # Execution marker (#4345, GOD ruling on #4025)
//!
//! Immediately after the effect lands, the unit stamps a durable EXECUTION
//! MARKER ([`EFFECT_MARKER_KEY`], a reserved key of the row's `payload` JSON —
//! no schema migration) BEFORE it commits the approval. The marker makes the
//! reverse window safe:
//!
//! * a row that is `pending` WITH a marker has an applied effect: the reject,
//!   timeout-sweep and expire paths REFUSE to record a decision over it (see
//!   [`EFFECT_MARKER_ABSENT_SQL`]), and a redelivered approval completes the
//!   approval WITHOUT re-running the effect;
//! * a row that is `approved` WITHOUT a marker is a legacy gap (approved before
//!   the marker existed, or through a local surface whose execution failed or
//!   was interrupted, #4172): [`FederatedApproveOutcome::AlreadyApprovedUnmarked`]
//!   reports it honestly and `doctor` counts it (#4345).
//!
//! The marker is the write that FOLLOWS the effect, not part of it: the effect
//! funnels commit on their own, and one transaction around effect + marker +
//! approval is the redesign tracked in #4346. A stop in the sliver between the
//! effect's commit and the marker's leaves the old residual: the effect landed
//! with the row `pending` and no marker, and a redelivery re-runs the effect
//! (at-least-once over effects that re-apply onto the same state; store/promote
//! land on the same `(title, namespace)` slot, delete is idempotent).

use anyhow::Result;
use rusqlite::{Connection, params};

use super::{
    ApproveSurface, ApproverEligibility, PENDING_ACTION_APPROVED_EVENT, emit_pending_action_event,
    evaluate_approver_eligibility, execute_pending_effect, get_pending_action,
    resolve_governance_policy,
};
use crate::models::{Approval, ApproverType};

/// Status string of an undecided pending action.
const STATUS_PENDING: &str = "pending";
/// Status string of an approved pending action.
const STATUS_APPROVED: &str = "approved";

/// #4025 — outcome of a federated pending-action approval
/// ([`approve_execute_pending_action`] and its postgres twin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedApproveOutcome {
    /// The effect landed and the approval was committed after it. Carries the
    /// executor's affected memory id.
    Executed(Option<String>),
    /// Consensus quorum not yet met; the vote was recorded, nothing executed.
    VotePending { votes: usize, quorum: u32 },
    /// The row is already `approved` AND carries the execution marker: the
    /// converged state a redelivered decision finds once this funnel has
    /// completed it.
    AlreadyApproved,
    /// The row is `approved` but carries NO execution marker (#4345): approved
    /// before the marker existed, or through a local surface whose execution
    /// failed or was interrupted (#4172). Whether its effect landed is
    /// unknown; the redelivery is acknowledged (a retry could not fix it) but
    /// reported, and `doctor` counts such rows.
    AlreadyApprovedUnmarked,
    /// No pending row with this id exists (converged no-op).
    NotFound,
    /// Refused: approver not eligible, or the row carries a CONFLICTING
    /// decision (`rejected` / `expired`). Carries the operator-facing reason.
    Refused(String),
}

/// #4345 — the reserved `payload` key holding the RFC3339 stamp of the moment
/// an approved action's effect landed (module docs).
pub const EFFECT_MARKER_KEY: &str = "__effect_applied_at";

/// #4416 — every payload key that only the SERVER may write. The wire never
/// carries one: [`strip_reserved_payload_keys`] removes them from every inbound
/// payload before it is stored.
pub const RESERVED_PAYLOAD_KEYS: &[&str] = &[EFFECT_MARKER_KEY];

/// #4416 — remove every [`RESERVED_PAYLOAD_KEYS`] entry from `payload`, so a
/// peer (or any remote-to-local funnel) can never plant the execution marker:
/// it can only be written server-side, after an effect landed. A non-object
/// payload has nothing to strip. Returns `true` when a key was removed.
pub fn strip_reserved_payload_keys(payload: &mut serde_json::Value) -> bool {
    let Some(obj) = payload.as_object_mut() else {
        return false;
    };
    let mut removed = false;
    for key in RESERVED_PAYLOAD_KEYS {
        removed |= obj.remove(*key).is_some();
    }
    removed
}

/// #4416 / F4 — the ONE definition of "this payload carries a marker": a JSON
/// OBJECT whose marker key holds a STRING. A `null`, a number, or a string
/// element inside an array is NOT a marker. The SQL macros below spell the
/// same predicate; every reader (approve, reject, sweep, doctor, local execute)
/// uses one of the two.
#[must_use]
pub fn payload_has_effect_marker(payload: &serde_json::Value) -> bool {
    payload
        .as_object()
        .and_then(|o| o.get(EFFECT_MARKER_KEY))
        .is_some_and(serde_json::Value::is_string)
}

/// SQLite: boolean SQL expression, true when column `$col` holds the marker
/// (mirror of [`payload_has_effect_marker`]); never errors on malformed JSON.
macro_rules! marker_present_sqlite {
    ($col:literal) => {
        concat!(
            "COALESCE(CASE WHEN json_valid(",
            $col,
            ") THEN json_type(",
            $col,
            ", '$.__effect_applied_at') = 'text' END, 0)"
        )
    };
}
/// SQLite: true when column `$col` carries NO marker.
macro_rules! marker_absent_sqlite {
    ($col:literal) => {
        concat!(
            "(NOT COALESCE(CASE WHEN json_valid(",
            $col,
            ") THEN json_type(",
            $col,
            ", '$.__effect_applied_at') = 'text' END, 0))"
        )
    };
}
/// PostgreSQL (jsonb): boolean SQL expression, true when column `$col` holds
/// the marker (mirror of [`payload_has_effect_marker`]).
#[cfg_attr(not(feature = "sal-postgres"), allow(unused_macros))]
macro_rules! marker_present_pg {
    ($col:literal) => {
        concat!(
            "COALESCE(jsonb_typeof(",
            $col,
            ") = 'object' AND jsonb_typeof(",
            $col,
            " -> '__effect_applied_at') = 'string', false)"
        )
    };
}
/// PostgreSQL: true when column `$col` carries NO marker.
macro_rules! marker_absent_pg {
    ($col:literal) => {
        concat!(
            "(NOT COALESCE(jsonb_typeof(",
            $col,
            ") = 'object' AND jsonb_typeof(",
            $col,
            " -> '__effect_applied_at') = 'string', false))"
        )
    };
}
pub(crate) use {marker_absent_pg, marker_absent_sqlite, marker_present_pg, marker_present_sqlite};

/// #4345 — `WHERE`-clause fragment (sqlite) that is true when the row's payload
/// carries NO execution marker. Every path that would record a refusal over a
/// `pending` row (reject, timeout sweep) ANDs this in, so a refused decision is
/// never recorded over an applied effect.
pub const EFFECT_MARKER_ABSENT_SQL: &str = marker_absent_sqlite!("payload");

/// #4345 — the postgres twin of [`EFFECT_MARKER_ABSENT_SQL`].
pub const PG_EFFECT_MARKER_ABSENT_SQL: &str = marker_absent_pg!("payload");

/// #4345 — count of `approved` rows with no execution marker (sqlite).
const SQL_COUNT_APPROVED_UNMARKED: &str = concat!(
    "SELECT COUNT(*) FROM pending_actions WHERE status = 'approved' AND ",
    marker_absent_sqlite!("payload")
);

/// #4345 — count of `approved` rows with no execution marker (postgres).
pub const PG_COUNT_APPROVED_UNMARKED_SQL: &str = concat!(
    "SELECT COUNT(*) FROM pending_actions WHERE status = 'approved' AND ",
    marker_absent_pg!("payload")
);

/// #4345 — stamp the execution marker on `pending_id` (sqlite). Called right
/// after the effect landed, before the approval commits. Idempotent: an
/// existing marker is kept.
///
/// # Errors
///
/// Propagates the storage failure.
pub fn mark_effect_applied(conn: &Connection, pending_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE pending_actions \
         SET payload = json_set(payload, '$.__effect_applied_at', ?1) \
         WHERE id = ?2 AND json_valid(payload) AND \
           (NOT COALESCE(json_type(payload, '$.__effect_applied_at') = 'text', 0))",
        params![chrono::Utc::now().to_rfc3339(), pending_id],
    )?;
    Ok(())
}

/// #4345 — number of `approved` pending actions that carry no execution marker
/// (sqlite). Non-zero means an approval whose effect cannot be proven landed.
///
/// # Errors
///
/// Propagates the storage failure.
pub fn count_approved_without_effect_marker(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row(SQL_COUNT_APPROVED_UNMARKED, [], |r| r.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// #4025 — the approval-commit compare-and-set: lands the decision (and the
/// final consensus vote) only if no other decision landed meanwhile.
const SQL_COMMIT_APPROVAL: &str = "UPDATE pending_actions \
     SET status = 'approved', decided_by = ?1, decided_at = ?2, approvals = ?3 \
     WHERE id = ?4 AND status = 'pending'";

/// Approve `pending_id` for the federation receive funnel, executing its
/// effect BEFORE the approval becomes durable (module docs).
///
/// Eligibility is the SAME [`evaluate_approver_eligibility`] gate
/// [`super::approve_with_approver_type`] runs (self-approval, named approver,
/// registered agent), with the caller-selected `surface` posture.
///
/// # Errors
///
/// Propagates a storage failure, and the effect's own error. On an effect
/// error NOTHING is committed (not the approval, not the final consensus
/// vote) — the row stays `pending` and a redelivery retries the unit.
pub fn approve_execute_pending_action(
    conn: &Connection,
    pending_id: &str,
    approver_agent_id: &str,
    surface: ApproveSurface,
) -> Result<FederatedApproveOutcome> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let Some(pa) = get_pending_action(conn, pending_id)? else {
        return Ok(FederatedApproveOutcome::NotFound);
    };
    if pa.status == STATUS_APPROVED {
        return Ok(if payload_has_effect_marker(&pa.payload) {
            FederatedApproveOutcome::AlreadyApproved
        } else {
            FederatedApproveOutcome::AlreadyApprovedUnmarked
        });
    }
    if pa.status != STATUS_PENDING {
        return Ok(FederatedApproveOutcome::Refused(
            crate::errors::msg::pending_already_decided(&pa.status),
        ));
    }
    let approver = resolve_governance_policy(conn, &pa.namespace)
        .map_or(ApproverType::Human, |p| p.core.approver);
    if let ApproverEligibility::Refused(reason) = evaluate_approver_eligibility(
        conn,
        &approver,
        &pa.requested_by,
        approver_agent_id,
        surface,
    )? {
        return Ok(FederatedApproveOutcome::Refused(reason));
    }

    // Decide WHO the approval is recorded as and the vote log it commits with.
    let (decider, approvals) = match approver {
        ApproverType::Human | ApproverType::Agent(_) => {
            (approver_agent_id.to_string(), pa.approvals.clone())
        }
        ApproverType::Consensus(quorum) => {
            let canonical_id = approver_agent_id.to_ascii_lowercase();
            let mut approvals = pa.approvals.clone();
            if approvals
                .iter()
                .any(|a| a.agent_id.eq_ignore_ascii_case(&canonical_id))
            {
                return Ok(FederatedApproveOutcome::VotePending {
                    votes: approvals.len(),
                    quorum,
                });
            }
            approvals.push(Approval {
                agent_id: canonical_id.clone(),
                approved_at: chrono::Utc::now().to_rfc3339(),
            });
            let votes = approvals.len();
            if u32::try_from(votes).unwrap_or(u32::MAX) < quorum {
                // Below threshold: record the vote only (nothing executes).
                conn.execute(
                    "UPDATE pending_actions SET approvals = ?1 WHERE id = ?2 AND status = 'pending'",
                    params![serde_json::to_string(&approvals)?, pending_id],
                )?;
                return Ok(FederatedApproveOutcome::VotePending { votes, quorum });
            }
            (canonical_id, approvals)
        }
    };

    // Run the effect against the row AS-IF approved; nothing is durable yet.
    let decided_at = chrono::Utc::now().to_rfc3339();
    let effect_already_applied = payload_has_effect_marker(&pa.payload);
    let mut as_approved = pa;
    as_approved.status = STATUS_APPROVED.to_string();
    as_approved.decided_by = Some(decider.clone());
    as_approved.decided_at = Some(decided_at.clone());
    as_approved.approvals = approvals;
    // #4345 — a `pending` row WITH the marker has its effect applied (a stop
    // after the effect, before the approval): complete the approval, never
    // re-run the effect.
    let memory_id = if effect_already_applied {
        None
    } else {
        let id = execute_pending_effect(conn, &as_approved)?;
        // The marker is stamped BEFORE the approval commits, so a stop (or a
        // lost race) from here on leaves a row the reject / sweep paths refuse.
        mark_effect_applied(conn, pending_id)?;
        id
    };

    // The effect landed: commit the decision that authorized it.
    let committed = conn.execute(
        SQL_COMMIT_APPROVAL,
        params![
            decider,
            decided_at,
            serde_json::to_string(&as_approved.approvals)?,
            pending_id
        ],
    )?;
    if committed == 0 {
        // Another connection decided the row while the effect ran (the
        // in-process caller holds the connection mutex, so only a second
        // process can reach this). Surface it loudly — never report success.
        anyhow::bail!(
            "pending action {pending_id}: effect executed but the approval lost a \
             concurrent decision race (#4025); operator review required"
        );
    }
    // S5-M1 parity: the approve audit row captures the post-execute state.
    // Best-effort (warn-only) exactly like `execute_pending_action`.
    emit_pending_action_event(
        conn,
        &as_approved,
        PENDING_ACTION_APPROVED_EVENT,
        Some(&decider),
    );
    Ok(FederatedApproveOutcome::Executed(memory_id))
}
