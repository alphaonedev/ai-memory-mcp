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
//! The residual window is the reverse one: a stop between the effect's commit
//! and the approval's commit leaves the effect landed with the row `pending`,
//! and a redelivery re-runs the effect. That is at-least-once over effects
//! that re-apply onto the same state (store/promote land on the same
//! `(title, namespace)` slot, delete is idempotent) — degraded, never an
//! authorized decision with its effect missing.

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
    /// The row is already `approved`: the converged state a redelivered
    /// decision finds once this funnel has completed it.
    AlreadyApproved,
    /// No pending row with this id exists (converged no-op).
    NotFound,
    /// Refused: approver not eligible, or the row carries a CONFLICTING
    /// decision (`rejected` / `expired`). Carries the operator-facing reason.
    Refused(String),
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
        return Ok(FederatedApproveOutcome::AlreadyApproved);
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
    let mut as_approved = pa;
    as_approved.status = STATUS_APPROVED.to_string();
    as_approved.decided_by = Some(decider.clone());
    as_approved.decided_at = Some(decided_at.clone());
    as_approved.approvals = approvals;
    let memory_id = execute_pending_effect(conn, &as_approved)?;

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
