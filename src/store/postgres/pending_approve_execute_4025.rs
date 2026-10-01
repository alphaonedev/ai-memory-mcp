// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4025 — the postgres twin of
//! [`crate::storage::approve_execute_pending_action`]: a federated pending
//! approval whose decision becomes durable only AFTER its effect landed.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits near its `qual_10_module_size_ceiling` budget;
//! the `postgres/reown_3124.rs` precedent. The trait arm forwards here.
//!
//! # Shape
//!
//! Two phases (#4345, GOD ruling on #4025). Phase 1: one transaction takes the
//! pending row `FOR UPDATE`, evaluates the eligibility gate (the SAME
//! [`PostgresStore::approver_refusal_reason`] the approve surface runs), runs
//! the effect through the standard SAL arms, then stamps the durable EXECUTION
//! MARKER and COMMITS it, the row still `pending`. An effect error rolls the
//! transaction back, so nothing about the decision is durable and a redelivery
//! retries the unit. Phase 2: a compare-and-set that requires the marker writes
//! the approval, and for a consensus threshold the final vote. Between the
//! phases the row is `pending` WITH an applied effect, which reject and the
//! timeout sweep refuse to overwrite and which a redelivered approval completes
//! without re-running the effect. The row lock keeps every other decision path
//! from deciding the row while its effect is in flight.
//!
//! The effect arms commit on their OWN pool connections (they are the shared
//! SAL surfaces), so this needs a pool of at least two connections; with one,
//! the effect's acquire times out, the transaction rolls back, and the row
//! stays `pending` (fail closed). The residual window is the reverse one: a
//! stop after the effect committed but before the marker did leaves the
//! row `pending` with the effect landed, and a redelivery re-runs the effect
//! (at-least-once over effects that re-apply onto the same state) — degraded,
//! never an authorized decision whose effect is missing.

use super::{
    CallerContext, PG_PENDING_ACTION_SELECT, PostgresStore, StoreError, StoreResult,
    pg_row_to_pending_action, to_store_err,
};
use crate::models::{Approval, ApproverType};
use crate::storage::{FederatedApproveOutcome, payload_has_effect_marker};
use crate::store::MemoryStore as _;

/// Status string of an undecided pending action.
const STATUS_PENDING: &str = "pending";
/// Status string of an approved pending action.
const STATUS_APPROVED: &str = "approved";

/// The approval commit (phase 2, after the marker committed).
const SQL_COMMIT_APPROVAL: &str = "UPDATE pending_actions \
     SET status = 'approved', decided_by = $1, decided_at = NOW(), approvals = $2 \
     WHERE id = $3 AND status = 'pending' AND payload ? '__effect_applied_at'";

/// #4345 — stamp the execution marker (idempotent: an existing one is kept).
const SQL_STAMP_MARKER: &str = "UPDATE pending_actions \
     SET payload = jsonb_set(payload, '{__effect_applied_at}', to_jsonb($1::text)) \
     WHERE id = $2 AND NOT (payload ? '__effect_applied_at')";

impl PostgresStore {
    /// Body of [`crate::store::MemoryStore::approve_execute_pending_action`]
    /// on postgres (module docs).
    ///
    /// # Errors
    ///
    /// A backend failure, or the effect's own error — in both cases the
    /// transaction rolls back and nothing about the decision is committed.
    pub(super) async fn pg_approve_execute_pending_action(
        &self,
        ctx: &CallerContext,
        pending_id: &str,
        approver_agent_id: &str,
    ) -> StoreResult<FederatedApproveOutcome> {
        self.gate_record_stop().await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("approve_execute_pending begin tx", e))?;
        let locked_sql = format!("{PG_PENDING_ACTION_SELECT} FOR UPDATE");
        let row = sqlx::query(&locked_sql)
            .bind(pending_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| to_store_err("approve_execute_pending lock row", e))?;
        let Some(row) = row else {
            return Ok(FederatedApproveOutcome::NotFound);
        };
        let pa = pg_row_to_pending_action(&row)?;
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
        let approver = self
            .resolve_governance_policy(&pa.namespace)
            .await?
            .map_or(ApproverType::Human, |p| p.core.approver);
        if let Some(reason) = self
            .approver_refusal_reason(&approver, &pa.requested_by, approver_agent_id)
            .await?
        {
            return Ok(FederatedApproveOutcome::Refused(reason));
        }

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
                    sqlx::query(
                        "UPDATE pending_actions SET approvals = $1 \
                         WHERE id = $2 AND status = 'pending'",
                    )
                    .bind(approvals_json(&approvals)?)
                    .bind(pending_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("approve_execute_pending record vote", e))?;
                    tx.commit()
                        .await
                        .map_err(|e| to_store_err("approve_execute_pending commit vote", e))?;
                    return Ok(FederatedApproveOutcome::VotePending { votes, quorum });
                }
                (canonical_id, approvals)
            }
        };

        // Run the effect against the row AS-IF approved while the row lock is
        // held; the decision is not yet durable.
        let effect_already_applied = payload_has_effect_marker(&pa.payload);
        let mut as_approved = pa;
        as_approved.status = STATUS_APPROVED.to_string();
        as_approved.decided_by = Some(decider.clone());
        as_approved.decided_at = Some(chrono::Utc::now().to_rfc3339());
        as_approved.approvals = approvals;
        // #4345 — a pending row WITH the marker has its effect applied: only
        // the approval is left to commit, never a second effect.
        let memory_id = if effect_already_applied {
            None
        } else {
            // An effect error returns here; dropping `tx` rolls the lock back.
            let id = self.pg_execute_pending_effect(ctx, &as_approved).await?;
            // Stamp the marker IN the locked transaction and COMMIT it before
            // the approval: from this commit on the row is `pending` WITH an
            // applied effect, which reject / sweep refuse to overwrite.
            sqlx::query(SQL_STAMP_MARKER)
                .bind(chrono::Utc::now().to_rfc3339())
                .bind(pending_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| to_store_err("approve_execute_pending stamp marker", e))?;
            id
        };
        tx.commit()
            .await
            .map_err(|e| to_store_err("approve_execute_pending commit marker", e))?;

        // Phase 2 — the approval compare-and-set, requiring the marker. A
        // single statement is atomic on its own; a concurrent approver that
        // won between the two phases leaves this one matching nothing.
        let committed = sqlx::query(SQL_COMMIT_APPROVAL)
            .bind(&decider)
            .bind(approvals_json(&as_approved.approvals)?)
            .bind(pending_id)
            .execute(&self.pool)
            .await
            .map_err(|e| to_store_err("approve_execute_pending commit approval", e))?
            .rows_affected();
        if committed == 0 {
            // Another approver completed the unit between the phases (the
            // marker is durable, so the effect is accounted for).
            return Ok(FederatedApproveOutcome::AlreadyApproved);
        }
        // S5-M1 parity: the approve audit row captures the post-execute state.
        // Best-effort, exactly like `execute_pending_action`.
        if let Err(e) = self
            .pg_emit_pending_action_event(
                &as_approved,
                crate::storage::PENDING_ACTION_APPROVED_EVENT,
                Some(&decider),
            )
            .await
        {
            tracing::warn!(
                target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                pending_id = %pending_id,
                "failed to append pending_action.approved audit row: {e}"
            );
        }
        Ok(FederatedApproveOutcome::Executed(memory_id))
    }
}

fn approvals_json(approvals: &[Approval]) -> StoreResult<serde_json::Value> {
    serde_json::to_value(approvals).map_err(|e| StoreError::IntegrityFailed {
        detail: format!("serialize approvals: {e}"),
    })
}

impl PostgresStore {
    /// #4345 — stamp the execution marker on `pending_id` after a LOCAL
    /// approve-then-execute landed its effect. Best-effort: the effect already
    /// committed, so a failure is logged, never returned.
    pub(super) async fn pg_mark_effect_applied(&self, pending_id: &str) {
        if let Err(e) = sqlx::query(SQL_STAMP_MARKER)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(pending_id)
            .execute(&self.pool)
            .await
        {
            tracing::warn!("execution marker not stamped for {pending_id}: {e}");
        }
    }
}
