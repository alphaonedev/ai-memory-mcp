// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3152 — the postgres lifecycle transition, applied INSIDE the
//! caller's update transaction.
//!
//! # The defect this closes
//!
//! Both postgres update funnels — the trait `update` and the If-Match
//! `update_with_expected_version_once` — committed the content patch and
//! only then applied the optional lifecycle transition through the POOL,
//! as a second, separately committed statement. A crash, an illegal edge or
//! any error between the two persisted the patch, dropped the transition
//! and returned `Err`: one logical update, two commits, a mixed row.
//!
//! The transition now runs on the update's own transaction, before its
//! single COMMIT. `SELECT … FOR UPDATE` holds the row lock across the read
//! and the write (the funnel's content `UPDATE` already holds it; the lock
//! clause keeps the helper safe for any caller that has not written the row
//! yet), so two racing transitions can never validate from the same prior
//! state.

use crate::models::LifecycleState;

use super::{StoreError, StoreResult, to_store_err};

/// #1726 / #3152 — apply an optional lifecycle transition on `tx`,
/// ENFORCING the transition machine
/// ([`LifecycleState::can_transition_to`]). Postgres twin of the sqlite
/// primitive [`crate::storage::set_lifecycle_state`]: an illegal edge
/// is a typed [`StoreError::InvalidTransition`] (→ HTTP 409, byte-parity
/// detail with the sqlite `Display`) and the caller's transaction rolls
/// back with the patch; a legal edge is written and bumps the Gap-1
/// `version`. A request equal to the stored state is an idempotent
/// no-op; `None` leaves the column untouched.
///
/// Returns `true` when a transition was written (the row's `version`
/// moved one further), `false` otherwise.
///
/// # Errors
///
/// * [`StoreError::InvalidTransition`] — the `current → target` edge is
///   not permitted.
/// * [`StoreError::NotFound`] — no live memory matches `id`.
/// * [`StoreError::BackendUnavailable`] — on SQL failure.
///
/// No record-stop gate here: both callers gate at entry, and the gate's
/// stale-cache refresh reads through the POOL. Holding this transaction's
/// connection while acquiring a second one from the same pool is a
/// hold-and-wait the helper has no reason to add.
pub(super) async fn apply_lifecycle_patch_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    target: Option<LifecycleState>,
) -> StoreResult<bool> {
    let Some(target) = target else {
        return Ok(false);
    };
    let current: Option<(String,)> =
        sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("read lifecycle_state for transition gate", e))?;
    let Some((current_str,)) = current else {
        return Err(StoreError::NotFound { id: id.to_string() });
    };
    let from = LifecycleState::from_str(&current_str).unwrap_or_default();
    // No-op (requested == current) is idempotent success, not a
    // self-loop error — mirrors the sqlite primitive + the memory_update
    // contract.
    if from == target {
        return Ok(false);
    }
    if !from.can_transition_to(target) {
        return Err(StoreError::InvalidTransition {
            detail: format!(
                "CONFLICT: illegal lifecycle transition for memory {id}: {from} -> {target} is not permitted"
            ),
        });
    }
    sqlx::query(
        "UPDATE memories SET lifecycle_state = $1, updated_at = NOW(), version = version + 1 \
         WHERE id = $2",
    )
    .bind(target.as_str())
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(|e| to_store_err("update lifecycle_state", e))?;
    Ok(true)
}
