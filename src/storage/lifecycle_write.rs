// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The caller-facing lifecycle transition writer ([`set_lifecycle_state`]),
//! kept out of `storage/mod.rs` for its `qual_10` budget (f1 goal4 FC, #3266).

use chrono::Utc;
use rusqlite::{Connection, params};

use super::{InvalidTransition, Result};

/// The read-under-the-write-lock of [`set_lifecycle_state`] (also used to name
/// the state a lost CAS moved to).
const SQL_SELECT_LIFECYCLE_STATE_BY_ID: &str = "SELECT lifecycle_state FROM memories WHERE id = ?1";

/// v0.8.0 Pillar 2 (#1709 / #1726) — persist a lifecycle-state transition
/// on a single memory, ENFORCING the transition machine
/// ([`crate::models::LifecycleState::can_transition_to`]). The current
/// state is read and an illegal edge (`open → done`, a move out of a
/// terminal state, a self-loop) is rejected with a typed
/// [`InvalidTransition`] BEFORE any write — #1726 wired this gate, which
/// the v64 column previously left inert. Bumps the Gap-1 `version` counter
/// because a lifecycle advance IS a mutation observable to
/// optimistic-concurrency callers.
///
/// f1 goal4 FC (#3266, GOD ruling): the read, the validation and the write run
/// in ONE `BEGIN IMMEDIATE` transaction (the sqlite write lock is held from the
/// read), and the UPDATE carries the validated `from` as a compare-and-set
/// (`AND lifecycle_state = from`). A route-IN quarantine or a contamination
/// stamp can therefore never be silently overwritten by a caller transition
/// validated against the state before it. A CAS miss (unreachable under the
/// write lock, kept as the structural guard) is a typed [`InvalidTransition`]
/// naming the state the row moved to — NEVER the `Ok(false)` of an absent row.
///
/// Returns `true` when a row was updated, `false` when `id` did not match
/// a row (no transition to validate).
///
/// # Errors
///
/// * [`InvalidTransition`] — the `current → state` edge is not permitted.
/// * Propagates rusqlite errors from the SELECT / UPDATE.
pub fn set_lifecycle_state(
    conn: &Connection,
    id: &str,
    state: crate::models::LifecycleState,
) -> Result<bool> {
    use crate::models::LifecycleState;
    use rusqlite::OptionalExtension;
    super::record_stop::gate_storage_conn(conn)?;
    let txn = super::connection::WriteTxn::begin(conn)?;
    let outcome = (|| -> Result<bool> {
        // #1726 — read the current state (under the write lock) and validate.
        let current: Option<String> = conn
            .query_row(SQL_SELECT_LIFECYCLE_STATE_BY_ID, params![id], |r| r.get(0))
            .optional()?;
        let Some(current_str) = current else {
            return Ok(false);
        };
        let from = LifecycleState::from_str(&current_str).unwrap_or_default();
        // A no-op (requested == current) is idempotent success, not a
        // self-loop error — mirrors the `memory_update` handler contract.
        if from == state {
            return Ok(true);
        }
        if !from.can_transition_to(state) {
            return Err(InvalidTransition {
                id: id.to_string(),
                from,
                to: state,
            }
            .into());
        }
        let n = conn.execute(
            "UPDATE memories SET lifecycle_state = ?1, updated_at = ?2, version = version + 1 \
             WHERE id = ?3 AND lifecycle_state = ?4",
            params![state.as_str(), Utc::now().to_rfc3339(), id, current_str],
        )?;
        if n == 0 {
            let moved_to: Option<String> = conn
                .query_row(SQL_SELECT_LIFECYCLE_STATE_BY_ID, params![id], |r| r.get(0))
                .optional()?;
            return Err(InvalidTransition {
                id: id.to_string(),
                from: moved_to
                    .as_deref()
                    .and_then(LifecycleState::from_str)
                    .unwrap_or(from),
                to: state,
            }
            .into());
        }
        Ok(true)
    })();
    match outcome {
        Ok(v) => {
            txn.commit()?;
            Ok(v)
        }
        Err(e) => {
            txn.rollback();
            Err(e)
        }
    }
}
