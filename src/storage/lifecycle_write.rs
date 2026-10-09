// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The caller-facing lifecycle transition writer ([`set_lifecycle_state`]),
//! kept out of `storage/mod.rs` for its `qual_10` budget (f1 goal4 FC, #3266).

use chrono::Utc;
use rusqlite::{Connection, params};

use super::{InvalidTransition, Result};
use crate::models::LifecycleState;

/// #4134 — decode a raw sqlite `lifecycle_state` column value FAIL-CLOSED
/// (the sqlite half of [`LifecycleState::decode_stored`]): `None` (column
/// absent on a pre-v64 read) and SQL NULL are the visible-legacy `Open`;
/// TEXT goes through the shared decoder; an INTEGER / REAL / BLOB value —
/// which no typed writer ever produces — is rendered to text and lands as
/// `Unknown`, so a damaged column hides its row rather than re-opening it.
pub(crate) fn decode_stored_value(
    memory_id: &str,
    raw: Option<rusqlite::types::Value>,
) -> LifecycleState {
    use rusqlite::types::Value;
    let rendered = match raw {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) => Some(s),
        Some(Value::Integer(i)) => Some(i.to_string()),
        Some(Value::Real(f)) => Some(f.to_string()),
        Some(Value::Blob(b)) => Some(format!("<blob {} bytes>", b.len())),
    };
    LifecycleState::decode_stored(memory_id, rendered.as_deref())
}

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
/// #3152 — the transaction is [`super::in_write_txn`]: standalone it opens and
/// commits its own `BEGIN IMMEDIATE`; inside a caller's transaction (the
/// `memory_update` / SAL update funnels) it JOINS it instead of nesting, so the
/// transition commits or rolls back WITH the content patch. There is no
/// intermediate COMMIT between the patch and the transition.
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
    use rusqlite::OptionalExtension;
    super::record_stop::gate_storage_conn(conn)?;
    // #3957 / #3152 — transaction-aware: the SAL `update` funnel runs its
    // ownership gate, the content write and this transition in ONE
    // caller-owned `BEGIN IMMEDIATE`, so `in_write_txn` JOINS the caller's
    // transaction when one is open instead of failing on a nested BEGIN, and
    // opens (and commits or rolls back) its own otherwise.
    super::in_write_txn(conn, || -> Result<bool> {
        // #1726 — read the current state (under the write lock) and validate.
        // #4134 — read the RAW column value: an unrecognised (or non-text)
        // current state decodes fail-closed as `Unknown`, which has no legal
        // outbound edge, so the row is left exactly as found.
        let current: Option<rusqlite::types::Value> = conn
            .query_row(SQL_SELECT_LIFECYCLE_STATE_BY_ID, params![id], |r| r.get(0))
            .optional()?;
        let Some(current_raw) = current else {
            return Ok(false);
        };
        let from = decode_stored_value(id, Some(current_raw.clone()));
        // A no-op (requested == current) is idempotent success, not a
        // self-loop error — mirrors the `memory_update` handler contract.
        if from == state {
            return Ok(true);
        }
        if !from.can_transition_to(&state) {
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
            params![state.as_str(), Utc::now().to_rfc3339(), id, current_raw],
        )?;
        if n == 0 {
            let moved_to: Option<rusqlite::types::Value> = conn
                .query_row(SQL_SELECT_LIFECYCLE_STATE_BY_ID, params![id], |r| r.get(0))
                .optional()?;
            return Err(InvalidTransition {
                id: id.to_string(),
                from: moved_to.map_or(from, |v| decode_stored_value(id, Some(v))),
                to: state,
            }
            .into());
        }
        Ok(true)
    })
}
