// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9147 / #9149 / #9150 — the receiver lifecycle MERGE BARRIER on the sqlite
//! federation write funnels (its own child module for the qual_10 split).
//!
//! Invariant: once THIS node holds an id at a terminal or hidden receiver
//! state, no inbound federation write may make that id's content live or open
//! again. The states are:
//!
//! * **tombstoned** — a `forget_tombstones` row exists (forget, delete, or a
//!   federated deletion);
//! * **archived** — the id sits in `archived_memories` with no live row
//!   (an owner / `archives[]` archive; a newer-dated replay of the pre-archive
//!   row must not re-insert it beside its archived copy, #9149);
//! * **held** — the live row occupying the inbound id OR the inbound
//!   `(title, namespace)` slot carries a node-local containment lifecycle
//!   ([`crate::models::crdt_merge::NODE_LOCAL_LIFECYCLE_STATES`]:
//!   quarantined / contaminated), so a peer's LWW win must not swap the
//!   content behind the hold (#9150).
//!
//! The barrier is read INSIDE the funnel's write transaction (the same
//! `BEGIN IMMEDIATE` the merge commits under), so no concurrent writer can
//! change the verdict between the probe and the write. A barrier hit is an
//! idempotent no-op that returns the inbound id (a refused inbound row would
//! make the pushing peer retry forever; the receiver keeps its state).
//!
//! The deletion half (#9147): a federated deletion erases EVERY local copy of
//! the id — the live row (via [`delete`]) AND any `archived_memories` copy —
//! and leaves a signed forget tombstone, so no restore path (the archive
//! restore verb on HTTP / MCP / CLI, or a later `restores[]` push) can bring
//! the deleted content back.

use super::*;
use crate::models::LifecycleState;

/// Tracing target for every merge-barrier drop (one greppable stream).
pub const MERGE_BARRIER_TRACE_TARGET: &str = "federation.merge_barrier";

/// Why the receiver refused to merge an inbound row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverMergeBarrier {
    /// A forget / delete tombstone exists for the inbound id.
    Tombstoned,
    /// The inbound id is archived on this node and has no live row.
    Archived,
    /// The live row the inbound would overwrite is under a node-local hold.
    Held(LifecycleState),
}

impl ReceiverMergeBarrier {
    /// The audit word logged for this barrier.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tombstoned => LifecycleState::Tombstoned.as_str(),
            Self::Archived => "archived",
            Self::Held(state) => state.as_str(),
        }
    }
}

/// Is `memory_id` archived with no live row of the same id?
fn archived_without_live(conn: &Connection, memory_id: &str) -> Result<bool> {
    let hit: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = ?1) \
             AND NOT EXISTS(SELECT 1 FROM memories WHERE id = ?1)",
        params![memory_id],
        |r| r.get(0),
    )?;
    Ok(hit)
}

/// The node-local hold state of the live row by `memory_id`, or of the live
/// row holding the `(title, namespace)` slot an upsert would land on.
fn held_state(
    conn: &Connection,
    memory_id: &str,
    title: Option<(&str, &str)>,
) -> Result<Option<LifecycleState>> {
    let mut states: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare_cached("SELECT lifecycle_state FROM memories WHERE id = ?1")?;
        let rows = stmt.query_map(params![memory_id], |r| r.get::<_, String>(0))?;
        for row in rows {
            states.push(row?);
        }
    }
    if let Some((slot_title, slot_namespace)) = title {
        let sql = format!(
            "SELECT lifecycle_state FROM memories \
             WHERE title = ?1 AND namespace = ?2 AND {}",
            crate::models::TITLE_SLOT_INDEX_PREDICATE
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![slot_title, slot_namespace], |r| {
            r.get::<_, String>(0)
        })?;
        for row in rows {
            states.push(row?);
        }
    }
    Ok(states
        .iter()
        .filter_map(|s| LifecycleState::from_str(s))
        .find(|s| crate::models::crdt_merge::is_node_local_lifecycle(*s)))
}

/// Probe the receiver merge barrier for an inbound row. `title_slot` is the
/// `(title, namespace)` the funnel would upsert onto (`None` for a same-id
/// overwrite that cannot move to another slot).
///
/// Call it inside the funnel's write transaction.
///
/// # Errors
///
/// Propagates the probe's rusqlite error (the funnel then rolls back: a probe
/// that cannot decide never lets the write through).
pub fn receiver_merge_barrier(
    conn: &Connection,
    memory_id: &str,
    title_slot: Option<(&str, &str)>,
) -> Result<Option<ReceiverMergeBarrier>> {
    if memory_is_tombstoned(conn, memory_id)? {
        return Ok(Some(ReceiverMergeBarrier::Tombstoned));
    }
    if archived_without_live(conn, memory_id)? {
        return Ok(Some(ReceiverMergeBarrier::Archived));
    }
    Ok(held_state(conn, memory_id, title_slot)?.map(ReceiverMergeBarrier::Held))
}

/// Log one barrier drop (identity only, never content).
pub fn trace_merge_barrier_drop(memory_id: &str, barrier: ReceiverMergeBarrier) {
    tracing::debug!(
        target: MERGE_BARRIER_TRACE_TARGET,
        memory_id = %memory_id,
        barrier = barrier.as_str(),
        "dropped inbound federation write: the receiver holds this id at a terminal or \
         hidden lifecycle state (#9147 merge barrier)"
    );
}

/// #1948 route-OUT exemption: only a `quarantined` hold yields, and only to
/// a push THIS receiver verified. The caller must still drop the write unless
/// the merged row is the exact verified signed unit
/// ([`crate::models::is_verified_signed_unit`]). Contaminated, tombstoned and
/// archived barriers never yield.
#[must_use]
pub fn barrier_yields_to_verified_release(
    barrier: ReceiverMergeBarrier,
    receiver_verified: bool,
) -> bool {
    receiver_verified && barrier == ReceiverMergeBarrier::Held(LifecycleState::Quarantined)
}

/// #9150 — the row a merge funnel writes once a quarantine barrier has
/// yielded ([`barrier_yields_to_verified_release`]). The LWW blend of
/// `existing` and `prepared` keeps the local `created_at` and so is never the
/// signed unit; when the inbound data won the merge the candidate is instead
/// the prepared inbound unit itself, keeping the local id and hold state (the
/// #1948 route-OUT `dequarantine` lifts the hold afterwards). When the local
/// data won, `merged` is returned and the caller's signed-unit check drops it.
#[must_use]
pub fn verified_release_candidate(existing: &Memory, prepared: &Memory, merged: Memory) -> Memory {
    if merged.content != prepared.content || merged.title != prepared.title {
        return merged;
    }
    let mut unit = prepared.clone();
    unit.id.clone_from(&existing.id);
    unit.lifecycle_state = existing.lifecycle_state;
    unit
}

/// The transaction-free core of a federated deletion: hard-delete the live
/// row (tombstoned by [`delete`]) and purge every archived copy, tombstoning
/// an archived-only id. Must run inside a write transaction.
///
/// The record-stop gate runs here, in the write-SQL target itself (B7
/// `b7_gate_must_be_called_by_the_target_itself_r4_g2`), so no future caller
/// can reach the deletion without the fence. It only reads the record-stop
/// state, so it is valid inside the open write transaction.
fn federated_delete_in_tx(conn: &Connection, id: &str) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let live_deleted = delete(conn, id)?;
    let Some(archived_ns) = archived_namespace_by_id(conn, id)? else {
        return Ok(live_deleted);
    };
    if !live_deleted {
        // No live row reached `delete`'s tombstone: tombstone (signed) and
        // record the erasure here so the id cannot be re-admitted by LWW.
        let now = Utc::now().to_rfc3339();
        tombstone_and_erase(
            conn,
            id,
            &archived_ns,
            None,
            &now,
            CRYPTO_ERASE_ACTOR_DELETE,
        )?;
    }
    let purged = conn.execute("DELETE FROM archived_memories WHERE id = ?1", params![id])?;
    Ok(live_deleted || purged > 0)
}

/// [`delete`] for the federated `deletions[]` lane WITHOUT a peer-scope
/// re-check (the unscoped `apply_remote_deletion` SAL method): erases the
/// live row AND every archived copy, and tombstones the id (#9147).
///
/// # Errors
///
/// Everything [`delete`] returns, plus the archive purge's rusqlite error
/// (the whole deletion rolls back).
pub fn federated_delete(conn: &Connection, id: &str) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    super::federation_by_id_4447::in_write_txn(conn, || federated_delete_in_tx(conn, id))
}

/// The `deletions[]` peer-scope re-check of the ARCHIVED copy, under the held
/// write lock (the live copy is re-checked by the caller).
///
/// # Errors
///
/// An [`InboundByIdNamespaceRefused`] when the archived copy is outside the
/// peer's scope.
pub(super) fn federated_delete_authorized_in_tx(
    conn: &Connection,
    id: &str,
    authorize: ByIdNamespaceAuthorizer<'_>,
) -> Result<bool> {
    if let Some(stored) = archived_namespace_by_id(conn, id)?
        && !authorize(id, &stored)
    {
        return Err(anyhow::Error::new(InboundByIdNamespaceRefused {
            lane: crate::federation::receive_auth::LANE_DELETIONS,
            id: id.to_string(),
            stored_namespace: stored,
        }));
    }
    federated_delete_in_tx(conn, id)
}

/// v1.0.0 R19/A3 (#1948, decision `560c8007`) — system-only RAW dequarantine.
///
/// Clears a [`crate::models::LifecycleState::Quarantined`] row back to
/// [`crate::models::LifecycleState::Open`] (per
/// [`crate::models::LifecycleState::dequarantine_target`]) via a raw UPDATE
/// that BYPASSES the [`super::set_lifecycle_state`] transition gate — `Quarantined`
/// is terminal + absent from `can_transition_to`, so the ordinary caller path
/// can neither reach nor leave it. The `WHERE lifecycle_state = 'quarantined'`
/// guard makes this idempotent and a strict no-op on any non-quarantined row.
///
/// This is the route-OUT primitive of dequarantine-on-attest (the federation
/// receive-attestation upgrade path; operator release is the separate
/// [`super::operator_dequarantine`]). Returns `true` when a quarantined row was
/// cleared.
///
/// #9150 — it lifts ONLY a row whose stored `metadata.attest_level` is
/// `agent_attested`: the receiver merge barrier lets an attested push through
/// a quarantine only as the exact verified signed unit (which re-asserts that
/// level), so a held row whose bytes this node never verified stays held.
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn dequarantine(conn: &Connection, id: &str) -> Result<bool> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let now = Utc::now().to_rfc3339();
    let sql = format!(
        "UPDATE memories SET lifecycle_state = ?1, updated_at = ?2, version = version + 1 \
         WHERE id = ?3 AND lifecycle_state = ?4 \
         AND json_extract(metadata, '$.{}') = ?5",
        crate::models::field_names::ATTEST_LEVEL
    );
    let n = conn.execute(
        &sql,
        params![
            crate::models::LifecycleState::Open.as_str(),
            now,
            id,
            crate::models::LifecycleState::Quarantined.as_str(),
            crate::identity::verify::AttestLevel::AgentAttested.as_str(),
        ],
    )?;
    Ok(n > 0)
}
