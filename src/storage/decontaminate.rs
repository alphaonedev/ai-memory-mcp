// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Boids item 3 R2.5 (#3266, ruling tmux-22 item 3) — DECONTAMINATE: the
//! deliberate, signed route OUT of [`LifecycleState::Contaminated`].
//!
//! The operator release primitive (`operator_dequarantine`, #2402) is extended
//! on BOTH backends to release a contaminated row as well as a quarantined
//! one — same admin gate, same route, same CLI; no new surface. The event kind
//! is chosen by the state OBSERVED under the compare-and-set, never by the
//! caller: a quarantined row keeps the `memory.dequarantined` path unchanged,
//! a contaminated row takes the path here and appends one signed
//! `swarm.decontaminate` event in the same transaction.
//!
//! * **Target state (ruling 3a):** the marker's recorded
//!   `prior_lifecycle_state` when it parses to a recall-VISIBLE state; any
//!   other value (absent, malformed, or itself a hidden state) restores `open`.
//! * **Marker (ruling 3b):** `metadata.contamination` is removed on release —
//!   a released row that kept it would read as a live taint to any tool that
//!   checks the key. The signed event's payload binds the released marker's
//!   `prior_lifecycle_state`, `contaminated_from` and `stamped_at`, so the
//!   audit chain keeps exactly what the row loses.
//!
//! The pure planning half ([`plan_release`], [`decontaminate_audit_payload`])
//! is shared by the sqlite funnel below and the postgres twin
//! (`store/postgres/swarm_rewind.rs`), so the two backends restore the same
//! state and hash the same payload by construction. Its own module keeps
//! `storage/mod.rs` inside its `qual_10` budget (ruling R6 precedent).

use super::Result;
use super::contamination_marker::{
    CONTAMINATED_FROM_KEY, PRIOR_LIFECYCLE_STATE_KEY, STAMPED_AT_KEY,
};
use crate::models::LifecycleState;

/// What a release of one contaminated row restores, and what the signed
/// event must remember about the marker it removes. The marker itself is
/// removed IN SQL by an atomic key delete (sqlite `json_remove`, postgres
/// `jsonb -`), never by writing back a copy of the metadata read earlier
/// (f1-review F2 discipline: no lost update of a concurrently committed key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleasePlan {
    /// The lifecycle state the row is restored to (ruling 3a).
    pub(crate) target: LifecycleState,
    /// The released marker's `prior_lifecycle_state`, verbatim (may be absent).
    pub(crate) prior: Option<String>,
    /// The released marker's `contaminated_from` root, verbatim.
    pub(crate) contaminated_from: Option<String>,
    /// The released marker's `stamped_at`, verbatim.
    pub(crate) stamped_at: Option<String>,
}

/// The release instant, truncated to microseconds so the RFC 3339 string
/// hashed into the event payload round-trips byte-identically through the
/// postgres `timestamptz` column (and reads the same on sqlite) — an auditor
/// can recompute the payload from the stored row.
pub(crate) fn release_now() -> chrono::DateTime<chrono::Utc> {
    chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 6)
}

/// Lenient parse of the sqlite `metadata` TEXT column (malformed → `None`).
pub(crate) fn parse_metadata(metadata: Option<&str>) -> Option<serde_json::Value> {
    metadata.and_then(|s| serde_json::from_str(s).ok())
}

fn marker_str(marker: Option<&serde_json::Value>, key: &str) -> Option<String> {
    marker
        .and_then(|m| m.get(key))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Plan the release of a contaminated row from its stored `metadata` (a
/// malformed / non-object blob is treated as `{}`, so the release degrades to
/// `open` and never fails on a damaged marker). Postgres passes the `jsonb`
/// value; sqlite passes its TEXT through [`parse_metadata`].
pub(crate) fn plan_release(metadata: Option<&serde_json::Value>) -> ReleasePlan {
    let marker = metadata
        .filter(|m| m.is_object())
        .and_then(|m| m.get(super::CONTAMINATION_METADATA_KEY))
        .cloned();
    let prior = marker_str(marker.as_ref(), PRIOR_LIFECYCLE_STATE_KEY);
    let target = prior
        .as_deref()
        .and_then(LifecycleState::from_str)
        .filter(|s| s.is_recall_visible())
        .unwrap_or(LifecycleState::Open);
    ReleasePlan {
        target,
        prior,
        contaminated_from: marker_str(marker.as_ref(), CONTAMINATED_FROM_KEY),
        stamped_at: marker_str(marker.as_ref(), STAMPED_AT_KEY),
    }
}

/// The canonical pre-image hashed into the `swarm.decontaminate` event's
/// `payload_hash` — identical on both backends. FAIL CLOSED: a serialization
/// error propagates rather than committing a wrong-hash audit row (the #3327
/// Sec-F6 rule).
pub(crate) fn decontaminate_audit_payload(
    id: &str,
    plan: &ReleasePlan,
    released_by: &str,
    timestamp: &str,
) -> Result<Vec<u8>> {
    let canonical = serde_json::json!({
        "action": crate::signed_events::event_types::SWARM_DECONTAMINATE,
        "memory_id": id,
        "restored_to": plan.target.as_str(),
        (PRIOR_LIFECYCLE_STATE_KEY): plan.prior,
        (CONTAMINATED_FROM_KEY): plan.contaminated_from,
        (STAMPED_AT_KEY): plan.stamped_at,
        "released_by": released_by,
        "timestamp": timestamp,
    });
    Ok(serde_json::to_vec(&canonical)?)
}

/// What the sqlite release primitive observed under its `BEGIN IMMEDIATE`
/// write lock (the event kind is decided from THIS, never from the caller).
pub(crate) enum Observed {
    /// The row is quarantined: the caller runs the unchanged #2402 release.
    Quarantined,
    /// The row was contaminated and is now released to this state (written +
    /// `swarm.decontaminate` appended; the caller commits, THEN warns).
    Decontaminated(LifecycleState),
    /// Absent, or neither contaminated nor quarantined: nothing was written.
    NotContained,
}

/// The sqlite half of R2.5, inside `operator_dequarantine`'s `BEGIN IMMEDIATE`
/// transaction (which holds the database write lock, so the read below and
/// the write are one atomic step). Reads the row's state; on `contaminated`,
/// restores the planned state, deletes the marker with an atomic
/// `json_remove` (every other key, including one committed an instant before
/// the lock, is carried by the row itself, never by a stale copy), re-asserts
/// the observed state (CAS) and appends ONE signed `swarm.decontaminate` event.
pub(crate) fn observe_and_release_sqlite(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    agent_id: &str,
) -> Result<Observed> {
    use rusqlite::OptionalExtension;
    super::record_stop::gate_storage_conn(tx)?;
    let row: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT lifecycle_state, metadata FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((state, meta)) = row else {
        return Ok(Observed::NotContained);
    };
    match LifecycleState::from_str(&state) {
        Some(LifecycleState::Quarantined) => return Ok(Observed::Quarantined),
        Some(LifecycleState::Contaminated) => {}
        _ => return Ok(Observed::NotContained),
    }
    let plan = plan_release(parse_metadata(meta.as_deref()).as_ref());
    let now = release_now().to_rfc3339();
    let changed = tx.execute(
        "UPDATE memories SET lifecycle_state = ?1, \
         metadata = CASE WHEN json_valid(metadata) THEN CASE WHEN json_type(metadata) = 'object' \
         THEN json_remove(metadata, '$.' || ?2) ELSE '{}' END ELSE '{}' END, \
         updated_at = ?3, version = version + 1 WHERE id = ?4 AND lifecycle_state = ?5",
        rusqlite::params![
            plan.target.as_str(),
            super::CONTAMINATION_METADATA_KEY,
            now,
            id,
            LifecycleState::Contaminated.as_str(),
        ],
    )?;
    if changed == 0 {
        return Ok(Observed::NotContained);
    }
    let kind = crate::signed_events::event_types::SWARM_DECONTAMINATE;
    let payload = decontaminate_audit_payload(id, &plan, agent_id, &now)?;
    let cause = crate::signed_events::compute_cause_hash(agent_id, kind, id, id);
    let event = crate::signed_events::SignedEvent::with_daemon_signature(
        crate::signed_events::payload_hash(&payload),
        agent_id.to_string(),
        kind.to_string(),
        now,
        Some(&cause),
    );
    crate::signed_events::append_signed_event_no_tx(tx, &event)?;
    Ok(Observed::Decontaminated(plan.target))
}

/// `tracing` target of the operator route-OUT WARNs (#2402 release and the
/// R2.5 decontaminate) on both backends — one name, so a log filter set for
/// one catches both.
pub(crate) const QUARANTINE_TRACE_TARGET: &str = "ai_memory::quarantine";

/// The fleet-watchable signal of a decontaminate, shared by both backends
/// (identifying fields only, never content).
pub(crate) fn warn_released(id: &str, agent_id: &str, target: LifecycleState) {
    tracing::warn!(
        target: QUARANTINE_TRACE_TARGET,
        memory_id = %id,
        operator = %agent_id,
        restored_to = %target.as_str(),
        "decontaminate.operator_release: an operator RELEASED a contaminated memory \
         (metadata.contamination removed; a swarm.decontaminate signed-chain row was \
         appended in the same transaction) (#3266 item 3 R2.5)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_a_visible_prior_else_open_and_reads_the_marker() {
        let key = super::super::CONTAMINATION_METADATA_KEY;
        let meta = serde_json::json!({
            "k": 1,
            key: {
                "prior_lifecycle_state": "done",
                "contaminated_from": "root-1",
                "stamped_at": "2026-09-24T00:00:00+00:00",
            }
        })
        .to_string();
        let plan = plan_release(parse_metadata(Some(&meta)).as_ref());
        assert_eq!(plan.target, LifecycleState::Done);
        assert_eq!(plan.prior.as_deref(), Some("done"));
        assert_eq!(plan.contaminated_from.as_deref(), Some("root-1"));
        assert_eq!(
            plan.stamped_at.as_deref(),
            Some("2026-09-24T00:00:00+00:00")
        );
        // A hidden / unknown / absent prior never resurfaces: open.
        for prior in [
            serde_json::json!("tombstoned"),
            serde_json::json!("quarantined"),
            serde_json::json!("contaminated"),
            serde_json::json!("nonsense"),
            serde_json::json!(7),
        ] {
            let m = serde_json::json!({ key: { "prior_lifecycle_state": prior } }).to_string();
            assert_eq!(
                plan_release(parse_metadata(Some(&m)).as_ref()).target,
                LifecycleState::Open
            );
        }
        assert_eq!(plan_release(None).target, LifecycleState::Open);
        assert_eq!(
            plan_release(parse_metadata(Some("not json")).as_ref()).target,
            LifecycleState::Open
        );
    }

    #[test]
    fn audit_payload_binds_the_released_marker() {
        let meta = serde_json::json!({
            super::super::CONTAMINATION_METADATA_KEY: {
                "prior_lifecycle_state": "blocked",
                "contaminated_from": "root-9",
                "stamped_at": "t0",
            }
        })
        .to_string();
        let plan = plan_release(parse_metadata(Some(&meta)).as_ref());
        let bytes = decontaminate_audit_payload("m1", &plan, "op", "t1").expect("payload");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["action"], "swarm.decontaminate");
        assert_eq!(v["memory_id"], "m1");
        assert_eq!(v["restored_to"], "blocked");
        assert_eq!(v["prior_lifecycle_state"], "blocked");
        assert_eq!(v["contaminated_from"], "root-9");
        assert_eq!(v["stamped_at"], "t0");
        assert_eq!(v["released_by"], "op");
        assert_eq!(v["timestamp"], "t1");
    }
}
