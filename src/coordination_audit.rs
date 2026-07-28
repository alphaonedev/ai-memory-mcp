// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1722) — coordination-substrate `signed_events`
//! observability.
//!
//! The Pillar-1 coordination primitives (signals, actions, leases,
//! checkpoints, routines) are state-mutating operations that, before #1722,
//! left no tamper-evident trace on the substrate's append-only audit chain.
//! This module is the single shared writer that closes that gap: every
//! coordination state-mutation handler calls [`emit`] AFTER the operation
//! commits, appending one `coordination.<op>` row to the same
//! `signed_events` V-4 cross-row hash chain the governance gate and
//! [`crate::signed_events::verify_audit_trail`] already walk.
//!
//! **Best-effort by design.** The audit row is emitted *after* the
//! coordination op has already committed, so the op's success does not
//! depend on the audit append. An append failure (e.g. a rare
//! chain-sequence race) is logged loudly via `tracing::warn!` under the
//! `ai_memory::coordination` target and never propagated — failing the
//! caller's already-committed op would be worse than a missing audit row.
//! The cross-row hash chain itself stays tamper-evident in either posture.
//!
//! **Payload hash, not payload.** [`emit`] commits a SHA-256 over the
//! operation's *identity* fields (joined by the 0x1F unit separator), not
//! the full operation body, so the chain row is bounded regardless of
//! payload size while still letting an auditor correlate the row to the
//! stored coordination object.

use sha2::{Digest, Sha256};

/// `signed_events.event_type` field separator. ASCII 0x1F ("Unit
/// Separator"), present in neither UUID ids nor the short identity fields
/// we hash, so the concatenation is unambiguous without escaping —
/// matching [`crate::signed_events`]'s own canonical-bytes separator.
const FIELD_SEP: u8 = 0x1F;

/// `tracing` target for best-effort coordination-audit append failures.
const TRACE_TARGET: &str = "ai_memory::coordination";

// --- SSOT: coordination `signed_events.event_type` slugs (#1722) ---
//
// Every coordination state-mutation emits one of these slugs. All are
// `"coordination.<op>"`. Keeping them in one block here (rather than
// scattered string literals at each emit site) makes the audit-coverage
// matrix auditable in a single place and lets tests assert on the exact
// slug a handler must write.

/// Outbound signal send (`memory_signal_send`).
pub const SIGNAL_SEND: &str = "coordination.signal_send";
/// Signal acknowledgement (`memory_signal_ack`).
pub const SIGNAL_ACK: &str = "coordination.signal_ack";
/// Coordination-action creation (`memory_action_create`).
pub const ACTION_CREATE: &str = "coordination.action_create";
/// Coordination-action state transition (`memory_action_transition`).
pub const ACTION_TRANSITION: &str = "coordination.action_transition";
/// Coordination-action DAG edge insert (`memory_action_add_edge`).
pub const ACTION_ADD_EDGE: &str = "coordination.action_add_edge";
/// Lease acquisition (`memory_lease_acquire`).
pub const LEASE_ACQUIRE: &str = "coordination.lease_acquire";
/// Lease heartbeat renewal (`memory_lease_renew`).
pub const LEASE_RENEW: &str = "coordination.lease_renew";
/// Lease release (`memory_lease_release`).
pub const LEASE_RELEASE: &str = "coordination.lease_release";
/// Forced lease reclamation by the background expiry sweeper
/// (`background::lease_sweep` / the postgres maintenance loop). The
/// asymmetric twin of the VOLUNTARY [`LEASE_RELEASE`]: the sweeper reclaims
/// coordination authority a holder did NOT voluntarily surrender, so — as the
/// only FORCED revocation of a lease — it MUST leave the same tamper-evident
/// forensic trace the voluntary ops do (#2371).
pub const LEASE_SWEEP_RECLAIM: &str = "coordination.lease_expire_reclaim";
/// Forced `claimed -> pending` requeue of an action whose lease the background
/// expiry sweeper reclaimed (#2419). Distinct from [`ACTION_TRANSITION`] (a
/// CALLER-requested state change) for the same reason [`LEASE_SWEEP_RECLAIM`]
/// is distinct from [`LEASE_RELEASE`]: this reversion is FORCED by the
/// substrate, so an auditor must be able to tell it apart from one an operator
/// asked for. Emitted only when the requeue actually applied (the
/// `state = 'claimed'` CAS guard held).
pub const ACTION_LEASE_EXPIRE_REQUEUE: &str = "coordination.action_lease_expire_requeue";
/// Attested-checkpoint creation (`memory_checkpoint_create`).
pub const CHECKPOINT_CREATE: &str = "coordination.checkpoint_create";
/// Attested-checkpoint resolution (`memory_checkpoint_resolve`).
pub const CHECKPOINT_RESOLVE: &str = "coordination.checkpoint_resolve";
/// Routine creation (`memory_routine_create`).
pub const ROUTINE_CREATE: &str = "coordination.routine_create";
/// Routine freeze (`memory_routine_freeze`).
pub const ROUTINE_FREEZE: &str = "coordination.routine_freeze";
/// Routine run / materialisation (`memory_routine_run`).
pub const ROUTINE_RUN: &str = "coordination.routine_run";

/// Build the coordination-audit `payload_hash`: SHA-256 over `identity_parts`
/// joined by the 0x1F unit separator (the module's canonical bounded-identity
/// digest). Shared by [`emit`] (the sqlite append) and the postgres
/// coordination-audit append so a given `identity_parts` hashes byte-identically
/// on both backends (#2371 lease-sweep parity).
#[must_use]
pub fn coordination_payload_hash(identity_parts: &[&str]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for (i, part) in identity_parts.iter().enumerate() {
        if i > 0 {
            hasher.update([FIELD_SEP]);
        }
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_vec()
}

/// Emit one `signed_events` audit row for a coordination state-mutation.
///
/// Builds a SHA-256 `payload_hash` over `identity_parts` joined by the
/// 0x1F unit separator, wraps it in a daemon-signed (or `unsigned` when no
/// audit signing key is installed) [`crate::signed_events::SignedEvent`]
/// attributed to `actor`, and appends it to the append-only chain via
/// [`crate::signed_events::append_signed_event`].
///
/// **Best-effort (#1722).** Call this AFTER the coordination op has
/// committed. On append error the failure is logged via `tracing::warn!`
/// under the `ai_memory::coordination` target and swallowed — the op
/// already succeeded, so an audit-append failure must not surface to the
/// caller. See the module docs for the rationale.
pub fn emit(conn: &rusqlite::Connection, event_type: &str, actor: &str, identity_parts: &[&str]) {
    let event = crate::signed_events::SignedEvent::with_daemon_signature(
        coordination_payload_hash(identity_parts),
        actor.to_string(),
        event_type.to_string(),
        chrono::Utc::now().to_rfc3339(),
        // v73 (#1822, G5a): no triggering cause bound on this path yet.
        None,
    );
    if let Err(e) = crate::signed_events::append_signed_event(conn, &event) {
        tracing::warn!(
            target: TRACE_TARGET,
            event_type,
            actor,
            error = %e,
            "coordination audit append failed (op already committed)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn emit_appends_exactly_one_row_attributed_to_actor() {
        let conn = fresh();
        emit(
            &conn,
            ACTION_CREATE,
            "ai:alice",
            &["action-1", "ai:alice", "create"],
        );

        // Exactly one row of the given event_type, attributed to `actor`.
        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![ACTION_CREATE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "expected exactly one {ACTION_CREATE} audit row");
        assert_eq!(agent, "ai:alice", "row attributed to the actor");
    }

    #[test]
    fn emit_keeps_the_append_only_chain_intact() {
        let conn = fresh();
        // Two distinct coordination ops on the same chain.
        emit(&conn, LEASE_ACQUIRE, "holder-a", &["lease-1", "holder-a"]);
        emit(
            &conn,
            CHECKPOINT_RESOLVE,
            "resolver-b",
            &["cp-1", "resolver-b", "resolved"],
        );

        let report = crate::signed_events::verify_audit_trail(&conn, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
        assert!(report.total_events >= 2);
    }

    #[test]
    fn emit_hashes_distinct_identities_to_distinct_payload_hashes() {
        let conn = fresh();
        emit(&conn, SIGNAL_SEND, "ai:a", &["sig-1", "ai:a"]);
        emit(&conn, SIGNAL_SEND, "ai:a", &["sig-2", "ai:a"]);

        let distinct: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT payload_hash) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![SIGNAL_SEND],
                |r| r.get(0),
            )
            .expect("query distinct payload hashes");
        assert_eq!(
            distinct, 2,
            "distinct identity_parts → distinct payload_hash"
        );
    }
}
