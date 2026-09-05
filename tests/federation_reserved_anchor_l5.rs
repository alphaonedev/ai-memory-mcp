// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PR-1 / L5 (#2708-sibling, CWE-284) — refuse substrate-RESERVED checkpoint
//! anchor kinds/namespaces at the federation ingress chokepoint.
//!
//! # The remote attack this closes
//!
//! The substrate itself EMITS and immediately resolves a small set of LOCAL-ONLY
//! audit / identity anchor checkpoints — audit-head witness, governance
//! verdict/enforcement, peer-head entanglement, re-anchor ceremony — under
//! reserved `_`-prefixed namespaces. `verify_audit_trail` reads the LATEST
//! `_audit_witness` / `audit_head_witness` checkpoint as its out-of-band anchor.
//! (`EpochAdvance` is DELIBERATELY EXCLUDED — it is the freeze anchor designed to
//! federate on the same transport, gated by the per-resolution signature gate;
//! see `epoch_advance_freeze_anchor_still_federates`.)
//!
//! FED-RQ-01 (#1936, #125) federates RESOLVED checkpoints over `/sync/push`, and
//! [`apply_inbound_resolution`] keys its CAS on `(id, state)` only. So a
//! WIRE-REACHABLE peer — a REMOTE attacker with NO host access — could push a
//! resolved `audit_head_witness` anchor (first-landing, or by-id under a benign
//! wire kind) and STEER this node's witness verdict: audit-signal poisoning.
//!
//! The refusal is applied at the CAS FUNNEL ([`apply_inbound_resolution`]) so
//! every caller is closed, and the SAME pure predicate closes the LOCAL
//! creation path (`memory_checkpoint_create`, unit-tested in
//! `src/mcp/tools/checkpoint.rs`).
//!
//! # Env discipline (#2905)
//!
//! These tests set NO posture env vars — the refusal is UNCONDITIONAL (there is
//! deliberately NO `security_profile::KNOBS` entry / no opt-out for it), so
//! there is nothing to subprocess-isolate. `compute_witness_verdict` is driven
//! as a pure function with `enrolled_pubkey = None` (the default no-pin posture)
//! rather than through any `AI_MEMORY_WITNESS_*` env.
//!
//! # K3 (sqlite ↔ postgres) parity
//!
//! **Updated at #3075.** This file previously recorded that the postgres
//! `/sync/push` funnel reported checkpoints as `unsupported_on_postgres` and
//! never reached an apply, so there was "no postgres twin to poison". That is
//! no longer true: #3075 lane L-PGP trait-covers the lane, and a postgres
//! receiver now APPLIES federated resolutions. The reserved-anchor refusal
//! therefore has a REAL postgres twin, and the sqlite refusal proven here is no
//! longer the complete closure for the reachable surface on its own.
//!
//! The refusal itself is SHARED, which is why it did not have to be re-derived:
//! both adapters call the backend-blind
//! [`inbound_checkpoint_kind_authorized`] on the CLAIMED wire kind and the
//! STORED by-id kind. The postgres cell that exercises it end-to-end against a
//! live receiver is
//! `tests/fed_checkpoint_lane_3075_pg.rs::reserved_anchor_kind_refused_on_postgres_3075`;
//! see `pg_checkpoint_apply_parity_note_3075` below.

use ai_memory::checkpoints::{
    InboundResolutionOutcome, apply_inbound_resolution, get, insert, query,
};
use ai_memory::federation::receive_auth::{
    RESERVED_SUBSTRATE_CONDITION_TYPES, RESERVED_SUBSTRATE_NAMESPACES, condition_type_is_reserved,
    inbound_checkpoint_kind_authorized,
};
use ai_memory::governance::audit::{
    GOVERNANCE_ENFORCEMENT_NAMESPACE, GOVERNANCE_VERDICT_NAMESPACE, REANCHOR_CHECKPOINT_NAMESPACE,
    WITNESS_CHECKPOINT_NAMESPACE,
};
use ai_memory::identity::equivocation::PEER_HEAD_ENTANGLEMENT_NAMESPACE;
use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};
use ai_memory::signed_events::{WitnessCheck, compute_witness_verdict};
use rusqlite::Connection;

const RESOLVED_AT: i64 = 1_700_000_500;

fn fresh() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::storage::open(&dir.path().join("l5.db")).expect("open l5 db");
    (dir, conn)
}

/// A PENDING checkpoint of the given kind/namespace (the shape the substrate
/// inserts directly for its own anchors, and the shape a caller-created gate
/// takes).
fn pending(id: &str, kind: ConditionType, namespace: &str) -> Checkpoint {
    Checkpoint {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: "anchor".to_string(),
        condition_type: kind,
        condition: serde_json::json!({}),
        state: CheckpointState::Pending,
        created_by: "substrate".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    }
}

/// An inbound (already-RESOLVED) checkpoint as it arrives on the `/sync/push`
/// wire — the attacker chooses every field, including `condition_type`,
/// `namespace`, and `resolved_at`.
fn inbound(id: &str, kind: ConditionType, namespace: &str, resolved_at: i64) -> Checkpoint {
    Checkpoint {
        state: CheckpointState::Resolved,
        resolved_by: Some("peer-resolver".to_string()),
        resolution: Some("approved".to_string()),
        resolution_note: Some("from peer".to_string()),
        resolved_at: Some(resolved_at),
        ..pending(id, kind, namespace)
    }
}

/// Newest resolved audit-head-witness anchor the substrate would consume as its
/// witness pin input (the `_audit_witness` / `audit_head_witness` /
/// `resolved` selection `read_latest_witness_checkpoint` performs).
fn latest_resolved_witness(conn: &Connection) -> Option<Checkpoint> {
    query(
        conn,
        WITNESS_CHECKPOINT_NAMESPACE,
        Some(ConditionType::AuditHeadWitness),
        Some(CheckpointState::Resolved),
        16,
    )
    .expect("query witness anchors")
    .into_iter()
    .next()
}

// ---------------------------------------------------------------------------
// Predicate-level unit coverage — the completed SSOT + the pure decision.
// ---------------------------------------------------------------------------

#[test]
fn reserved_ssot_is_complete() {
    // The completed RESERVED_SUBSTRATE_NAMESPACES SSOT — all five reserved
    // underscore namespaces, including the two the pre-PR-1 partial set was
    // missing (_governance_verdict + _reanchor_ceremony).
    for ns in [
        WITNESS_CHECKPOINT_NAMESPACE,
        GOVERNANCE_VERDICT_NAMESPACE,
        GOVERNANCE_ENFORCEMENT_NAMESPACE,
        REANCHOR_CHECKPOINT_NAMESPACE,
        PEER_HEAD_ENTANGLEMENT_NAMESPACE,
    ] {
        assert!(
            RESERVED_SUBSTRATE_NAMESPACES.contains(&ns),
            "reserved namespace SSOT is missing {ns}"
        );
    }
    assert_eq!(
        RESERVED_SUBSTRATE_NAMESPACES.len(),
        5,
        "exactly the five reserved substrate namespaces"
    );

    // Every LOCAL-ONLY audit/identity trust anchor is reserved — asserted
    // against the LOAD-BEARING wildcard-free classifier, not just the listing.
    for kind in [
        ConditionType::AuditHeadWitness,
        ConditionType::GovernanceVerdict,
        ConditionType::GovernanceEnforcement,
        ConditionType::PeerHeadEntanglement,
        ConditionType::ReAnchor,
    ] {
        assert!(
            condition_type_is_reserved(kind),
            "load-bearing classifier must reserve {}",
            kind.as_str()
        );
    }
    // Caller coordination kinds are NOT reserved — AND `EpochAdvance` is NOT
    // reserved either: it is the freeze anchor DESIGNED to federate on the
    // FED-RQ-01 checkpoint-resolution transport (#1936/#125, #2650), gated by
    // the per-resolution signature gate, not an audit-signal spine. Refusing it
    // would break legitimate epoch federation
    // (`tests/federation_1936_checkpoint_fed.rs`).
    for kind in [
        ConditionType::Approval,
        ConditionType::ExternalSignal,
        ConditionType::ConditionPredicate,
        ConditionType::Deadline,
        ConditionType::EpochAdvance,
    ] {
        assert!(
            !condition_type_is_reserved(kind),
            "kind {} must NOT be reserved (caller coordination or legitimately federated)",
            kind.as_str()
        );
    }

    // Drift guard: the DERIVED `RESERVED_SUBSTRATE_CONDITION_TYPES` listing must
    // agree with the authoritative match over EVERY `ConditionType` variant, so
    // the docs/tests listing can never silently diverge from the load-bearing
    // classifier. (The enum has no `all()` roster, so the variants are
    // enumerated explicitly — the load-bearing compile-time gate against a NEW
    // unclassified variant is the wildcard-free match in
    // `condition_type_is_reserved`, which fails the BUILD, not this test.)
    for kind in [
        ConditionType::Approval,
        ConditionType::ExternalSignal,
        ConditionType::ConditionPredicate,
        ConditionType::Deadline,
        ConditionType::AuditHeadWitness,
        ConditionType::GovernanceVerdict,
        ConditionType::GovernanceEnforcement,
        ConditionType::EpochAdvance,
        ConditionType::PeerHeadEntanglement,
        ConditionType::ReAnchor,
    ] {
        assert_eq!(
            RESERVED_SUBSTRATE_CONDITION_TYPES.contains(&kind),
            condition_type_is_reserved(kind),
            "derived listing disagrees with the load-bearing match for {}",
            kind.as_str()
        );
    }
}

#[test]
fn predicate_refuses_reserved_kind_or_namespace_either_end() {
    // Reserved by KIND (any namespace).
    assert!(!inbound_checkpoint_kind_authorized(
        ConditionType::GovernanceVerdict,
        "public/ok",
        None
    ));
    // Reserved by NAMESPACE (benign kind) — the belt-and-braces arm.
    assert!(!inbound_checkpoint_kind_authorized(
        ConditionType::Approval,
        WITNESS_CHECKPOINT_NAMESPACE,
        None
    ));
    // Padded reserved namespace cannot slip past (trimmed compare).
    assert!(!inbound_checkpoint_kind_authorized(
        ConditionType::Approval,
        "  _audit_witness  ",
        None
    ));
    // Benign claimed but reserved STORED (the CAS-arm subject).
    assert!(!inbound_checkpoint_kind_authorized(
        ConditionType::Approval,
        "public/ok",
        Some((
            ConditionType::AuditHeadWitness,
            WITNESS_CHECKPOINT_NAMESPACE
        )),
    ));
    // Fully benign both ends → authorized.
    assert!(inbound_checkpoint_kind_authorized(
        ConditionType::Approval,
        "team/ops",
        Some((ConditionType::Approval, "team/ops")),
    ));
}

// ---------------------------------------------------------------------------
// (a) WIRE-KIND refusal — first-landing resolution of a reserved anchor.
// ---------------------------------------------------------------------------

#[test]
fn wire_kind_reserved_anchor_resolution_refused_and_nothing_lands() {
    let (_dir, conn) = fresh();

    // Reserved by KIND: attacker pushes a resolved audit-head-witness anchor
    // that does not exist locally (first-landing).
    let forged = inbound(
        "wire-witness",
        ConditionType::AuditHeadWitness,
        WITNESS_CHECKPOINT_NAMESPACE,
        RESOLVED_AT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &forged).unwrap(),
        InboundResolutionOutcome::RefusedReservedKind
    );
    // Fail CLOSED: the anchor NEVER landed — no row, no witness input created.
    assert!(get(&conn, "wire-witness").unwrap().is_none());
    assert!(latest_resolved_witness(&conn).is_none());

    // Reserved by NAMESPACE (benign kind, reserved location) is refused too.
    let forged_ns = inbound(
        "wire-verdict-ns",
        ConditionType::Approval,
        GOVERNANCE_VERDICT_NAMESPACE,
        RESOLVED_AT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &forged_ns).unwrap(),
        InboundResolutionOutcome::RefusedReservedKind
    );
    assert!(get(&conn, "wire-verdict-ns").unwrap().is_none());
}

#[test]
fn benign_coordination_resolution_still_applies() {
    // The refusal must not over-block: a normal caller coordination checkpoint
    // (approval, non-reserved namespace) federates exactly as before.
    let (_dir, conn) = fresh();
    let benign = inbound(
        "benign-gate",
        ConditionType::Approval,
        "team/ops",
        RESOLVED_AT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &benign).unwrap(),
        InboundResolutionOutcome::Applied
    );
    let landed = get(&conn, "benign-gate")
        .unwrap()
        .expect("benign gate landed");
    assert_eq!(landed.state, CheckpointState::Resolved);
}

#[test]
fn epoch_advance_freeze_anchor_still_federates() {
    // `EpochAdvance` is DELIBERATELY EXCLUDED from the reserved set: it is the
    // freeze anchor designed to ride the FED-RQ-01 checkpoint-resolution
    // transport (#1936/#125, #2650), gated by the per-resolution signature gate
    // rather than being an audit-signal spine. It lives in `_epoch`, not a
    // reserved namespace, and MUST still apply through the ingress.
    let (_dir, conn) = fresh();
    let epoch = inbound(
        "epoch-1",
        ConditionType::EpochAdvance,
        "_epoch",
        RESOLVED_AT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &epoch).unwrap(),
        InboundResolutionOutcome::Applied,
        "the epoch-advance freeze anchor must still federate (not reserved)"
    );
    assert_eq!(
        get(&conn, "epoch-1")
            .unwrap()
            .expect("epoch anchor landed")
            .state,
        CheckpointState::Resolved
    );
}

// ---------------------------------------------------------------------------
// (b) STORED-KIND / CAS refusal — benign wire kind resolving a reserved
//     by-id anchor. Assert refusal AND the stored row stays Pending.
// ---------------------------------------------------------------------------

#[test]
fn stored_reserved_anchor_not_resolvable_by_benign_wire_kind() {
    let (_dir, conn) = fresh();

    // The substrate created a PENDING reserved anchor locally (direct insert —
    // the real substrate emission path, which bypasses this funnel).
    let stored = pending(
        "cas-witness",
        ConditionType::AuditHeadWitness,
        WITNESS_CHECKPOINT_NAMESPACE,
    );
    insert(&conn, &stored).unwrap();

    // Attacker pushes a BENIGN-LOOKING resolution for that id — approval kind,
    // an in-scope public namespace — trying to resolve the reserved anchor by
    // id (the CAS keys on `(id, state)`, so the wire kind/namespace are not the
    // write subject on the pending→resolved arm).
    let benign_looking = inbound(
        "cas-witness",
        ConditionType::Approval,
        "public/ok",
        RESOLVED_AT,
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &benign_looking).unwrap(),
        InboundResolutionOutcome::RefusedReservedKind,
        "the STORED reserved kind must refuse a benign-looking by-id resolution"
    );

    // The stored anchor stays PENDING — nothing was resolved, the CAS never
    // fired, no attestation was stamped.
    let after = get(&conn, "cas-witness")
        .unwrap()
        .expect("stored anchor present");
    assert_eq!(
        after.state,
        CheckpointState::Pending,
        "the stored reserved anchor must remain unresolved"
    );
    assert_eq!(after.condition_type, ConditionType::AuditHeadWitness);
    assert!(after.resolution.is_none());
    assert!(after.resolved_by.is_none());
}

// ---------------------------------------------------------------------------
// (c) ALARM-SUPPRESSION PIN — with NO out-of-band witness pin enrolled (the
//     default), an injected anchor must NOT move the witness verdict off its
//     honest value. Pins the SUPPRESSION direction: the attacker's newer anchor
//     is designed to DISPLACE the honest one (become the input
//     `read_latest_witness_checkpoint` returns), and the refusal prevents that
//     displacement BELOW the K1 pin — so it holds even in the no-pin posture
//     where the Forged/K1 outcome has nothing to bite on.
// ---------------------------------------------------------------------------

#[test]
fn injected_witness_anchor_cannot_suppress_or_move_the_verdict() {
    let (_dir, conn) = fresh();

    // The DB's real chain heads (what verify would compare a pinned anchor to).
    let db_signed_head = 128_i64;
    let db_revisions_head = 64_i64;

    // The substrate emitted its OWN honest witness anchor locally.
    let honest = inbound(
        "honest-witness",
        ConditionType::AuditHeadWitness,
        WITNESS_CHECKPOINT_NAMESPACE,
        RESOLVED_AT,
    );
    insert(&conn, &honest).unwrap();

    // No out-of-band pin enrolled (the default): the honest witness verdict
    // WITHHOLDS (Unknown) — it cannot cryptographically anchor the pubkey.
    let honest_latest = latest_resolved_witness(&conn).expect("honest anchor is latest");
    assert_eq!(honest_latest.id, "honest-witness");
    let honest_verdict = compute_witness_verdict(
        Some(&honest_latest),
        None, // NO enrolled pin — the default posture
        db_signed_head,
        db_revisions_head,
        false,
    );
    assert!(
        matches!(honest_verdict, WitnessCheck::Unknown),
        "honest no-pin witness verdict withholds (Unknown), got {honest_verdict:?}"
    );

    // A REMOTE attacker /sync/push-es a NEWER resolved witness anchor to
    // DISPLACE the honest one and become the substrate's witness input.
    let forged = inbound(
        "attacker-witness",
        ConditionType::AuditHeadWitness,
        WITNESS_CHECKPOINT_NAMESPACE,
        RESOLVED_AT + 1_000, // newer → would out-rank the honest anchor
    );
    assert_eq!(
        apply_inbound_resolution(&conn, &forged).unwrap(),
        InboundResolutionOutcome::RefusedReservedKind
    );

    // The attacker anchor NEVER landed: the substrate's witness input is STILL
    // the honest anchor, unmoved.
    assert!(get(&conn, "attacker-witness").unwrap().is_none());
    let latest_after = latest_resolved_witness(&conn).expect("witness input unchanged");
    assert_eq!(
        latest_after.id, "honest-witness",
        "the injected anchor must NOT displace the substrate's witness input"
    );

    // The witness verdict — a pure function of that unchanged input — stays at
    // its honest value. The injection moved it NEITHER toward a false-clean
    // NotDetected (suppression) NOR anywhere else.
    let verdict_after = compute_witness_verdict(
        Some(&latest_after),
        None,
        db_signed_head,
        db_revisions_head,
        false,
    );
    assert!(
        matches!(verdict_after, WitnessCheck::Unknown),
        "post-injection verdict must equal the honest value (Unknown), got {verdict_after:?}"
    );
    assert!(
        !matches!(verdict_after, WitnessCheck::NotDetected),
        "the injected anchor must never be able to move the verdict to a clean pass"
    );
}

// ---------------------------------------------------------------------------
// K3 parity note (compile-time assertion of the documented disposition).
// ---------------------------------------------------------------------------

/// #3075 — K3 parity, RE-STATED. The postgres `/sync/push` funnel now DOES
/// reach an inbound-checkpoint apply (`MemoryStore::apply_remote_checkpoint_
/// resolution`, postgres impl in `src/store/postgres/federation_3075.rs`), so
/// the prior conclusion — "postgres refuses every inbound resolution, a
/// strictly stronger disposition, therefore no twin to poison" — is retired.
///
/// Parity is preserved by SHARING the classifier rather than by absence: both
/// adapters gate on the same backend-blind
/// [`inbound_checkpoint_kind_authorized`], checked on the CLAIMED wire kind AND
/// the STORED by-id kind, at the head of their respective apply funnels. This
/// test asserts the property that keeps that true — the classifier is a PURE
/// function with no backend in its signature, so there is exactly one
/// definition of "reserved" for both receivers to obey. The end-to-end postgres
/// proof (live receiver, row state) is
/// `tests/fed_checkpoint_lane_3075_pg.rs::reserved_anchor_kind_refused_on_postgres_3075`.
#[test]
fn pg_checkpoint_apply_parity_note_3075() {
    // The pure classifier both apply funnels call. If a future change gave
    // either backend its own copy, this cell would still pass — which is why
    // the load-bearing pg proof is the live-receiver cell named above; this one
    // pins the SHAPE (one shared, backend-blind verdict) that makes the two
    // funnels agree by construction.
    assert!(
        !inbound_checkpoint_kind_authorized(
            ai_memory::models::ConditionType::AuditHeadWitness,
            "team/ops",
            None,
        ),
        "the shared reserved-kind classifier must refuse a reserved wire kind"
    );
    assert!(
        inbound_checkpoint_kind_authorized(
            ai_memory::models::ConditionType::Approval,
            "team/ops",
            None,
        ),
        "and must admit an ordinary coordination gate"
    );
}
