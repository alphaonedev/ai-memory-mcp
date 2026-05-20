// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #963 Phase 2 — cross-surface refusal envelope parity.
//!
//! Phase 1 (commit `2231e8290`) landed the typed
//! [`ai_memory::governance::GovernanceRefusal`] envelope as a
//! self-contained module. Phase 2 wires it through the
//! `GovernanceDecision::Deny` variant so the substrate gate-evaluator
//! produces a *typed* refusal that every surface (HTTP handler, MCP
//! tool, CLI stderr line) renders to the same byte-identical wire
//! string.
//!
//! Pre-#963 each surface composed its refusal locally from
//! `Deny(String)` (the substrate had no structured context to expose),
//! and the sqlite path additionally double-prefixed `"governance: "`
//! because the substrate pre-formatted the reason and the consumer
//! re-wrapped it via [`ai_memory::governance::deny_message`].
//!
//! This test pins:
//!
//! 1. **Typed envelope.** `enforce_governance` returns
//!    `Deny(GovernanceRefusal)` with `denied_level`, `namespace`,
//!    `owner`, and `agent_id` populated.
//! 2. **Display = canonical wire shape.** The envelope's
//!    `Display` reads
//!    `"<action> denied by governance: <reason>"` and matches what
//!    every consumer surface produces.
//! 3. **Cross-surface parity.** The substrate Display, the
//!    handler-style HTTP error body, the MCP-style tool error string,
//!    and the CLI-style stderr line all reduce to the same string and
//!    expose the same `denied_level`.
//! 4. **anyhow round-trip.** Wrapping the typed refusal in
//!    `anyhow::Error` and converting through `From<anyhow::Error>` for
//!    [`ai_memory::errors::MemoryError`] surfaces the canonical Display
//!    in `message()` and preserves the typed fields via the
//!    `RefusedByGovernanceGate` variant.
//!
//! Self-contained: uses an in-memory sqlite db, no postgres, no LLM,
//! no daemon spin-up. Runs under the standard cargo gate.

use ai_memory::db;
use ai_memory::errors::MemoryError;
use ai_memory::governance::{DenyGate, GovernanceRefusal, deny_message};
use ai_memory::models::{
    ApproverType, ConfidenceSource, CorePolicy, GovernanceDecision, GovernanceLevel,
    GovernancePolicy, GovernedAction, Memory, MemoryKind, Tier, default_metadata,
};
use rusqlite::Connection;

/// Seed `namespace` with the supplied policy + owner. Mirrors the
/// helper in `tests/governance_inheritance.rs` but kept inline so the
/// integration-test crate stays single-file.
fn seed_policy(
    conn: &Connection,
    namespace: &str,
    policy: &GovernancePolicy,
    owner_agent_id: &str,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(owner_agent_id.to_string()),
        );
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(policy).unwrap(),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{namespace}"),
        title: format!("standard for {namespace}"),
        content: "policy".to_string(),
        tags: vec![],
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    let standard_id = db::insert(conn, &standard).unwrap();
    db::set_namespace_standard(conn, namespace, &standard_id, None).unwrap();
}

fn owner_write_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Owner,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
        },
        ..Default::default()
    }
}

/// Locked-in enforce mode for the duration of these assertions —
/// substrate `enforce_governance` short-circuits to Allow in `Off` and
/// downgrades `Deny` to a warn-log in `Advisory`. The test runs in a
/// separate process under the default cargo test harness, so this
/// override is local to the test.
fn force_enforce_mode() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
}

#[test]
fn refusal_envelope_carries_typed_context_and_canonical_display() {
    force_enforce_mode();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let namespace = "team/prod";
    let owner = "ai:alice";
    let intruder = "ai:bob";
    seed_policy(&conn, namespace, &owner_write_policy(), owner);

    // Non-owner store at the gated namespace MUST refuse with the typed
    // envelope. We probe the substrate directly so the test is anchored
    // at the construction site, not at a consumer's downstream wrapper.
    let payload = serde_json::json!({"title": "intruder write"});
    let decision = db::enforce_governance(
        &conn,
        GovernedAction::Store,
        namespace,
        intruder,
        None,
        None,
        &payload,
    )
    .expect("enforce_governance must not error on a well-formed call");

    let refusal = match decision {
        GovernanceDecision::Deny(r) => r,
        other => panic!("non-owner store under write=owner policy must Deny; got {other:?}"),
    };

    // Typed-fields pin — every field the Phase 1 envelope advertised
    // is populated by the Phase 2 wire-up.
    assert_eq!(refusal.action, GovernedAction::Store);
    assert_eq!(refusal.denied_level, GovernanceLevel::Owner);
    assert_eq!(refusal.agent_id, intruder);
    assert_eq!(refusal.namespace.as_deref(), Some(namespace));
    assert_eq!(refusal.owner.as_deref(), Some(owner));
    assert!(
        refusal.reason.contains("not the owner"),
        "owner-mismatch refusal should cite ownership: {refusal:?}"
    );
    // The redundant pre-#963 `"governance: "` prefix MUST NOT leak
    // back into the typed envelope's reason; the envelope's Display
    // owns the `"<action> denied by governance: "` header.
    assert!(
        !refusal.reason.starts_with("governance:"),
        "typed reason MUST drop the redundant `governance:` prefix; got {:?}",
        refusal.reason,
    );

    // Display = canonical wire shape.
    let canonical = format!("{refusal}");
    assert_eq!(
        canonical,
        format!("store denied by governance: caller '{intruder}' is not the owner ('{owner}')",),
    );
}

#[test]
fn refusal_renders_byte_identically_across_surfaces() {
    force_enforce_mode();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let namespace = "team/prod";
    let owner = "ai:alice";
    let intruder = "ai:bob";
    seed_policy(&conn, namespace, &owner_write_policy(), owner);

    let payload = serde_json::json!({"title": "intruder write"});
    let refusal = match db::enforce_governance(
        &conn,
        GovernedAction::Store,
        namespace,
        intruder,
        None,
        None,
        &payload,
    )
    .expect("enforce_governance must not error")
    {
        GovernanceDecision::Deny(r) => r,
        other => panic!("expected Deny; got {other:?}"),
    };

    let canonical = refusal.to_string();

    // 1) Substrate Display (envelope) — the source of truth.
    //    Anchored above; pulled forward here to anchor the rest.
    assert_eq!(
        canonical,
        format!("store denied by governance: caller '{intruder}' is not the owner ('{owner}')",),
    );

    // 2) Handler-style HTTP refusal — `handlers/memories.rs::delete`,
    //    `handlers/memories.rs::promote`, `handlers/create.rs::create`
    //    all compose the JSON body via
    //    `deny_message("<action>", DenyGate::Governance, &refusal.reason)`.
    let handler_body = deny_message("store", DenyGate::Governance, &refusal.reason);
    assert_eq!(handler_body, canonical);

    // 3) MCP-style tool error — `mcp/tools/store/mod.rs::store_handler`
    //    et al. return `Err(deny_message(..., &refusal.reason))`. Same
    //    composer, same input, same output.
    let mcp_error = deny_message("store", DenyGate::Governance, &refusal.reason);
    assert_eq!(mcp_error, canonical);

    // 4) CLI-style stderr line — `cli/governance.rs::execute` writes
    //    `"<action> denied by governance: {reason}"` directly. The
    //    string composition is local to the CLI but anchored to the
    //    same canonical shape.
    let cli_stderr = format!(
        "{} denied by governance: {reason}",
        GovernedAction::Store.as_str(),
        reason = refusal.reason,
    );
    assert_eq!(cli_stderr, canonical);

    // Every surface MUST also expose the same denied_level when the
    // typed envelope is in hand — handlers / MCP / CLI can project it
    // into structured response fields without re-parsing.
    assert_eq!(refusal.denied_level, GovernanceLevel::Owner);
    assert_eq!(refusal.denied_level.as_str(), "owner");
}

#[test]
fn registered_level_refusal_surfaces_typed_context() {
    force_enforce_mode();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let namespace = "team/registered";
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Registered,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
        },
        ..Default::default()
    };
    seed_policy(&conn, namespace, &policy, "ai:registrar");

    let anon = "ai:anonymous";
    let payload = serde_json::json!({"title": "anon write"});
    let refusal = match db::enforce_governance(
        &conn,
        GovernedAction::Store,
        namespace,
        anon,
        None,
        None,
        &payload,
    )
    .expect("enforce_governance must not error")
    {
        GovernanceDecision::Deny(r) => r,
        other => panic!("anon write at registered-level ns must Deny; got {other:?}"),
    };

    assert_eq!(refusal.action, GovernedAction::Store);
    assert_eq!(refusal.denied_level, GovernanceLevel::Registered);
    assert_eq!(refusal.agent_id, anon);
    assert_eq!(refusal.namespace.as_deref(), Some(namespace));
    // Registered-level refusals have no resolvable owner — the typed
    // field stays None and the JSON wire shape drops the key (envelope
    // serde uses `skip_serializing_if = Option::is_none`).
    assert!(
        refusal.owner.is_none(),
        "registered-level refusal must NOT set owner: {refusal:?}"
    );
    assert!(
        refusal.reason.contains("not a registered agent"),
        "registered-level refusal should cite registration: {refusal:?}"
    );
    assert_eq!(
        refusal.to_string(),
        format!("store denied by governance: caller '{anon}' is not a registered agent"),
    );
}

#[test]
fn refusal_round_trips_through_anyhow_to_memory_error() {
    // #963 Phase 2 — the typed envelope rides `anyhow::Error` cleanly
    // and surfaces through `From<anyhow::Error> for MemoryError` into
    // the new `RefusedByGovernanceGate` variant. Pin the
    // wire-relevant projections (code, HTTP status, canonical message)
    // so any future refactor that breaks the downcast surfaces here.
    force_enforce_mode();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let namespace = "team/prod";
    let owner = "ai:alice";
    let intruder = "ai:bob";
    seed_policy(&conn, namespace, &owner_write_policy(), owner);

    let payload = serde_json::json!({"title": "intruder write"});
    let refusal = match db::enforce_governance(
        &conn,
        GovernedAction::Store,
        namespace,
        intruder,
        None,
        None,
        &payload,
    )
    .expect("enforce_governance must not error")
    {
        GovernanceDecision::Deny(r) => r,
        other => panic!("expected Deny; got {other:?}"),
    };

    let canonical = refusal.to_string();
    let anyhow_err: anyhow::Error = anyhow::Error::new(refusal.clone());

    // Direct downcast still works (envelope is a `std::error::Error`).
    let back = anyhow_err
        .downcast_ref::<GovernanceRefusal>()
        .expect("typed envelope MUST survive anyhow round-trip");
    assert_eq!(back, &refusal);

    // From<anyhow::Error> for MemoryError — the production wrapper.
    let mem_err: MemoryError = anyhow_err.into();
    assert_eq!(mem_err.code(), "GOVERNANCE_REFUSED");
    assert_eq!(mem_err.status(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(mem_err.message(), canonical);
    match &mem_err {
        MemoryError::RefusedByGovernanceGate(r) => {
            assert_eq!(r, &refusal);
            assert_eq!(r.denied_level, GovernanceLevel::Owner);
            assert_eq!(r.namespace.as_deref(), Some(namespace));
            assert_eq!(r.owner.as_deref(), Some(owner));
        }
        other => panic!(
            "From<anyhow::Error> MUST land the typed gate refusal in \
             MemoryError::RefusedByGovernanceGate; got {other:?}",
        ),
    }
}
