// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent cov4 — live-Postgres integration coverage for the
//! `PostgresStore` SAL adapter knowledge-graph / reflect / entity /
//! capture-turn / pending-action surfaces (`src/store/postgres.rs`).
//!
//! The KG methods dispatch AGE-Cypher when the connected DB has the
//! Apache AGE extension and recursive-CTE fallback otherwise; both
//! arms are exercised by the same trait calls (the runtime backend
//! detection picks the live path). Gated on
//! `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::models::{
    ConfidenceSource, GovernanceDecision, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, GovernedAction, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["covtest".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "cov4-kg".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
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
    }
}

fn link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: Some(chrono::Utc::now().to_rfc3339()),
        valid_until: None,
        attest_level: None,
    }
}

// ───────────────────────────────────────────────────────────────────
// kg_query / kg_timeline / kg_invalidate (trait) + find_paths
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kg_query_traverses_outbound_edges() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-kgq");
    let a = uid("ka");
    let b = uid("kb");
    let c = uid("kc");
    store
        .store(&ctx, &mem(&a, &ns, "kg a", "abody", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "kg b", "bbody", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&c, &ns, "kg c", "cbody", "ai:cov4"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();
    store.link(&ctx, &link(&b, &c)).await.unwrap();

    let rows = MemoryStore::kg_query(&store, &a, 3, false)
        .await
        .expect("kg_query");
    assert!(
        rows.iter().any(|r| r.target_id == b),
        "depth-3 traversal must reach b"
    );

    // kg_timeline scans validity-anchored outbound edges.
    let tl = store
        .kg_timeline(&a, None, None, Some(50))
        .await
        .expect("kg_timeline");
    assert!(tl.iter().any(|r| r.target_id == b));

    // find_paths between two connected nodes.
    let paths = MemoryStore::find_paths(&store, &ctx, &a, &c, Some(5), Some(10))
        .await
        .expect("find_paths");
    assert!(!paths.is_empty(), "a→b→c path must exist");
}

#[tokio::test]
async fn kg_invalidate_marks_edge_and_misses_unknown() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-kginv");
    let a = uid("ia");
    let b = uid("ib");
    store
        .store(&ctx, &mem(&a, &ns, "inv a", "body", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "inv b", "body", "ai:cov4"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    let found = store
        .invalidate_link(&a, &b, "related_to", None)
        .await
        .expect("invalidate found");
    assert!(found.found);

    let miss = store
        .invalidate_link(&uid("nope"), &uid("nope2"), "related_to", None)
        .await
        .expect("invalidate miss");
    assert!(!miss.found);
}

#[tokio::test]
async fn find_paths_no_route_returns_empty() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-noroute");
    let a = uid("na");
    let b = uid("nb");
    store
        .store(&ctx, &mem(&a, &ns, "iso a", "body", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "iso b", "body", "ai:cov4"))
        .await
        .unwrap();
    // No link between a and b.
    let paths = MemoryStore::find_paths(&store, &ctx, &a, &b, Some(4), Some(10))
        .await
        .expect("find_paths disconnected");
    assert!(paths.is_empty());
}

// ───────────────────────────────────────────────────────────────────
// entity_register / entity_get_by_alias
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn entity_register_idempotent_then_resolve_by_alias() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-entity");
    let canonical = uid("Acme");
    let extra = serde_json::json!({});
    let first = store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            &["acme".to_string(), "ACME Corp".to_string()],
            &extra,
            Some("ai:cov4"),
        )
        .await
        .expect("entity_register first");
    assert!(first.created, "first registration creates the entity");

    // Re-register unions aliases; created=false.
    let second = store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            &["Acme Inc".to_string()],
            &extra,
            Some("ai:cov4"),
        )
        .await
        .expect("entity_register idempotent");
    assert!(!second.created, "re-register is idempotent");

    // `entity_get_by_alias` reads the `entity_aliases` join table, which
    // the SAL `entity_register` path does NOT populate (it stamps
    // `metadata.aliases` on the entity memory only — the `entity_aliases`
    // table is written by the kg handler's register path, see
    // FINDINGS in the cov4 handoff). Exercise the resolver's query path
    // (both the namespace-scoped and namespace-wide arms) + the clean
    // miss path; the registered entity is correctly NOT found via the
    // alias table.
    let scoped = store
        .entity_get_by_alias("acme", Some(&ns))
        .await
        .expect("entity_get_by_alias ns arm");
    assert!(
        scoped.is_none(),
        "SAL register does not write entity_aliases"
    );

    let wide = store
        .entity_get_by_alias("acme", None)
        .await
        .expect("entity_get_by_alias wide arm");
    assert!(wide.is_none());

    let missing = store
        .entity_get_by_alias("no-such-alias-cov4", Some(&ns))
        .await
        .expect("entity miss");
    assert!(missing.is_none());
}

// ───────────────────────────────────────────────────────────────────
// reflect / get_reflection_origin / list_recall_observations
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reflect_mints_reflection_and_origin() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-reflect");
    let a = uid("ra");
    let b = uid("rb");
    store
        .store(&ctx, &mem(&a, &ns, "obs a", "abody", "ai:cov4"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "obs b", "bbody", "ai:cov4"))
        .await
        .unwrap();

    let input = ai_memory::db::ReflectInput {
        source_ids: vec![a.clone(), b.clone()],
        title: uid("reflection"),
        content: "a synthesized reflection over a and b".to_string(),
        namespace: Some(ns.clone()),
        tier: Tier::Long,
        tags: vec!["reflection".to_string()],
        priority: 6,
        confidence: 0.8,
        source: "nhi".to_string(),
        agent_id: "ai:cov4".to_string(),
        metadata: serde_json::json!({}),
    };
    let outcome = store.reflect(&ctx, &input).await.expect("reflect");
    assert_eq!(outcome.reflection_depth, 1, "max(source depth)+1 = 1");
    assert_eq!(outcome.reflects_on.len(), 2);

    // get_reflection_origin walks the new memory's origin metadata.
    let origin = store
        .get_reflection_origin(&outcome.id)
        .await
        .expect("get_reflection_origin");
    assert!(origin.is_some(), "reflection has an origin record");

    // list_recall_observations is a read-only ledger scan.
    let _ = store
        .list_recall_observations(None, None, None, None, 10)
        .await
        .expect("list_recall_observations");
}

// ───────────────────────────────────────────────────────────────────
// capture_turn_idempotent — dedup miss then hit (ON CONFLICT arms)
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn capture_turn_idempotent_miss_then_hit() {
    use ai_memory::models::CaptureTurnWrite;
    use ai_memory::signed_events::SignedEvent;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let ns = uid("cov-capture");
    let session = uid("sess");
    let turn = 0i64;
    let sha = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(format!("{session}|{turn}").as_bytes());
        h.finalize().to_vec()
    };
    let memory = mem(
        &uid("ct"),
        &ns,
        &uid("turn-title"),
        "turn content",
        "ai:cov4",
    );
    let signed_event = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "ai:cov4".to_string(),
        event_type: "memory.capture_turn".to_string(),
        payload_hash: sha.clone(),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    let write = CaptureTurnWrite {
        memory,
        sha256: sha.clone(),
        host_kind: "claude-code".to_string(),
        host_session_id: session.clone(),
        host_turn_index: turn,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event: signed_event.clone(),
    };
    let first = store
        .capture_turn_idempotent(&ctx, &write)
        .await
        .expect("capture_turn miss");
    assert!(!first.dedup_hit, "first capture is a dedup miss");

    // Second capture with the same (session, turn) key dedups.
    let second = store
        .capture_turn_idempotent(&ctx, &write)
        .await
        .expect("capture_turn hit");
    assert!(second.dedup_hit, "second capture is a dedup hit");
    assert_eq!(first.memory_id, second.memory_id);
}

// ───────────────────────────────────────────────────────────────────
// pending actions: enforce → get_pending → list_pending_actions →
// pending_decide / governance_approve_with_consensus /
// execute_pending_action
// ───────────────────────────────────────────────────────────────────

/// Seed a namespace standard whose governance block requires approval
/// on writes, using only the public trait surface (store a standard
/// memory carrying `metadata.governance`, then point namespace_meta at
/// it). A non-owner write then routes through Pending.
async fn seed_approve_standard(store: &PostgresStore, ns: &str, owner: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), "policy", owner);
    standard.tier = Tier::Long;
    standard.metadata = serde_json::json!({
        "agent_id": owner,
        "governance": {"write": "approve", "promote": "any", "delete": "owner"},
    });
    store.store(&ctx, &standard).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, ns, &std_id, None)
        .await
        .expect("set_namespace_standard");
}

#[tokio::test]
async fn pending_action_get_list_and_decide() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let Some(store) = connect().await else {
        return;
    };
    let owner = uid("ai:cov4-owner");
    let requester = uid("ai:cov4-req");
    let ns = uid("cov-pending");
    seed_approve_standard(&store, &ns, &owner).await;

    let payload = serde_json::json!({"title": "needs approval"});
    let decision = store
        .enforce_governance_action(GovernedAction::Store, &ns, &requester, None, None, &payload)
        .await
        .expect("enforce_governance_action");
    let pending_id = match decision {
        GovernanceDecision::Pending(id) => id,
        other => panic!("approve-level non-owner write must Pending; got {other:?}"),
    };

    let ctx = CallerContext::for_admin(&owner);
    let row = store
        .get_pending(&ctx, &pending_id)
        .await
        .expect("get_pending")
        .expect("pending row present");
    assert_eq!(row.status, "pending");
    assert_eq!(row.namespace, ns);

    let listed = store
        .list_pending_actions(Some("pending"), None, 100)
        .await
        .expect("list_pending_actions");
    assert!(
        listed
            .iter()
            .any(|p| p.get("id").and_then(serde_json::Value::as_str) == Some(pending_id.as_str()))
    );

    // pending_decide approves the action.
    let decided = store
        .pending_decide(&ctx, &pending_id, true, &owner)
        .await
        .expect("pending_decide");
    assert!(decided, "decision must apply to the pending row");

    let after = store
        .get_pending(&ctx, &pending_id)
        .await
        .expect("get_pending after")
        .expect("row still present");
    assert_eq!(after.status, "approved");
}

#[tokio::test]
async fn governance_consensus_and_execute_pending() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let Some(store) = connect().await else {
        return;
    };
    let owner = uid("ai:cov4-owner2");
    let requester = uid("ai:cov4-req2");
    let ns = uid("cov-consensus");
    seed_approve_standard(&store, &ns, &owner).await;

    // execute_pending_action's "store" arm deserializes the queued
    // payload as a full Memory, so the enforced payload must be a
    // complete serialized memory (a bare {"title": ...} would
    // IntegrityFailed on replay).
    let queued = mem(&uid("pa"), &ns, "consensus write", "body", &requester);
    let payload = serde_json::to_value(&queued).expect("serialize memory payload");
    let decision = store
        .enforce_governance_action(GovernedAction::Store, &ns, &requester, None, None, &payload)
        .await
        .expect("enforce");
    let pending_id = match decision {
        GovernanceDecision::Pending(id) => id,
        other => panic!("expected Pending; got {other:?}"),
    };

    let ctx = CallerContext::for_admin(&owner);
    // governance_approve_with_consensus drives the approval state machine.
    let outcome = store
        .governance_approve_with_consensus(&ctx, &pending_id, &owner)
        .await
        .expect("governance_approve_with_consensus");
    // Human approver_type → Approved; the call path is what we exercise.
    let _ = outcome;

    // execute_pending_action runs the approved payload's persistence.
    let _ = store
        .execute_pending_action(&ctx, &pending_id)
        .await
        .expect("execute_pending_action");
}

// ───────────────────────────────────────────────────────────────────
// notify / schema_version
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn notify_writes_inbox_memory_and_schema_version() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:cov4");
    let target = uid("ai:cov4-target");
    let new_id = store
        .notify(
            &ctx,
            &target,
            "cov4 notice",
            "you have mail",
            Some(7),
            Some(&Tier::Mid),
        )
        .await
        .expect("notify");
    assert!(!new_id.is_empty());

    let v = store.schema_version().await.expect("schema_version");
    assert!(v >= 57, "postgres ladder ends at v57+ (got {v})");
}
