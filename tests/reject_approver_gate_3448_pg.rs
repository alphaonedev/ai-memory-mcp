// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3448 — LIVE-postgres proof that REJECTING a pending action requires the
//! SAME approver eligibility as APPROVING one.
//!
//! **The defect.** `MemoryStore::pending_decide(.., false, ..)` is the raw
//! structural transition: it asks nothing about WHO is deciding. Every
//! caller-originated reject surface reached it directly — the MCP tool
//! (closed by #3388), `POST /api/v1/pending/{id}/reject`, the K10
//! `/approvals/decide` deny arm, and the CLI. On postgres, which exists
//! precisely for the multi-tenant HTTP daemon, that meant any `X-Agent-Id`
//! principal — including the REQUESTER, whom
//! [`MemoryStore::governance_approve_with_consensus`] explicitly refuses
//! (#1793 / #2538) — could veto any other tenant's queued governance action.
//!
//! **The #2538 trap this file exists to avoid.** The approve rules live in
//! `PostgresStore`'s own impl; `SqliteStore`'s overrides are never reached on
//! postgres. #3448 therefore moved the RULES to one backend-agnostic predicate
//! (`ai_memory::approvals::approver_eligibility_step`) that both backends
//! call, and this suite proves the postgres binding of it actually refuses.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset. Every id
//! and namespace is uuid-randomised and every seeded row is reaped in-test,
//! because the `sal-postgres` suite shares ONE `ai_memory_test` database with
//! no per-test schema isolation (#2287). NO schema change.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use ai_memory::models::{
    AgentRegistration, ApproverType, ConfidenceSource, CorePolicy, GovernanceDecision,
    GovernanceLevel, GovernancePolicy, Memory, MemoryKind, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, GovernedAction, MemoryStore, RejectOutcome};

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn mem(id: &str, ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        tags: vec!["reject3448".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "reject3448".to_string(),
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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    }
}

/// Attach a namespace standard whose policy is `write: Approve` with the
/// DEFAULT `ApproverType::Human` arm — the arm every namespace that pins no
/// approver falls into, and the one the reject surfaces were entirely missing.
async fn seed_human_approver_ns(store: &PostgresStore, ns: &str, owner: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std3448");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), owner);
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        ..Default::default()
    };
    standard.metadata = serde_json::json!({
        "agent_id": owner,
        "governance": policy,
    });
    store.store(&ctx, &standard).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, ns, &std_id, None)
        .await
        .expect("set_namespace_standard");
}

/// Queue an approve-gated pending Store action authored by `requester`.
async fn seed_pending(store: &PostgresStore, ns: &str, requester: &str) -> String {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let queued = mem(&uid("pa3448"), ns, "needs approval", requester);
    let payload = serde_json::to_value(&queued).expect("serialize payload");
    let decision = store
        .enforce_governance_action(
            GovernedAction::Store,
            ns,
            requester,
            None,
            None,
            &payload,
            None,
        )
        .await
        .expect("enforce_governance_action");
    match decision {
        GovernanceDecision::Pending(id) => id,
        other => panic!("approve-level write must Pending; got {other:?}"),
    }
}

async fn register(store: &PostgresStore, agent_id: &str) {
    store
        .register_agent(
            &CallerContext::for_admin(agent_id),
            &AgentRegistration {
                agent_id: agent_id.to_string(),
                agent_type: "nhi".to_string(),
                capabilities: vec!["read".to_string(), "write".to_string()],
                registered_at: chrono::Utc::now().to_rfc3339(),
                last_seen_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .expect("register agent");
}

/// Read a pending row's `(status, decided_by)` so a refusal can be proven INERT.
async fn status_of(
    store: &PostgresStore,
    ctx: &CallerContext,
    id: &str,
) -> (String, Option<String>) {
    let pa = store
        .get_pending(ctx, id)
        .await
        .expect("get_pending")
        .expect("pending row exists");
    (pa.status, pa.decided_by)
}

/// #2287 — the sal-postgres suite shares one database; reap every row this
/// suite seeded so it never leaks into another suite's global assertions.
async fn cleanup(store: &PostgresStore, ns_prefix: &str) {
    let pool = store.pool();
    // Order matters: `namespace_meta.standard_id` references a memory, so the
    // meta row goes before the memories it points at.
    for sql in [
        "DELETE FROM pending_actions WHERE namespace LIKE $1",
        "DELETE FROM namespace_meta WHERE namespace LIKE $1",
        "DELETE FROM memories WHERE namespace LIKE $1",
    ] {
        let _ = sqlx::query(sql)
            .bind(format!("{ns_prefix}%"))
            .execute(pool)
            .await;
    }
    // Agent-registry rows live in the shared `_agents` namespace, not in
    // `ns_prefix`; every id this suite mints carries the `3448` discriminator.
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1 AND title LIKE '%3448%'")
        .bind(ai_memory::models::AGENTS_NAMESPACE)
        .execute(pool)
        .await;
}

/// DENIED (core): the REQUESTER vetoes their own queued action. Pre-#3448 the
/// surfaces reached `pending_decide(.., false, ..)` and this transitioned to
/// `rejected`; approve refuses the identical caller.
#[tokio::test]
async fn requester_cannot_self_veto_pg_3448() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("reject3448-self");
    let alice = uid("ai:alice3448");
    seed_human_approver_ns(&store, &ns, &uid("ai:owner3448")).await;
    // Registered, so the ONLY thing standing between alice and the veto is the
    // separation-of-duties rule.
    register(&store, &alice).await;
    let ctx = CallerContext::for_agent(&alice);
    let pid = seed_pending(&store, &ns, &alice).await;

    let outcome = store
        .reject_with_approver_type(&ctx, &pid, &alice)
        .await
        .expect("reject_with_approver_type");
    let (status, decided_by) = status_of(&store, &ctx, &pid).await;
    cleanup(&store, &ns).await;

    match outcome {
        RejectOutcome::Refused(reason) => assert!(
            reason.contains("self-approval"),
            "the requester must not veto their own action, got: {reason}"
        ),
        other => panic!("expected a self-veto refusal, got {other:?}"),
    }
    assert_eq!(status, "pending", "a refused veto must not decide");
    assert!(decided_by.is_none(), "no decider may be recorded");
}

/// DENIED: a non-requester the operator never REGISTERED cannot veto — the
/// cross-tenant sabotage shape. Mirrors the Human approve arm (#1793).
#[tokio::test]
async fn unregistered_approver_cannot_veto_pg_3448() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("reject3448-unreg");
    let alice = uid("ai:alice3448");
    let mallory = uid("ai:mallory3448"); // deliberately never registered
    seed_human_approver_ns(&store, &ns, &uid("ai:owner3448")).await;
    register(&store, &alice).await;
    let pid = seed_pending(&store, &ns, &alice).await;
    let ctx = CallerContext::for_agent(&mallory);

    let outcome = store
        .reject_with_approver_type(&ctx, &pid, &mallory)
        .await
        .expect("reject_with_approver_type");
    let (status, decided_by) = status_of(&store, &ctx, &pid).await;
    cleanup(&store, &ns).await;

    match outcome {
        RejectOutcome::Refused(reason) => assert!(
            reason.contains("is not a registered agent"),
            "an unregistered agent must not veto, got: {reason}"
        ),
        other => panic!("expected an unregistered-approver refusal, got {other:?}"),
    }
    assert_eq!(status, "pending", "a refused veto must not decide");
    assert!(decided_by.is_none(), "no decider may be recorded");
}

/// ALLOWED: a REGISTERED, non-requester approver still vetoes. The gate must
/// not break the legitimate governance path.
#[tokio::test]
async fn registered_non_requester_can_veto_pg_3448() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("reject3448-ok");
    let alice = uid("ai:alice3448");
    let bob = uid("ai:bob3448");
    seed_human_approver_ns(&store, &ns, &uid("ai:owner3448")).await;
    register(&store, &bob).await;
    let pid = seed_pending(&store, &ns, &alice).await;
    let ctx = CallerContext::for_agent(&bob);

    let outcome = store
        .reject_with_approver_type(&ctx, &pid, &bob)
        .await
        .expect("reject_with_approver_type");
    let (status, decided_by) = status_of(&store, &ctx, &pid).await;
    cleanup(&store, &ns).await;

    assert_eq!(
        outcome,
        RejectOutcome::Rejected,
        "a registered non-requester approver must be allowed to veto"
    );
    assert_eq!(status, "rejected");
    assert_eq!(decided_by.as_deref(), Some(bob.as_str()));
}

/// An absent (or already-decided) pending id is `NotFound`, NOT a refusal —
/// the handlers render it as their existing 404 envelope, so the wire contract
/// for the operational no-op is unchanged by the gate.
#[tokio::test]
async fn unknown_pending_id_is_not_found_not_refused_pg_3448() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let bob = uid("ai:bob3448");
    let ctx = CallerContext::for_agent(&bob);
    let outcome = store
        .reject_with_approver_type(&ctx, &uid("no-such-pending3448"), &bob)
        .await
        .expect("reject_with_approver_type");
    assert_eq!(outcome, RejectOutcome::NotFound);
}
