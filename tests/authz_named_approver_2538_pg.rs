// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2538 (CWE-863) — LIVE-postgres proof that the
//! `ApproverType::Agent(required)` NAMED-APPROVER arm refuses self-approval
//! and refuses an unregistered designated approver.
//!
//! **Why this file exists at all — the trap.**
//! [`MemoryStore::approve_with_approver_type`] is overridden by `SqliteStore`
//! ONLY (`src/store/sqlite.rs`). Postgres never sees that override: it falls
//! through to the trait DEFAULT in `src/store/mod.rs`, which delegates to
//! [`MemoryStore::governance_approve_with_consensus`] — a method `PostgresStore`
//! implements with its OWN, byte-for-byte duplicated copy of the same
//! Human / Agent / Consensus state machine. A fix landed in the sqlite override
//! (or in `crate::storage::approve_with_approver_type`) alone would therefore
//! NEVER execute on postgres, and the defect would ship half-closed.
//!
//! So this suite deliberately drives the fix through BOTH postgres entry
//! points and asserts they agree:
//!   1. `store.approve_with_approver_type(..)` — the TRAIT-DEFAULT route (the
//!      one the handler layer calls, and the one that silently bypasses a
//!      sqlite-only fix);
//!   2. `store.governance_approve_with_consensus(..)` — the concrete postgres
//!      implementation the default forwards to.
//!
//! **R-203 (parent `5449b6da`).** Before the fix the postgres Agent arm read:
//! ```ignore
//! if approver_agent_id != required { reject } else { pending_decide(.., true, ..) }
//! ```
//! so `named_approver_cannot_self_approve_pg` observed
//! `ApproveOutcome::Approved` and failed with
//! `expected self-approval rejection, got Approved`; the sqlite twin
//! `storage::tests::agent_arm_refuses_self_approval_and_unregistered_2538`
//! failed with the identical message.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset. Every id /
//! namespace is uuid-randomised and every seeded row is reaped in-test, because
//! the `sal-postgres` suite shares ONE `ai_memory_test` database with no
//! per-test schema isolation (#2287). NO schema change — the tier stays at the
//! #2445-guarded v87.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use ai_memory::models::{
    AgentRegistration, ApproverType, ConfidenceSource, CorePolicy, GovernanceDecision,
    GovernanceLevel, GovernancePolicy, Memory, MemoryKind, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{ApproveOutcome, CallerContext, GovernedAction, MemoryStore};

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
        tags: vec!["authz2538".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "authz2538".to_string(),
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

/// Attach a namespace standard whose policy names `approver` as the single
/// DESIGNATED approver, with `write: Approve` so the arm is live.
async fn seed_agent_approver_ns(store: &PostgresStore, ns: &str, owner: &str, approver: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std2538");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), owner);
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Agent(approver.to_string()),
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
    // The governance court only routes to `Pending` under enforce mode; the
    // process-wide default in a test binary is otherwise permissive and the
    // approve-level write would resolve `Allow` (the `cov_ga2_pg_handlers_1`
    // `seed_pending_store` convention).
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let queued = mem(&uid("pa2538"), ns, "needs approval", requester);
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
    // The agent-registry rows this suite creates live in the shared
    // `_agents` namespace, not in `ns_prefix`, so they need their own reap.
    // Every id this suite mints carries the `2538` discriminator.
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1 AND title LIKE '%2538%'")
        .bind(ai_memory::models::AGENTS_NAMESPACE)
        .execute(pool)
        .await;
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

/// R-203 CORE: the designated approver IS the requester. Pre-fix this returned
/// `Approved` on postgres through BOTH entry points.
#[tokio::test]
async fn named_approver_cannot_self_approve_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("authz2538-self");
    let alice = uid("ai:alice2538");
    // The namespace's DESIGNATED approver is alice, and alice is also the
    // requester — the exact separation-of-duties violation the arm forbids.
    seed_agent_approver_ns(&store, &ns, &uid("ai:owner2538"), &alice).await;
    register(&store, &alice).await;
    let ctx = CallerContext::for_agent(&alice);

    // (1) TRAIT-DEFAULT route — `approve_with_approver_type` is overridden by
    //     SqliteStore only, so postgres reaches the fix through the default's
    //     delegation to `governance_approve_with_consensus`. A sqlite-only fix
    //     would return `Approved` here.
    let pid_default = seed_pending(&store, &ns, &alice).await;
    let via_default = store
        .approve_with_approver_type(&ctx, &pid_default, &alice)
        .await
        .expect("approve_with_approver_type");

    // (2) The concrete postgres implementation, driven directly.
    let pid_concrete = seed_pending(&store, &ns, &alice).await;
    let via_concrete = store
        .governance_approve_with_consensus(&ctx, &pid_concrete, &alice)
        .await
        .expect("governance_approve_with_consensus");

    cleanup(&store, &ns).await;

    for (label, outcome) in [
        ("trait-default approve_with_approver_type", via_default),
        ("concrete governance_approve_with_consensus", via_concrete),
    ] {
        match outcome {
            ApproveOutcome::Rejected(m) => assert!(
                m.contains("self-approval"),
                "[{label}] named approver must not self-approve, got: {m}"
            ),
            other => {
                panic!("[{label}] expected self-approval rejection, got {other:?}");
            }
        }
    }
}

/// A designated approver the operator never REGISTERED is refused, mirroring
/// the Human arm (#1793) and the Consensus arm (#216) — "claim any string"
/// is raised to "the operator pre-registered this id". Pre-fix: `Approved`.
#[tokio::test]
async fn unregistered_named_approver_refused_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("authz2538-unreg");
    let requester = uid("ai:req2538");
    let approver = uid("ai:ghost2538"); // deliberately never registered
    seed_agent_approver_ns(&store, &ns, &uid("ai:owner2538"), &approver).await;

    let pid = seed_pending(&store, &ns, &requester).await;
    let outcome = store
        .approve_with_approver_type(&CallerContext::for_agent(&approver), &pid, &approver)
        .await
        .expect("approve_with_approver_type");
    cleanup(&store, &ns).await;

    match outcome {
        ApproveOutcome::Rejected(m) => assert!(
            m.contains("not a registered agent"),
            "unregistered designated approver must be refused, got: {m}"
        ),
        other => panic!("expected unregistered rejection, got {other:?}"),
    }
}

/// LIVENESS — the gate narrows the arm, it does not brick it. A REGISTERED
/// designated approver who is NOT the requester still approves, and the
/// pre-existing wrong-approver refusal is unchanged and still fires FIRST
/// (so the new checks never leak whether some other id is registered).
#[tokio::test]
async fn registered_non_requester_named_approver_still_approves_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("authz2538-live");
    let requester = uid("ai:req2538live");
    let approver = uid("ai:maint2538");
    seed_agent_approver_ns(&store, &ns, &uid("ai:owner2538"), &approver).await;
    register(&store, &approver).await;

    // Wrong approver → the ORIGINAL message, ahead of the new gate.
    let pid_wrong = seed_pending(&store, &ns, &requester).await;
    let wrong = store
        .approve_with_approver_type(
            &CallerContext::for_agent("ai:mallory2538"),
            &pid_wrong,
            "ai:mallory2538",
        )
        .await
        .expect("approve wrong");

    // Correct, registered, non-requester approver → Approved.
    let pid_ok = seed_pending(&store, &ns, &requester).await;
    let ok = store
        .approve_with_approver_type(&CallerContext::for_agent(&approver), &pid_ok, &approver)
        .await
        .expect("approve ok");

    cleanup(&store, &ns).await;

    match wrong {
        ApproveOutcome::Rejected(m) => assert!(
            m.contains("designated approver is"),
            "wrong-approver message must be unchanged, got: {m}"
        ),
        other => panic!("expected wrong-approver rejection, got {other:?}"),
    }
    assert!(
        matches!(ok, ApproveOutcome::Approved),
        "registered non-requester designated approver must approve, got {ok:?}"
    );
}
