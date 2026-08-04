// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2633 — the postgres `find_paths` path-traversal visibility filter carried
//! its OWN inline copy of the scope predicate, and that copy had drifted twice.
//!
//! `<PostgresStore as MemoryStore>::find_paths` filters each returned path by
//! resolving every node's `metadata` and applying a visibility check. Until
//! this fix that check was written out longhand:
//!
//! ```ignore
//! if scope != MemoryScope::Private.as_str() { true } else { owner == caller }
//! ```
//!
//! with a comment asserting it matched `crate::visibility::is_visible_to_caller`.
//! It did not, in two independent ways:
//!
//! 1. **#2633** — an UNRECOGNISED `metadata.scope` token (a typo: `"privat"`,
//!    `"sharedd"`, `"Private"`) is `!= "private"`, so the node was treated as
//!    world-readable. That is this issue's defect, reachable through a second
//!    funnel that a fix to `src/visibility.rs` alone would not have closed.
//! 2. **#1921 residual** — `team` / `unit` / `org` are also `!= "private"`, so
//!    they were WORLD-READABLE here long after #1921 restricted them to the
//!    caller's namespace subtree on every other read path. Converging this
//!    call site onto the canonical predicate closes that too; it is a strictly
//!    NARROWING change (fewer paths returned, never more).
//!
//! Both are cross-tenant disclosure on a postgres-backed daemon: `find_paths`
//! returns memory IDs, and an id is the key to `GET /memories/{id}`.
//!
//! **R-203 (parent `5449b6da`):** `find_paths_drops_typo_scope_node_pg` FAILED
//! with `path through a typo'd-scope node must be dropped` and
//! `find_paths_drops_team_scope_node_outside_subtree_pg` FAILED with
//! `path through an out-of-subtree team node must be dropped` — the pre-fix
//! inline predicate returned `true` for both. `find_paths_keeps_visible_nodes_pg`
//! passes in both states and is the liveness leg.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset. No schema
//! change; uuid-randomised ids; every seeded row reaped in-test (#2287).

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::models::{
    ConfidenceSource, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

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

fn node(id: &str, ns: &str, owner: &str, scope: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = match scope {
        Some(s) => serde_json::json!({ "agent_id": owner, "scope": s }),
        None => serde_json::json!({ "agent_id": owner }),
    };
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("t-{id}"),
        content: "body".to_string(),
        tags: vec!["fp2633".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "fp2633".to_string(),
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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    }
}

async fn edge(store: &PostgresStore, ctx: &CallerContext, from: &str, to: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .link(
            ctx,
            &MemoryLink {
                source_id: from.to_string(),
                target_id: to.to_string(),
                relation: MemoryLinkRelation::RelatedTo,
                created_at: now.clone(),
                valid_from: Some(now),
                valid_until: None,
                observed_by: None,
                signature: None,
                attest_level: None,
                source_cid: None,
                target_cid: None,
            },
        )
        .await
        .expect("link");
}

async fn cleanup(store: &PostgresStore, ns_prefix: &str) {
    let pool = store.pool();
    let _ = sqlx::query(
        "DELETE FROM memory_links WHERE source_id IN \
         (SELECT id FROM memories WHERE namespace LIKE $1) \
         OR target_id IN (SELECT id FROM memories WHERE namespace LIKE $1)",
    )
    .bind(format!("{ns_prefix}%"))
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
        .bind(format!("{ns_prefix}%"))
        .execute(pool)
        .await;
}

/// Seed `A -> MID -> B` where MID carries `mid_scope` in `mid_ns`, and return
/// the paths `find_paths` yields for `caller`. A and B are `collective`, so the
/// ONLY thing that can drop the path is MID's visibility.
async fn paths_through_mid(
    store: &PostgresStore,
    root: &str,
    mid_ns: &str,
    mid_scope: Option<&str>,
    caller: &str,
) -> Vec<Vec<String>> {
    let owner = uid("ai:victim2633");
    let ctx = CallerContext::for_admin(&owner);
    let a = uid("fp-a");
    let m = uid("fp-m");
    let b = uid("fp-b");
    for n in [
        node(&a, &format!("{root}/ends"), &owner, Some("collective")),
        node(&m, mid_ns, &owner, mid_scope),
        node(&b, &format!("{root}/ends"), &owner, Some("collective")),
    ] {
        store.store(&ctx, &n).await.expect("store node");
    }
    edge(store, &ctx, &a, &m).await;
    edge(store, &ctx, &m, &b).await;

    // The TRAIT method explicitly: the inherent `PostgresStore::find_paths`
    // (4 args, no ctx) SHADOWS it and carries NO visibility filter at all —
    // the trait impl is the one that applies the #910 SAL-level gate this
    // test is about, and it is what every handler reaches through
    // `Arc<dyn MemoryStore>`.
    MemoryStore::find_paths(
        store,
        &CallerContext::for_agent(caller),
        &a,
        &b,
        Some(4),
        Some(20),
    )
    .await
    .expect("find_paths")
}

/// R-203 CORE — a node whose scope is a TYPO must not publish the path.
#[tokio::test]
async fn find_paths_drops_typo_scope_node_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let root = uid("fp2633-typo");
    for token in ["privat", "sharedd", "Private", "public"] {
        let mid_ns = format!("{root}/secret");
        let paths = paths_through_mid(&store, &root, &mid_ns, Some(token), "ai:mallory2633").await;
        assert!(
            paths.is_empty(),
            "path through a typo'd-scope node must be dropped (scope={token:?}), got {paths:?}"
        );
    }
    cleanup(&store, &root).await;
}

/// R-203 — the #1921 residual on this same call site: a `team`-scoped node
/// OUTSIDE the caller's subtree must not publish the path either.
#[tokio::test]
async fn find_paths_drops_team_scope_node_outside_subtree_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let root = uid("fp2633-team");
    let mid_ns = format!("{root}/victimorg/unitB/teamC");
    let paths = paths_through_mid(
        &store,
        &root,
        &mid_ns,
        Some("team"),
        "attackerorg/unitZ/teamZ/mallory",
    )
    .await;
    assert!(
        paths.is_empty(),
        "path through an out-of-subtree team node must be dropped, got {paths:?}"
    );
    cleanup(&store, &root).await;
}

/// LIVENESS — the converged predicate still returns paths it should. A
/// `collective` middle node, and a `private` middle node read by its OWNER,
/// both keep the path. This leg passes before AND after the fix; without it a
/// predicate that simply returned `false` would look like a successful fix.
#[tokio::test]
async fn find_paths_keeps_visible_nodes_pg() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let root = uid("fp2633-live");
    let mid_ns = format!("{root}/open");
    let paths = paths_through_mid(&store, &root, &mid_ns, Some("collective"), "ai:anyone").await;
    assert!(
        !paths.is_empty(),
        "a collective middle node must keep the path visible"
    );
    cleanup(&store, &root).await;

    // Owner reading their own private middle node.
    let root2 = uid("fp2633-owner");
    let owner = uid("ai:owner2633");
    let ctx = CallerContext::for_admin(&owner);
    let a = uid("fp-a");
    let m = uid("fp-m");
    let b = uid("fp-b");
    for n in [
        node(&a, &format!("{root2}/ends"), &owner, Some("collective")),
        node(&m, &format!("{root2}/mine"), &owner, Some("private")),
        node(&b, &format!("{root2}/ends"), &owner, Some("collective")),
    ] {
        store.store(&ctx, &n).await.expect("store node");
    }
    edge(&store, &ctx, &a, &m).await;
    edge(&store, &ctx, &m, &b).await;

    let owner_paths = MemoryStore::find_paths(
        &store,
        &CallerContext::for_agent(&owner),
        &a,
        &b,
        Some(4),
        Some(20),
    )
    .await
    .expect("find_paths");
    assert!(
        !owner_paths.is_empty(),
        "the owner must still traverse their own private node"
    );

    let stranger_paths = MemoryStore::find_paths(
        &store,
        &CallerContext::for_agent("ai:stranger2633"),
        &a,
        &b,
        Some(4),
        Some(20),
    )
    .await
    .expect("find_paths");
    assert!(
        stranger_paths.is_empty(),
        "a stranger must NOT traverse someone else's private node (pre-existing #910 gate)"
    );
    cleanup(&store, &root2).await;
}
