// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3946: containment must see committed relational edges even when a healthy
//! AGE projection is missing them. No AGE catalog mutation or drainer races.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};
use serde_json::json;

const OWNER: &str = "ai:tester";
const DEPTH: usize = ai_memory::storage::LINEAGE_MAX_DEPTH;

fn mem(ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

fn edge(child: &Memory, parent: &Memory) -> MemoryLink {
    MemoryLink {
        source_id: child.id.clone(),
        target_id: parent.id.clone(),
        relation: MemoryLinkRelation::DerivesFrom,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

async fn pending_edge(store: &PostgresStore, child: &Memory, parent: &Memory) {
    // Reproduce the committed source-of-truth + queued projection state without
    // touching AGE catalogs (pooled backends may cache graph identifiers).
    let mut tx = store.pool().begin().await.expect("fixture transaction");
    for sql in [
        "INSERT INTO memory_links (source_id, target_id, relation) VALUES ($1, $2, $3)",
        "INSERT INTO kg_projection_outbox (source_id, target_id, relation) VALUES ($1, $2, $3)",
    ] {
        sqlx::query(sql)
            .bind(&child.id)
            .bind(&parent.id)
            .bind(MemoryLinkRelation::DerivesFrom.as_str())
            .execute(&mut *tx)
            .await
            .expect("pending relational edge");
    }
    tx.commit().await.expect("commit fixture");
}

async fn fixture() -> (PostgresStore, Memory, Memory, Memory) {
    static WARMED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("live test requires its own PostgreSQL/AGE database");
    let store = PostgresStore::connect(&url).await.expect("connect");
    assert_eq!(store.kg_backend(), KgBackend::Age);
    assert!(matches!(
        ai_memory::config::age_projection_mode(),
        ai_memory::config::AgeProjectionMode::Sync
    ));
    // Warm the label serially; all tested closures are distinct. This makes
    // successful-empty AGE (rather than an AGE error / CTE fallback) explicit.
    WARMED
        .get_or_init(|| async {
            let ns = format!("warm-3946-{}", uuid::Uuid::new_v4());
            let (root, child) = (mem(&ns, "root"), mem(&ns, "child"));
            let ctx = CallerContext::for_agent(OWNER);
            for m in [&root, &child] {
                store.store(&ctx, m).await.expect("warm memory");
            }
            store
                .link(&ctx, &edge(&child, &root))
                .await
                .expect("warm edge");
            assert_eq!(
                store
                    .lineage_cypher(&root.id, DEPTH, false)
                    .await
                    .expect("healthy AGE")
                    .len(),
                1
            );
        })
        .await;
    let ns = format!("containment-3946-{}", uuid::Uuid::new_v4());
    let (mut root, child, grandchild) =
        (mem(&ns, "root"), mem(&ns, "child"), mem(&ns, "grandchild"));
    root.memory_kind = MemoryKind::Reflection;
    root.reflection_depth = 1;
    for m in [&root, &child, &grandchild] {
        store
            .store(&CallerContext::for_agent(OWNER), m)
            .await
            .expect("product store");
    }
    pending_edge(&store, &child, &root).await;
    pending_edge(&store, &grandchild, &child).await;
    assert_eq!(
        store
            .lineage_cte(&root.id, DEPTH, false)
            .await
            .expect("relational truth")
            .len(),
        2
    );
    assert!(
        store
            .lineage_cypher(&root.id, DEPTH, false)
            .await
            .expect("healthy, stale AGE")
            .is_empty()
    );
    assert!(
        store
            .lineage_descendants(&root.id, DEPTH)
            .await
            .expect("general query retains AGE dispatch")
            .is_empty()
    );
    (store, root, child, grandchild)
}

async fn state(store: &PostgresStore, id: &str) -> String {
    sqlx::query_scalar("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("state")
}

async fn assert_pending(store: &PostgresStore, child: &Memory) {
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kg_projection_outbox WHERE source_id = $1 AND projected_at IS NULL",
    )
    .bind(&child.id)
    .fetch_one(store.pool())
    .await
    .expect("pending projection");
    assert_eq!(pending, 1, "containment must not rely on draining AGE");
}

#[tokio::test]
#[ignore = "live PostgreSQL/AGE: AI_MEMORY_TEST_POSTGRES_URL"]
async fn rewind_contains_pending_age_descendants_3946() {
    let (store, root, child, grandchild) = fixture().await;
    let admin = CallerContext::for_admin_checked("ai:rewind-3946", true);
    let preview = store
        .swarm_rewind(&admin, &root.id, 1, "memory", &[], true)
        .await
        .expect("preview");
    assert_eq!(
        state(&store, &child.id).await,
        "open",
        "dry run has zero writes"
    );
    let report = store
        .swarm_rewind(&admin, &root.id, DEPTH, "memory", &[], false)
        .await
        .expect("rewind");
    assert_eq!(
        state(&store, &child.id).await,
        "contaminated",
        "RED on 8d53e98d9: AGE misses committed child"
    );
    assert_eq!(state(&store, &grandchild.id).await, "contaminated");
    assert_eq!(
        preview.descendants_total, 1,
        "depth budget includes only child"
    );
    assert_eq!(report.descendants_total, 2);
    assert_eq!(report.descendants_stamped, 2);
    assert!(report.signed_event_id.is_some());
    let expected = ai_memory::cost::postgres::lineage_rollup_pg(store.pool(), &root.id, DEPTH)
        .await
        .expect("relational cost");
    assert_eq!(report.cost.tokens_written, expected.tokens_written);
    assert!(report.cost.tokens_written > 0);
    assert_pending(&store, &child).await;
}

#[tokio::test]
#[ignore = "live PostgreSQL/AGE: AI_MEMORY_TEST_POSTGRES_URL"]
async fn stamp_contains_pending_age_descendants_3946() {
    let (store, root, child, grandchild) = fixture().await;
    let report = store
        .stamp_contaminated_descendants_pg(&root.id, DEPTH)
        .await
        .expect("stamp");
    assert_eq!(report.stamped, 2);
    assert_eq!(state(&store, &root.id).await, "open");
    for m in [&child, &grandchild] {
        assert_eq!(state(&store, &m.id).await, "contaminated");
    }
    assert_pending(&store, &child).await;
}

#[tokio::test]
#[ignore = "live PostgreSQL/AGE: AI_MEMORY_TEST_POSTGRES_URL"]
async fn supersedes_contains_pending_age_descendants_with_caller_authority_3946() {
    let (store, root, child, grandchild) = fixture().await;
    // A private descendant belonging to another owner remains outside this
    // caller's mutation authority even though the relational walk reaches it.
    sqlx::query("UPDATE memories SET metadata = metadata || jsonb_build_object('agent_id', 'ai:victim') WHERE id = $1")
        .bind(&grandchild.id).execute(store.pool()).await.expect("victim fixture");
    let mut superseder = mem(&root.namespace, "superseder");
    superseder.memory_kind = MemoryKind::Reflection;
    superseder.reflection_depth = 1;
    let caller = CallerContext::for_agent(OWNER);
    store.store(&caller, &superseder).await.expect("superseder");
    let mut link = edge(&superseder, &root);
    link.relation = MemoryLinkRelation::Supersedes;
    store
        .link_signed(&caller, &link, None)
        .await
        .expect("supersedes");
    assert_eq!(state(&store, &child.id).await, "contaminated");
    assert_eq!(
        state(&store, &grandchild.id).await,
        "open",
        "authority remains fail-closed"
    );
    assert_eq!(state(&store, &root.id).await, "open");
    assert_pending(&store, &child).await;
}

#[tokio::test]
#[ignore = "live PostgreSQL/AGE: AI_MEMORY_TEST_POSTGRES_URL"]
async fn rewind_cost_uses_the_containment_node_set_3946() {
    let (store, root, child, grandchild) = fixture().await;
    sqlx::query("UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = $1")
        .bind(&child.id)
        .execute(store.pool())
        .await
        .expect("quarantine fixture");
    // Distinct exact counters make accidental inclusion of the hidden child
    // detectable independently of the product's rollup implementation.
    for (m, tokens) in [(&root, 10_i64), (&child, 100), (&grandchild, 1_000)] {
        sqlx::query("UPDATE token_cost_counters SET tokens_written = $1, tokens_recalled = $1, write_events = 1, recall_events = 1 WHERE scope_kind = $2 AND scope_key = $3")
            .bind(tokens).bind(ai_memory::cost::SCOPE_LINEAGE).bind(&m.id)
            .execute(store.pool()).await.expect("exact cost fixture");
    }
    let report = store
        .swarm_rewind(
            &CallerContext::for_admin_checked("ai:cost-3946", true),
            &root.id,
            DEPTH,
            "memory",
            &[],
            false,
        )
        .await
        .expect("rewind");
    assert_eq!(
        report.descendants_total, 1,
        "walk continues through hidden child"
    );
    assert_eq!(report.descendants_stamped, 1);
    assert_eq!(state(&store, &child.id).await, "quarantined");
    assert_eq!(state(&store, &grandchild.id).await, "contaminated");
    assert_eq!(
        report.cost.tokens_written, 1_010,
        "only root + selected grandchild"
    );
    assert_eq!(report.cost.tokens_recalled, 1_010);
    assert_eq!(report.cost.write_events, 2);
    assert_eq!(report.cost.recall_events, 2);
}
