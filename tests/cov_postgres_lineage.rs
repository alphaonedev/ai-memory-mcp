// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G13-mem (#1859) — live-Postgres integration coverage for the
//! memory-derivation lineage-DAG (`PostgresStore::lineage_traverse` /
//! `lineage_cte` / `lineage_cypher`, the consolidate tombstone path, the
//! COND-1 single CONSOLIDATE-leaf emission, and the `memory_links`
//! `source_cid`/`target_cid` mirror population in `link_internal`).
//!
//! Both-backend parity: the fixtures + assertions mirror
//! `tests/lineage_dag_g13.rs` (the sqlite twin) so the wire shape
//! `{id, cid, relation, depth}` cannot drift between adapters. The AGE
//! branch is exercised implicitly when the target DB carries the
//! extension (the runtime `KgBackend` detection picks the live path,
//! with the CTE fallback taking over otherwise) and EXPLICITLY via
//! `lineage_cte` so the relational walk is pinned on both postures.
//! COND 5(a) is pinned by `lineage_age_deferred_mode_routes_to_cte`:
//! under `AgeProjectionMode::Deferred` a freshly-written edge must be
//! readable in the same request (read-your-own-write) because the
//! dispatcher reroutes to the relational CTE.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names
)]
// The process-wide lineage-flag atomics MUST stay pinned for the whole
// test body (including its awaits) or a parallel test could flip them
// mid-assertion; each #[tokio::test] runs on its own runtime thread, so
// holding the std Mutex across awaits here cannot deadlock — it merely
// serializes the file's tests, which is the point.
#![allow(clippy::await_holding_lock)]

use std::sync::Mutex;

use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

/// Serializes the tests: the lineage flags are process-wide atomics.
static FLAG_LOCK: Mutex<()> = Mutex::new(());

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lineage_on() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

fn lineage_off() {
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    ai_memory::config::set_append_only(false);
}

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

async fn raw_pool() -> Option<sqlx::PgPool> {
    let url = postgres_url()?;
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect raw pool"),
    )
}

fn mem(id: &str, ns: &str, title: &str, content: &str, created_at: &str) -> Memory {
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["lineage-g13".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "consolidation".to_string(),
        access_count: 0,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:lineage-test" }),
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
        lifecycle_state: LifecycleState::Open,
    }
}

fn link(src: &str, tgt: &str, relation: MemoryLinkRelation, created_at: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation,
        created_at: created_at.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(created_at.to_string()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

async fn consolidate_leaf_count(pool: &sqlx::PgPool, ids: &[&str]) -> i64 {
    let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory_revisions \
         WHERE kind = 'CONSOLIDATE' AND memory_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_one(pool)
    .await
    .expect("count CONSOLIDATE leaves")
}

// ---------------------------------------------------------------------------
// 1. Multi-hop ancestry across the consolidation boundary (the acceptance
//    test), postgres side.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_multi_hop_ancestry_store_reflect_consolidate() {
    let Some(store) = connect().await else { return };
    let Some(pool) = raw_pool().await else { return };
    let _g = flag_guard();
    lineage_on();

    let ns = format!("lineage-g13-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:lineage-test");
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let r = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &mem(&a, &ns, "A", "base a", "2026-01-01T00:00:00+00:00"),
        )
        .await
        .unwrap();
    store
        .store(
            &ctx,
            &mem(&b, &ns, "B", "base b", "2026-01-02T00:00:00+00:00"),
        )
        .await
        .unwrap();
    store
        .store(
            &ctx,
            &mem(&r, &ns, "R", "reflection", "2026-03-01T00:00:00+00:00"),
        )
        .await
        .unwrap();

    // R reflects_on A and B — link_internal stamps the cid mirror.
    store
        .link(
            &ctx,
            &link(
                &r,
                &a,
                MemoryLinkRelation::ReflectsOn,
                "2026-03-01T00:00:01+00:00",
            ),
        )
        .await
        .unwrap();
    store
        .link(
            &ctx,
            &link(
                &r,
                &b,
                MemoryLinkRelation::ReflectsOn,
                "2026-03-01T00:00:01+00:00",
            ),
        )
        .await
        .unwrap();
    let (edge_source_cid, edge_target_cid): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT source_cid, target_cid FROM memory_links \
             WHERE source_id = $1 AND target_id = $2",
    )
    .bind(&r)
    .bind(&a)
    .fetch_one(&pool)
    .await
    .unwrap();
    let a_cid: Option<String> = sqlx::query_scalar("SELECT cid FROM memories WHERE id = $1")
        .bind(&a)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        edge_source_cid.is_some(),
        "lineage-on pg edge must carry the source cid mirror"
    );
    assert_eq!(
        edge_target_cid, a_cid,
        "pg edge target_cid mirrors memories.cid at link-creation time"
    );

    // Consolidate [R] into C.
    let c = store
        .consolidate(
            &ctx,
            std::slice::from_ref(&r),
            "C",
            "consolidated",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:consolidator",
        )
        .await
        .unwrap();

    // R is tombstoned yet still resident.
    let r_state: String = sqlx::query_scalar("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(&r)
        .fetch_one(&pool)
        .await
        .expect("tombstoned R must remain resident in memories");
    assert_eq!(r_state, "tombstoned");

    // EXACTLY ONE CONSOLIDATE leaf for the single source (COND 1).
    assert_eq!(
        consolidate_leaf_count(&pool, &[r.as_str()]).await,
        1,
        "exactly one CONSOLIDATE leaf per source (not >= 1)"
    );

    // Multi-hop ancestry through the dispatcher (AGE or CTE, whichever the
    // live DB resolved).
    let ancestors = store.lineage_ancestors(&c, 5).await.unwrap();
    let mut ids: Vec<String> = ancestors.iter().map(|n| n.id.clone()).collect();
    ids.sort();
    let mut want = vec![a.clone(), b.clone(), r.clone()];
    want.sort();
    assert_eq!(ids, want, "ancestors of C must be exactly {{R, A, B}}");
    for n in &ancestors {
        assert!(n.cid.is_some(), "node {} must resolve a cid", n.id);
    }
    let r_node = ancestors.iter().find(|n| n.id == r).unwrap();
    assert_eq!(r_node.depth, 1);
    assert_eq!(r_node.relation, "derived_from");

    // Explicit CTE-branch parity (pins the relational walk even when the
    // dispatcher resolved AGE above).
    let cte = store.lineage_cte(&c, 5, true).await.unwrap();
    let mut cte_ids: Vec<String> = cte.iter().map(|n| n.id.clone()).collect();
    cte_ids.sort();
    assert_eq!(cte_ids, want, "CTE branch matches the dispatcher result");

    // Descendants are the reverse walk: A's descendants include R and C.
    let desc = store.lineage_descendants(&a, 5).await.unwrap();
    assert!(desc.iter().any(|n| n.id == r), "R descends from A");
    assert!(desc.iter().any(|n| n.id == c), "C descends from A (2 hops)");

    lineage_off();
}

// ---------------------------------------------------------------------------
// 2. COND 5(a) — AGE + Deferred projection mode must route to the CTE so a
//    freshly-written edge is read-your-own-write visible.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_lineage_age_deferred_mode_routes_to_cte() {
    let Some(store) = connect().await else { return };
    let _g = flag_guard();
    lineage_on();

    let ns = format!("lineage-g13-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:lineage-test");
    let a = uuid::Uuid::new_v4().to_string();
    let r = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &mem(&a, &ns, "A", "base", "2026-01-01T00:00:00+00:00"),
        )
        .await
        .unwrap();
    store
        .store(
            &ctx,
            &mem(&r, &ns, "R", "derived", "2026-03-01T00:00:00+00:00"),
        )
        .await
        .unwrap();

    // Flip to Deferred BEFORE the link write: the edge lands relationally +
    // in kg_projection_outbox only (no inline AGE MERGE). A dispatcher that
    // consulted stale AGE would see a successful-EMPTY ancestry here.
    ai_memory::config::set_age_projection_mode(ai_memory::config::AgeProjectionMode::Deferred);
    let outcome = async {
        store
            .link(
                &ctx,
                &link(
                    &r,
                    &a,
                    MemoryLinkRelation::DerivesFrom,
                    "2026-03-01T00:00:01+00:00",
                ),
            )
            .await
            .unwrap();
        store.lineage_ancestors(&r, 5).await
    }
    .await;
    // Restore sync mode before asserting so a failure can't leak the mode.
    ai_memory::config::set_age_projection_mode(ai_memory::config::AgeProjectionMode::Sync);

    let ancestors = outcome.unwrap();
    assert!(
        ancestors.iter().any(|n| n.id == a),
        "deferred-mode lineage must read its own write via the CTE reroute"
    );
    lineage_off();
}

// ---------------------------------------------------------------------------
// 3. Flags OFF preserve the legacy hard-delete + append-only-only emission.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_consolidate_flag_off_preserves_legacy_and_append_only_emits() {
    let Some(store) = connect().await else { return };
    let Some(pool) = raw_pool().await else { return };
    let _g = flag_guard();

    // (a) All flags OFF — hard delete, no leaf.
    lineage_off();
    let ns = format!("lineage-g13-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:lineage-test");
    let x = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&x, &ns, "X", "x", "2026-02-01T00:00:00+00:00"))
        .await
        .unwrap();
    store
        .consolidate(
            &ctx,
            std::slice::from_ref(&x),
            "XC",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:consolidator",
        )
        .await
        .unwrap();
    let x_gone: Option<String> = sqlx::query_scalar("SELECT id FROM memories WHERE id = $1")
        .bind(&x)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(x_gone.is_none(), "flags OFF hard-delete the source");
    assert_eq!(
        consolidate_leaf_count(&pool, &[x.as_str()]).await,
        0,
        "flags OFF emit no CONSOLIDATE leaf"
    );

    // (b) append-only ON + tombstone OFF — legacy delete + exactly one leaf
    //     (the shared COND-1 predicate).
    ai_memory::config::set_append_only(true);
    let y = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&y, &ns, "Y", "y", "2026-02-01T00:00:00+00:00"))
        .await
        .unwrap();
    store
        .consolidate(
            &ctx,
            std::slice::from_ref(&y),
            "YC",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:consolidator",
        )
        .await
        .unwrap();
    ai_memory::config::set_append_only(false);
    assert_eq!(
        consolidate_leaf_count(&pool, &[y.as_str()]).await,
        1,
        "append-only alone emits exactly one leaf per source"
    );
}

// ---------------------------------------------------------------------------
// 4. Depth budget parity with the sqlite twin.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_lineage_depth_budget_is_enforced() {
    let Some(store) = connect().await else { return };
    let _g = flag_guard();
    lineage_on();

    let err = store
        .lineage_ancestors("00000000-0000-0000-0000-000000000000", 0)
        .await
        .expect_err("depth 0 refused");
    assert!(err.to_string().contains("max_depth"), "got: {err}");
    let err = store
        .lineage_ancestors(
            "00000000-0000-0000-0000-000000000000",
            ai_memory::db::LINEAGE_MAX_DEPTH + 1,
        )
        .await
        .expect_err("depth over budget refused");
    assert!(err.to_string().contains("max_depth"), "got: {err}");
    lineage_off();
}
