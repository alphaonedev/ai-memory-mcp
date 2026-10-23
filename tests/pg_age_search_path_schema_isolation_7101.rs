// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7101: AGE projection must preserve the configured relational schema.

#![cfg(feature = "sal")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

#[cfg(feature = "sal-postgres")]
#[path = "common/lane_db.rs"]
mod lane_db;
#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

const AGENT: &str = "ai:7101";
const NAMESPACE: &str = "schema-isolation-7101";
const DESTINATION: &str = "destination-7101";
const SOURCE_IDS: [&str; 3] = ["first-7101", "second-7101", "third-7101"];
const SUMMARY: &str = "consolidated schema isolation evidence";
const CREATED_AT: &str = "2026-01-01T00:00:00Z";
static FLAGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct LineageFlags;

impl LineageFlags {
    fn enable() -> Self {
        ai_memory::config::set_lineage_dag(true);
        ai_memory::config::set_consolidate_tombstone_sources(true);
        Self
    }
}

impl Drop for LineageFlags {
    fn drop(&mut self) {
        ai_memory::config::set_consolidate_tombstone_sources(false);
        ai_memory::config::set_lineage_dag(false);
    }
}

async fn seed(store: &dyn MemoryStore, ids: &[&str]) {
    let ctx = CallerContext::for_agent(AGENT);
    for id in ids {
        let memory = Memory {
            id: id.to_string(),
            title: id.to_string(),
            content: format!("original {id}"),
            namespace: NAMESPACE.to_string(),
            tier: Tier::Long,
            created_at: CREATED_AT.to_string(),
            updated_at: CREATED_AT.to_string(),
            metadata: serde_json::json!({"agent_id": AGENT}),
            ..Memory::default()
        };
        store.store(&ctx, &memory).await.expect("seed fixture");
    }
}

async fn consolidate(store: &dyn MemoryStore, versions: &[i64]) -> Result<String, StoreError> {
    store
        .consolidate_with_expected_versions(
            &CallerContext::for_agent(AGENT),
            &SOURCE_IDS.map(str::to_string),
            DESTINATION,
            SUMMARY,
            NAMESPACE,
            &Tier::Long,
            "consolidation",
            AGENT,
            Some(versions),
        )
        .await
}

async fn reject_stale_versions(store: &dyn MemoryStore) -> Vec<i64> {
    let ctx = CallerContext::for_agent(AGENT);
    let mut originals = Vec::new();
    for id in SOURCE_IDS {
        originals.push(store.get(&ctx, id).await.expect("fixture exists"));
    }
    let versions: Vec<_> = originals[..SOURCE_IDS.len()]
        .iter()
        .map(|m| m.version)
        .collect();
    let mut stale = versions.clone();
    stale[0] -= 1;
    assert!(
        matches!(
            consolidate(store, &stale).await,
            Err(StoreError::Conflict { .. })
        ),
        "stale versions must fail closed"
    );
    for original in originals {
        let after = store
            .get(&ctx, &original.id)
            .await
            .expect("refused source survives");
        assert_eq!(after.content, original.content, "refusal preserves content");
        assert_eq!(after.version, original.version, "refusal preserves version");
        assert_eq!(
            after.lifecycle_state, original.lifecycle_state,
            "refusal preserves lifecycle"
        );
    }
    assert!(
        store
            .list_links(None)
            .await
            .expect("links after refusal")
            .is_empty()
    );
    versions
}

async fn assert_healthy_lineage(store: &dyn MemoryStore, destination: &str) {
    let links = store.list_links(None).await.expect("committed lineage");
    assert_eq!(
        links.len(),
        SOURCE_IDS.len(),
        "all edges stay in the configured store"
    );
    for id in SOURCE_IDS {
        assert!(links.iter().any(|link| link.source_id == destination
            && link.target_id == id
            && link.relation == ai_memory::models::MemoryLinkRelation::DerivedFrom));
    }
}

#[tokio::test]
async fn sqlite_consolidation_refusal_and_healthy_control() {
    let _lock = FLAGS.lock().await;
    let _flags = LineageFlags::enable();
    let scratch = tempfile::tempdir().expect("sqlite scratch");
    let store = ai_memory::store::sqlite::SqliteStore::open(scratch.path().join("memory.db"))
        .expect("sqlite store");
    seed(&store, &SOURCE_IDS).await;
    let versions = reject_stale_versions(&store).await;
    let destination = consolidate(&store, &versions)
        .await
        .expect("healthy consolidation");
    assert_healthy_lineage(&store, &destination).await;
}

#[cfg(feature = "sal-postgres")]
async fn public_snapshot(pool: &sqlx::PgPool) -> Vec<serde_json::Value> {
    // Include complete row payloads, so even an UPDATE that preserves counts is visible.
    let mut snapshot = Vec::new();
    for table in ["memories", "memory_links", "memory_revisions"] {
        let value = sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb) FROM public.{table} t"
        ))
        .fetch_one(pool)
        .await
        .expect("public snapshot");
        snapshot.push(value);
    }
    snapshot
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn age_preserves_configured_schema_and_public_rows() {
    use ai_memory::store::KgBackend;
    use ai_memory::store::postgres::PostgresStore;

    const SCRATCH_PREFIX: &str = "ai_memory_7101";
    const TENANT_OPTIONS: &str = "options=-c%20search_path=tenant_7101,public";
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset; #7101 postgres cell NOT executed");
        return;
    };
    lane_db::assert_lane_database(&url);
    let _lock = FLAGS.lock().await;
    let _flags = LineageFlags::enable();
    let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
        .await
        .expect("private scratch database");
    let scratch_url = scratch.url();
    let admin = sqlx::PgPool::connect(&scratch_url)
        .await
        .expect("scratch pool");
    sqlx::raw_sql("CREATE EXTENSION vector; CREATE EXTENSION age; CREATE SCHEMA tenant_7101;")
        .execute(&admin)
        .await
        .expect("native AGE/vector and tenant schema");
    let separator = if scratch_url.contains('?') { '&' } else { '?' };
    let tenant_url = format!("{scratch_url}{separator}{TENANT_OPTIONS}");
    let tenant = PostgresStore::connect(&tenant_url)
        .await
        .expect("tenant store");
    // Bootstrap tenant tables before public tables can satisfy IF NOT EXISTS lookups.
    let public = PostgresStore::connect(&scratch_url)
        .await
        .expect("public store");
    // Matching IDs in public ensure a wrong-schema write can satisfy its foreign keys.
    seed(&public, &SOURCE_IDS).await;
    seed(&public, &[DESTINATION]).await;
    assert_eq!(
        tenant.kg_backend(),
        KgBackend::Age,
        "must exercise real AGE"
    );
    assert_eq!(
        ai_memory::config::age_projection_mode(),
        ai_memory::config::AgeProjectionMode::Sync
    );
    seed(&tenant, &SOURCE_IDS).await;
    seed(&tenant, &[DESTINATION]).await;
    let before = public_snapshot(&admin).await;
    let versions = reject_stale_versions(&tenant).await;
    assert_eq!(
        public_snapshot(&admin).await,
        before,
        "refusal leaves public untouched"
    );
    let result = consolidate(&tenant, &versions).await;
    assert_eq!(
        public_snapshot(&admin).await,
        before,
        "AGE must never redirect relational writes into public"
    );
    assert_eq!(
        result.expect("healthy tenant consolidation commits"),
        DESTINATION
    );
    assert_healthy_lineage(&tenant, DESTINATION).await;
    let projected: i64 = sqlx::query_scalar("SELECT count(*) FROM memory_graph.derived_from")
        .fetch_one(&admin)
        .await
        .expect("real AGE projection exists");
    assert_eq!(
        projected,
        i64::try_from(SOURCE_IDS.len()).expect("source count fits")
    );
    let tombstones: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tenant_7101.memories WHERE lifecycle_state = 'tombstoned'",
    )
    .fetch_one(&admin)
    .await
    .expect("tenant tombstones");
    assert_eq!(
        tombstones,
        i64::try_from(SOURCE_IDS.len()).expect("source count fits")
    );
    tenant.pool().close().await;
    public.pool().close().await;
    admin.close().await;
}
