// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
//! Boids predator plan item 3 (#3266 / #3922, 5-agent vote `4d3ea1c5`) — the
//! postgres `swarm_rewind` (store level). Before item 3 the MVG rewind was
//! SQLite-only: `PostgresStore` had no implementation, so an enterprise
//! Postgres fleet could not contain a cascade (the Boids review's T7
//! UNCONTROLLED finding).
//!
//! Live-PG cells: `#[ignore]`-gated (the postgres-ignored tier) AND skipped
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset. RED on the parent: the trait
//! default returns `UnsupportedCapability`.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

const ISSUER: &str = "ai:rewind-admin";
/// The product lineage ceiling both backends clamp to (the MCP handler and the
/// route pass an already-clamped depth).
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

async fn connect() -> Option<PostgresStore> {
    static WARMED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    // On a FRESH database, parallel first-touch AGE label creation can defer
    // one `derives_from` edge's graph projection to the outbox, and the
    // (sync-mode AGE) lineage walk then misses it — a pre-existing
    // AGE-projection window, not what these cells measure. Seed one lineage
    // serially first so every cell's own edges project normally.
    WARMED
        .get_or_init(|| async {
            seed(&store).await;
        })
        .await;
    Some(store)
}

/// root <- child <- grandchild (`derives_from`), plus an off-DAG row, each in a
/// fresh namespace so cells never see each other's rows.
async fn seed(store: &PostgresStore) -> (Memory, Memory, Memory, Memory) {
    let ns = format!("rewind-{}", uuid::Uuid::new_v4().simple());
    let ctx = CallerContext::for_agent("ai:tester");
    let root = mem(&ns, "root");
    let child = mem(&ns, "child");
    let grandchild = mem(&ns, "grandchild");
    let off = mem(&ns, "off-dag");
    for m in [&root, &child, &grandchild, &off] {
        store.store(&ctx, m).await.expect("seed memory");
    }
    for (c, p) in [(&child, &root), (&grandchild, &child)] {
        let link = MemoryLink {
            source_id: c.id.clone(),
            target_id: p.id.clone(),
            relation: MemoryLinkRelation::DerivesFrom,
            created_at: chrono::Utc::now().to_rfc3339(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link(&ctx, &link).await.expect("derives_from edge");
    }
    (root, child, grandchild, off)
}

async fn state(store: &PostgresStore, id: &str) -> String {
    let (s,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .expect("read state");
    s
}

/// `swarm.rewind` events issued by THIS cell's `issuer` — scoped so cells
/// running in parallel against the shared database cannot skew the count.
async fn rewind_events(store: &PostgresStore, issuer: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM signed_events WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(ai_memory::signed_events::event_types::SWARM_REWIND)
    .bind(issuer)
    .fetch_one(store.pool())
    .await
    .expect("count events");
    n
}

/// A per-cell admin issuer (the event's `agent_id`), so event counts are
/// scoped to the cell.
fn cell_issuer() -> String {
    format!("{ISSUER}-{}", uuid::Uuid::new_v4().simple())
}

fn admin(issuer: &str) -> CallerContext {
    CallerContext::for_admin_checked(issuer, true)
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_swarm_rewind_stamps_root_and_descendants_3266() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    let (root, child, grandchild, off) = seed(&store).await;
    let r = store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], false)
        .await
        .expect("pg swarm_rewind must be implemented (RED on the parent: UnsupportedCapability)");
    assert!(r.root_contaminated, "root is stamped");
    assert_eq!(
        r.descendants_stamped, 2,
        "child + grandchild stamped: {r:?}"
    );
    assert_eq!(r.descendants_total, 2);
    assert!(r.signed_event_id.is_some(), "one signed swarm.rewind event");
    for id in [&root.id, &child.id, &grandchild.id] {
        assert_eq!(state(&store, id).await, "contaminated");
    }
    assert_eq!(
        state(&store, &off.id).await,
        "open",
        "off-DAG row untouched"
    );
    // Recall surfaces hide contaminated rows (the PG lifecycle fold).
    let ctx = CallerContext::for_agent("ai:tester");
    assert!(
        store.get(&ctx, &child.id).await.is_err(),
        "a contaminated descendant must not be readable through the lifecycle-folded get"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_swarm_rewind_idempotent_single_audit_3266() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    let (root, ..) = seed(&store).await;
    let before = rewind_events(&store, &issuer).await;
    store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], false)
        .await
        .expect("first rewind");
    let again = store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], false)
        .await
        .expect("second rewind is a no-op, not an error");
    assert!(again.already_rewound, "second call reports already_rewound");
    assert_eq!(again.signed_event_id, None, "no second audit event");
    assert_eq!(
        rewind_events(&store, &issuer).await,
        before + 1,
        "exactly ONE swarm.rewind appended"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_swarm_rewind_refuses_system_only_root_3266() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    let (root, child, ..) = seed(&store).await;
    sqlx::query("UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = $1")
        .bind(&root.id)
        .execute(store.pool())
        .await
        .expect("quarantine root");
    let before = rewind_events(&store, &issuer).await;
    let err = store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], false)
        .await
        .expect_err("a quarantined root is already contained");
    assert!(
        err.to_string().contains("system-only"),
        "typed refusal: {err}"
    );
    assert_eq!(
        state(&store, &child.id).await,
        "open",
        "zero writes on refusal"
    );
    assert_eq!(
        rewind_events(&store, &issuer).await,
        before,
        "no audit event on refusal"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_swarm_rewind_dry_run_zero_writes_3266() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    let (root, child, grandchild, _) = seed(&store).await;
    let before = rewind_events(&store, &issuer).await;
    let r = store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], true)
        .await
        .expect("dry run");
    assert!(r.dry_run);
    assert!(
        r.root_contaminated,
        "preview reports the root would be stamped"
    );
    assert_eq!(r.descendants_stamped, 2, "preview counts the cascade");
    for id in [&root.id, &child.id, &grandchild.id] {
        assert_eq!(state(&store, id).await, "open", "dry run writes nothing");
    }
    assert_eq!(
        rewind_events(&store, &issuer).await,
        before,
        "dry run appends no event"
    );
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_sqlite_contamination_marker_parity_3266() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    // Postgres side.
    let (root, child, ..) = seed(&store).await;
    store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], false)
        .await
        .expect("pg rewind");
    let (pg_meta,): (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM memories WHERE id = $1")
            .bind(&child.id)
            .fetch_one(store.pool())
            .await
            .expect("pg child metadata");
    // SQLite side, same shape.
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("sqlite");
    let (sr, sc) = (mem("p", "root"), mem("p", "child"));
    ai_memory::db::insert(&conn, &sr).expect("insert root");
    ai_memory::db::insert(&conn, &sc).expect("insert child");
    ai_memory::db::create_link(&conn, &sc.id, &sr.id, "derives_from").expect("edge");
    ai_memory::storage::swarm_rewind(&conn, &sr.id, DEPTH, ISSUER, "memory", &[], false)
        .expect("sqlite rewind");
    let sq_meta: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            [&sc.id],
            |r| r.get(0),
        )
        .expect("sqlite child metadata");
    let sq_meta: serde_json::Value = serde_json::from_str(&sq_meta).expect("json");

    let key = ai_memory::storage::CONTAMINATION_METADATA_KEY;
    let keys = |v: &serde_json::Value| -> Vec<String> {
        v[key]
            .as_object()
            .expect("marker object")
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(
        keys(&pg_meta),
        keys(&sq_meta),
        "same marker keys, same order, both backends"
    );
    for k in ["prior_lifecycle_state", "via"] {
        assert_eq!(
            pg_meta[key][k], sq_meta[key][k],
            "marker field {k} identical"
        );
    }
}

#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_swarm_rewind_cost_is_lineage_rollup_pg_3323() {
    let Some(store) = connect().await else { return };
    let issuer = cell_issuer();
    let (root, ..) = seed(&store).await;
    let r = store
        .swarm_rewind(&admin(&issuer), &root.id, DEPTH, "memory", &[], true)
        .await
        .expect("dry run");
    let rollup = ai_memory::cost::postgres::lineage_rollup_pg(store.pool(), &root.id, DEPTH)
        .await
        .expect("rollup");
    assert_eq!(r.cost.scope_key, rollup.scope_key);
    assert_eq!(r.cost.tokens_written, rollup.tokens_written);
    assert_eq!(
        r.cost.usd,
        rollup.usd_string(),
        "the rewind report reads the PG rollup"
    );
}
