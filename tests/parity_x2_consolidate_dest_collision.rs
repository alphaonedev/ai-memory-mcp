// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X2 — `MemoryStore::consolidate` onto an already-occupied
//! destination `(title, namespace)` slot, one scenario and one expected
//! outcome per backend.
//!
//! - #7111: postgres upserts the summary onto an existing same-owner row of
//!   that title (the surviving id is returned, the sources are consumed) and
//!   refuses a HIDDEN holder with a typed, unnamed `StoreError::Conflict`.
//!   sqlite ran a plain `INSERT` and failed with a raw UNIQUE violation
//!   flattened to `StoreError::Backend`. Both backends must agree.
//!
//! The postgres cells connect to the shared test database named by
//! `AI_MEMORY_TEST_POSTGRES_URL` (the tombstone path writes `memory_links`,
//! whose foreign keys the per-test schema does not carry) and use a unique
//! namespace per cell. They skip cleanly without the variable.

#![cfg(feature = "sal")]

use ai_memory::models::{LifecycleState, Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError};
use serde_json::json;

const OWNER: &str = "ai:owner-x2-dest";

fn unique_ns(cell: &str) -> String {
    format!("parity-x2d-{cell}-{}", uuid::Uuid::new_v4().simple())
}

fn row(ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        ..Default::default()
    }
}

/// Process-wide flags, set once and never reset (cells run concurrently).
fn enable_tombstone_path() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

async fn rows_in_ns(store: &dyn MemoryStore, ctx: &CallerContext, ns: &str) -> Vec<Memory> {
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    // `Filter::new()` carries limit 0, which both adapters clamp to ONE row.
    filter.limit = 100;
    let mut rows = store.list(ctx, &filter).await.expect("list");
    rows.sort_by(|a, b| a.title.cmp(&b.title));
    rows
}

/// Control: a fresh destination title consolidates as before.
async fn fresh_destination_control(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("fresh");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a fresh", "alpha");
    let b = row(&ns, "b fresh", "beta");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest fresh",
            "merged fresh",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("a fresh destination consolidates");
    let rows = rows_in_ns(store, &ctx, &ns).await;
    assert_eq!(rows.len(), 1, "only the summary stays visible");
    assert_eq!(rows[0].id, id);
}

/// #7111 scenario A: the destination title is already held by a visible
/// same-owner row. The consolidation merges into it in place and returns the
/// SURVIVING id; the sources leave the visible set; no duplicate title.
async fn existing_destination_is_upserted(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("upsert");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a upsert", "alpha");
    let b = row(&ns, "b upsert", "beta");
    let dest = row(&ns, "dest upsert", "old destination content");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store.store(&ctx, &dest).await.expect("seed destination");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest upsert",
            "merged upsert",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("#7111: consolidate onto an existing same-owner title upserts");
    assert_eq!(
        id, dest.id,
        "#7111: the surviving destination id is returned"
    );
    let rows = rows_in_ns(store, &ctx, &ns).await;
    assert_eq!(
        rows.len(),
        1,
        "#7111: one destination row, sources consumed"
    );
    assert_eq!(rows[0].title, "dest upsert");
    assert_eq!(
        rows[0].content, "merged upsert",
        "content overwritten in place"
    );
}

/// #7111 scenario B: the destination title is held by a quarantined (hidden)
/// row. The refusal is the typed, unnamed `Conflict`, and the cluster is
/// atomic: no source is tombstoned, the holder is untouched.
async fn hidden_destination_holder_is_conflict(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("hidden");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a hidden-dest", "alpha");
    let b = row(&ns, "b hidden-dest", "beta");
    let mut holder = row(&ns, "dest hidden", "quarantined content");
    holder.lifecycle_state = LifecycleState::Quarantined;
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    store
        .store(&ctx, &holder)
        .await
        .expect("seed quarantined holder");
    let err = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "dest hidden",
            "merged hidden",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect_err("a hidden destination holder refuses the cluster");
    match &err {
        StoreError::Conflict { id } => {
            assert!(
                id.is_empty(),
                "#7111: the hidden holder is never named, got {id:?}"
            );
        }
        other => panic!("#7111: expected StoreError::Conflict, got {other:?}"),
    }
    let titles: Vec<String> = rows_in_ns(store, &ctx, &ns)
        .await
        .into_iter()
        .map(|m| m.title)
        .collect();
    assert_eq!(
        titles,
        vec!["a hidden-dest".to_string(), "b hidden-dest".to_string()],
        "the refused cluster tombstoned no source and wrote no summary"
    );
}

fn sqlite_store() -> (tempfile::TempDir, SqliteStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x2d.db")).expect("open sqlite store");
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_fresh_destination_control() {
    let (_dir, store) = sqlite_store();
    fresh_destination_control(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_existing_destination_is_upserted_7111() {
    let (_dir, store) = sqlite_store();
    existing_destination_is_upserted(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_hidden_destination_is_conflict_7111() {
    let (_dir, store) = sqlite_store();
    hidden_destination_holder_is_conflict(&store).await;
}

#[cfg(feature = "sal-postgres")]
async fn pg_store() -> Option<ai_memory::store::postgres::PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    Some(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_fresh_destination_control() {
    let Some(store) = pg_store().await else {
        return;
    };
    fresh_destination_control(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_existing_destination_is_upserted_7111() {
    let Some(store) = pg_store().await else {
        return;
    };
    existing_destination_is_upserted(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_hidden_destination_is_conflict_7111() {
    let Some(store) = pg_store().await else {
        return;
    };
    hidden_destination_holder_is_conflict(&store).await;
}
