// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X2 — `MemoryStore::consolidate` typed-error parity between
//! the sqlite and postgres adapters, one scenario and one expected outcome
//! per backend.
//!
//! - #7091: a missing source is `StoreError::NotFound { id }` and a source
//!   that stopped being caller-visible is `StoreError::InvalidTransition` on
//!   postgres; sqlite flattened both to `StoreError::Backend`. Both backends
//!   must return the same variant, and the refused cluster must leave every
//!   source and the destination slot untouched.
//!
//! The postgres cells connect to the shared test database named by
//! `AI_MEMORY_TEST_POSTGRES_URL` (the tombstone path writes `memory_links`,
//! whose foreign keys the per-test search_path schema does not carry) and use
//! a unique namespace per cell. They skip cleanly without the variable.

use ai_memory::models::{LifecycleState, Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError};
use serde_json::json;

const OWNER: &str = "ai:owner-x2";

fn unique_ns(cell: &str) -> String {
    format!("parity-x2-{cell}-{}", uuid::Uuid::new_v4().simple())
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

/// The tombstone path is the only one that reaches the hidden-source guard;
/// every cell in this binary wants it on, so it is set once and never reset
/// (a process-wide flag must not be toggled by concurrently running cells).
fn enable_tombstone_path() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

async fn titles_in_ns(store: &dyn MemoryStore, ctx: &CallerContext, ns: &str) -> Vec<String> {
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    // `Filter::new()` carries limit 0, which both adapters clamp to ONE row,
    // so without this the single-title assertions could not see a second row.
    filter.limit = 100;
    let mut titles: Vec<String> = store
        .list(ctx, &filter)
        .await
        .expect("list")
        .into_iter()
        .map(|m| m.title)
        .collect();
    titles.sort();
    titles
}

/// Control: with no interference a visible cluster consolidates on both
/// backends and the sources leave the visible set.
async fn visible_cluster_consolidates(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("control");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a control", "alpha");
    let b = row(&ns, "b control", "beta");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let id = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "summary control",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("a visible cluster consolidates");
    assert!(!id.is_empty());
    assert_eq!(
        titles_in_ns(store, &ctx, &ns).await,
        vec!["summary control".to_string()],
        "only the summary stays visible"
    );
}

/// #7091 scenario A: the second source id does not exist.
async fn missing_source_is_not_found(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("missing");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a missing-src", "alpha");
    store.store(&ctx, &a).await.expect("seed a");
    let ghost = uuid::Uuid::new_v4().to_string();
    let err = store
        .consolidate(
            &ctx,
            &[a.id.clone(), ghost.clone()],
            "summary missing-src",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect_err("a missing source refuses the cluster");
    match &err {
        StoreError::NotFound { id } => assert_eq!(id, &ghost, "NotFound names the missing id"),
        other => panic!("#7091: expected StoreError::NotFound, got {other:?}"),
    }
    assert_eq!(
        titles_in_ns(store, &ctx, &ns).await,
        vec!["a missing-src".to_string()],
        "the refused cluster wrote no summary and kept the source"
    );
}

/// #7091 scenario B: the second source is quarantined (a system-only hidden
/// state). The refusal is the typed `InvalidTransition` naming that source,
/// not `Backend`, and the visible source is not tombstoned.
async fn hidden_source_is_invalid_transition(store: &dyn MemoryStore) {
    enable_tombstone_path();
    let ns = unique_ns("hidden");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a hidden-src", "alpha");
    let mut b = row(&ns, "b hidden-src", "beta");
    b.lifecycle_state = LifecycleState::Quarantined;
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed quarantined b");
    let err = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "summary hidden-src",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect_err("a hidden source refuses the cluster");
    match &err {
        StoreError::InvalidTransition { detail } => assert!(
            detail.contains(&b.id),
            "#7091: the refusal names the hidden source, got {detail:?}"
        ),
        other => panic!("#7091: expected StoreError::InvalidTransition, got {other:?}"),
    }
    assert_eq!(
        titles_in_ns(store, &ctx, &ns).await,
        vec!["a hidden-src".to_string()],
        "the refused cluster wrote no summary and kept the visible source"
    );
}

fn sqlite_store() -> (tempfile::TempDir, SqliteStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x2.db")).expect("open sqlite store");
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_visible_cluster_control() {
    let (_dir, store) = sqlite_store();
    visible_cluster_consolidates(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_missing_source_is_not_found_7091() {
    let (_dir, store) = sqlite_store();
    missing_source_is_not_found(&store).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_hidden_source_is_invalid_transition_7091() {
    let (_dir, store) = sqlite_store();
    hidden_source_is_invalid_transition(&store).await;
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
async fn postgres_consolidate_visible_cluster_control() {
    let Some(store) = pg_store().await else {
        return;
    };
    visible_cluster_consolidates(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_missing_source_is_not_found_7091() {
    let Some(store) = pg_store().await else {
        return;
    };
    missing_source_is_not_found(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_hidden_source_is_invalid_transition_7091() {
    let Some(store) = pg_store().await else {
        return;
    };
    hidden_source_is_invalid_transition(&store).await;
}
