// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! #4045 (5-agent vote 4d3ea1c5, memory 656eb5ff) — error parity of the
//! version-checked consolidate on BOTH backends. A source edited after it was
//! summarized must surface as `StoreError::Conflict { id }` on sqlite AND
//! postgres, never as an opaque `Backend(String)` (the pre-parity sqlite
//! mapping), and the refusal must leave every source untouched.
//!
//! Sqlite always runs. Postgres runs when `AI_MEMORY_TEST_POSTGRES_URL` is set
//! (falling back to `AI_MEMORY_TEST_PG_URL`); with neither set that cell
//! returns early and is NOT a proof of the postgres path.

use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

#[cfg(feature = "sal-postgres")]
fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_PG_URL").ok())
        .filter(|u| !u.trim().is_empty())
}

async fn seed(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    namespace: &str,
    title: &str,
) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("original content of {title}"),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    store.store(ctx, &memory).await.expect("seed store");
    store.get(ctx, &memory.id).await.expect("seed get")
}

async fn stale_consolidate_is_conflict(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_admin("ai:consolidator-4045");
    let namespace = format!("consolidate-conflict-4045-{}", uuid::Uuid::new_v4());
    let first = seed(store, &ctx, &namespace, "first").await;
    let second = seed(store, &ctx, &namespace, "second").await;
    let versions = [first.version, second.version];

    // A concurrent edit lands AFTER the versions were read.
    store
        .update(
            &ctx,
            &first.id,
            UpdatePatch {
                content: Some("edited after the summary was computed".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("concurrent edit");

    let ids = [first.id.clone(), second.id.clone()];
    let result = store
        .consolidate_with_expected_versions(
            &ctx,
            &ids,
            "summary title",
            "summary of the stale versions",
            &namespace,
            &Tier::Mid,
            "test",
            "ai:consolidator-4045",
            Some(&versions),
        )
        .await;
    match result {
        Err(StoreError::Conflict { id }) => {
            assert_eq!(id, first.id, "conflict names the edited source");
        }
        other => panic!("expected StoreError::Conflict for a stale source version, got {other:?}"),
    }

    // Nothing was consolidated: both sources survive, the edit is intact.
    let first_after = store.get(&ctx, &first.id).await.expect("first survives");
    assert_eq!(first_after.content, "edited after the summary was computed");
    store.get(&ctx, &second.id).await.expect("second survives");
    let mut filter = ai_memory::store::Filter::new();
    filter.namespace = Some(namespace.clone());
    filter.limit = 10;
    assert_eq!(
        store.list(&ctx, &filter).await.expect("list").len(),
        2,
        "a refused consolidation must not commit a summary row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_consolidate_maps_to_conflict_sqlite_4045() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ai_memory::store::sqlite::SqliteStore::open(dir.path().join("t.db"))
        .expect("open SqliteStore");
    stale_consolidate_is_conflict(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_consolidate_maps_to_conflict_postgres_4045() {
    let Some(url) = postgres_url() else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset; postgres cell NOT run");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("PostgresStore::connect");
    stale_consolidate_is_conflict(&store).await;
}
