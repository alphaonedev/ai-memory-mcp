// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1481 regression — `MemoryStore::store_batch()` on the postgres
//! adapter persists a whole bulk-ingest batch in ONE multi-row upsert
//! instead of streaming a `store()` round-trip per row.
//!
//! Spun out of #1472. The postgres `bulk_create` HTTP handler looped
//! `app.store.store(&ctx, &mem)` once per row — `2N` round-trips
//! (memory INSERT + `agent_quotas` upsert per row). `store_batch`
//! collapses that to `1 + G` (one multi-row INSERT + one quota upsert
//! per distinct `(agent, namespace)` group).
//!
//! These tests prove the BEHAVIOUR the optimisation must preserve, not
//! the round-trip count:
//!   * every Allowed row lands and is retrievable by its returned id;
//!   * the count-aware quota path advances `current_memories_today` by
//!     the full batch size (the `1`-per-row regression the naive
//!     "one quota call" shortcut would reintroduce);
//!   * an intra-batch `(title, namespace)` duplicate upserts to
//!     last-write-wins instead of tripping postgres's "ON CONFLICT DO
//!     UPDATE cannot affect row a second time" error — and the returned
//!     id vector stays 1:1 with the input so the caller's `created`
//!     count is unchanged.
//!
//! Gated on `feature = "sal-postgres"` and skipped without
//! `AI_MEMORY_TEST_POSTGRES_URL`, matching the postgres test convention.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

mod common;
use common::postgres_url;

use serde_json::json;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;

/// Batch size for the happy-path persist/quota assertion. Small enough
/// to run fast on a scratch DB, large enough to prove the multi-row
/// VALUES list and the aggregated quota increment both span many rows.
const BATCH_N: usize = 25;

/// Build a distinct memory under the given namespace/agent. The
/// `metadata.agent_id` stamp makes the row visible to `get()` for the
/// same caller (matching the bulk-ingest stamp the handler applies).
fn make_memory(namespace: &str, agent_id: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": agent_id }),
        ..Default::default()
    }
}

async fn quota_count(url: &str, agent_id: &str, namespace: &str) -> i64 {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("quota probe pool");
    let row = sqlx::query(
        "SELECT current_memories_today FROM agent_quotas \
         WHERE agent_id = $1 AND namespace = $2",
    )
    .bind(agent_id)
    .bind(namespace)
    .fetch_one(&pool)
    .await
    .expect("agent_quotas row for batch agent");
    row.try_get::<i64, _>("current_memories_today")
        .expect("current_memories_today column")
}

#[tokio::test(flavor = "multi_thread")]
async fn store_batch_persists_all_rows_and_aggregates_quota() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: connect failed: {e}");
            return;
        }
    };

    // Fresh agent + namespace so a shared scratch DB can't collide and
    // the upsert always takes the INSERT branch (RETURNING id == the id
    // we supplied).
    let suffix = uuid::Uuid::new_v4();
    let agent_id = format!("batch-agent-{suffix}");
    let namespace = format!("batch-ns-{suffix}");
    let ctx = CallerContext::for_agent(agent_id.clone());

    let memories: Vec<Memory> = (0..BATCH_N)
        .map(|i| {
            make_memory(
                &namespace,
                &agent_id,
                &format!("batch title #{i}"),
                &format!("batch body #{i}"),
            )
        })
        .collect();

    let ids = store
        .store_batch(&ctx, &memories)
        .await
        .expect("store_batch persists the whole batch");

    assert_eq!(
        ids.len(),
        BATCH_N,
        "#1481: store_batch must return one id per input row"
    );
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        BATCH_N,
        "#1481: distinct (title, namespace) rows must yield distinct ids"
    );

    // Every row is retrievable by its returned id with the right body.
    for (i, id) in ids.iter().enumerate() {
        let got = store
            .get(&ctx, id)
            .await
            .expect("each batched row is gettable");
        assert_eq!(
            got.content,
            format!("batch body #{i}"),
            "#1481: row {i} must round-trip its content"
        );
    }

    // Count-aware quota: a single batch by one (agent, namespace) must
    // advance the daily counter by the FULL batch size, not by 1.
    let count = quota_count(&url, &agent_id, &namespace).await;
    let expected = i64::try_from(BATCH_N).expect("BATCH_N fits i64");
    assert_eq!(
        count, expected,
        "#1481: store_batch must increment current_memories_today by the \
         whole batch size ({BATCH_N}); got {count}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn store_batch_intrabatch_duplicate_is_last_write_wins() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: connect failed: {e}");
            return;
        }
    };

    let suffix = uuid::Uuid::new_v4();
    let agent_id = format!("batch-dup-agent-{suffix}");
    let namespace = format!("batch-dup-ns-{suffix}");
    let ctx = CallerContext::for_agent(agent_id.clone());

    // Two rows sharing (title, namespace): a naive multi-row upsert would
    // error ("cannot affect row a second time"). store_batch keeps the
    // LAST occurrence and maps BOTH input positions to its id.
    let title = "duplicate title";
    let first = make_memory(&namespace, &agent_id, title, "v1 — superseded");
    let second = make_memory(&namespace, &agent_id, title, "v2 — winner");
    let first_id = first.id.clone();
    let second_id = second.id.clone();

    let ids = store
        .store_batch(&ctx, &[first, second])
        .await
        .expect("store_batch tolerates an intra-batch (title, namespace) duplicate");

    assert_eq!(ids.len(), 2, "#1481: returned ids stay 1:1 with input rows");
    assert_eq!(
        ids[0], ids[1],
        "#1481: both duplicate positions must resolve to the same persisted id"
    );
    assert_eq!(
        ids[0], second_id,
        "#1481: last-write-wins — the surviving id is the LAST occurrence's"
    );

    // The winner's content is what persisted.
    let got = store
        .get(&ctx, &second_id)
        .await
        .expect("winner row is gettable");
    assert_eq!(
        got.content, "v2 — winner",
        "#1481: last-write-wins content must be the one that persisted"
    );

    // The superseded id was never inserted as its own row.
    match store.get(&ctx, &first_id).await {
        Err(StoreError::NotFound { .. }) => {}
        other => panic!(
            "#1481: the superseded duplicate id must not exist as its own row; got {other:?}"
        ),
    }

    // Both positions still count toward quota (each was a caller-requested
    // write, matching the sequential `store` loop's created count).
    let count = quota_count(&url, &agent_id, &namespace).await;
    assert_eq!(
        count, 2,
        "#1481: both duplicate positions count toward current_memories_today; got {count}"
    );
}
