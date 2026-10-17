// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X1 — `MemoryStore::store_batch` quota parity between the
//! sqlite and postgres adapters, one scenario and one expected outcome per
//! backend.
//!
//! - #7090: sqlite `store_batch` wrote the rows but recorded no `agent_quotas`
//!   row; postgres records it in the batch transaction. Both must record
//!   `(current_memories_today, current_storage_bytes)` for the accepted rows.
//!
//! The postgres cell is gated on `feature = "sal-postgres"` and skips
//! cleanly without `AI_MEMORY_TEST_POSTGRES_URL`.

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

#[cfg(feature = "sal-postgres")]
mod common;

const NS: &str = "parity-x1";
const BOB: &str = "ai:bob-x1";

fn row(owner: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        ..Default::default()
    }
}

fn bytes_of(rows: &[Memory]) -> i64 {
    rows.iter()
        .map(|m| i64::try_from(m.title.len() + m.content.len()).expect("small row"))
        .sum()
}

/// #7090 scenario: Bob batch-stores four distinct rows; the quota row for
/// `(Bob, NS)` must equal the batch width and the title+content byte sum.
async fn batch_records_quota(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_agent(BOB.to_string());
    let rows: Vec<Memory> = (0..4)
        .map(|i| row(BOB, &format!("quota title {i}"), &format!("quota body {i}")))
        .collect();
    let want_bytes = bytes_of(&rows);
    let ids = store
        .store_batch(&ctx, &rows)
        .await
        .expect("batch of four distinct rows is accepted");
    assert_eq!(ids.len(), rows.len(), "one id per input row");
    let q = store.quota_status_ns(BOB, NS).await.expect("quota status");
    assert_eq!(
        (q.current_memories_today, q.current_storage_bytes),
        (4, want_bytes),
        "#7090: store_batch must record (memories, bytes) for the accepted rows"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_store_batch_records_quota_7090() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x1.db")).expect("open sqlite store");
    batch_records_quota(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_store_batch_records_quota_7090() {
    let Some(env) = common::postgres_env::PostgresTestEnv::new("x1_quota_7090").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(env.url())
        .await
        .expect("connect postgres");
    batch_records_quota(&store).await;
}
