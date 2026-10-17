// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X1 — `MemoryStore::store_batch` slot-conflict parity
//! between the sqlite and postgres adapters.
//!
//! - #7099: a `(title, namespace)` slot held by a row the caller cannot see is
//!   the typed, unnamed `StoreError::Conflict` on postgres; sqlite flattened it
//!   to `StoreError::Backend` (and, with no viewer on the insert, let the
//!   batch overwrite the hidden row). Both must return `Conflict` with an
//!   empty id, roll the whole batch back, and charge no quota.
//!
//! The postgres cell is gated on `feature = "sal-postgres"` and skips
//! cleanly without `AI_MEMORY_TEST_POSTGRES_URL`.

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError};
use serde_json::json;

#[cfg(feature = "sal-postgres")]
mod common;

const NS: &str = "parity-x1c";
const ALICE: &str = "ai:alice-x1c";
const BOB: &str = "ai:bob-x1c";
const HELD_TITLE: &str = "held slot";

fn row(owner: &str, title: &str, content: &str, private: bool) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = if private {
        json!({ "agent_id": owner, "scope": "private" })
    } else {
        json!({ "agent_id": owner })
    };
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Default::default()
    }
}

/// #7099 scenario: Alice holds a private slot; Bob's batch `[ok, held, ok]`
/// is refused as a typed unnamed Conflict, rolls back every row, and leaves
/// Bob's quota row at zero.
async fn faulted_batch_is_conflict_and_atomic(store: &dyn MemoryStore) {
    let alice = CallerContext::for_agent(ALICE.to_string());
    let bob = CallerContext::for_agent(BOB.to_string());
    store
        .store(&alice, &row(ALICE, HELD_TITLE, "alice private text", true))
        .await
        .expect("seed the held slot");
    let rows = vec![
        row(BOB, "fault first", "first body", false),
        row(BOB, HELD_TITLE, "bob text for the held slot", false),
        row(BOB, "fault last", "last body", false),
    ];
    let err = store
        .store_batch(&bob, &rows)
        .await
        .expect_err("a hidden-holder slot refuses the whole batch");
    match &err {
        StoreError::Conflict { id } => assert!(
            id.is_empty(),
            "#7099: the hidden holder must stay unnamed, got id {id:?}"
        ),
        other => panic!("#7099: expected StoreError::Conflict, got {other:?}"),
    }
    let q = store.quota_status_ns(BOB, NS).await.expect("quota status");
    assert_eq!(
        (q.current_memories_today, q.current_storage_bytes),
        (0, 0),
        "a refused batch must leave the quota row untouched"
    );
    let mut filter = Filter::new();
    filter.namespace = Some(NS.to_string());
    let listed = store.list(&bob, &filter).await.expect("list as bob");
    assert!(
        listed
            .iter()
            .all(|m| m.title != "fault first" && m.title != "fault last"),
        "#7099: the refused batch must roll back every row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_store_batch_hidden_slot_conflict_atomic_7099() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("x1c.db")).expect("open sqlite store");
    faulted_batch_is_conflict_and_atomic(&store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_store_batch_hidden_slot_conflict_atomic_7099() {
    let Some(env) = common::postgres_env::PostgresTestEnv::new("x1_conflict_7099").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(env.url())
        .await
        .expect("connect postgres");
    faulted_batch_is_conflict_and_atomic(&store).await;
}
