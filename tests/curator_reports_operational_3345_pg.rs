// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3345 — LIVE-postgres half of the embedding-backfill lifecycle gate.
//!
//! `list_unembedded` has two genuinely different implementations — the SQLite
//! substrate scan (`storage::unembedded_predicate`) and this adapter's OR-chain
//! over the NULL-embedding / unattributed-space / foreign-space arms. A
//! one-sided fix would hide and stop embedding the curator's self-reports on a
//! fleet's SQLite nodes while its PostgreSQL nodes kept recalling and paying to
//! embed them: mixed state across a heterogeneous fleet, which is the failure
//! class the SAL parity rule exists to prevent. So the DENIED and ALLOWED
//! assertions are made against the live adapter, not inferred from the twin.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset. Every id
//! and namespace is uuid-randomised and every seeded row is reaped in-test,
//! because the `sal-postgres` suite shares ONE `ai_memory_test` database with
//! no per-test schema isolation (#2287). NO schema change.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::models::{LifecycleState, Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn mem(id: &str, ns: &str, state: LifecycleState) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("t-{id}"),
        content: format!("body for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test3345".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({}),
        version: 1,
        lifecycle_state: state,
        ..Memory::default()
    }
}

async fn cleanup(store: &PostgresStore, ns: &str) {
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(ns)
        .execute(store.pool())
        .await;
}

/// DENIED + ALLOWED in one live pass: `list_unembedded` returns the
/// recall-visible row and NONE of the hidden ones.
#[tokio::test]
async fn non_visible_rows_are_never_selected_for_embedding_pg_3345() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("reports3345");
    let ctx = CallerContext::for_admin("ai:admin3345");
    let visible = uid("open3345");
    store
        .store(&ctx, &mem(&visible, &ns, LifecycleState::Open))
        .await
        .expect("store visible");
    for state in [
        LifecycleState::Operational,
        LifecycleState::Tombstoned,
        LifecycleState::Quarantined,
        LifecycleState::Contaminated,
    ] {
        store
            .store(&ctx, &mem(&uid("hidden3345"), &ns, state))
            .await
            .expect("store hidden");
    }

    let rows = store
        .list_unembedded(&ctx, 1000)
        .await
        .expect("list_unembedded");
    cleanup(&store, &ns).await;

    let picked: Vec<&str> = rows
        .iter()
        .filter(|(id, _, _)| id.starts_with("open3345") || id.starts_with("hidden3345"))
        .map(|(id, _, _)| id.as_str())
        .collect();
    assert_eq!(
        picked,
        vec![visible.as_str()],
        "only the recall-visible row may be selected for embedding"
    );
}

/// The backlog stamp is chunked, idempotent, self-terminating and
/// stamp-never-delete on the live adapter too.
#[tokio::test]
async fn backlog_stamp_is_idempotent_pg_3345() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uid("reports3345-stamp");
    let ctx = CallerContext::for_admin("ai:admin3345");
    for _ in 0..3 {
        store
            .store(&ctx, &mem(&uid("legacy3345"), &ns, LifecycleState::Open))
            .await
            .expect("store legacy");
    }

    let first = store
        .stamp_operational_backlog(&ctx, &ns)
        .await
        .expect("stamp");
    let second = store
        .stamp_operational_backlog(&ctx, &ns)
        .await
        .expect("stamp again");
    let surviving: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM memories WHERE namespace = $1 AND lifecycle_state = 'operational'",
    )
    .bind(&ns)
    .fetch_one(store.pool())
    .await
    .expect("count");
    cleanup(&store, &ns).await;

    assert_eq!(first, 3, "every legacy row is stamped");
    assert_eq!(second, 0, "a second run stamps nothing (self-terminating)");
    assert_eq!(surviving, 3, "the stamp never deletes");
}
