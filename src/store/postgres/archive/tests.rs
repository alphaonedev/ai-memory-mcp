// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 — archive composition, rollback and owner-gate regression tests.

use super::*;
use crate::models::{Memory, Tier};
use crate::store::MemoryStore;

const OWNER: &str = "ai:archive-3587";

async fn fixture() -> Option<(PostgresStore, CallerContext, String, String)> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent(OWNER);
    let ns = format!("archive-tx-3587-{}", uuid::Uuid::new_v4());
    let old = seed(&store, &ctx, &ns, "old").await;
    let next = seed(&store, &ctx, &ns, "next").await;
    // Fixture-only relational writes avoid unrelated signed-link admission.
    sqlx::query(
        "INSERT INTO memory_links (source_id, target_id, relation) VALUES ($1, $2, 'related_to')",
    )
    .bind(&old)
    .bind(&next)
    .execute(&store.pool)
    .await
    .expect("link");
    sqlx::query("INSERT INTO namespace_meta (namespace, standard_id) VALUES ($1, $2)")
        .bind(&ns)
        .bind(&old)
        .execute(&store.pool)
        .await
        .expect("standard");
    Some((store, ctx, old, ns))
}

async fn seed(store: &PostgresStore, ctx: &CallerContext, ns: &str, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    store
        .store(
            ctx,
            &Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: ns.into(),
                title: title.into(),
                content: format!("durable {title}"),
                created_at: now.clone(),
                updated_at: now,
                metadata: serde_json::json!({"agent_id": OWNER}),
                ..Memory::default()
            },
        )
        .await
        .expect("seed")
}

async fn count_for(store: &PostgresStore, table: &str, column: &str, id: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = $1"))
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .expect("count")
}

async fn snapshot(store: &PostgresStore, old: &str) -> serde_json::Value {
    sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id = $1")
        .bind(old)
        .fetch_one(&store.pool)
        .await
        .expect("snapshot")
}

#[tokio::test]
async fn archive_transaction_rolls_back_snapshot_links_and_standard_3587() {
    let Some((store, ctx, old, ns)) = fixture().await else {
        return;
    };
    let before = snapshot(&store, &old).await;
    store.gate_record_stop().await.expect("preflight");
    let mut tx = store.pool.begin().await.expect("begin");
    assert_eq!(
        store
            .archive_by_ids_in_tx(
                &mut tx,
                &ctx,
                std::slice::from_ref(&old),
                "superseded",
                chrono::Utc::now()
            )
            .await
            .expect("archive"),
        1
    );
    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories WHERE id = $1")
        .bind(&old)
        .fetch_one(&mut *tx)
        .await
        .expect("archived in tx");
    assert_eq!(
        archived, 1,
        "the archive must happen before the injected fault"
    );
    // PostgreSQL aborts this transaction; every archive side effect must revert.
    assert!(sqlx::query("SELECT 1 / 0").execute(&mut *tx).await.is_err());
    tx.rollback().await.expect("rollback");
    assert_eq!(snapshot(&store, &old).await, before);
    assert_eq!(count_for(&store, "archived_memories", "id", &old).await, 0);
    assert_eq!(
        count_for(&store, "archived_memory_links", "source_id", &old).await,
        0
    );
    assert_eq!(
        count_for(&store, "memory_links", "source_id", &old).await,
        1
    );
    let standard: Option<String> =
        sqlx::query_scalar("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
            .bind(&ns)
            .fetch_one(&store.pool)
            .await
            .expect("standard");
    assert_eq!(standard.as_deref(), Some(old.as_str()));
    store.pool.close().await;
}

#[tokio::test]
async fn archive_transaction_commits_once_and_missing_id_is_noop_3587() {
    let Some((store, ctx, old, ns)) = fixture().await else {
        return;
    };
    store.gate_record_stop().await.expect("preflight");
    let mut tx = store.pool.begin().await.expect("begin");
    let ids = [old.clone(), old.clone(), uuid::Uuid::new_v4().to_string()];
    assert_eq!(
        store
            .archive_by_ids_in_tx(&mut tx, &ctx, &ids, "superseded", chrono::Utc::now())
            .await
            .expect("archive"),
        1
    );
    tx.commit().await.expect("commit");
    assert_eq!(count_for(&store, "memories", "id", &old).await, 0);
    assert_eq!(count_for(&store, "archived_memories", "id", &old).await, 1);
    assert_eq!(
        count_for(&store, "archived_memory_links", "source_id", &old).await,
        1
    );
    assert_eq!(
        count_for(&store, "memory_links", "source_id", &old).await,
        0
    );
    let (reason, standard): (String, Option<String>) = sqlx::query_as("SELECT a.archive_reason, n.standard_id FROM archived_memories a, namespace_meta n WHERE a.id = $1 AND n.namespace = $2")
        .bind(&old).bind(&ns).fetch_one(&store.pool).await.expect("archive and standard");
    assert_eq!(reason, "superseded");
    assert_eq!(standard, None);
    store.pool.close().await;
}

#[tokio::test]
async fn archive_transaction_refuses_non_owner_without_changes_3587() {
    let Some((store, _, old, _)) = fixture().await else {
        return;
    };
    let before = snapshot(&store, &old).await;
    store.gate_record_stop().await.expect("preflight");
    let mut tx = store.pool.begin().await.expect("begin");
    let refused = store
        .archive_by_ids_in_tx(
            &mut tx,
            &CallerContext::for_agent("ai:other-3587"),
            std::slice::from_ref(&old),
            "superseded",
            chrono::Utc::now(),
        )
        .await;
    assert!(matches!(refused, Err(StoreError::PermissionDenied { .. })));
    tx.rollback().await.expect("rollback");
    assert_eq!(snapshot(&store, &old).await, before);
    assert_eq!(count_for(&store, "archived_memories", "id", &old).await, 0);
    assert_eq!(
        count_for(&store, "memory_links", "source_id", &old).await,
        1
    );
    store.pool.close().await;
}

#[tokio::test]
async fn archive_transaction_rechecks_cached_stop_before_mutation_3587() {
    let Some((store, ctx, old, _)) = fixture().await else {
        return;
    };
    let before = snapshot(&store, &old).await;
    store.gate_record_stop().await.expect("preflight");
    let mut tx = store.pool.begin().await.expect("begin");
    // A stop arrives after the outer preflight. The core must still refuse.
    store.record_stop.engage("ai:operator-3587", "record-plane");
    let refused = store
        .archive_by_ids_in_tx(
            &mut tx,
            &ctx,
            std::slice::from_ref(&old),
            "superseded",
            chrono::Utc::now(),
        )
        .await;
    assert!(matches!(refused, Err(StoreError::Stopped { .. })));
    tx.rollback().await.expect("rollback");
    assert_eq!(snapshot(&store, &old).await, before);
    assert_eq!(count_for(&store, "archived_memories", "id", &old).await, 0);
    store.pool.close().await;
}
