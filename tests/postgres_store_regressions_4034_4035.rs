// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};
use std::sync::Arc;
use std::time::Duration;

fn memory() -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "snapshot parity".into(),
        content: "originalalpha".into(),
        namespace: format!("regression-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        metadata: serde_json::json!({"agent_id": "ai:4034-owner"}),
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        ..Memory::default()
    }
}

async fn store() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("live postgres required when configured"),
    )
}

#[tokio::test]
async fn postgres_unchanged_merge_does_not_create_snapshot_4035() {
    let Some(store) = store().await else { return };
    let ctx = CallerContext::for_admin("ai:4034-owner");
    let a = memory();
    store.store(&ctx, &a).await.unwrap();
    store.merge_inbound(&ctx, &a, false).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM archived_memories WHERE id=$1")
        .bind(&a.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "unchanged content needs no recovery snapshot");
}

#[tokio::test]
async fn postgres_merge_replay_preserves_snapshot_4035() {
    let Some(store) = store().await else { return };
    let ctx = CallerContext::for_admin("ai:4034-owner");
    let a = memory();
    store.store(&ctx, &a).await.unwrap();
    let mut b = a.clone();
    b.content = "newerbeta".into();
    b.updated_at = "2026-01-02T00:00:00+00:00".into();
    let mut older = a.clone();
    older.priority = 9;
    for inbound in [&b, &b, &older] {
        store.merge_inbound(&ctx, inbound, false).await.unwrap();
        let prior: String = sqlx::query_scalar("SELECT content FROM archived_memories WHERE id=$1 AND archive_reason='federation_merge'").bind(&a.id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(prior, a.content);
    }
    assert_eq!(store.get(&ctx, &a.id).await.unwrap().priority, 9);
    let mut c = b.clone();
    c.content = "latestgamma".into();
    c.updated_at = "2026-01-03T00:00:00+00:00".into();
    store.merge_inbound(&ctx, &c, false).await.unwrap();
    let prior: String = sqlx::query_scalar("SELECT content FROM archived_memories WHERE id=$1")
        .bind(&a.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(prior, b.content);
    let mut title_only = c.clone();
    title_only.title = "renamed".into();
    title_only.updated_at = "2026-01-04T00:00:00+00:00".into();
    store.merge_inbound(&ctx, &title_only, false).await.unwrap();
    let prior: String = sqlx::query_scalar("SELECT content FROM archived_memories WHERE id=$1")
        .bind(&a.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(prior, c.content);
}

async fn admin_update_locks_preimage(versioned: bool) {
    let Some(store) = store().await else { return };
    let store = Arc::new(store);
    let ctx = CallerContext::for_admin("ai:4034-owner");
    for _ in 0..20 {
        let a = memory();
        store.store(&ctx, &a).await.unwrap();
        let mut writer = store.pool().begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *writer)
            .await
            .unwrap();
        sqlx::query("UPDATE memories SET content='concurrentbeta' WHERE id=$1")
            .bind(&a.id)
            .execute(&mut *writer)
            .await
            .unwrap();
        let patch_store = Arc::clone(&store);
        let patch_ctx = ctx.clone();
        let id = a.id.clone();
        let content = a.content.clone();
        let task = tokio::spawn(async move {
            let patch = UpdatePatch {
                content: Some(content),
                ..Default::default()
            };
            if versioned {
                patch_store
                    .update_with_expected_version(&patch_ctx, &id, patch, None)
                    .await
                    .map(|_| ())
            } else {
                patch_store.update(&patch_ctx, &id, patch).await
            }
        });
        // Wait until the patch reaches a row lock, then release the writer.
        // The old admin path blocks at UPDATE, having already decided that
        // A->A needs no archive. The fixed path blocks at the pre-read.
        tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(store.pool()).await.unwrap();
                    if blocked { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.unwrap();
        writer.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(store.get(&ctx, &a.id).await.unwrap().content, a.content);
        let prior: Option<String> =
            sqlx::query_scalar("SELECT content FROM archived_memories WHERE id=$1")
                .bind(&a.id)
                .fetch_optional(store.pool())
                .await
                .unwrap();
        assert_eq!(
            prior.as_deref(),
            Some("concurrentbeta"),
            "#4034 admin snapshot must use locked preimage"
        );
    }
}

#[tokio::test]
async fn postgres_admin_trait_update_locks_preimage_4034() {
    admin_update_locks_preimage(false).await;
}

#[tokio::test]
async fn postgres_admin_versioned_update_locks_preimage_4034() {
    admin_update_locks_preimage(true).await;
}
