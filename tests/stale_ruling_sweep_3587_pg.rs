// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U3 — postgres twin of `stale_ruling_sweep_3587`.
//!
//! The U3 guarantee must hold on BOTH backends: the stale-ruling scan is a
//! pure SELECT — the ruling rows' `version` / `updated_at` are unchanged and
//! `archived_memories` delta is 0 — and the predicate (ruling tag OR
//! `metadata.ruling_key`, no supersede/verify marker, latest-per-key) matches
//! the SQLite twin. Exercised here against a LIVE cluster via the SAL
//! `MemoryStore::list_stale_rulings` surface.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; every seeded row is reaped in-test
//! (#2287) and every namespace is uuid-suffixed so concurrent lanes on one
//! cluster cannot collide.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

/// Insert a ruling row directly (substrate namespaces are write-gated), with
/// explicit tags + metadata so the predicate is exercised exactly.
async fn raw_ruling(
    store: &PostgresStore,
    namespace: &str,
    tags: &[&str],
    metadata: serde_json::Value,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, priority, \
                               confidence, created_at, updated_at, metadata, tags) \
         VALUES ($1, 'long', $2, $3, 'a ruling body', 'test-3587', 5, 1.0, $4, $4, \
                 $5::jsonb, $6::jsonb)",
    )
    .bind(&id)
    .bind(namespace)
    .bind(format!("ruling {id}"))
    .bind(updated_at)
    .bind(metadata)
    .bind(serde_json::to_value(tags).expect("tags json"))
    .execute(store.pool())
    .await
    .expect("raw insert ruling");
    id
}

async fn snapshot(store: &PostgresStore, id: &str) -> (i64, chrono::DateTime<chrono::Utc>) {
    sqlx::query_as::<_, (i64, chrono::DateTime<chrono::Utc>)>(
        "SELECT version, updated_at FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .expect("snapshot ruling")
}

async fn cleanup(store: &PostgresStore, marker: &str) {
    let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
        .bind(format!("%{marker}%"))
        .execute(store.pool())
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_ruling_sweep_writes_nothing_to_the_rulings_3587_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3587 live-pg suite");
    };
    let marker = format!("m3587-{}", uuid::Uuid::new_v4());
    let ns = format!("proj/{marker}");
    let now = chrono::Utc::now();
    let cutoff = (now - chrono::Duration::days(14)).to_rfc3339();

    let id = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-write"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let before = snapshot(&store, &id).await;
    let archived_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");

    let found = store.list_stale_rulings(&cutoff, 500).await.expect("scan");
    let hit = found
        .iter()
        .find(|r| r.id == id)
        .expect("seeded ruling found");
    assert_eq!(hit.namespace, ns);
    assert_eq!(hit.ruling_key.as_deref(), Some("k-write"));

    assert_eq!(snapshot(&store, &id).await, before, "ruling drifted");
    let archived_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories")
        .fetch_one(store.pool())
        .await
        .expect("archived count");
    assert_eq!(archived_after, archived_before, "scan must not archive");

    cleanup(&store, &marker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_ruling_markers_and_latest_only_3587_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3587 live-pg suite");
    };
    let marker = format!("m3587-{}", uuid::Uuid::new_v4());
    let ns = format!("proj/{marker}");
    let now = chrono::Utc::now();
    let cutoff = (now - chrono::Duration::days(14)).to_rfc3339();

    let plain = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let verified = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "verified_at": now.to_rfc3339()}),
        now - chrono::Duration::days(30),
    )
    .await;
    let superseded = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "superseded_id": "prior"}),
        now - chrono::Duration::days(30),
    )
    .await;
    let older = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-latest"}),
        now - chrono::Duration::days(40),
    )
    .await;
    let newer = raw_ruling(
        &store,
        &ns,
        &["ruling"],
        serde_json::json!({"agent_id": "ai:fable", "ruling_key": "k-latest"}),
        now - chrono::Duration::days(30),
    )
    .await;

    let found = store.list_stale_rulings(&cutoff, 500).await.expect("scan");
    let ids: Vec<&str> = found.iter().map(|r| r.id.as_str()).collect();

    assert!(ids.contains(&plain.as_str()), "plain ruling is stale");
    assert!(!ids.contains(&verified.as_str()), "verified is not stale");
    assert!(
        !ids.contains(&superseded.as_str()),
        "superseded is not stale"
    );
    assert!(ids.contains(&newer.as_str()), "latest for key is stale");
    assert!(
        !ids.contains(&older.as_str()),
        "older same-key row is history"
    );

    cleanup(&store, &marker).await;
}
