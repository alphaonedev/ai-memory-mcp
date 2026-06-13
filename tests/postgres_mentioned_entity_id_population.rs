// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! v0.7.x #1383 — postgres `mentioned_entity_id` denormalisation
//! regression.
//!
//! Pins the contract that every postgres INSERT path that lands a
//! `Memory` row also populates the `mentioned_entity_id` partial-index
//! column when the row is a Reflection carrying a `metadata.entity_id`
//! or `[entity:X]` title marker. Pre-#1383 the postgres adapter
//! dropped the column entirely on `store()`, `store_with_embedding()`,
//! the dedicated `reflect()` path, and the federation
//! `apply_remote_memory()` ingress — so `memory_persona_generate`'s
//! `WHERE mentioned_entity_id = ?` query returned zero reflections
//! against postgres-backed daemons (the v3 NHI assessment defect
//! D-v3-1, reproducible against alice in `infra/lan-parity-test/`).
//!
//! Soft-skips when `AI_MEMORY_TEST_POSTGRES_URL` is unset (matches the
//! pattern from sister `postgres_*.rs` tests). Uses uuid-suffixed
//! namespaces + titles so concurrent test runs don't collide on the
//! `(title, namespace)` unique index.

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use chrono::Utc;
use serde_json::json;
use sqlx::Row;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn inspection_pool(url: &str) -> sqlx::PgPool {
    sqlx::PgPool::connect(url)
        .await
        .expect("inspection_pool: connect")
}

fn reflection(namespace: &str, title: &str, content: &str, metadata: serde_json::Value) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["i1383-test".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 1,
        memory_kind: MemoryKind::Reflection,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

async fn fetch_mentioned_entity_id(pool: &sqlx::PgPool, id: &str) -> Option<String> {
    let row = sqlx::query("SELECT mentioned_entity_id FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch_one mentioned_entity_id");
    row.try_get::<Option<String>, _>("mentioned_entity_id")
        .expect("read mentioned_entity_id")
}

#[tokio::test]
async fn store_reflection_with_metadata_entity_id_populates_mentioned_entity_id_column() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = inspection_pool(&url).await;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("i1383-meta-{suffix}");
    let entity_id = format!("entity-{suffix}");
    let mem = reflection(
        &namespace,
        &format!("reflection-meta-{suffix}"),
        "reflection body — metadata.entity_id propagation contract",
        json!({"agent_id": "ai:i1383-test", "entity_id": entity_id}),
    );

    let ctx = CallerContext::for_agent("ai:i1383-test".to_string());
    let id = store.store(&ctx, &mem).await.expect("store");

    let stored = fetch_mentioned_entity_id(&pool, &id).await;
    assert_eq!(
        stored.as_deref(),
        Some(entity_id.as_str()),
        "postgres store() must denormalise metadata.entity_id into the \
         mentioned_entity_id column so memory_persona_generate's \
         `WHERE mentioned_entity_id = ?` query reaches the reflection \
         (#1383 regression — pre-fix this column was always NULL on \
         postgres-backed daemons, mirroring the v3 NHI assessment \
         alice defect)"
    );
}

#[tokio::test]
async fn store_with_embedding_reflection_with_metadata_entity_id_populates_mentioned_entity_id() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = inspection_pool(&url).await;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("i1383-embed-{suffix}");
    let entity_id = format!("entity-{suffix}");
    let mem = reflection(
        &namespace,
        &format!("reflection-embed-{suffix}"),
        "reflection body — store_with_embedding propagation contract",
        json!({"agent_id": "ai:i1383-test", "entity_id": entity_id}),
    );

    let ctx = CallerContext::for_agent("ai:i1383-test".to_string());
    let id = store
        .store_with_embedding(&ctx, &mem, None)
        .await
        .expect("store_with_embedding");

    let stored = fetch_mentioned_entity_id(&pool, &id).await;
    assert_eq!(
        stored.as_deref(),
        Some(entity_id.as_str()),
        "postgres store_with_embedding() must denormalise \
         metadata.entity_id into the mentioned_entity_id column. \
         This is the load-bearing path for HTTP POST /api/v1/memories \
         on postgres-backed daemons (`create_memory_postgres` → \
         `app.store.store_with_embedding`)."
    );
}

#[tokio::test]
async fn store_reflection_with_entity_title_marker_populates_mentioned_entity_id() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = inspection_pool(&url).await;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("i1383-marker-{suffix}");
    let entity_id = format!("entity-{suffix}");
    let mem = reflection(
        &namespace,
        &format!("title-marker [entity:{entity_id}]"),
        "reflection body — title-marker fallback (no metadata.entity_id)",
        json!({"agent_id": "ai:i1383-test"}),
    );

    let ctx = CallerContext::for_agent("ai:i1383-test".to_string());
    let id = store.store(&ctx, &mem).await.expect("store");

    let stored = fetch_mentioned_entity_id(&pool, &id).await;
    assert_eq!(
        stored.as_deref(),
        Some(entity_id.as_str()),
        "postgres store() must honour the `[entity:X]` title marker as a \
         fallback when metadata.entity_id is absent — matches the sqlite \
         resolution order in `extract_mentioned_entity_id` at \
         src/storage/mod.rs:549-576"
    );
}

#[tokio::test]
async fn store_non_reflection_memory_leaves_mentioned_entity_id_null() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let store = PostgresStore::connect(&url).await.expect("connect");
    let pool = inspection_pool(&url).await;

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("i1383-obs-{suffix}");
    let entity_id = format!("entity-{suffix}");
    let mut mem = reflection(
        &namespace,
        &format!("observation-{suffix}"),
        "observation body — non-reflection kind",
        json!({"agent_id": "ai:i1383-test", "entity_id": entity_id}),
    );
    // Downcast to Observation so the matcher returns None per
    // `extract_mentioned_entity_id`'s first guard.
    mem.memory_kind = MemoryKind::Observation;
    mem.reflection_depth = 0;

    let ctx = CallerContext::for_agent("ai:i1383-test".to_string());
    let id = store.store(&ctx, &mem).await.expect("store");

    let stored = fetch_mentioned_entity_id(&pool, &id).await;
    assert!(
        stored.is_none(),
        "non-Reflection rows must NOT populate mentioned_entity_id even \
         when metadata.entity_id is present — the partial index predicate \
         (`WHERE mentioned_entity_id IS NOT NULL`) would otherwise inflate \
         on every observation in the substrate. Resolution lives in \
         `extract_mentioned_entity_id` at src/storage/mod.rs:550-552. \
         Got: {stored:?}"
    );
}
