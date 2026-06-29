// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W2 / gap G30 — postgres parity for the erasure fanout: a forget
//! records a FORGET tombstone and the receive funnel (`merge_inbound`)
//! rejects a re-pushed forgotten row (resurrection guard), identically to
//! sqlite.
//!
//! `#[ignore]` + `sal-postgres`; run with a live instance:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://aimem:aimem@127.0.0.1:5432/aimem_test \
//!   cargo test --features sal-postgres --test erasure_fanout_postgres_g30 \
//!   -- --include-ignored --nocapture
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::postgres::PgPoolOptions;

fn mem(namespace: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-g30".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:test:g30" }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_forget_tombstone_blocks_resurrection_g30() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let pg = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("test skipped: connect failed: {e}");
            return;
        }
    };
    let admin = CallerContext::for_admin("operator:test-g30");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g30-pg-{tag}");

    let id = pg
        .store(&admin, &mem(&ns, "rnote", "original secret content"))
        .await
        .expect("pg store");

    // Separate inspection pool to read the raw tables.
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("inspection pool");

    pg.forget(&admin, Some(&ns), None, None, false)
        .await
        .expect("pg forget");

    let mem_n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(mem_n, 0, "the row must be gone after forget");

    let tomb_n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(tomb_n, 1, "postgres forget must record a FORGET tombstone");

    // A peer re-pushes the forgotten row with a far-future updated_at via the
    // receive funnel; the tombstone-wins guard must drop it.
    let revived = Memory {
        id: id.clone(),
        updated_at: "2999-01-01T00:00:00Z".to_string(),
        ..mem(&ns, "rnote", "original secret content")
    };
    let returned = pg
        .merge_inbound(&admin, &revived)
        .await
        .expect("merge_inbound");
    assert_eq!(
        returned, id,
        "tombstone-wins returns the id without inserting"
    );

    let mem_n2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        mem_n2, 0,
        "G30 W2.3 (postgres): a forgotten row must NOT be resurrected by a peer re-push"
    );
}
