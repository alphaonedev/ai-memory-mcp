// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2621 — live-postgres twin of the `SqliteStore`-backed unit test
//! `memories_gauge::tests::sal_refresh_counts_the_active_store_not_the_sqlite_sidecar`.
//!
//! Proves the `ai_memory_memories` corpus-size gauge counts the SERVED
//! postgres corpus through the SAL trait (`stats().total`), not the local
//! sqlite sidecar `prometheus_metrics` used to read regardless of backend.
//! On a postgres-backed daemon the sidecar is empty, so the pre-#2621 gauge
//! published `0` for a populated corpus; here the SAL refresher's published
//! count GROWS by exactly the rows inserted into the pg corpus.
//!
//! Live-postgres gated via the SKIP-IF-URL-UNSET convention of the shipped
//! `pg_*` suite (`tests/claim_bitemporal_1834_pg.rs` precedent): the test
//! self-skips with an eprintln when `AI_MEMORY_TEST_POSTGRES_URL` is unset
//! so a plain `cargo test` stays green on nodes without postgres routing,
//! and runs the real assertions when it points at a live schema. The delta
//! (after − before) assertion is robust against a shared test database.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test pg_memories_gauge_2621
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::background::memories_gauge::refresh_once_sal;
use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn mem(id: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "gauge-2621 pg corpus body".to_string(),
        priority: 5,
        confidence: 0.9,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

#[tokio::test]
async fn sal_gauge_counts_the_pg_corpus_growth() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset — pg gauge twin not exercised");
        return;
    };
    let store: std::sync::Arc<dyn MemoryStore> = std::sync::Arc::new(store);
    let dynstore = store.as_ref();
    let ctx = CallerContext::for_agent("gauge-2621-pg");
    let now = chrono::Utc::now().timestamp();

    // The gauge's published count is `stats().total` — a whole-corpus
    // physical COUNT(*). On a shared test DB the baseline is nonzero, so
    // assert on the DELTA the pg inserts produce, not an absolute value.
    let before = refresh_once_sal(dynstore, now)
        .await
        .expect("baseline pg corpus count");

    let ns = format!("gauge2621/{}", uuid::Uuid::new_v4());
    for i in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        store
            .store(&ctx, &mem(&id, &ns, &format!("gauge-row-{i}")))
            .await
            .expect("store pg row");
    }

    let after = refresh_once_sal(dynstore, now + 1)
        .await
        .expect("post-insert pg corpus count");

    assert_eq!(
        after - before,
        3,
        "the SAL gauge counts the SERVED postgres corpus (grew by 3), \
         not the empty sqlite sidecar (#2621)"
    );
}
