// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2167 — postgres T-INV twin: the pgvector `<=>` recall predicate
//! (`AND embedding_space = $fp`) NEVER scores a stored vector from a DIFFERENT
//! embedding space (a same-dim model swap). Runtime proof of the sqlite
//! T-INV-1 invariant on the postgres backend.
//!
//! Live-postgres gated (skip-if-env-unset pattern of the other `pg_*` tests):
//! self-skips with an eprintln when `AI_MEMORY_TEST_POSTGRES_URL` is unset so
//! a plain `cargo test` stays green on nodes without postgres routing, and
//! RUNS the real assertions when it points at a live schema. The static pg
//! `<=>` site-count PIN (`tests/embedding_space_provenance_2167.rs`) already
//! guarantees EVERY cosine query carries the gate feature-independently; this
//! twin proves the runtime exclusion in CI's Postgres feature gate.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test embedding_space_provenance_2167_pg \
//!   -- --include-ignored
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::embeddings::embedding_space_fingerprint;
use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

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

fn mem(id: &str, namespace: &str, title: &str, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "pg space-provenance corpus body zzznoftshitzzzpg".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 0.9,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_recall_never_scores_foreign_space_2167() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:2167-pg";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("space2167-{}", uuid::Uuid::new_v4());

    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, other space
    assert_ne!(active, foreign);

    // Resolve the fixture's pgvector dim so identical vectors compare at
    // cosine 1.0 (the space gate is the ONLY differentiator).
    let dim = usize::try_from(
        store
            .current_embedding_dim()
            .await
            .expect("current_embedding_dim")
            .unwrap_or(384),
    )
    .unwrap_or(384);
    let vec: Vec<f32> = {
        let mut v = vec![0.0_f32; dim];
        v[0] = 1.0;
        v
    };

    let active_id = uuid::Uuid::new_v4().to_string();
    let foreign_id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&active_id, &ns, "active row", owner))
        .await
        .expect("store active");
    store
        .store(&ctx, &mem(&foreign_id, &ns, "foreign row", owner))
        .await
        .expect("store foreign");
    // Identical vectors, DIFFERENT spaces.
    store
        .update_embedding(&ctx, &active_id, Some(&vec), &active)
        .await
        .expect("stamp active");
    store
        .update_embedding(&ctx, &foreign_id, Some(&vec), &foreign)
        .await
        .expect("stamp foreign");

    // A query text that matches NO content token → the FTS/keyword pool is
    // empty, so the returned set is exactly the SEMANTIC-scored set. The
    // active-space fingerprint gates the `<=>` pool.
    let filter = Filter {
        namespace: Some(ns.clone()),
        tier: None,
        tags_any: vec![],
        agent_id: None,
        since: None,
        until: None,
        limit: 50,
        active_embedding_space: Some(active.clone()),
    };
    let results = store
        .recall_hybrid(&ctx, "zzznomatchtokenzzz", Some(&vec), &filter)
        .await
        .expect("recall_hybrid");
    let ids: std::collections::HashSet<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();

    assert!(
        ids.contains(active_id.as_str()),
        "the active-space row MUST be semantically recalled; got {ids:?}"
    );
    assert!(
        !ids.contains(foreign_id.as_str()),
        "the foreign-space (same-dim model swap) row MUST NEVER be scored by the \
         pgvector `<=>` recall (#2167 §3.4); got {ids:?}"
    );

    // Cleanup.
    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;
}
