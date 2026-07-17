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

/// Resolve the fixture's pgvector column dim (defaults to 384).
async fn pg_dim(store: &PostgresStore) -> usize {
    usize::try_from(
        store
            .current_embedding_dim()
            .await
            .expect("current_embedding_dim")
            .unwrap_or(384),
    )
    .unwrap_or(384)
}

fn unit_vec(dim: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; dim];
    v[0] = 1.0;
    v
}

/// #2178 — `store_with_embedding` stamps `embedding_space` atomically with
/// the vector on BOTH the fresh INSERT and the ON-CONFLICT upsert-merge arm,
/// so a same-dim model swap-back can never leave a stamp attesting a foreign
/// vector (the cross-space score path #2167 forbids).
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_store_with_embedding_stamps_space_2178() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:2178-pg";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("space2178-{}", uuid::Uuid::new_v4());
    let title = "swap-back row";
    let space_a = embedding_space_fingerprint("nomic-embed-text");
    let space_b = embedding_space_fingerprint("granite-embedding");
    assert_ne!(space_a, space_b);
    let dim = pg_dim(&store).await;
    let vec = unit_vec(dim);

    // Fresh INSERT stamps space_a with the vector.
    let id = store
        .store_with_embedding(
            &ctx,
            &mem(&uuid::Uuid::new_v4().to_string(), &ns, title, owner),
            Some(&vec),
            Some(&space_a),
        )
        .await
        .expect("insert stamps");
    let got: Option<String> =
        sqlx::query_scalar("SELECT embedding_space FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("read space after insert");
    assert_eq!(
        got.as_deref(),
        Some(space_a.as_str()),
        "fresh INSERT must stamp the vector's space; got {got:?}"
    );

    // Upsert-merge (same title+namespace) with a NEW vector in space_b: the
    // DO-UPDATE arm must REPLACE the stamp with space_b, not keep the stale
    // space_a (that would be a lying stamp).
    store
        .store_with_embedding(
            &ctx,
            &mem(&uuid::Uuid::new_v4().to_string(), &ns, title, owner),
            Some(&vec),
            Some(&space_b),
        )
        .await
        .expect("upsert re-stamps");
    let after: Option<String> =
        sqlx::query_scalar("SELECT embedding_space FROM memories WHERE namespace = $1 LIMIT 1")
            .bind(&ns)
            .fetch_one(store.pool())
            .await
            .expect("read space after upsert");
    assert_eq!(
        after.as_deref(),
        Some(space_b.as_str()),
        "upsert-merge that replaces the vector MUST re-stamp with the new space; got {after:?}"
    );

    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;
}

/// #2179 — the §5 pg adoption twin stamps legacy NULL-space dim-matching
/// rows with the active fingerprint (no-nuke), and the §6 census reports the
/// heterogeneity. Without the twin every legacy pg row is permanently
/// excluded from semantic recall after a v84 upgrade.
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_adoption_stamps_legacy_null_space_2179() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:2179-pg";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("space2179a-{}", uuid::Uuid::new_v4());
    let active = embedding_space_fingerprint("nomic-embed-text");
    let dim = pg_dim(&store).await;
    let vec = unit_vec(dim);

    // Two legacy rows: vector present, embedding_space NULL (simulating a
    // pre-v84 corpus). update_embedding stamps, then we NULL the stamp.
    let id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&id, &ns, "legacy row", owner))
        .await
        .expect("store");
    store
        .update_embedding(&ctx, &id, Some(&vec), &active)
        .await
        .expect("embed");
    sqlx::query("UPDATE memories SET embedding_space = NULL WHERE id = $1")
        .bind(&id)
        .execute(store.pool())
        .await
        .expect("simulate legacy NULL space");

    // Adoption stamps it active (no-nuke: dim matches, no differently-stamped
    // row → [G2] passes).
    let stamped = store
        .adopt_legacy_embedding_space(&active, dim)
        .await
        .expect("adopt");
    assert!(stamped >= 1, "adoption must stamp the legacy row; got {stamped}");
    let got: Option<String> =
        sqlx::query_scalar("SELECT embedding_space FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("read space");
    assert_eq!(
        got.as_deref(),
        Some(active.as_str()),
        "adopted row must carry the active fingerprint; got {got:?}"
    );

    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;
}

/// #2179 — the §5 pg adoption [G2] guard REFUSES on a multi-space corpus (a
/// row already carries a DIFFERENT non-NULL stamp), so a foreign vector is
/// never silently adopted into the active space. Preserving [G2] exactly is
/// load-bearing: a weakened guard = silent adoption of a foreign vector =
/// corruption.
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_adoption_g2_refuses_multispace_2179() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:2179g2-pg";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("space2179b-{}", uuid::Uuid::new_v4());
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    let dim = pg_dim(&store).await;
    let vec = unit_vec(dim);

    // One foreign-stamped row (multi-space history signal) + one NULL-space
    // legacy row.
    let foreign_id = uuid::Uuid::new_v4().to_string();
    let null_id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&foreign_id, &ns, "foreign", owner))
        .await
        .expect("store foreign");
    store
        .update_embedding(&ctx, &foreign_id, Some(&vec), &foreign)
        .await
        .expect("stamp foreign");
    store
        .store(&ctx, &mem(&null_id, &ns, "legacy", owner))
        .await
        .expect("store legacy");
    store
        .update_embedding(&ctx, &null_id, Some(&vec), &active)
        .await
        .expect("embed legacy");
    sqlx::query("UPDATE memories SET embedding_space = NULL WHERE id = $1")
        .bind(&null_id)
        .execute(store.pool())
        .await
        .expect("null the legacy stamp");

    // [G2] must refuse: the foreign-stamped row proves multi-space history.
    let stamped = store
        .adopt_legacy_embedding_space(&active, dim)
        .await
        .expect("adopt");
    assert_eq!(stamped, 0, "[G2] must refuse adoption on a multi-space corpus; got {stamped}");
    let null_space: Option<String> =
        sqlx::query_scalar("SELECT embedding_space FROM memories WHERE id = $1")
            .bind(&null_id)
            .fetch_one(store.pool())
            .await
            .expect("read null space");
    assert!(
        null_space.is_none(),
        "the NULL-space row must STAY NULL under [G2] refusal (excluded until reembed); got \
         {null_space:?}"
    );

    let _ = store.forget(&ctx, Some(&ns), None, None, true).await;
}
