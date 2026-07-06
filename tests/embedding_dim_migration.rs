// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #877 (HIGH-SEV) — embedding-dim auto-migrate regression.
//!
//! Plan-C re-test surfaced that a fresh container schema bootstraps
//! `memories.embedding` at `vector(384)` (the `DEFAULT_EMBEDDING_DIM`),
//! while an autonomous-tier daemon loads `nomic-embed-text-v1.5` (768).
//! Every HTTP POST `/api/v1/memories` then failed with `expected 384
//! dimensions, not 768` at the pgvector layer.
//!
//! Fix: the postgres adapter exposes
//! `connect_with_dim_and_timeout_auto_migrate(url, dim, secs)` — a new
//! daemon-bootstrap entry point that detects the dim mismatch and runs
//! the destructive `migrate_embedding_dim` in-place. The daemon
//! `bootstrap_serve` path resolves the configured embedder dim from the
//! same ladder `build_embedder` uses (`app_config` override > tier preset)
//! and threads it through `build_store_handle` → the new auto-migrate
//! entry point so a misaligned-dim schema is healed before the first
//! write hits the wire.
//!
//! # Gating
//!
//! Requires `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`
//! pointing at a fresh, disposable database. Without either the test
//! `eprintln!`s a skip and returns Ok — matches the rest of the
//! postgres integration suite.
//!
//! # What the test pins
//!
//! 1. Bootstrap at dim=384, sanity-check the column declared at 384.
//! 2. Re-open with the auto-migrate entry point at dim=768 — verify the
//!    column flipped to `vector(768)`.
//! 3. Idempotence: a second auto-migrate call at dim=768 is a no-op.
//! 4. End-to-end write-path regression: after the auto-migrate, the
//!    postgres adapter accepts a 768-dim embedding insert end-to-end
//!    (the actual failure mode the Plan-C retest hit).

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::{PoolConfig, PostgresStore};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_env::PublicSchemaLock;
use common::postgres_url;

// Issue #1381 (2026-05-28): the three tests in this file exercise
// substrate paths that are HARDCODED to probe + mutate
// `public.memories` (see `current_embedding_dim` at
// `src/store/postgres.rs:2782` — the `n.nspname = 'public'` filter
// is intentional). Per-test schema isolation via `PostgresTestEnv`
// does NOT fit this file, because the substrate's auto-migrate
// path would still target `public.memories` regardless of the
// test's `search_path`.
//
// Instead, every `#[tokio::test]` here acquires the cross-process
// `PublicSchemaLock` (defined in `tests/common/postgres_env.rs`) at
// the top of the body. The lock serialises ownership of
// `public.memories` across every parallel test binary in the same
// `cargo test --features sal,sal-postgres` invocation, not just
// the three tests in this file — that is the actual race the
// pre-#1381 in-process `tokio::sync::Mutex` could not close,
// because a sibling test binary (e.g. `migrate_links_roundtrip`)
// running in parallel would still race us on `public.memories`.
//
// `current_dim` is ALSO scoped to `n.nspname = 'public'` so a
// stale `memories` relation in `ic_alice`/`ic_bob`/etc on the
// LAN-parity stack does NOT shadow our reset → bootstrap sequence
// (the pre-#1381 unscoped probe surfaced whichever schema's
// row Postgres picked first by oid, often the wrong one).

/// Drop ai-memory tables so each test gets a fresh schema. The postgres
/// fixture is shared across tests in the suite, so we tear down the
/// adapter-owned tables (CREATE TABLE IF NOT EXISTS is the bootstrap
/// idiom, so dropping = full reset on the next connect). We DO NOT
/// drop the `vector` extension itself — that's a database-level install
/// that other tests in the binary may still need.
async fn reset_schema(pool: &PgPool) {
    let stmts = [
        "DROP TABLE IF EXISTS archived_memories CASCADE",
        "DROP TABLE IF EXISTS memory_links CASCADE",
        "DROP TABLE IF EXISTS memories CASCADE",
        "DROP TABLE IF EXISTS namespace_meta CASCADE",
        "DROP TABLE IF EXISTS pending_actions CASCADE",
        "DROP TABLE IF EXISTS sync_state CASCADE",
        "DROP TABLE IF EXISTS subscriptions CASCADE",
        "DROP TABLE IF EXISTS subscription_events CASCADE",
        "DROP TABLE IF EXISTS subscription_dlq CASCADE",
        "DROP TABLE IF EXISTS signed_events CASCADE",
        "DROP TABLE IF EXISTS audit_log CASCADE",
        "DROP TABLE IF EXISTS entity_aliases CASCADE",
        "DROP TABLE IF EXISTS memory_transcripts CASCADE",
        "DROP TABLE IF EXISTS memory_transcript_links CASCADE",
        "DROP TABLE IF EXISTS agent_quotas CASCADE",
        "DROP TABLE IF EXISTS schema_version CASCADE",
        "DROP VIEW IF EXISTS kg_query_view CASCADE",
        "DROP VIEW IF EXISTS kg_timeline_view CASCADE",
    ];
    for sql in stmts {
        let _ = sqlx::query(sql).execute(pool).await;
    }
}

async fn inspection_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .expect("inspection pool connect")
}

async fn current_dim(pool: &PgPool) -> Option<i32> {
    // Issue #1381: scope to `public.memories` so a sibling
    // `<other_schema>.memories` (e.g. the LAN-parity stack's
    // long-lived `ic_alice`/`ic_bob` daemon schemas or any other
    // test binary's residual schema) does NOT shadow the dim we
    // just bootstrapped into `public`. Mirrors the substrate's own
    // probe at `src/store/postgres.rs:2787` (`current_embedding_dim`).
    sqlx::query_scalar::<_, i32>(
        "SELECT atttypmod FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Core regression: bootstrap at 384, then re-open with the
/// auto-migrate entry point at 768 — the column flips in-place.
#[tokio::test]
async fn auto_migrate_converts_384_schema_to_768_on_daemon_bootstrap() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    // Issue #1381: cross-process serialise on `public.memories`
    // ownership so a sibling test binary's bootstrap can't race us.
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    // Step 1: bootstrap the schema at the legacy MiniLM dim (384). This
    // mirrors a fresh container that booted before the operator
    // configured an embedder, or that booted with the default
    // `MiniLmL6V2` preset.
    {
        let _store = PostgresStore::connect_with_dim(&url, 384)
            .await
            .expect("connect at dim=384");
    }
    assert_eq!(
        current_dim(&inspect).await,
        Some(384),
        "step-1: fresh bootstrap must land vector(384)"
    );

    // Step 2: re-open via the auto-migrate entry point at dim=768. This
    // is what the daemon does at `bootstrap_serve` time when the
    // configured tier is `autonomous` / `smart` (= NomicEmbedV15, 768).
    {
        let _store = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
            &url,
            768,
            30,
            PoolConfig::default(),
        )
        .await
        .expect("auto-migrate to dim=768");
    }
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "step-2: auto-migrate must convert the column to vector(768) in place"
    );

    // Step 3: idempotence — a second auto-migrate at 768 is a no-op
    // and leaves the column unchanged.
    {
        let _store = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
            &url,
            768,
            30,
            PoolConfig::default(),
        )
        .await
        .expect("idempotent auto-migrate");
    }
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "step-3: re-opening at the matching dim must be a no-op"
    );
}

/// Direct bootstrap at 768 via the auto-migrate entry point: the
/// fresh schema lands `vector(768)` so the no-op-after-bootstrap path
/// also passes (we don't need to do the conversion at all).
#[tokio::test]
async fn auto_migrate_no_op_when_fresh_schema_already_matches() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    {
        let _store = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
            &url,
            768,
            30,
            PoolConfig::default(),
        )
        .await
        .expect("fresh bootstrap at dim=768 via auto-migrate path");
    }
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "fresh-bootstrap path must land vector(768) directly without a destructive migrate"
    );
}

/// HTTP-write-path regression closeout: after the auto-migrate runs,
/// the postgres adapter accepts a 768-dim embedding insert end-to-end.
/// This is the actual failure mode the Plan-C container retest hit
/// (`expected 384 dimensions, not 768`); the test pins the recovery.
#[tokio::test]
async fn http_write_path_accepts_768_after_auto_migrate() {
    use ai_memory::models::Memory;
    use ai_memory::store::{CallerContext, MemoryStore};
    use chrono::Utc;

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    // 1) Bootstrap the schema at 384 (the bug-trigger state).
    let _ = PostgresStore::connect_with_dim(&url, 384)
        .await
        .expect("seed bootstrap");

    // 2) Re-open with auto-migrate at 768 (simulates the fixed daemon
    //    bootstrap path with an autonomous-tier embedder).
    let store = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
        &url,
        768,
        30,
        PoolConfig::default(),
    )
    .await
    .expect("auto-migrate at bootstrap");

    // 3) Insert a memory with a 768-dim embedding via the SAL surface
    //    the HTTP create_memory handler uses. `store_with_embedding`
    //    is the postgres-aware fork — bypassing it (plain `store`)
    //    would never bind the vector and the test would degenerate to
    //    a schema-only check.
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: "issue-877-retest".to_string(),
        namespace: "ai-memory-mcp".to_string(),
        title: "issue #877 retest".to_string(),
        content: "auto-migrate must let a 768-dim insert succeed".to_string(),
        tags: vec!["issue-877".to_string()],
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id":"issue-877-test"}),
        ..Default::default()
    };

    let ctx = CallerContext::for_agent("issue-877-test");
    let embedding: Vec<f32> = vec![0.0_f32; 768];
    store
        .store_with_embedding(&ctx, &mem, Some(&embedding))
        .await
        .expect("768-dim insert must succeed after auto-migrate");

    // 4) Read-back sanity: row landed.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT id FROM memories WHERE id = 'issue-877-retest'")
            .fetch_optional(&inspect)
            .await
            .expect("inspect row");
    assert!(
        row.is_some(),
        "issue-877 row must persist through the postgres write path post-auto-migrate"
    );
}

/// Issue #1881 (v0.9.0 tag-gate minimal harden) — after the #877
/// embedding-dim auto-migrate runs its in-place `ALTER TABLE ... ALTER
/// COLUMN embedding TYPE vector(N)`, the SAME sqlx pool must keep
/// serving `list` (and any read whose prepared plan selects the
/// embedding column) WITHOUT the transient
/// `cached plan must not change result type` 503 that the live DO PG16
/// GA round surfaced.
///
/// Root cause: the `list` path prepares `SELECT * FROM memories ...`,
/// whose cached result type includes the `vector(384)` embedding
/// column. The dim ALTER (384→768) changes that result type, so any
/// pooled connection still holding the pre-ALTER plan fails at the
/// server on its next `list` — alternating 200/503 across pool
/// connections until they recycle. The fix
/// ([`PostgresStore::discard_pool_cached_plans`], invoked at the tail of
/// `migrate_embedding_dim`) evicts every pooled connection's
/// prepared-statement cache immediately after the DDL commits.
///
/// This is the production-faithful reproduction: warm the serving pool
/// by running `list` at dim=384 (caching the `SELECT *` plan across the
/// pool's connections), migrate the embedding column in place to 768 on
/// that SAME pool, then hammer `list` again. PRE-FIX this asserts fails
/// with the cached-plan 503 (empirically ~1-in-3 to persistent across
/// the 40 iterations); POST-FIX all 40 reads return rows cleanly.
#[tokio::test]
async fn list_survives_embedding_dim_alter_without_cached_plan_503_1881() {
    use ai_memory::models::Memory;
    use ai_memory::store::{CallerContext, Filter, MemoryStore};
    use chrono::Utc;

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    // Bootstrap at the legacy MiniLM dim (384) and seed a handful of
    // rows WITH 384-dim embeddings so `list` returns a non-empty result
    // set whose `SELECT *` plan genuinely binds the `vector(384)` column.
    let store = PostgresStore::connect_with_dim(&url, 384)
        .await
        .expect("connect at dim=384");
    assert_eq!(current_dim(&inspect).await, Some(384), "bootstrap at 384");

    let ctx = CallerContext::for_agent("issue-1881-test");
    for i in 0..5 {
        let now = Utc::now().to_rfc3339();
        let mem = Memory {
            id: format!("issue-1881-{i}"),
            namespace: "issue-1881".to_string(),
            title: format!("row {i}"),
            content: "cached-plan regression fixture".to_string(),
            tags: vec!["issue-1881".to_string()],
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id":"issue-1881-test","scope":"shared"}),
            ..Default::default()
        };
        let embedding: Vec<f32> = vec![0.1_f32; 384];
        store
            .store_with_embedding(&ctx, &mem, Some(&embedding))
            .await
            .expect("seed 384-dim row");
    }

    // Warm the serving pool: run `list` repeatedly so the `SELECT *`
    // prepared plan (result type includes `vector(384)`) is cached across
    // the pool's connections — exactly what a live daemon does while
    // serving `GET /api/v1/memories` before the boot-time auto-migrate.
    let filter = Filter {
        namespace: Some("issue-1881".to_string()),
        limit: 50,
        ..Default::default()
    };
    for _ in 0..10 {
        store
            .list(&ctx, &filter)
            .await
            .expect("warm-up list at dim=384 must succeed");
    }

    // The #877 in-place dim migrate (384→768) on the SAME warmed pool.
    // `force = true` mirrors the daemon auto-migrate opt-in. This is the
    // DDL whose column-type change invalidates the cached `SELECT *`
    // plans; the fix must evict them here.
    let converted = store
        .migrate_embedding_dim(768, true)
        .await
        .expect("in-place embedding-dim migrate to 768");
    assert!(converted, "a real 384→768 conversion returns Ok(true)");
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "column must be vector(768) after the migrate"
    );

    // The regression assertion: every `list` on the post-ALTER pool must
    // succeed. Pre-fix, a subset (the connections holding stale plans)
    // returns `cached plan must not change result type`; post-fix, the
    // cache eviction guarantees all reads re-plan against vector(768).
    let mut cached_plan_503s = 0;
    for _ in 0..40 {
        match store.list(&ctx, &filter).await {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("cached plan must not change result type"),
                    "unexpected non-#1881 list failure after dim migrate: {msg}"
                );
                cached_plan_503s += 1;
            }
        }
    }
    assert_eq!(
        cached_plan_503s, 0,
        "issue #1881: {cached_plan_503s}/40 `list` reads on the post-ALTER pool returned \
         `cached plan must not change result type` — the pool's cached plans were not \
         evicted after the embedding-dim auto-migrate"
    );
}

/// Issue #1781 — refuse-destructive-by-default guard on
/// `migrate_embedding_dim`. With stored embeddings present, a real
/// dim conversion REFUSES (typed `InvalidInput`) without `force` and
/// leaves the embedding intact; with `force = true` it proceeds and
/// NULLs the embedding. Precedent: the #1785 DROP-confirm pattern.
#[tokio::test]
async fn migrate_embedding_dim_refuses_when_embeddings_exist_without_force() {
    use ai_memory::models::Memory;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};
    use chrono::Utc;

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    // Bootstrap at 384 and insert a memory WITH a 384-dim embedding so
    // the corpus is populated — the exact state the guard protects.
    let store = PostgresStore::connect_with_dim(&url, 384)
        .await
        .expect("connect at dim=384");
    assert_eq!(current_dim(&inspect).await, Some(384), "bootstrap at 384");

    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: "issue-1781-guard".to_string(),
        namespace: "ai-memory-mcp".to_string(),
        title: "issue #1781 guard".to_string(),
        content: "this embedding must survive a refused conversion".to_string(),
        tags: vec!["issue-1781".to_string()],
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id":"issue-1781-test"}),
        ..Default::default()
    };
    let ctx = CallerContext::for_agent("issue-1781-test");
    let embedding: Vec<f32> = vec![0.25_f32; 384];
    store
        .store_with_embedding(&ctx, &mem, Some(&embedding))
        .await
        .expect("seed 384-dim embedding");

    // 1) A real conversion (384 -> 768) with stored embeddings present
    //    and force = false MUST refuse with a typed InvalidInput and
    //    MUST NOT mutate anything.
    let refusal = store
        .migrate_embedding_dim(768, false)
        .await
        .expect_err("must refuse a destructive conversion of a populated corpus");
    match &refusal {
        StoreError::InvalidInput { detail } => {
            assert!(
                detail.contains("refusing destructive embedding-dim conversion")
                    && detail.contains("--force-reembed"),
                "refusal message must name the guard + the escape hatch; got: {detail}"
            );
        }
        other => panic!("expected StoreError::InvalidInput, got {other:?}"),
    }

    // Nothing destroyed: the column dim is unchanged AND the embedding
    // is still non-NULL.
    assert_eq!(
        current_dim(&inspect).await,
        Some(384),
        "refusal must leave the column dim untouched"
    );
    let still_present: Option<(bool,)> =
        sqlx::query_as("SELECT embedding IS NOT NULL FROM memories WHERE id = 'issue-1781-guard'")
            .fetch_optional(&inspect)
            .await
            .expect("inspect embedding nullability");
    assert_eq!(
        still_present,
        Some((true,)),
        "refusal must leave the stored embedding non-NULL (nothing destroyed)"
    );

    // 2) With force = true the same conversion proceeds: Ok(true), the
    //    column flips to vector(768), and the embedding is NULLed.
    let did_convert = store
        .migrate_embedding_dim(768, true)
        .await
        .expect("force = true must proceed with the destructive conversion");
    assert!(did_convert, "a real conversion returns Ok(true)");
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "forced conversion must flip the column to vector(768)"
    );
    let nulled: Option<(bool,)> =
        sqlx::query_as("SELECT embedding IS NULL FROM memories WHERE id = 'issue-1781-guard'")
            .fetch_optional(&inspect)
            .await
            .expect("inspect post-conversion embedding nullability");
    assert_eq!(
        nulled,
        Some((true,)),
        "forced conversion must NULL the stored embedding (re-embed required)"
    );
}
