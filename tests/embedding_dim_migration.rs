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

/// \#1882 helper — run `schema-init --json` with the given config-resolved
/// default and NO explicit `--embedding-dim` (the common deploy-pipeline
/// invocation), returning the parsed report. Exercises the real public
/// [`ai_memory::cli::schema_init::run`] entry-point so the default-dim
/// resolution under test is the production one.
async fn run_schema_init_default(url: &str, config_default_dim: Option<u32>) -> serde_json::Value {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run as schema_init_run};

    let args = SchemaInitArgs {
        store_url: url.to_string(),
        json: true,
        // Operator omits the flag → dim resolves from `config_default_dim`.
        embedding_dim: None,
        force_reembed: false,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        schema_init_run(&args, config_default_dim, &mut out)
            .await
            .expect("schema-init run");
    }
    let raw = String::from_utf8(so).expect("utf-8 schema-init json");
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parseable JSON, got {raw}: {e}"))
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
            // #2567 — embedder available: this test exercises the destructive
            // migrate/backfill path, which is reachable only when an embedder
            // can regenerate the NULLed vectors.
            true,
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
            // #2567 — embedder available: this test exercises the destructive
            // migrate/backfill path, which is reachable only when an embedder
            // can regenerate the NULLed vectors.
            true,
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
            // #2567 — embedder available: this test exercises the destructive
            // migrate/backfill path, which is reachable only when an embedder
            // can regenerate the NULLed vectors.
            true,
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
        // #2567 — embedder available: this test exercises the destructive
        // migrate/backfill path, which is reachable only when an embedder
        // can regenerate the NULLed vectors.
        true,
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
        .store_with_embedding(&ctx, &mem, Some(&embedding), Some("test-space#none"))
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
            .store_with_embedding(&ctx, &mem, Some(&embedding), Some("test-space#none"))
            .await
            .expect("seed 384-dim row");
    }

    // Warm the serving pool: run `list` repeatedly so the `SELECT *`
    // prepared plan (result type includes `vector(384)`) is cached across
    // the pool's connections — exactly what a live daemon does while
    // serving `GET /api/v1/memories` before the boot-time auto-migrate.
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some("issue-1881".to_string());
        __f.limit = 50;
        __f
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

/// Issue #1882 — CROSS-PROCESS closeout of the #1881 cached-plan 503.
///
/// The #1881 minimal harden ([`PostgresStore::discard_pool_cached_plans`])
/// evicted the MIGRATING process's own pool, but a SEPARATELY-running
/// serving daemon's pool was unreachable — so a `schema-init` re-flipping
/// the column in one process still invalidated a serving daemon's cached
/// plans in another. #1882 removes the boot-time ALTER at its SOURCE:
/// `schema-init` and `serve` now resolve the embedding dim from the SAME
/// config-driven source, so a fresh DEFAULT deploy (any tier) never
/// disagrees on the dim and no boot-time
/// `ALTER TABLE ... embedding TYPE vector(N)` fires — hence the
/// cross-process cached-plan invalidation is impossible.
///
/// This is the production-faithful cross-process reproduction:
///  - **Process A** = `schema-init` with NO `--embedding-dim` (the common
///    deploy-pipeline invocation). Post-#1882 it provisions the column at
///    the daemon-resolved default (768 for a smart/autonomous deploy);
///    pre-#1882 it hardcoded 384 — the first assertion pins this and FAILS
///    against pre-fix behaviour.
///  - **Process B** = a separate serving pool booting via the #877
///    auto-migrate entry point at the SAME daemon default, then warming
///    `list` (caching the `SELECT *` plan that binds vector(768)).
///  - **Process A redeploy** = `schema-init` runs again (idempotent deploy
///    step). Post-#1882 it reports `embedding_dim_migrated == false` (NO
///    ALTER), so process B's cached plans are untouched.
///
/// Pre-#1882 the redeploy would flip 768→384 under process B's warmed pool
/// and a subset of its reads would return `cached plan must not change
/// result type`. Post-#1882 all 40 reads succeed and no ALTER ever fires.
#[tokio::test]
async fn default_deploy_no_boot_alter_cross_process_1882() {
    use ai_memory::store::{CallerContext, Filter, MemoryStore};

    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");

    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;

    // The daemon's resolved embedder dim for a fresh DEFAULT smart/autonomous
    // deploy: `NomicEmbedV15` = 768. This is exactly what
    // `resolve_configured_embedding_dim` returns for that tier (pinned by
    // the daemon_runtime unit tests) and what the SchemaInit dispatch hands
    // to `schema-init` as `config_default_dim` when `--embedding-dim` is
    // omitted.
    let daemon_default_dim: u32 = 768;

    // ---- Process A: schema-init WITHOUT --embedding-dim ----
    // Post-#1882 this lands vector(768) from the config-resolved default.
    // Pre-#1882 it would land vector(384) (hardcoded) → this assert FAILS.
    let report_a = run_schema_init_default(&url, Some(daemon_default_dim)).await;
    assert_eq!(
        report_a["embedding_dim"].as_i64(),
        Some(768),
        "#1882: schema-init with no --embedding-dim must provision the \
         daemon-resolved default dim (768), not the legacy hardcoded 384: {report_a}"
    );
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "column must be vector(768) after the default-deploy schema-init"
    );

    // ---- Process B: a SEPARATE serving daemon pool ----
    // Boots via the #877 auto-migrate entry point at the SAME daemon
    // default. Because process A already provisioned 768, this is a no-op:
    // NO boot-time ALTER.
    let serve = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
        &url,
        daemon_default_dim,
        30,
        PoolConfig::default(),
        // #2567 — embedder available: this test exercises the destructive
        // migrate/backfill path, which is reachable only when an embedder
        // can regenerate the NULLed vectors.
        true,
    )
    .await
    .expect("serving pool boots at the daemon default dim");
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "serve boot at a matching dim must NOT fire an ALTER"
    );

    // Warm the serving pool so `SELECT *` (result type includes
    // vector(768)) is cached across its connections — the plan the #1881
    // 503 came from invalidating.
    let ctx = CallerContext::for_agent("issue-1882-test");
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some("issue-1882".to_string());
        __f.limit = 50;
        __f
    };
    for _ in 0..10 {
        serve
            .list(&ctx, &filter)
            .await
            .expect("warm-up list on the serving pool must succeed");
    }

    // ---- Process A redeploy: schema-init runs AGAIN ----
    // The cross-process trigger the #1881 minimal harden could not reach.
    // Post-#1882 both processes resolve 768, so the re-run is a pure no-op:
    // `embedding_dim_migrated == false` — NO ALTER — so process B's cached
    // plans cannot be invalidated.
    let report_a2 = run_schema_init_default(&url, Some(daemon_default_dim)).await;
    assert_eq!(
        report_a2["embedding_dim_migrated"], false,
        "#1882: a default redeploy must fire NO embedding-dim ALTER: {report_a2}"
    );
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "redeploy must leave the column at vector(768)"
    );

    // ---- The cross-process assertion ----
    // Every `list` on process B's warmed pool must still succeed: no ALTER
    // happened anywhere, so no cached plan was invalidated across processes.
    let mut cached_plan_503s = 0;
    for _ in 0..40 {
        match serve.list(&ctx, &filter).await {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("cached plan must not change result type"),
                    "unexpected non-#1882 list failure on the serving pool: {msg}"
                );
                cached_plan_503s += 1;
            }
        }
    }
    assert_eq!(
        cached_plan_503s, 0,
        "issue #1882: {cached_plan_503s}/40 serving-pool `list` reads hit the cross-process \
         `cached plan must not change result type` 503 — a boot-time embedding-dim ALTER \
         fired on a default deploy that #1882 was meant to eliminate"
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
        .store_with_embedding(&ctx, &mem, Some(&embedding), Some("test-space#none"))
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

/// \#2567 (5-agent vote `4d3ea1c5`) — DEGRADE, never destroy. When the
/// stored `memories.embedding` column dim disagrees with the incoming
/// configured dim AND NO embedder is constructible
/// (`embedder_available = false`: keyword tier / inference-egress denied /
/// the embedder failed to build), the daemon-bootstrap auto-migrate MUST
/// PRESERVE the stored embeddings rather than clear them. Clearing derived
/// state that cannot be regenerated (no embedder ⇒ no backfill) is
/// irreversible data loss, and `updated_at` is untouched so it would be
/// invisible to staleness checks. The connect still SUCCEEDS (degrade, not
/// error), the column dim stays untouched, and the vectors stay non-NULL;
/// the schema self-heals the next boot that DOES build an embedder.
#[tokio::test]
async fn auto_migrate_preserves_embeddings_without_embedder_2567() {
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

    // Bootstrap at 768 and seed a 768-dim embedding — a POPULATED corpus at
    // a dim that will disagree with the incoming (keyword-only) config.
    let store = PostgresStore::connect_with_dim(&url, 768)
        .await
        .expect("connect at dim=768");
    assert_eq!(current_dim(&inspect).await, Some(768), "bootstrap at 768");

    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: "issue-2567-preserve".to_string(),
        namespace: "ai-memory-mcp".to_string(),
        title: "issue #2567 preserve".to_string(),
        content: "this embedding must survive a no-embedder dim disagreement".to_string(),
        tags: vec!["issue-2567".to_string()],
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id":"issue-2567-test"}),
        ..Default::default()
    };
    let ctx = CallerContext::for_agent("issue-2567-test");
    let embedding: Vec<f32> = vec![0.25_f32; 768];
    store
        .store_with_embedding(&ctx, &mem, Some(&embedding), Some("test-space#none"))
        .await
        .expect("seed 768-dim embedding");
    drop(store);

    // Boot the auto-migrate entry point at a DIFFERENT dim (384) with
    // embedder_available = FALSE — the #2567 no-embedder case. The dims
    // disagree (768 != 384) but there is no embedder to regenerate the
    // vectors, so the destructive migrate MUST be skipped and the connect
    // MUST still succeed.
    {
        let _serve = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
            &url,
            384,
            30,
            PoolConfig::default(),
            // #2567 — NO constructible embedder ⇒ preserve, do not NULL.
            false,
        )
        .await
        .expect("no-embedder auto-migrate connect must SUCCEED (degrade, never error)");
    }

    // Nothing destroyed: the column dim is UNCHANGED (still 768) and the
    // stored embedding is still non-NULL.
    assert_eq!(
        current_dim(&inspect).await,
        Some(768),
        "#2567: no-embedder auto-migrate must leave the column dim untouched (no destructive ALTER)"
    );
    let still_present: Option<(bool,)> = sqlx::query_as(
        "SELECT embedding IS NOT NULL FROM memories WHERE id = 'issue-2567-preserve'",
    )
    .fetch_optional(&inspect)
    .await
    .expect("inspect embedding nullability");
    assert_eq!(
        still_present,
        Some((true,)),
        "#2567: no-embedder auto-migrate must PRESERVE the stored embedding \
         (never NULL derived state that cannot be regenerated)"
    );
}

/// \#2567 — the CONTRAST case that keeps the #877 fix intact. With
/// `embedder_available = true` the SAME dim disagreement over a populated
/// corpus DOES take the destructive migrate (a live embedder will
/// regenerate the vectors from the durable text), flipping the column and
/// clearing the stored embedding. This pins that the #2567 gate degrades
/// ONLY the no-embedder path and does not break the embedder-present path.
#[tokio::test]
async fn auto_migrate_nulls_embeddings_with_embedder_2567() {
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

    let store = PostgresStore::connect_with_dim(&url, 768)
        .await
        .expect("connect at dim=768");
    assert_eq!(current_dim(&inspect).await, Some(768), "bootstrap at 768");

    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: "issue-2567-migrate".to_string(),
        namespace: "ai-memory-mcp".to_string(),
        title: "issue #2567 migrate".to_string(),
        content: "this embedding is NULLed because a live embedder will re-derive it".to_string(),
        tags: vec!["issue-2567".to_string()],
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id":"issue-2567-test"}),
        ..Default::default()
    };
    let ctx = CallerContext::for_agent("issue-2567-test");
    let embedding: Vec<f32> = vec![0.25_f32; 768];
    store
        .store_with_embedding(&ctx, &mem, Some(&embedding), Some("test-space#none"))
        .await
        .expect("seed 768-dim embedding");
    drop(store);

    {
        let _serve = PostgresStore::connect_with_dim_and_timeout_auto_migrate(
            &url,
            384,
            30,
            PoolConfig::default(),
            // #2567 — a live embedder IS available ⇒ the #877 migrate runs.
            true,
        )
        .await
        .expect("with-embedder auto-migrate to dim=384");
    }

    assert_eq!(
        current_dim(&inspect).await,
        Some(384),
        "#2567: with-embedder auto-migrate must flip the column to vector(384)"
    );
    let nulled: Option<(bool,)> =
        sqlx::query_as("SELECT embedding IS NULL FROM memories WHERE id = 'issue-2567-migrate'")
            .fetch_optional(&inspect)
            .await
            .expect("inspect post-conversion embedding nullability");
    assert_eq!(
        nulled,
        Some((true,)),
        "#2567: with-embedder auto-migrate NULLs the stored embedding (re-embed regenerates it)"
    );
}
