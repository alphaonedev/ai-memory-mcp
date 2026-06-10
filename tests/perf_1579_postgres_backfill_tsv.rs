// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1579 (v0.7.0 performance final gate) — postgres remediation pins.
//!
//! **A4 — serve-boot embedding-backfill sweep.** The legacy backfill
//! (`crate::mcp::run_embedding_backfill*`) is bound to a
//! `rusqlite::Connection` and is invoked ONLY from the MCP stdio boot
//! path; the `serve` daemon — the only postgres-capable surface —
//! never ran ANY sweep, so rows whose embeddings were `NULL`ed by the
//! v29 embedding-dim migration stayed NULL forever (P3 fleet audit:
//! 37/7,994 rows embedded = 0.46%, semantic recall dead). The fix is
//! the SAL-level pair `MemoryStore::list_unembedded` +
//! `MemoryStore::set_embeddings_batch` driven by
//! `store::run_embedding_backfill_on_store`, spawned at `serve` boot
//! (`src/daemon_runtime.rs`). Tests here pin the sweep end-to-end
//! against a live postgres: NULL-embedding rows + a configured
//! embedder ⇒ the sweep embeds them, in bounded batches.
//!
//! **B2 — stored generated tsvector column (schema v57).** Pre-fix
//! the recall/search shapes ranked with
//! `ts_rank(to_tsvector('english', title || ' ' || content), …)` —
//! the GIN EXPRESSION index served only the `@@` match, and `ts_rank`
//! re-parsed the document text PER MATCHED ROW (~305 of 306 ms at 8k
//! rows; 1.86 s measured on a worst-case all-rows-match probe). v57
//! adds `tsv tsvector GENERATED ALWAYS AS (…) STORED` +
//! `memories_tsv_gin`, and the queries read `tsv` for match AND rank.
//! The timing win is asserted structurally (plan shape), not by a
//! flaky wall-clock bound: the EXPLAIN output must cite the stored
//! column / its GIN index and must NOT contain any `to_tsvector`
//! recompute.
//!
//! ## Gating
//!
//! `--features sal-postgres` + `AI_MEMORY_TEST_POSTGRES_URL` at run
//! time (skip-and-return otherwise) — same shape as
//! `tests/postgres_touch_batch.rs`. Each test isolates itself in a
//! per-test schema via `common::postgres_env::PostgresTestEnv`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::needless_update)]

mod common;

use std::sync::Arc;

use ai_memory::embeddings::Embed;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, run_embedding_backfill_on_store};
use anyhow::Result;
use common::postgres_env::PostgresTestEnv;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;

/// Local mock embedder — mirrors `tests/embedding_backfill_batch.rs`
/// (the `test_support::MockEmbedder` is `#[cfg(test)]`-gated inside
/// `src/embeddings.rs` and invisible to integration tests).
/// Deterministic per-text output; 384 dims to match the default
/// `PostgresStore::connect` embedding column declaration.
struct IntegrationMockEmbedder;

const MOCK_DIM: usize = 384;

impl IntegrationMockEmbedder {
    fn embed_one(text: &str) -> Vec<f32> {
        let hash = text.bytes().fold(0u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(u32::from(b))
        });
        let base = f32::from(u16::try_from(hash % 1000).unwrap_or(0)) / 1000.0;
        (0..MOCK_DIM)
            .map(|i| {
                let idx_f32 = u16::try_from(i).map_or(0.0_f32, f32::from);
                base + (idx_f32 * 0.0001).sin().abs()
            })
            .collect()
    }
}

impl Embed for IntegrationMockEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        Ok(Self::embed_one(text))
    }
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| Self::embed_one(t)).collect())
    }
}

fn fixture_memory(idx: usize, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("perf-1579 substrate recall probe {idx:03}"),
        content: format!(
            "Synthetic federation quorum content for the #1579 postgres remediation \
             pin, row {idx:03}. Keyword tokens: substrate recall semantic embedding."
        ),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:perf-1579-test"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Raw inspection pool against the per-test schema URL so unqualified
/// `memories` resolves to the isolated schema, independent of the
/// adapter's own pool.
async fn inspection_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .expect("inspection pool connect")
}

/// A4 — the SAL sweep must embed every NULL-embedding row in bounded
/// batches and drain to an empty scan. Seeds 7 rows through the plain
/// `store()` path (no embedding), then drives
/// `run_embedding_backfill_on_store` with `batch_size=3` (forcing 3
/// passes: 3+3+1) and asserts (a) the return count, (b) the
/// post-sweep `list_unembedded` scan is empty, (c) the `embedding`
/// column is actually populated row-by-row.
#[tokio::test(flavor = "multi_thread")]
async fn a4_backfill_sweep_embeds_null_embedding_rows() {
    let Some(env) = PostgresTestEnv::new("a4_backfill_sweep").await else {
        eprintln!(
            "skip a4_backfill_sweep_embeds_null_embedding_rows: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(env.url())
            .await
            .expect("connect postgres adapter"),
    );
    let ctx = CallerContext::for_agent("ai:perf-1579-test");
    let ns = format!("perf-1579-a4-{}", uuid::Uuid::new_v4());

    for i in 0..7 {
        let mem = fixture_memory(i, &ns);
        store.store(&ctx, &mem).await.expect("seed store");
    }

    // Pre-sweep: every seeded row reports unembedded; the LIMIT is
    // honoured (bounded batches, F5.6 semantics).
    let pre = store
        .list_unembedded(&ctx, 100)
        .await
        .expect("pre-sweep scan");
    assert_eq!(pre.len(), 7, "all 7 seeded rows must report unembedded");
    let bounded = store.list_unembedded(&ctx, 3).await.expect("bounded scan");
    assert_eq!(bounded.len(), 3, "LIMIT must bound the scan");

    let emb = IntegrationMockEmbedder;
    let written = run_embedding_backfill_on_store(store.as_ref(), &ctx, &emb, 3).await;
    assert_eq!(written, 7, "sweep must embed all 7 rows across 3 passes");

    let post = store
        .list_unembedded(&ctx, 100)
        .await
        .expect("post-sweep scan");
    assert!(
        post.is_empty(),
        "post-sweep scan must be empty, got {} rows",
        post.len()
    );

    // Idempotence: a second sweep is a true no-op.
    let again = run_embedding_backfill_on_store(store.as_ref(), &ctx, &emb, 3).await;
    assert_eq!(again, 0, "re-running the sweep on a drained store writes 0");

    // Belt-and-suspenders: the vectors are actually on the rows.
    let pool = inspection_pool(env.url()).await;
    let embedded: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE embedding IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("count embedded");
    assert_eq!(
        embedded, 7,
        "embedding column must be populated on all rows"
    );
}

/// B2 — schema v57 must land `tsv` as a STORED generated column with
/// the `memories_tsv_gin` GIN index, and must drop the legacy
/// expression index `memories_content_fts`.
#[tokio::test(flavor = "multi_thread")]
async fn b2_tsv_is_stored_generated_gin_indexed_and_expression_index_dropped() {
    let Some(env) = PostgresTestEnv::new("b2_tsv_catalog").await else {
        eprintln!(
            "skip b2_tsv_is_stored_generated_gin_indexed_and_expression_index_dropped: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    let _store = PostgresStore::connect(env.url())
        .await
        .expect("connect postgres adapter");
    let pool = inspection_pool(env.url()).await;

    // attgenerated = 's' ⇒ STORED generated column.
    let generated: Option<String> = sqlx::query_scalar(
        "SELECT a.attgenerated::text FROM pg_attribute a
          JOIN pg_class c ON c.oid = a.attrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relname = 'memories' AND a.attname = 'tsv' AND n.nspname = $1",
    )
    .bind(env.schema_name())
    .fetch_optional(&pool)
    .await
    .expect("probe tsv column");
    assert_eq!(
        generated.as_deref(),
        Some("s"),
        "memories.tsv must exist as a STORED generated column (attgenerated='s')"
    );

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE tablename = 'memories' AND schemaname = $1",
    )
    .bind(env.schema_name())
    .fetch_all(&pool)
    .await
    .expect("list memories indexes");
    assert!(
        indexes.iter().any(|i| i == "memories_tsv_gin"),
        "memories_tsv_gin must exist; saw: {indexes:?}"
    );
    assert!(
        !indexes.iter().any(|i| i == "memories_content_fts"),
        "legacy expression index memories_content_fts must be dropped; saw: {indexes:?}"
    );
}

/// B2 — the search plan must read the stored `tsv` column (GIN index
/// on the COLUMN) and must not recompute `to_tsvector` anywhere — not
/// for the `@@` match, not for the `ts_rank` sort key. Plan-shape
/// assertion instead of a wall-clock bound (timing asserts are flaky
/// in CI); the EXPLAIN ANALYZE output is logged for the perf-evidence
/// trail.
#[tokio::test(flavor = "multi_thread")]
async fn b2_search_plan_reads_tsv_column_not_expression_recompute() {
    let Some(env) = PostgresTestEnv::new("b2_tsv_plan").await else {
        eprintln!(
            "skip b2_search_plan_reads_tsv_column_not_expression_recompute: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(env.url())
            .await
            .expect("connect postgres adapter"),
    );
    let ctx = CallerContext::for_agent("ai:perf-1579-test");
    let ns = format!("perf-1579-b2-{}", uuid::Uuid::new_v4());
    for i in 0..50 {
        let mem = fixture_memory(i, &ns);
        store.store(&ctx, &mem).await.expect("seed store");
    }

    let pool = inspection_pool(env.url()).await;
    let mut conn = pool.acquire().await.expect("acquire explain conn");
    // Small table — without this the planner may legitimately prefer
    // a seq scan over the GIN index. The assertion target is "the
    // index on the stored column is the plan's access path when index
    // access is viable", not the planner's small-table heuristics.
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .expect("disable seqscan");

    // Probe 1 — pure-FTS shape (no namespace predicate): the GIN
    // index on the stored column must be the access path. The full
    // production shape below may legitimately route through the
    // (more selective) namespace index instead — index CHOICE is the
    // planner's; what B2 pins is that the tsvector source is the
    // stored column either way.
    let gin_rows = sqlx::query(
        "EXPLAIN SELECT id, ts_rank(tsv, to_tsquery('english', $1)) AS rank
           FROM memories
          WHERE tsv @@ to_tsquery('english', $1)
          ORDER BY rank DESC
          LIMIT 10",
    )
    .bind("substrate | recall")
    .fetch_all(&mut *conn)
    .await
    .expect("explain pure-FTS shape");
    let gin_plan = gin_rows
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n");
    eprintln!("#1579 B2 post-fix EXPLAIN (pure-FTS shape):\n{gin_plan}");
    assert!(
        gin_plan.contains("memories_tsv_gin"),
        "pure-FTS plan must use the GIN index on the stored tsv column:\n{gin_plan}"
    );
    assert!(
        !gin_plan.contains("to_tsvector"),
        "pure-FTS plan must not recompute to_tsvector:\n{gin_plan}"
    );

    // Probe 2 — mirror of `PostgresStore::search`'s post-#1579-B2 SQL
    // shape (rank blend + namespace + expiry predicates), EXPLAIN
    // ANALYZE logged for the perf-evidence trail.
    let explain_sql = "EXPLAIN ANALYZE SELECT *,
            ts_rank(tsv, to_tsquery('english', $1))
            + (priority * 0.5)
            + (LEAST(access_count, 50) * 0.1)
            + (confidence * 2.0)
            + CASE tier WHEN 'long' THEN 3.0 WHEN 'mid' THEN 1.0 ELSE 0.0 END
            + (1.0 / (1.0 + EXTRACT(EPOCH FROM (NOW() - updated_at)) / 86400.0 * 0.1))
              AS rank
         FROM memories
         WHERE tsv @@ to_tsquery('english', $1)
           AND ($2::text IS NULL OR namespace = $2)
           AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY rank DESC, priority DESC
         LIMIT 10";
    let rows = sqlx::query(explain_sql)
        .bind("substrate | recall")
        .bind(Some(ns.as_str()))
        .fetch_all(&mut *conn)
        .await
        .expect("explain analyze search shape");
    let plan = rows
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n");
    eprintln!("#1579 B2 post-fix EXPLAIN ANALYZE (full search shape):\n{plan}");

    // The load-bearing B2 assertion: NO to_tsvector recompute anywhere
    // in the plan — not in the match filter, not in the ts_rank sort
    // key. Pre-fix this appeared in BOTH (Sort Key + Filter), costing
    // ~305 of 306 ms at 8k rows.
    assert!(
        !plan.contains("to_tsvector"),
        "plan must not recompute to_tsvector anywhere (match OR rank):\n{plan}"
    );
    assert!(
        plan.contains("ts_rank(tsv,"),
        "rank must read the stored tsv column:\n{plan}"
    );
}

/// B2 — functional sanity: the rewritten `search` shape still returns
/// the seeded matches through the SAL surface (byte-equal wire
/// contract; only the tsvector source moved to the stored column).
#[tokio::test(flavor = "multi_thread")]
async fn b2_search_still_returns_matches_through_sal() {
    let Some(env) = PostgresTestEnv::new("b2_search_sanity").await else {
        eprintln!(
            "skip b2_search_still_returns_matches_through_sal: AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(env.url())
            .await
            .expect("connect postgres adapter"),
    );
    let ctx = CallerContext::for_agent("ai:perf-1579-test");
    let ns = format!("perf-1579-sanity-{}", uuid::Uuid::new_v4());
    for i in 0..5 {
        let mem = fixture_memory(i, &ns);
        store.store(&ctx, &mem).await.expect("seed store");
    }

    let filter = Filter {
        namespace: Some(ns.clone()),
        tier: None,
        tags_any: vec![],
        agent_id: None,
        since: None,
        until: None,
        limit: 10,
    };
    let hits = store
        .search(&ctx, "substrate recall", &filter)
        .await
        .expect("search through SAL");
    assert_eq!(
        hits.len(),
        5,
        "all 5 seeded rows must match the keyword search via the tsv column"
    );
    // find_contradictions also moved to the tsv column — sanity-pin it
    // (the trait method feeds the contradiction detector).
    let candidates = store
        .find_contradictions("perf-1579 substrate recall probe 001", &ns)
        .await
        .expect("find_contradictions via tsv");
    assert!(
        !candidates.is_empty(),
        "find_contradictions must surface same-namespace FTS candidates via tsv"
    );
}
