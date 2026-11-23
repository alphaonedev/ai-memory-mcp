// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #9933 (data loss) — no boot or migrate path may NULL stored
//! embeddings because a configured or DEFAULTED dimension differs from the
//! live `vector(N)` column.
//!
//! Observed: under `AI_MEMORY_NO_CONFIG=1` with no `AI_MEMORY_EMBED_DIM`, the
//! daemon resolved the embedding dimension from the tier preset (384) and the
//! #877 boot auto-migrate set to NULL every stored 768-dim vector. The invariant
//! pinned here, for every row of the table below:
//!
//! 1. A dimension mismatch over a populated column is a REFUSAL with the exact
//!    error text (both dimensions, the source, the explicit opt-in), never a
//!    silent conversion. Every stored vector stays byte-for-byte unchanged.
//! 2. A defaulted dimension never drives a destructive change: `schema-init`
//!    without `--embedding-dim` adopts the live column.
//! 3. The only destructive re-dimension is the existing explicit opt-in,
//!    `ai-memory schema-init --embedding-dim N --force-reembed`.
//!
//! Table: (configured, defaulted, absent) x (matching, differing) at boot,
//! plus the schema-init rows. Every test serialises on `public.memories`
//! through [`PublicSchemaLock`] (the substrate's dim probe is pinned to the
//! `public` schema; see `tests/embedding_dim_migration.rs`).
//!
//! Gating: `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL` (the CI
//! v2 per-binary wrapper hands this binary its own cloned database).

#![cfg(feature = "sal-postgres")]

use ai_memory::models::Memory;
use ai_memory::store::postgres::{
    DEFAULT_EMBEDDING_DIM, EmbeddingDimIntent, PoolConfig, PostgresStore,
};
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_env::PublicSchemaLock;
use common::postgres_url;

/// The live column dimension the corpus is seeded at (nomic-embed-text-v1.5).
const LIVE_DIM: u32 = 768;
/// The dimension the issue's `NO_CONFIG` boot resolved to (`MiniLM` tier preset,
/// also the compiled default).
const OTHER_DIM: u32 = 384;
/// Distinct seeded rows; each carries a different vector so a rewrite of any
/// single row is visible.
const SEED_ROWS: usize = 3;
/// Statement timeout handed to the boot entry points.
const TIMEOUT_SECS: u64 = 30;
/// Namespace of the seeded rows.
const SEED_NAMESPACE: &str = "issue-9933";
/// Agent id of the seeded rows.
const SEED_AGENT: &str = "issue-9933-test";

/// Exact refusal for a DEFAULTED 384 boot over the seeded 768 corpus,
/// written out by hand (not computed from the code under test). The leading
/// `invalid input: ` is `StoreError::InvalidInput`'s Display prefix.
const EXPECTED_DEFAULTED_REFUSAL: &str = "invalid input: refusing destructive embedding-dim \
conversion: live column is vector(768), requested vector(384) from a defaulted dimension \
(tier preset or compiled default); 3 stored embeddings would be NULLed. To keep them, \
configure an embedder whose dimension is 768; to convert them and re-embed, run \
`ai-memory schema-init --embedding-dim 384 --force-reembed`.";

/// Exact refusal for a CONFIGURED 384 (boot) over the seeded 768 corpus.
const EXPECTED_CONFIGURED_REFUSAL: &str = "invalid input: refusing destructive embedding-dim \
conversion: live column is vector(768), requested vector(384) from a configured dimension \
(environment variable, config file or embedding model); 3 stored embeddings would be NULLed. \
To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run \
`ai-memory schema-init --embedding-dim 384 --force-reembed`.";

/// Exact refusal for an argv `--embedding-dim 384` over the seeded 768 corpus.
const EXPECTED_EXPLICIT_REFUSAL: &str = "invalid input: refusing destructive embedding-dim \
conversion: live column is vector(768), requested vector(384) from an explicit \
--embedding-dim argument; 3 stored embeddings would be NULLed. To keep them, configure an \
embedder whose dimension is 768; to convert them and re-embed, run \
`ai-memory schema-init --embedding-dim 384 --force-reembed`.";

/// Where the boot's dimension came from (the first table axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// An operator pin: `[embeddings].model`, the legacy model field, an
    /// `AI_MEMORY_EMBED_DIM` / `[embeddings].dim` pin.
    Configured,
    /// A tier preset or the compiled default (the issue's `NO_CONFIG` case).
    Defaulted,
    /// No dimension resolved at all (keyword tier): the plain connect.
    Absent,
}

/// Whether the requested dimension equals the live column (second axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    Matching,
    Differing,
}

/// The expected result of one boot row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Boot succeeds and the column keeps the live dimension.
    Boots,
    /// Boot refuses with exactly this text.
    Refuses(&'static str),
}

/// One row: (source, relation, expected). Every row also asserts that every
/// seeded vector is non-null and unchanged afterwards.
const BOOT_TABLE: [(Source, Relation, Expect); 6] = [
    (Source::Configured, Relation::Matching, Expect::Boots),
    (
        Source::Configured,
        Relation::Differing,
        Expect::Refuses(EXPECTED_CONFIGURED_REFUSAL),
    ),
    (Source::Defaulted, Relation::Matching, Expect::Boots),
    (
        Source::Defaulted,
        Relation::Differing,
        Expect::Refuses(EXPECTED_DEFAULTED_REFUSAL),
    ),
    (Source::Absent, Relation::Matching, Expect::Boots),
    (Source::Absent, Relation::Differing, Expect::Boots),
];

/// Drop the adapter-owned tables so the next connect bootstraps afresh
/// (same list as `tests/embedding_dim_migration.rs::reset_schema`).
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
        sqlx::query(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("reset_schema `{sql}` failed: {e}"));
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

/// The live `public.memories.embedding` dimension (the substrate's own probe
/// is scoped to `public` too).
async fn current_dim(pool: &PgPool) -> Option<i32> {
    sqlx::query_scalar::<_, i32>(
        "SELECT atttypmod FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .fetch_optional(pool)
    .await
    .expect("probe embedding atttypmod")
}

fn as_i32(dim: u32) -> i32 {
    i32::try_from(dim).expect("test dims fit i32")
}

/// A distinct, deterministic vector per row: row `r`, component `i` is
/// `(r + 1) * 0.001 + i * 1e-6`, so no two rows (and no two components)
/// are equal.
fn seed_vector(row: usize, dim: u32) -> Vec<f32> {
    let n = usize::try_from(dim).expect("dim fits usize");
    let row_f = f32::from(u16::try_from(row + 1).expect("row fits u16"));
    (0..n)
        .map(|i| {
            let i_f = f32::from(u16::try_from(i).expect("component fits u16"));
            row_f * 0.001 + i_f * 0.000_001
        })
        .collect()
}

/// Bootstrap a fresh schema at `dim` and store `SEED_ROWS` vectors.
/// Returns the seeded (id, vector) pairs sorted by id.
async fn seed_corpus(url: &str, dim: u32) -> Vec<(String, Vec<f32>)> {
    let store = PostgresStore::connect_with_dim(url, dim)
        .await
        .expect("bootstrap connect");
    let ctx = CallerContext::for_agent(SEED_AGENT);
    let now = chrono::Utc::now().to_rfc3339();
    let mut seeded = Vec::with_capacity(SEED_ROWS);
    for row in 0..SEED_ROWS {
        let id = format!("issue-9933-row-{row}");
        let mem = Memory {
            id: id.clone(),
            namespace: SEED_NAMESPACE.to_string(),
            title: format!("issue 9933 row {row}"),
            content: format!("stored vector {row} must survive every dim disagreement"),
            tags: vec!["issue-9933".to_string()],
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({ "agent_id": SEED_AGENT }),
            ..Default::default()
        };
        let vector = seed_vector(row, dim);
        store
            .store_with_embedding(&ctx, &mem, Some(&vector), Some("test-space#none"))
            .await
            .expect("seed embedding");
        seeded.push((id, vector));
    }
    seeded.sort_by(|a, b| a.0.cmp(&b.0));
    seeded
}

/// Read every seeded row's vector back as `real[]` (exact f32 values).
/// A NULL vector reads back as `None`, which can never equal a seeded one.
async fn read_vectors(pool: &PgPool) -> Vec<(String, Option<Vec<f32>>)> {
    sqlx::query_as::<_, (String, Option<Vec<f32>>)>(
        "SELECT id, embedding::real[] FROM memories WHERE namespace = $1 ORDER BY id",
    )
    .bind(SEED_NAMESPACE)
    .fetch_all(pool)
    .await
    .expect("read seeded vectors")
}

/// Assert every seeded vector is non-null and unchanged, and the column
/// still has `dim`.
async fn assert_intact(pool: &PgPool, seeded: &[(String, Vec<f32>)], dim: u32, row: &str) {
    assert_eq!(
        current_dim(pool).await,
        Some(as_i32(dim)),
        "{row}: the live column must keep vector({dim})"
    );
    let got = read_vectors(pool).await;
    assert_eq!(
        got.len(),
        seeded.len(),
        "{row}: every seeded row must remain"
    );
    for ((want_id, want_vec), (got_id, got_vec)) in seeded.iter().zip(got.iter()) {
        assert_eq!(want_id, got_id, "{row}: row order");
        assert_eq!(
            got_vec.as_deref(),
            Some(want_vec.as_slice()),
            "{row}: stored vector {want_id} must be non-null and unchanged"
        );
    }
}

/// Boot the daemon store the way `serve` does for `source` at `dim`.
///
/// The ONLY function in this file that names the boot entry points: the red
/// commit and the fix commit differ in this body, `schema_init_config` and
/// the `EmbeddingDimIntent` import alone.
async fn boot(
    url: &str,
    source: Source,
    dim: u32,
    embedder_available: bool,
) -> Result<PostgresStore, String> {
    let intent = match source {
        Source::Configured => Some(EmbeddingDimIntent::Configured(dim)),
        Source::Defaulted => Some(EmbeddingDimIntent::Defaulted(dim)),
        Source::Absent => None,
    };
    let res = match intent {
        // #9933 — the funnel takes the dim WITH its source.
        Some(intent) => {
            PostgresStore::connect_with_dim_and_timeout_auto_migrate(
                url,
                intent,
                TIMEOUT_SECS,
                PoolConfig::default(),
                embedder_available,
            )
            .await
        }
        // `build_store_handle` with no resolved dim: the plain connect at the
        // compiled default, which never converts.
        None => {
            PostgresStore::connect_with_dim_and_timeout(
                url,
                DEFAULT_EMBEDDING_DIM,
                TIMEOUT_SECS,
                PoolConfig::default(),
            )
            .await
        }
    };
    res.map_err(|e| e.to_string())
}

/// The (live, requested) dims for a row. `Absent` always requests the
/// compiled default, so its "matching" row seeds the corpus at that default.
fn row_dims(source: Source, relation: Relation) -> (u32, u32) {
    match (source, relation) {
        (Source::Configured | Source::Defaulted, Relation::Matching) => (LIVE_DIM, LIVE_DIM),
        (Source::Configured | Source::Defaulted, Relation::Differing) => (LIVE_DIM, OTHER_DIM),
        (Source::Absent, Relation::Matching) => (DEFAULT_EMBEDDING_DIM, DEFAULT_EMBEDDING_DIM),
        (Source::Absent, Relation::Differing) => (LIVE_DIM, DEFAULT_EMBEDDING_DIM),
    }
}

/// The whole boot table with a live embedder (the destructive case: with no
/// embedder the #2567 preserve gate already held).
#[tokio::test]
async fn boot_table_never_nulls_stored_vectors_9933() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;

    for (source, relation, expect) in BOOT_TABLE {
        let row = format!("{source:?}/{relation:?}");
        let (live, requested) = row_dims(source, relation);
        reset_schema(&inspect).await;
        let seeded = seed_corpus(&url, live).await;
        assert_eq!(seeded.len(), SEED_ROWS, "{row}: seeded rows");

        let got = boot(&url, source, requested, true).await;
        match (expect, got) {
            (Expect::Boots, Ok(store)) => drop(store),
            (Expect::Boots, Err(e)) => panic!("{row}: boot must succeed, got error: {e}"),
            (Expect::Refuses(text), Err(e)) => {
                assert_eq!(e, text, "{row}: exact refusal text");
            }
            (Expect::Refuses(text), Ok(_)) => {
                panic!("{row}: boot must refuse with `{text}`, but it succeeded")
            }
        }
        assert_intact(&inspect, &seeded, live, &row).await;
    }
}

/// The issue's exact scenario with no embedder: the #2567 preserve gate
/// must keep holding (boot succeeds, nothing rewritten).
#[tokio::test]
async fn defaulted_boot_without_embedder_preserves_vectors_9933() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    let seeded = seed_corpus(&url, LIVE_DIM).await;

    let store = boot(&url, Source::Defaulted, OTHER_DIM, false)
        .await
        .unwrap_or_else(|e| panic!("no-embedder defaulted boot must succeed, got: {e}"));
    drop(store);
    assert_intact(&inspect, &seeded, LIVE_DIM, "defaulted/no-embedder").await;
}

/// The #877 heal is kept: a differing column with NO stored embeddings
/// (nothing to lose) is converted at boot, whatever the source.
#[tokio::test]
async fn empty_column_still_converts_at_boot_877_9933() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;

    for source in [Source::Configured, Source::Defaulted] {
        reset_schema(&inspect).await;
        drop(
            PostgresStore::connect_with_dim(&url, OTHER_DIM)
                .await
                .expect("bootstrap empty schema"),
        );
        assert_eq!(current_dim(&inspect).await, Some(as_i32(OTHER_DIM)));
        let store = boot(&url, source, LIVE_DIM, true)
            .await
            .unwrap_or_else(|e| panic!("{source:?}: empty-column boot must convert, got: {e}"));
        drop(store);
        assert_eq!(
            current_dim(&inspect).await,
            Some(as_i32(LIVE_DIM)),
            "{source:?}: #877 heal of an empty column must still run"
        );
    }
}

/// Run `schema-init --json` with the given flags; Ok is the parsed report,
/// Err is the error's Display text.
async fn run_schema_init(
    url: &str,
    embedding_dim: Option<u32>,
    force_reembed: bool,
    config_default: Option<u32>,
) -> Result<serde_json::Value, String> {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run as schema_init_run};

    let args = SchemaInitArgs {
        store_url: url.to_string(),
        json: true,
        embedding_dim,
        force_reembed,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let res = {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        // The daemon dispatch hands schema-init the DEFAULTED tier-preset
        // dimension under NO_CONFIG (the issue's case).
        schema_init_run(&args, schema_init_config(config_default), &mut out).await
    };
    match res {
        Ok(()) => {
            let raw = String::from_utf8(so).expect("utf-8 schema-init json");
            Ok(serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parseable JSON, got {raw}: {e}")))
        }
        // `{e:#}` renders the whole anyhow context chain.
        Err(e) => Err(format!("{e:#}")),
    }
}

/// The config-resolved default schema-init receives from the daemon
/// dispatch, as a DEFAULTED dimension (tier preset under `NO_CONFIG`).
fn schema_init_config(dim: Option<u32>) -> Option<EmbeddingDimIntent> {
    dim.map(EmbeddingDimIntent::Defaulted)
}

/// schema-init with no `--embedding-dim`, with and without `--force-reembed`:
/// a defaulted dimension never converts a populated column; the report
/// adopts the live dimension.
#[tokio::test]
async fn schema_init_defaulted_dim_adopts_live_column_9933() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;

    // No force: Ok, adopts the live column, nothing converted.
    reset_schema(&inspect).await;
    let seeded = seed_corpus(&url, LIVE_DIM).await;
    let report = run_schema_init(&url, None, false, Some(OTHER_DIM))
        .await
        .unwrap_or_else(|e| panic!("defaulted schema-init must adopt the live dim, got: {e}"));
    assert_eq!(report["embedding_dim"].as_i64(), Some(i64::from(LIVE_DIM)));
    assert_eq!(report["embedding_dim_migrated"], false, "{report}");
    assert_intact(&inspect, &seeded, LIVE_DIM, "schema-init/defaulted").await;

    // `--force-reembed` WITHOUT `--embedding-dim`: the opt-in names no
    // target, so a defaulted dimension cannot be its target. Refused.
    let err = run_schema_init(&url, None, true, Some(OTHER_DIM))
        .await
        .expect_err("--force-reembed with a defaulted dim must refuse");
    assert_eq!(
        err, EXPECTED_DEFAULTED_REFUSAL,
        "schema-init/defaulted+force"
    );
    assert_intact(&inspect, &seeded, LIVE_DIM, "schema-init/defaulted+force").await;
}

/// schema-init `--embedding-dim 384` without the opt-in refuses with the
/// exact text; with `--force-reembed` (the opt-in) it converts.
#[tokio::test]
async fn schema_init_explicit_dim_refuses_then_opt_in_converts_9933() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    let seeded = seed_corpus(&url, LIVE_DIM).await;

    let err = run_schema_init(&url, Some(OTHER_DIM), false, None)
        .await
        .expect_err("explicit differing dim without --force-reembed must refuse");
    assert_eq!(
        err,
        format!("migrate embedding dim to {OTHER_DIM}: {EXPECTED_EXPLICIT_REFUSAL}"),
        "schema-init/explicit: exact refusal text"
    );
    assert_intact(&inspect, &seeded, LIVE_DIM, "schema-init/explicit").await;

    let report = run_schema_init(&url, Some(OTHER_DIM), true, None)
        .await
        .unwrap_or_else(|e| panic!("the explicit opt-in must convert, got: {e}"));
    assert_eq!(report["embedding_dim"].as_i64(), Some(i64::from(OTHER_DIM)));
    assert_eq!(report["embedding_dim_migrated"], true, "{report}");
    assert_eq!(current_dim(&inspect).await, Some(as_i32(OTHER_DIM)));
    let after = read_vectors(&inspect).await;
    assert_eq!(after.len(), SEED_ROWS, "opt-in keeps every row");
    assert!(
        after.iter().all(|(_, v)| v.is_none()),
        "the opt-in conversion NULLs the vectors (re-embed required): {after:?}"
    );
}
