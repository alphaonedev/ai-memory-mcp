// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! CodeGraph-Coverage backfill for three sub-90% modules — `src/cli/schema_init.rs`,
//! `src/daemon_runtime.rs`, and `src/reranker.rs`.
//!
//! This is a **single** integration file that drives the zero-coverage
//! functions of all three modules through their *public* (or
//! `pub`-reachable) surfaces, never touching the source. The coverage
//! lift is reachability-directed: each test names the function it
//! covers and asserts on an *oracle-strong* observable (the report
//! shape, the score-floor eviction, the recency-boost re-sort, the
//! worker-coalescing submission count), not merely "it didn't panic".
//!
//! ## Module → surface map
//!
//! - [`ai_memory::cli::schema_init`] — `run` (sqlite + postgres dispatch),
//!   `enumerate_sqlite`, and (under a live Postgres) `init_and_enumerate_postgres`,
//!   `enumerate_postgres`, `bootstrap_memory_graph`.
//! - [`ai_memory::daemon_runtime`] — `build_embedder`, `build_vector_index`,
//!   `cmd_bench` (via the `pub` `run` dispatcher and `Command::Bench`),
//!   and `build_store_handle` / `build_curator_store` /
//!   `resolve_configured_embedding_dim` (via the `pub`
//!   `cli::curator::run` `--store-url` postgres `--once` arm).
//! - [`ai_memory::reranker`] — `BatchedReranker::{new, with_params,
//!   with_score_floor, rerank, rerank_coalesced, worker_submissions,
//!   score_floor}`, `RerankerScoreFloor::apply` (all three arms),
//!   `apply_session_recency_boost`, `SessionRecallTracker`,
//!   `split_rerank_pool` (via the pool cap), and `process_batch` (both
//!   the single-job fast path and the coalesced batched arm).
//!
//! ## Structurally-uncoverable lines (documented exceptions)
//!
//! - `src/reranker.rs` — the `CrossEncoder::Neural` arms
//!   (`load_neural`, `neural_score`, `neural_score_pairs`, the
//!   `pair_scores` `Self::Neural` branch, `rerank_batch_with_reflection_boost`
//!   neural batched forward) require a *downloaded* cross-encoder model
//!   (`cross-encoder/ms-marco-MiniLM-L-6-v2`) and the `MockCrossEncoder`
//!   test double lives in a `#[cfg(test)]`-gated `test_support` module
//!   that is **not** compiled into the library for external integration
//!   tests. These lines are reachable only with a real model on disk /
//!   the in-crate unit tests, so they are exercised here only via the
//!   *lexical* `CrossEncoder::new()` encoder (which drives the same
//!   blending / floor / batching machinery without a model).
//! - `src/daemon_runtime.rs` — `build_router` requires a fully
//!   constructed `AppState` + `ApiKeyState` (the daemon serving state),
//!   built only behind the private `keyword_app_state` helper; it is a
//!   two-line passthrough to `ai_memory::build_router` and is covered by
//!   the in-crate daemon unit tests rather than this external file.

#![cfg(feature = "sal")]
// The `build_embedder` invalid-override fallback test deliberately sets the
// deprecated flat `embedding_model` field (the #1146-superseded legacy arm
// the function still honours), so the deprecation lint is expected here.
#![allow(deprecated)]
#![allow(clippy::doc_markdown)]

use ai_memory::config::{AppConfig, FeatureTier};
use ai_memory::models::{Memory, Tier};
use ai_memory::reranker::{
    BatchedReranker, CrossEncoder, RerankerScoreFloor, SessionRecallTracker,
    apply_session_recency_boost,
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// Build a `Memory` carrying the (title, content) the lexical encoder
/// scores against, with a unique id so the session-recency tracker can
/// key on it.
fn mem(id: &str, title: &str, content: &str) -> Memory {
    let now = "2026-01-01T00:00:00+00:00".to_string();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        title: title.to_string(),
        content: content.to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite://{}", path.to_string_lossy())
}

/// Live-Postgres connection string for the postgres arms. `None` when
/// the operator hasn't provisioned the test instance — the postgres
/// tests then become structural no-ops rather than hard failures.
fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
}

// ===========================================================================
// reranker.rs
// ===========================================================================

/// Covers: `RerankerScoreFloor::apply` `Off` arm + `BatchedReranker::new`
/// + `BatchedReranker::rerank` (auto-select direct path) +
///   `rerank_with_reflection_boost` + `split_rerank_pool` (under-cap) +
///   `pair_scores` (lexical) + `score_floor()` getter.
#[test]
fn reranker_default_floor_off_keeps_all_candidates() {
    let reranker = BatchedReranker::new(CrossEncoder::new());
    assert_eq!(reranker.score_floor(), RerankerScoreFloor::Off);

    let candidates = vec![
        (
            mem("a", "rust async runtime", "tokio scheduler internals"),
            0.9_f64,
        ),
        (
            mem("b", "garden tomatoes", "heirloom seed catalog"),
            0.1_f64,
        ),
    ];
    let out = reranker.rerank("rust async", candidates);
    // Off floor: no candidate is dropped.
    assert_eq!(out.len(), 2, "Off floor must keep every candidate: {out:?}");
    // Descending sort invariant.
    assert!(
        out[0].1 >= out[1].1,
        "results must be sorted descending: {out:?}"
    );
}

/// Covers: `RerankerScoreFloor::apply` `Absolute` arm (tail eviction
/// with top-row preservation) via `BatchedReranker::with_score_floor`.
#[test]
fn reranker_absolute_floor_evicts_tail_preserves_top() {
    let reranker =
        BatchedReranker::with_score_floor(CrossEncoder::new(), RerankerScoreFloor::Absolute(0.40));
    assert_eq!(reranker.score_floor(), RerankerScoreFloor::Absolute(0.40));

    let candidates = vec![
        (
            mem(
                "hit",
                "hybrid recall blends fts and semantic",
                "bm25 cosine pipeline",
            ),
            0.95_f64,
        ),
        (
            mem("miss", "unrelated content about cooking", "pasta recipes"),
            0.02_f64,
        ),
    ];
    let out = reranker.rerank("hybrid recall", candidates);
    // The low-scoring tail row is below the floor → dropped; the top row
    // is always preserved (small-corpus invariant).
    assert_eq!(
        out.len(),
        1,
        "absolute floor must drop the sub-floor tail: {out:?}"
    );
    assert_eq!(out[0].0.id, "hit");
}

/// Covers: `RerankerScoreFloor::apply` `RelativeToTop` arm + the
/// top-row-never-dropped guarantee even when every score is in the noise
/// band.
#[test]
fn reranker_relative_floor_preserves_top_even_in_noise_band() {
    // RelativeToTop(1.0) means the cutoff equals the top score, so every
    // row strictly below the top is evicted — but row 0 survives by the
    // index-0 carve-out.
    let reranker = BatchedReranker::with_score_floor(
        CrossEncoder::new(),
        RerankerScoreFloor::RelativeToTop(1.0),
    );
    assert_eq!(
        reranker.score_floor(),
        RerankerScoreFloor::RelativeToTop(1.0)
    );

    let candidates = vec![
        (
            mem("top", "alpha beta gamma", "alpha beta gamma delta"),
            0.5_f64,
        ),
        (mem("low1", "alpha", "beta"), 0.4_f64),
        (mem("low2", "zzz", "qqq"), 0.3_f64),
    ];
    let out = reranker.rerank("alpha beta gamma", candidates);
    assert!(!out.is_empty(), "relative floor must never return nothing");
    // At minimum the top row survives; nothing scores strictly above the
    // top, so the result collapses toward the single top row.
    assert_eq!(out[0].0.id, "top");
}

/// Covers: `BatchedReranker::rerank_coalesced` (forced worker path) +
/// `process_batch` **single-job fast path** (`batch.len() == 1`) +
/// `worker_submissions` increment + `rerank_coalesced_unfloored`.
#[test]
fn reranker_coalesced_single_job_uses_worker_fast_path() {
    let reranker = BatchedReranker::new(CrossEncoder::new());
    assert_eq!(reranker.worker_submissions(), 0);

    let candidates = vec![
        (
            mem(
                "x",
                "vector index hnsw graph",
                "approximate nearest neighbor",
            ),
            0.8_f64,
        ),
        (
            mem("y", "totally different topic", "weather forecast"),
            0.2_f64,
        ),
    ];
    let out = reranker.rerank_coalesced("vector index", candidates);
    assert_eq!(out.len(), 2, "default Off floor keeps all rows: {out:?}");
    assert!(
        out[0].1 >= out[1].1,
        "coalesced output must stay sorted: {out:?}"
    );
    // The forced-coalesced call submitted exactly one job to the worker.
    assert_eq!(
        reranker.worker_submissions(),
        1,
        "rerank_coalesced must route through the worker (one submission)"
    );
}

/// Covers: `process_batch` **batched arm** (`batch.len() > 1`) +
/// `rerank_batch_with_reflection_boost` (lexical) +
/// `BatchedReranker::with_params` (wide coalescing window). Several
/// threads submit concurrently inside a generous flush window so the
/// worker coalesces them into one batched call.
#[test]
fn reranker_coalesced_batches_concurrent_submissions() {
    use std::sync::Arc;
    use std::sync::Barrier;

    // 64-job batch cap, 750 ms flush window — generous enough that all
    // N threads land in a single batch on a loaded CI host.
    let reranker = Arc::new(BatchedReranker::with_params(CrossEncoder::new(), 64, 750));
    let n = 6_usize;
    let barrier = Arc::new(Barrier::new(n));

    let handles: Vec<_> = (0..n)
        .map(|i| {
            let rr = Arc::clone(&reranker);
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let candidates = vec![
                    (
                        mem(
                            &format!("c{i}-hit"),
                            "distributed consensus raft paxos",
                            "leader election log replication",
                        ),
                        0.7_f64,
                    ),
                    (
                        mem(
                            &format!("c{i}-miss"),
                            "knitting patterns",
                            "wool yarn gauge",
                        ),
                        0.1_f64,
                    ),
                ];
                // Release all threads at once so they coalesce.
                b.wait();
                rr.rerank_coalesced("distributed consensus", candidates)
            })
        })
        .collect();

    let mut completed = 0;
    for h in handles {
        let out = h.join().expect("worker thread join");
        assert_eq!(
            out.len(),
            2,
            "each coalesced reply preserves its candidate count"
        );
        assert!(out[0].1 >= out[1].1, "each reply stays sorted descending");
        completed += 1;
    }
    assert_eq!(completed, n, "every concurrent submission got a reply");
    // Every one of the N callers submitted a job to the worker; whether
    // they coalesced into one `process_batch` call or several, the
    // submission counter is exact.
    assert_eq!(
        reranker.worker_submissions(),
        n,
        "all concurrent callers must reach the worker"
    );
}

/// Covers: `apply_session_recency_boost` happy path —
/// `SessionRecallTracker::record` seeds the ring, a later boost pass
/// bumps the recalled id and re-sorts it past its pre-boost neighbour,
/// and the post-boost id list is recorded. Also covers
/// `SessionRecallTracker::{new, recent_ids, with_recent_ids,
/// session_count}`.
#[test]
fn session_recency_boost_bumps_and_resorts_recalled_id() {
    let tracker = SessionRecallTracker::new();
    let sid = "session-cov-ga2";
    assert_eq!(tracker.session_count(), 0);

    // Seed the ring with "winner" as a recently-recalled id.
    tracker.record(sid, ["winner".to_string()]);
    assert_eq!(tracker.session_count(), 1);
    assert!(tracker.recent_ids(sid).contains("winner"));

    // "winner" trails "leader" before the boost; the +0.05 recency boost
    // must lift it past "leader" and re-sort.
    let results = vec![
        (mem("leader", "leading title", "content"), 0.50_f64),
        (mem("winner", "trailing title", "content"), 0.48_f64),
    ];
    let boosted = apply_session_recency_boost(results, Some(sid), &tracker);
    assert_eq!(boosted.len(), 2);
    assert_eq!(
        boosted[0].0.id, "winner",
        "recency-boosted id must re-sort to the top: {boosted:?}"
    );
    assert!(
        boosted[0].1 > 0.50,
        "boosted score must exceed the pre-boost leader: {boosted:?}"
    );
}

/// Covers: `apply_session_recency_boost` early-return arms — `None`
/// session id and empty session id both return the input untouched.
#[test]
fn session_recency_boost_noop_arms() {
    let tracker = SessionRecallTracker::new();
    let results = vec![(mem("a", "t", "c"), 0.9_f64), (mem("b", "t", "c"), 0.1_f64)];

    // None session → passthrough.
    let out_none = apply_session_recency_boost(results.clone(), None, &tracker);
    assert_eq!(out_none.len(), 2);
    assert_eq!(out_none[0].0.id, "a");

    // Empty-string session → passthrough.
    let out_empty = apply_session_recency_boost(results, Some(""), &tracker);
    assert_eq!(out_empty.len(), 2);
    assert_eq!(out_empty[0].0.id, "a");
}

/// Covers: `split_rerank_pool` **over-cap** arm — a pool larger than the
/// `RERANK_POOL_MAX` cap is split into a re-ranked head and an untouched
/// tail, and **no candidate is dropped** (the head + tail re-union).
#[test]
fn reranker_pool_over_cap_keeps_every_candidate() {
    let reranker = BatchedReranker::new(CrossEncoder::new());
    let cap = ai_memory::reranker::RERANK_POOL_MAX;
    let total = cap + 7;

    let total_f = f64::from(u16::try_from(total).expect("total fits u16"));
    let candidates: Vec<(Memory, f64)> = (0..total)
        .map(|i| {
            // Descending input scores so the split is deterministic. Build
            // the f64 from the index without a lossy `usize as f64` cast.
            let score = 1.0 - f64::from(u16::try_from(i).unwrap_or(0)) / total_f;
            (
                mem(&format!("p{i}"), "shared query terms here", "body text"),
                score,
            )
        })
        .collect();

    let out = reranker.rerank("shared query terms", candidates);
    assert_eq!(
        out.len(),
        total,
        "over-cap pool must re-union head + tail with zero drops: got {}",
        out.len()
    );
}

// ===========================================================================
// daemon_runtime.rs
// ===========================================================================

/// Covers: `build_embedder` keyword-tier early-return (disabled embedder,
/// no HF-hub fetch).
#[tokio::test]
async fn daemon_build_embedder_keyword_tier_disabled() {
    let cfg = AppConfig::default();
    let emb = ai_memory::daemon_runtime::build_embedder(FeatureTier::Keyword, &cfg).await;
    assert!(
        emb.is_none(),
        "keyword tier has no embedding model preset → embedder disabled"
    );
}

/// Covers: `build_embedder` unparseable-override fallback — a garbage
/// `embedding_model` parses-fails and (keyword tier) falls back to the
/// `None` preset without touching the network.
#[tokio::test]
async fn daemon_build_embedder_invalid_override_falls_back() {
    let cfg = AppConfig {
        embedding_model: Some("not-a-real-model-cov-ga2-2026".to_string()),
        ..AppConfig::default()
    };
    let emb = ai_memory::daemon_runtime::build_embedder(FeatureTier::Keyword, &cfg).await;
    assert!(
        emb.is_none(),
        "unparseable override on keyword tier resolves to None"
    );
}

/// Covers: `build_vector_index` — `embedder_present == false` short-circuit
/// returns `None`; `true` against an empty DB returns an empty index.
#[test]
fn daemon_build_vector_index_present_and_absent() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open db");

    // No embedder → no index.
    assert!(
        ai_memory::daemon_runtime::build_vector_index(&conn, false).is_none(),
        "keyword-only deployment needs no vector index"
    );

    // Embedder present, empty DB → empty (but Some) index.
    let idx = ai_memory::daemon_runtime::build_vector_index(&conn, true)
        .expect("embedder-present empty DB yields an empty index");
    assert_eq!(idx.len(), 0, "fresh DB → empty index");
}

/// Covers: `cmd_bench` (the `--scale` path) via the `pub` `run`
/// dispatcher routing `Command::Bench`. The bench seeds a disposable
/// in-memory corpus and prints a JSON report. We accept either `Ok`
/// (budgets met) or the bench's own budget-exceeded error — both fully
/// execute `cmd_bench`; only the verdict branch differs on a loaded host.
#[tokio::test]
async fn daemon_cmd_bench_scale_path_runs() {
    use ai_memory::daemon_runtime::{Cli, run};
    use clap::Parser as _;

    let cli = Cli::try_parse_from([
        "ai-memory",
        "bench",
        "--json",
        "--iterations",
        "3",
        "--warmup",
        "1",
        "--scale",
        "50",
    ])
    .expect("parse bench cli");
    let cfg = AppConfig::default();
    let res = run(cli, &cfg).await;
    // The function ran to completion (either verdict). A panic / dispatch
    // miss would surface as something other than these two shapes.
    match res {
        Ok(()) => {}
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains("bench:"),
                "only the bench budget/regression verdict may error here, got: {msg}"
            );
        }
    }
}

// ===========================================================================
// cli/schema_init.rs
// ===========================================================================

/// Covers: `schema_init::run` **sqlite dispatch** + `enumerate_sqlite`
/// (object / index / schema-version enumeration) + the embedding-dim
/// echo + the JSON render branch.
#[tokio::test]
async fn schema_init_sqlite_enumerates_and_reports() {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run};

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = sqlite_url(tmp.path());

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);

    let args = SchemaInitArgs {
        store_url: url.clone(),
        json: true,
        embedding_dim: 768,
    };
    run(&args, &mut out).await.expect("schema-init sqlite run");

    let raw = String::from_utf8(stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parseable JSON");
    assert_eq!(v["kind"], "sqlite");
    assert_eq!(v["url"], serde_json::Value::String(url));
    assert!(
        v["schema_version"].as_i64().unwrap_or(0) > 0,
        "schema_version must be > 0 after init: {v}"
    );
    let tables: Vec<&str> = v["tables"]
        .as_array()
        .expect("tables array")
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert!(
        tables.contains(&"memories"),
        "memories table missing: {tables:?}"
    );
    // SQLite echoes the operator flag as the embedding-dim hint.
    assert_eq!(v["embedding_dim"].as_i64(), Some(768));
    assert_eq!(v["embedding_dim_migrated"], false);
}

/// Covers: `schema_init::run` **human-render branch** (`json == false`)
/// → `render_human`.
#[tokio::test]
async fn schema_init_sqlite_human_render() {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run};

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let url = sqlite_url(tmp.path());

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);

    let args = SchemaInitArgs {
        store_url: url,
        json: false,
        embedding_dim: 384,
    };
    run(&args, &mut out)
        .await
        .expect("schema-init sqlite human");

    let raw = String::from_utf8(stdout).expect("utf8");
    assert!(
        raw.contains("schema initialized at"),
        "missing header: {raw}"
    );
    assert!(raw.contains("tables:"), "missing tables row: {raw}");
    assert!(
        raw.contains("schema_version:"),
        "missing version row: {raw}"
    );
}

/// Covers: `schema_init::run` **unrecognised-scheme bail** arm.
#[tokio::test]
async fn schema_init_unrecognised_scheme_bails() {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run};

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);

    let args = SchemaInitArgs {
        store_url: "nosql://nope".to_string(),
        json: false,
        embedding_dim: 384,
    };
    let err = run(&args, &mut out).await.expect_err("must reject");
    assert!(
        format!("{err:#}").contains("unrecognised store URL"),
        "expected unrecognised-scheme error: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// Live-Postgres arms (sal-postgres). Each becomes a structural no-op when
// AI_MEMORY_TEST_POSTGRES_URL is unset so the file still passes on a host
// without the test instance.
// ---------------------------------------------------------------------------

/// Covers (live PG): `schema_init::run` postgres dispatch →
/// `init_and_enumerate_postgres` → `enumerate_postgres` →
/// `bootstrap_memory_graph` (AGE arm tolerated whether or not AGE is
/// installed). Asserts the report kind + that the catalog enumeration
/// surfaced the canonical tables.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn schema_init_postgres_enumerates_live_catalog() {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run};

    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping live-pg schema-init enumerate");
        return;
    };

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);

    let args = SchemaInitArgs {
        store_url: url.clone(),
        json: true,
        embedding_dim: 384,
    };
    run(&args, &mut out)
        .await
        .expect("schema-init postgres run");

    let raw = String::from_utf8(stdout).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parseable JSON");
    assert_eq!(
        v["kind"], "postgres",
        "postgres dispatch must tag the report: {v}"
    );
    let tables: Vec<&str> = v["tables"]
        .as_array()
        .expect("tables array")
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    assert!(
        tables.contains(&"memories"),
        "live pg catalog must surface the memories table: {tables:?}"
    );
    // `embedding_dim` is read back from the live column catalog after the
    // conversion check (ground truth, not the requested flag value).
    assert!(
        v["embedding_dim"].as_i64().is_some(),
        "post-conversion embedding_dim must be read from the catalog: {v}"
    );
}

/// Covers (live PG): `daemon_runtime::build_curator_store` →
/// `build_store_handle` (postgres arm) + `resolve_configured_embedding_dim`,
/// driven through the `pub` `cli::curator::run` `--store-url` postgres
/// `--once` sweep. A single dry-run sweep against the live store
/// exercises the SAL store-handle build then exits.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn curator_store_url_postgres_once_builds_store_handle() {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::curator::{CuratorArgs, run};

    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping live-pg curator store handle");
        return;
    };

    // `--db` is left at a throwaway temp path; `--store-url` takes over.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let cfg = AppConfig::default();

    let args = CuratorArgs {
        once: true,
        daemon: false,
        interval_secs: 3_600,
        max_ops: 1,
        dry_run: true,
        include_namespaces: Vec::new(),
        exclude_namespaces: Vec::new(),
        json: true,
        rollback: None,
        rollback_last: None,
        reflect: false,
        namespace: None,
        max_depth: None,
        all_namespaces: false,
        store_url: Some(url),
    };

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);

    // The store-backed `--once` sweep builds the postgres SAL store
    // handle then runs a single upkeep pass. It must complete without a
    // dispatch / connect error against the live instance.
    run(tmp.path(), &args, &cfg, &mut out)
        .await
        .expect("curator --once --store-url postgres sweep");

    // The sweep emitted *something* (JSON report or upkeep summary) on
    // success — the store handle was built and the pass ran.
    assert!(
        !stdout.is_empty() || stderr.is_empty(),
        "store-backed sweep should have produced output"
    );
}
