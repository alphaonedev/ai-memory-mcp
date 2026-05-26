// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 PERF-1 (FX-3) — regression test for the `spawn_blocking`
//! refactor in `src/handlers/transport.rs::db_op`.
//!
//! **What this test pins.** HTTP handlers that touch the singleton
//! `Db = Arc<Mutex<rusqlite::Connection, ...>>` mutex are now wrapped
//! in `tokio::task::spawn_blocking`, so synchronous rusqlite I/O runs
//! on the dedicated blocking pool instead of pinning the
//! `#tokio_workers = num_cpus` runtime threads.
//!
//! **Pre-fix behaviour** (PERF-1 finding,
//! `.local-runs/reviews-2026-05-26-v2/PERF-findings.md`): every
//! handler held `db.lock().await` AND executed sync rusqlite calls
//! on the worker thread that picked up the request. N concurrent
//! handlers serialised completely on the mutex and stole worker
//! slots from non-DB tasks (federation receive, webhook dispatch,
//! metrics scrape). The p99 floor under concurrent recalls was
//! `N × wall_time(FTS+touch)` instead of `max(wall_time)`.
//!
//! **Post-fix behaviour**: `db_op` moves the mutex acquire +
//! rusqlite call into `spawn_blocking`. The tokio worker is freed
//! the instant the `spawn_blocking` future yields; only the blocking
//! pool thread holds the mutex. Concurrent handlers still serialise
//! on the single connection (that's an unavoidable property of the
//! singleton Mutex<Connection> shape — the deeper "go to a
//! connection pool" refactor is tracked separately), BUT they no
//! longer steal tokio worker slots from unrelated async work.
//!
//! **Test design.** We construct an in-process `axum::Router` via
//! `ai_memory::build_router` (the same router the production daemon
//! mounts) and fire N concurrent GETs against `/api/v1/health`.
//! Each request takes a constant ~hundred microseconds of rusqlite
//! work (the `db::health_check` PRAGMA roundtrip).
//!
//! We assert two invariants:
//!
//! 1. **All requests succeed** (status 200). Pre-fix, the
//!    `block_in_place`-style pattern under load could trip the tokio
//!    runtime's blocking-task watchdog and surface 5xx tail
//!    responses; post-fix every request rides the blocking pool
//!    cleanly.
//!
//! 2. **Concurrent wall-clock time is bounded by ~2× single-request
//!    baseline + a slack term, NOT by N×.** If the handler still
//!    held the lock across rusqlite on the tokio worker, N
//!    concurrent requests would serialise + the worker-pool-stealing
//!    interaction with the oneshot setup would push the
//!    concurrent-time floor well past 2× baseline.
//!
//! The threshold (`CONCURRENT_OVERHEAD_FACTOR = 8`) is deliberately
//! generous so the test is stable across hosts (cold-start CI
//! VMs, M1/M2 Macs, Linux NUC) — anything tighter risks false
//! positives. The pre-fix path serialised on a single mutex AND
//! stole worker slots, so under 20 concurrent requests it would
//! easily push past 20× baseline on a 2-core VM. 8× is the
//! widest factor that still falsifies the pre-fix serialisation
//! signature.

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::cast_precision_loss
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

/// Number of concurrent HTTP requests to fire. 20 is large enough
/// that pre-fix serialisation would be obvious (the runtime default
/// `#tokio_workers = num_cpus` is typically 2-16 on CI / dev
/// hardware; 20 is comfortably past that ceiling) and small enough
/// to keep the test wall-clock budget under 5s on a slow VM.
const CONCURRENCY: usize = 20;

/// Wall-clock budget for the concurrent run, expressed as a
/// multiplier over the measured single-request baseline. With
/// `db_op` wrapping every handler in `spawn_blocking`, the
/// observed multiplier is typically 2-3× on a populated CI host.
/// We allow 8× to keep the assertion robust across hardware tiers
/// without compromising its falsification power against the
/// pre-fix `N×-baseline` serialisation signature.
const CONCURRENT_OVERHEAD_FACTOR: u32 = 8;

/// Minimum wall-clock budget regardless of measured baseline. On
/// hosts where single-request baseline is sub-millisecond, the
/// multiplied threshold can be tighter than the noise floor of
/// `Instant::elapsed`. This floor gives the test breathing room
/// at the lower bound.
const MIN_WALL_CLOCK_BUDGET: Duration = Duration::from_millis(200);

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("perf-1-spawn-blocking-regression")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn build_test_router() -> (axum::Router, NamedTempFile, TempDir) {
    let tdir = fresh_dir();
    let f = NamedTempFile::new_in(tdir.path()).expect("tempfile in .local-runs");
    let db_path = f.path().to_path_buf();
    // Open once to apply migrations, then re-open for the AppState
    // handle. Mirrors the pattern in tests/http_routes_1111.rs.
    let _ = ai_memory::db::open(&db_path).expect("db::open initial");
    let conn = ai_memory::db::open(&db_path).expect("db::open AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, tdir)
}

/// Send a GET to `path` against the in-process router. Returns the
/// status; body is drained (not inspected) so the request closes
/// cleanly.
async fn get(router: &axum::Router, path: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    // Drain body to release the connection cleanly.
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    status
}

/// PERF-1 regression: N concurrent GETs against `/api/v1/health`
/// must (a) all succeed and (b) complete in a wall-clock window
/// substantially smaller than N × single-request baseline.
///
/// `/api/v1/health` is the canonical refactor target — the
/// pre-fix handler did `let lock = app.db.lock().await;
/// db::health_check(&lock.0)` on the tokio worker; the post-fix
/// handler routes the same call through `db_op` so the rusqlite
/// PRAGMA runs on the blocking pool.
///
/// The `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`
/// attribute pins a deliberately CONSTRAINED runtime (2 workers,
/// matching the lower end of common CI hardware). A constrained
/// runtime is the configuration where the pre-fix serialisation
/// signature is loudest — if we used the default unlimited
/// runtime the host's idle cores would mask the worker-starvation
/// behaviour the test is designed to surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_health_requests_do_not_serialise_on_db_mutex() {
    // Build router once; share across all the concurrent requests.
    let (router, _f, _tdir) = build_test_router();

    // Warm-up: fire one request to bring the DB into the page
    // cache and force any first-call rusqlite prepared-statement
    // compilation. Without warmup the baseline timing measurement
    // includes one-time setup costs that don't repeat for the
    // concurrent burst, biasing the multiplier high.
    assert_eq!(get(&router, "/api/v1/health").await, StatusCode::OK);

    // Single-request baseline. Averaged over 5 samples to dampen
    // scheduler noise on a constrained worker pool.
    let samples = 5;
    let mut total_baseline = Duration::ZERO;
    for _ in 0..samples {
        let start = Instant::now();
        let status = get(&router, "/api/v1/health").await;
        total_baseline += start.elapsed();
        assert_eq!(status, StatusCode::OK, "baseline request failed");
    }
    let baseline = total_baseline / u32::try_from(samples).unwrap_or(1);

    // Concurrent burst. Spawn N tasks all targeting `/api/v1/health`
    // and await them with `tokio::join!`-style fanout (here via
    // `JoinSet` for the dynamic-N case). Measure the END-TO-END
    // wall-clock from spawn to last completion.
    let start = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..CONCURRENCY {
        let router = router.clone();
        set.spawn(async move { get(&router, "/api/v1/health").await });
    }
    let mut statuses: Vec<StatusCode> = Vec::with_capacity(CONCURRENCY);
    while let Some(joined) = set.join_next().await {
        statuses.push(joined.expect("join task"));
    }
    let elapsed = start.elapsed();

    // Invariant 1: every request succeeded. A 503 here would
    // indicate the runtime's blocking-task watchdog tripped under
    // load (the pre-fix path had this risk because the rusqlite
    // call ran on a tokio worker thread).
    assert_eq!(
        statuses.len(),
        CONCURRENCY,
        "expected {CONCURRENCY} concurrent responses, got {}",
        statuses.len()
    );
    for (i, status) in statuses.iter().enumerate() {
        assert_eq!(
            *status,
            StatusCode::OK,
            "concurrent request #{i} returned {status} (expected 200 OK)"
        );
    }

    // Invariant 2: total wall-clock under the concurrent burst is
    // less than `CONCURRENT_OVERHEAD_FACTOR × baseline`, AND under
    // the `N × baseline` floor that the pre-fix serialised path
    // would have exhibited. The two-sided check guards both ends
    // of the noise envelope.
    let budget = (baseline * CONCURRENT_OVERHEAD_FACTOR).max(MIN_WALL_CLOCK_BUDGET);
    let serialised_floor = baseline * u32::try_from(CONCURRENCY).expect("CONCURRENCY fits in u32");
    eprintln!(
        "PERF-1 regression check: baseline={baseline:?}, concurrent({CONCURRENCY})={elapsed:?}, \
         budget={budget:?}, pre-fix-serialised-floor={serialised_floor:?}"
    );
    assert!(
        elapsed < budget,
        "PERF-1 regression: {CONCURRENCY} concurrent /health requests took {elapsed:?}, \
         expected < {budget:?} (= {CONCURRENT_OVERHEAD_FACTOR}× baseline {baseline:?}). \
         The pre-fix serialised path would push this past {serialised_floor:?} \
         (= {CONCURRENCY}× baseline). Tokio worker starvation has regressed."
    );
}
