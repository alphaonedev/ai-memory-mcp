// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #4089 — every HTTP handler that embeds or reranks keeps the tokio worker
//! free while the forward pass runs (rust-1.98 CONCURRENCY-22).
//!
//! ## The defect
//!
//! The HTTP handlers ran the embedder (a candle forward pass, or a blocking
//! remote call) and the cross-encoder reranker INLINE on a tokio worker.
//! That takes the worker out of service for the whole forward; since tokio
//! 1.52.2 reverted LIFO-slot stealing, a task parked behind it (`/health`,
//! the postgres pool acquire, shutdown) stays stranded until it returns.
//! The #3988 boot backfill had the same defect.
//!
//! ## The shape of every test (the #3988 one-worker pattern)
//!
//! A runtime with ONE worker drives the real router. The handler's embed (or
//! rerank) goes through a REAL `Embedder` armed with
//! `embeddings::test_hold_hook`, which blocks the calling thread for `HOLD`
//! as a model forward would. Once the handler is inside that forward, a
//! freshly spawned task measures how long it waits to be polled. Inline, the
//! one worker is pinned and the probe waits out the whole `HOLD`; on the
//! blocking pool the worker is free and the probe runs at once.
//!
//! RED on the carrier (ee0aac10b / 7b6ad0731): every `*_4089` probe test
//! below fails with a probe wait of ~2 s. GREEN with the fix.
//!
//! Every site is covered on the sqlite branch and, where the handler has one,
//! on the postgres branch (the "fake-PG" pattern: `StorageBackend::Postgres`
//! over a `SqliteStore`, which runs the postgres handler code
//! deterministically) and, with `--features sal-postgres` and
//! `AI_MEMORY_TEST_POSTGRES_URL` set, on a real postgres store.

mod common;

use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::common::sqlite_tempfile::SqliteTempFile;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::{Embedder, test_hold_hook};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::runtime_context::RuntimeContext;

/// How long the stand-in forward pass holds its thread.
const HOLD: Duration = Duration::from_secs(2);
/// A probe polled within this bound was NOT stuck behind the forward.
const PROBE_BOUND: Duration = Duration::from_secs(1);
/// Vector width of the stand-in embedder (the postgres default dim).
const DIM: usize = 384;
const AGENT: &str = "ai:t4089";
const NAMESPACE: &str = "t4089";

/// Which handler branch a scenario drives.
#[derive(Clone, Copy, Debug)]
enum Branch {
    Sqlite,
    /// `StorageBackend::Postgres` over a `SqliteStore` (postgres handler code).
    #[cfg(feature = "sal")]
    FakePg,
    /// A real `PostgresStore` from `AI_MEMORY_TEST_POSTGRES_URL`.
    #[cfg(feature = "sal-postgres")]
    RealPg,
}

struct Fixture {
    router: axum::Router,
    db_path: std::path::PathBuf,
    model: String,
    marker: String,
    _db: SqliteTempFile,
    #[cfg(feature = "sal-postgres")]
    _pg: Option<common::postgres_env::PostgresTestEnv>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        test_hold_hook::disarm(&self.model);
    }
}

/// A unique model name + marker per scenario, so parallel tests never share
/// a hold.
fn unique(label: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    (
        format!("hold-4089-{label}-{id}"),
        format!("zqxhold{}", &id[..12]),
    )
}

/// Build the router for `branch`, with the armed embedder and (optionally) a
/// reranker. Returns `None` when a real-postgres branch has no URL. (Only the
/// real-postgres arm awaits, so the async is unused without that feature.)
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn fixture(
    label: &str,
    branch: Branch,
    reranker: Option<Arc<ai_memory::reranker::BatchedReranker>>,
) -> Option<Fixture> {
    common::permissive_attestation_for_tests();
    let (model, marker) = unique(label);
    let embedder: Embedder = test_hold_hook::embedder(&model, DIM).expect("stand-in embedder");
    let f = SqliteTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let runtime = match reranker {
        None => RuntimeContext::global_arc(),
        Some(rr) => {
            let ctx = RuntimeContext::default();
            ctx.install_reranker(rr);
            Arc::new(ctx)
        }
    };
    #[cfg(feature = "sal-postgres")]
    let mut pg_env = None;
    let storage_backend = match branch {
        Branch::Sqlite => StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        Branch::FakePg => StorageBackend::Postgres,
        #[cfg(feature = "sal-postgres")]
        Branch::RealPg => StorageBackend::Postgres,
    };
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = match branch {
        #[cfg(feature = "sal-postgres")]
        Branch::RealPg => {
            let env = common::postgres_env::PostgresTestEnv::new(label).await?;
            let store = ai_memory::store::postgres::PostgresStore::connect_with_dim(
                env.url(),
                u32::try_from(DIM).expect("dim fits"),
            )
            .await
            .expect("connect postgres adapter");
            pg_env = Some(env);
            Arc::new(store)
        }
        _ => Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
    };
    let app_state = AppState {
        db,
        embedder: Arc::new(Some(embedder)),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime,
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    Some(Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        db_path,
        model,
        marker,
        _db: f,
        #[cfg(feature = "sal-postgres")]
        _pg: pg_env,
    })
}

fn request(method: &str, uri: &str, body: Option<&Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", AGENT);
    match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(b).expect("json body")))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    }
}

async fn send(router: axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.oneshot(req).await.expect("router is infallible");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn memory_body(title: &str, content: &str) -> Value {
    json!({
        "tier": "long",
        "namespace": NAMESPACE,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "agent_id": AGENT,
    })
}

/// Seed one memory (not holding: no marker) and return its id.
async fn seed(router: &axum::Router, title: &str, content: &str) -> String {
    let (status, body) = send(
        router.clone(),
        request(
            "POST",
            "/api/v1/memories",
            Some(&memory_body(title, content)),
        ),
    )
    .await;
    assert!(status.is_success(), "seed {title}: {status} {body}");
    body["id"].as_str().expect("seed id").to_string()
}

/// Spawn `req` on the runtime, wait until the forward pass has started,
/// then measure how long a freshly spawned task waits to be polled.
async fn probe_while_in_flight(
    router: axum::Router,
    req: Request<Body>,
    entered: &Receiver<()>,
) -> (Duration, StatusCode, Value) {
    let inflight = tokio::spawn(send(router, req));
    // Blocks THIS thread (the `block_on` driver, not a runtime worker).
    entered
        .recv_timeout(Duration::from_secs(20))
        .expect("the handler reached the forward pass");
    let started = Instant::now();
    tokio::spawn(async {}).await.expect("probe task joined");
    let wait = started.elapsed();
    let (status, body) = inflight.await.expect("request task joined");
    (wait, status, body)
}

/// The stand-in embedder's vector for `doc`, WITHOUT the hold: re-arms the
/// fixture's model with a marker that never occurs (same deterministic
/// vectors).
fn unheld_embedding(fx: &Fixture, doc: &str) -> Vec<f32> {
    let _rx = test_hold_hook::arm(&fx.model, "\u{0}never\u{0}", HOLD);
    test_hold_hook::embedder(&fx.model, DIM)
        .expect("embedder")
        .embed(doc)
        .expect("stand-in vector")
}

fn one_worker_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("one-worker runtime")
}

fn assert_probe(label: &str, wait: Duration) {
    assert!(
        wait < PROBE_BOUND,
        "{label}: a spawned task waited {wait:?} to be polled while the handler's forward \
         pass held the ONE runtime worker (hold was {HOLD:?}) — the embed/rerank ran \
         inline on a tokio worker (#4089, rust-1.98 CONCURRENCY-22)"
    );
}

// ---------------------------------------------------------------------------
// Scenarios. Each runs on its own one-worker runtime.
// ---------------------------------------------------------------------------

fn create_scenario(branch: Branch) {
    let label = format!("create {branch:?}");
    one_worker_runtime().block_on(async {
        let Some(fx) = fixture("create", branch, None).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let body = memory_body("create-4089", &format!("create body {}", fx.marker));
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("POST", "/api/v1/memories", Some(&body)),
            &entered,
        )
        .await;
        assert!(status.is_success(), "{label}: {status} {resp}");
        assert!(
            resp.get("embed_status").is_none(),
            "{label}: the offloaded embed must still index the row; got {resp}"
        );
        assert_probe(&label, wait);
    });
}

fn bulk_scenario(branch: Branch) {
    let label = format!("bulk {branch:?}");
    one_worker_runtime().block_on(async {
        let Some(fx) = fixture("bulk", branch, None).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let rows = json!([
            {"title": "bulk-4089-a", "content": format!("first {}", fx.marker),
             "namespace": NAMESPACE, "tier": "mid"},
            {"title": "bulk-4089-b", "content": "second row", "namespace": NAMESPACE, "tier": "mid"},
        ]);
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("POST", "/api/v1/memories/bulk", Some(&rows)),
            &entered,
        )
        .await;
        assert!(status.is_success(), "{label}: {status} {resp}");
        assert_eq!(resp["created"].as_u64(), Some(2), "{label}: {resp}");
        assert_probe(&label, wait);
    });
}

fn check_duplicate_scenario(branch: Branch) {
    let label = format!("check_duplicate {branch:?}");
    one_worker_runtime().block_on(async {
        let Some(fx) = fixture("dup", branch, None).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let body = json!({
            "title": "dup-4089",
            "content": format!("candidate {}", fx.marker),
            "namespace": NAMESPACE,
        });
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("POST", "/api/v1/check_duplicate", Some(&body)),
            &entered,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        assert_probe(&label, wait);
    });
}

fn recall_scenario(branch: Branch) {
    let label = format!("recall {branch:?}");
    one_worker_runtime().block_on(async {
        let Some(fx) = fixture("recall", branch, None).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        seed(&fx.router, "recall-4089", "the quarterly harvest ledger").await;
        let uri = format!(
            "/api/v1/recall?context=harvest%20ledger%20{}&namespace={NAMESPACE}",
            fx.marker
        );
        let (wait, status, resp) =
            probe_while_in_flight(fx.router.clone(), request("GET", &uri, None), &entered).await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        assert_eq!(
            resp["mode"].as_str(),
            Some(ai_memory::models::RECALL_MODE_HYBRID),
            "{label}: the offloaded query embedding must keep recall hybrid; got {resp}"
        );
        assert_probe(&label, wait);
    });
}

/// A cross-encoder stand-in: holds the calling thread for `HOLD` when the
/// query carries the marker (after announcing it), else scores instantly.
struct HoldScorer {
    marker: String,
    entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl ai_memory::reranker::PairScorer for HoldScorer {
    fn score_pairs(
        &self,
        query: &str,
        candidates: &[(ai_memory::models::Memory, f64)],
    ) -> Vec<f32> {
        if query.contains(self.marker.as_str()) {
            let tx = self
                .entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
            std::thread::sleep(HOLD);
        }
        vec![0.5; candidates.len()]
    }

    fn scorer_is_neural(&self) -> bool {
        false
    }
}

fn rerank_scenario(branch: Branch) {
    let label = format!("rerank {branch:?}");
    one_worker_runtime().block_on(async {
        let (tx, entered) = std::sync::mpsc::channel();
        let (_, rerank_marker) = unique("rerank-marker");
        let scorer = Arc::new(HoldScorer {
            marker: rerank_marker.clone(),
            entered: std::sync::Mutex::new(Some(tx)),
        });
        let reranker = Arc::new(ai_memory::reranker::BatchedReranker::with_scorer(
            scorer,
            ai_memory::reranker::RerankerScoreFloor::Off,
        ));
        let Some(fx) = fixture("rerank", branch, Some(reranker)).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        // The embedder is armed but never holds (its marker is not in the
        // query): only the rerank forward holds here.
        let _unused = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        seed(&fx.router, "rerank-4089", "the orchard irrigation schedule").await;
        let uri = format!(
            "/api/v1/recall?context=orchard%20irrigation%20{rerank_marker}&namespace={NAMESPACE}"
        );
        let (wait, status, resp) =
            probe_while_in_flight(fx.router.clone(), request("GET", &uri, None), &entered).await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        assert_eq!(
            resp["mode"].as_str(),
            Some(ai_memory::models::RECALL_MODE_HYBRID_RERANK),
            "{label}: the offloaded rerank must still run; got {resp}"
        );
        assert_probe(&label, wait);
    });
}

fn smart_load_scenario(branch: Branch) {
    let label = format!("smart_load {branch:?}");
    one_worker_runtime().block_on(async {
        let Some(fx) = fixture("smart", branch, None).await else {
            eprintln!("skip {label}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let body = json!({"intent": format!("remember this {}", fx.marker)});
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("POST", "/api/v1/memory_smart_load", Some(&body)),
            &entered,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        assert!(resp["chosen_family"].is_string(), "{label}: {resp}");
        assert_probe(&label, wait);
    });
}

fn update_scenario() {
    let label = "update Sqlite";
    one_worker_runtime().block_on(async {
        let fx = fixture("update", Branch::Sqlite, None)
            .await
            .expect("sqlite fixture");
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let id = seed(&fx.router, "update-4089", "before the update").await;
        let body = json!({"content": format!("after the update {}", fx.marker), "agent_id": AGENT});
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("PUT", &format!("/api/v1/memories/{id}"), Some(&body)),
            &entered,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        assert_probe(label, wait);
    });
}

fn reflect_scenario() {
    let label = "reflect Sqlite";
    one_worker_runtime().block_on(async {
        let fx = fixture("reflect", Branch::Sqlite, None)
            .await
            .expect("sqlite fixture");
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let source = seed(
            &fx.router,
            "reflect-src-4089",
            "an observation worth reflecting on",
        )
        .await;
        let body = json!({
            "source_ids": [source],
            "title": "reflect-4089",
            "content": format!("a reflection {}", fx.marker),
            "namespace": NAMESPACE,
            "agent_id": AGENT,
        });
        let (wait, status, resp) = probe_while_in_flight(
            fx.router.clone(),
            request("POST", "/api/v1/memory_reflect", Some(&body)),
            &entered,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        let id = resp["id"].as_str().expect("reflection id").to_string();
        assert_probe(label, wait);
        // The precomputed vector is the one the inline path would have
        // stored: the embedding of the SAME `title content` document.
        let conn = ai_memory::db::open(&fx.db_path).expect("reopen");
        let stored = ai_memory::db::get_embedding(&conn, &id)
            .expect("read embedding")
            .expect("the reflection is embedded");
        let expected = unheld_embedding(
            &fx,
            &ai_memory::embeddings::embedding_document(
                "reflect-4089",
                format!("a reflection {}", fx.marker),
            ),
        );
        assert_eq!(stored, expected, "{label}: wrong reflection vector");
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn create_sqlite_embeds_off_the_worker_4089() {
    create_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn create_postgres_branch_embeds_off_the_worker_4089() {
    create_scenario(Branch::FakePg);
}

#[test]
fn bulk_sqlite_embeds_off_the_worker_4089() {
    bulk_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn bulk_postgres_branch_embeds_off_the_worker_4089() {
    bulk_scenario(Branch::FakePg);
}

#[test]
fn update_sqlite_embeds_off_the_worker_4089() {
    update_scenario();
}

#[test]
fn check_duplicate_sqlite_embeds_off_the_worker_4089() {
    check_duplicate_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn check_duplicate_postgres_branch_embeds_off_the_worker_4089() {
    check_duplicate_scenario(Branch::FakePg);
}

#[test]
fn recall_sqlite_embeds_off_the_worker_4089() {
    recall_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn recall_postgres_branch_embeds_off_the_worker_4089() {
    recall_scenario(Branch::FakePg);
}

#[test]
fn rerank_sqlite_runs_off_the_worker_4089() {
    rerank_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn rerank_postgres_branch_runs_off_the_worker_4089() {
    rerank_scenario(Branch::FakePg);
}

#[test]
fn smart_load_sqlite_embeds_off_the_worker_4089() {
    smart_load_scenario(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn smart_load_postgres_branch_embeds_off_the_worker_4089() {
    smart_load_scenario(Branch::FakePg);
}

#[test]
fn reflect_sqlite_embeds_off_the_worker_4089() {
    reflect_scenario();
}

#[cfg(feature = "sal-postgres")]
#[test]
fn real_postgres_embeds_off_the_worker_4089() {
    create_scenario(Branch::RealPg);
    bulk_scenario(Branch::RealPg);
    check_duplicate_scenario(Branch::RealPg);
    recall_scenario(Branch::RealPg);
    rerank_scenario(Branch::RealPg);
    smart_load_scenario(Branch::RealPg);
}

/// The update's embedding regeneration runs AFTER the new text is committed,
/// so it must not be abandoned when the request is dropped mid-forward (a
/// client disconnect): the row would keep its OLD vector for its NEW text
/// and semantic recall would rank it wrong. The regeneration is one
/// blocking-pool unit that tokio runs to completion regardless.
#[test]
fn update_regeneration_survives_a_dropped_request_4089() {
    one_worker_runtime().block_on(async {
        let fx = fixture("update-drop", Branch::Sqlite, None)
            .await
            .expect("sqlite fixture");
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let id = seed(&fx.router, "update-drop-4089", "the old text").await;
        let new_content = format!("the new text {}", fx.marker);
        let body = json!({"content": new_content, "agent_id": AGENT});
        let inflight = tokio::spawn(send(
            fx.router.clone(),
            request("PUT", &format!("/api/v1/memories/{id}"), Some(&body)),
        ));
        entered
            .recv_timeout(Duration::from_secs(20))
            .expect("the update reached its embedding regeneration");
        // The client goes away mid-forward: the handler future is dropped at
        // its next suspension point. (An inline, non-yielding regeneration
        // cannot be dropped mid-forward at all and simply completes; either
        // way the stored vector below must match the NEW text.)
        inflight.abort();
        match inflight.await {
            Ok((status, resp)) => assert_eq!(status, StatusCode::OK, "update: {resp}"),
            Err(e) => assert!(e.is_cancelled(), "update task panicked: {e}"),
        }
        // Compute the vector the regeneration must store. The marker is part
        // of the new text, so re-arm with a marker that never occurs first:
        // same deterministic vectors, no second hold.
        let expected_doc =
            ai_memory::embeddings::embedding_document("update-drop-4089", &new_content);
        let expected = unheld_embedding(&fx, &expected_doc);
        // Wait (bounded) for the regeneration to land.
        let deadline = Instant::now() + HOLD * 5;
        loop {
            let conn = ai_memory::db::open(&fx.db_path).expect("reopen");
            let stored = ai_memory::db::get_embedding(&conn, &id).expect("read embedding");
            if stored.as_ref() == Some(&expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the dropped update left the row with a STALE vector for its new text \
                 (stored {:?}…) — the regeneration was abandoned at an await",
                stored.map(|v| v.into_iter().take(3).collect::<Vec<_>>())
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}
