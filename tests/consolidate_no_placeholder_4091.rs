// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4091 — `POST /api/v1/consolidate` must FAIL CLOSED when no summary can
//! be produced, never consolidate the sources under a content-free
//! placeholder.
//!
//! Pre-fix `resolve_consolidate_summary` answered a successful summary in
//! four cases where no model produced one — no LLM wired, the LLM call
//! exceeded `llm_call_timeout`, the LLM errored, the LLM returned an empty
//! body — and the consolidation then PROCEEDED: the consolidated row's
//! content was `"Consolidated summary of 2 memories: <title>; <title>"` (or
//! the timeout / unavailable variants), the sources were tombstoned (default)
//! or hard-deleted (`AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES=0`), and the
//! memories' meaning was gone — driven by a transient LLM failure.
//!
//! Every cell here: the route answers `503` with the `SUMMARY_UNAVAILABLE`
//! code, both source rows are byte-identical and still `open`, and no
//! consolidated row exists. The control proves the same router consolidates
//! when the model does answer.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::llm::OllamaClient;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALICE: &str = "ai:alice-4091";
const API_KEY: &str = "consolidate-4091";
const NS: &str = "consolidate-4091";
const TITLE: &str = "consolidated-4091";
const CONTENT_A: &str = "first source body: the retry path was hardened in AOM-101";
const CONTENT_B: &str = "second source body: backoff plus jitter landed in the retry loop";
/// The wire slug the refusal must carry.
const SUMMARY_UNAVAILABLE: &str = "SUMMARY_UNAVAILABLE";

#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("consolidate-4091-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir under .local-runs")
}

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`; under `sal` its inner Arc is \
                  MOVED into the struct literal, so one signature keeps both legs."
    )
)]
fn app_state(
    dir: &std::path::Path,
    llm: Option<OllamaClient>,
    llm_call_timeout: Duration,
) -> AppState {
    let path = dir.join("consolidate.db");
    let conn = ai_memory::db::open(&path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    let _ = &store;
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: store.0,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(llm)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout,
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
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router(app: AppState) -> Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app,
    )
}

fn source(title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": ALICE }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// Seed the two sources the caller owns; returns their ids.
async fn seed(app: &AppState) -> (String, String) {
    let lock = app.db.lock().await;
    let a = ai_memory::db::insert(&lock.0, &source("src-4091-a", CONTENT_A)).unwrap();
    let b = ai_memory::db::insert(&lock.0, &source("src-4091-b", CONTENT_B)).unwrap();
    (a, b)
}

async fn consolidate(router: &Router, ids: &[&str]) -> (StatusCode, Value) {
    let body = json!({ "ids": ids, "title": TITLE, "namespace": NS });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/consolidate")
        .header("x-api-key", API_KEY)
        .header("x-agent-id", ALICE)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The sources are untouched (content, lifecycle `open`, still readable by
/// id) and no consolidated row was minted.
async fn assert_nothing_consolidated(app: &AppState, ids: &(String, String), case: &str) {
    let lock = app.db.lock().await;
    for (id, content) in [(&ids.0, CONTENT_A), (&ids.1, CONTENT_B)] {
        let row = ai_memory::db::get(&lock.0, id)
            .expect("read source")
            .unwrap_or_else(|| panic!("{case}: source {id} must still exist"));
        assert_eq!(row.content, content, "{case}: source content must be untouched");
        assert_eq!(
            row.lifecycle_state,
            LifecycleState::Open,
            "{case}: source must not be tombstoned"
        );
    }
    let minted: i64 = lock
        .0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
            [NS, TITLE],
            |r| r.get(0),
        )
        .expect("count consolidated rows");
    assert_eq!(minted, 0, "{case}: no consolidated row may be created");
}

fn assert_summary_unavailable(status: StatusCode, body: &Value, case: &str) {
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{case}: #4091 the consolidation must be refused, not fabricated: {body}"
    );
    assert_eq!(body["code"], SUMMARY_UNAVAILABLE, "{case}: {body}");
    assert!(
        !body.to_string().contains("deterministic fallback"),
        "{case}: no placeholder text may leak: {body}"
    );
}

/// A mock Ollama whose `/api/chat` answers `template`.
async fn mock_llm(template: ResponseTemplate) -> (MockServer, OllamaClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(template)
        .mount(&server)
        .await;
    let client = OllamaClient::new_with_url_no_health_check(&server.uri(), "test-model-4091")
        .expect("mock-backed client");
    (server, client)
}

#[tokio::test]
async fn llm_absent_refuses_and_leaves_sources_untouched_4091() {
    let dir = scratch();
    let app = app_state(dir.path(), None, Duration::from_secs(5));
    let ids = seed(&app).await;
    let router = router(app.clone());
    let (status, body) = consolidate(&router, &[&ids.0, &ids.1]).await;
    assert_summary_unavailable(status, &body, "llm absent");
    assert_nothing_consolidated(&app, &ids, "llm absent").await;
}

#[tokio::test]
async fn llm_timeout_refuses_and_leaves_sources_untouched_4091() {
    let (_server, client) = mock_llm(
        ResponseTemplate::new(200)
            .set_delay(Duration::from_secs(3))
            .set_body_json(json!({
                "message": {"role": "assistant", "content": "too late to matter"},
                "done": true,
            })),
    )
    .await;
    let dir = scratch();
    let app = app_state(dir.path(), Some(client), Duration::from_millis(200));
    let ids = seed(&app).await;
    let router = router(app.clone());
    let (status, body) = consolidate(&router, &[&ids.0, &ids.1]).await;
    assert_summary_unavailable(status, &body, "llm timeout");
    assert_nothing_consolidated(&app, &ids, "llm timeout").await;
}

#[tokio::test]
async fn llm_error_refuses_and_leaves_sources_untouched_4091() {
    let (_server, client) = mock_llm(ResponseTemplate::new(500)).await;
    let dir = scratch();
    let app = app_state(dir.path(), Some(client), Duration::from_secs(5));
    let ids = seed(&app).await;
    let router = router(app.clone());
    let (status, body) = consolidate(&router, &[&ids.0, &ids.1]).await;
    assert_summary_unavailable(status, &body, "llm error");
    assert_nothing_consolidated(&app, &ids, "llm error").await;
}

#[tokio::test]
async fn llm_empty_summary_refuses_and_leaves_sources_untouched_4091() {
    let (_server, client) = mock_llm(ResponseTemplate::new(200).set_body_json(json!({
        "message": {"role": "assistant", "content": "   "},
        "done": true,
    })))
    .await;
    let dir = scratch();
    let app = app_state(dir.path(), Some(client), Duration::from_secs(5));
    let ids = seed(&app).await;
    let router = router(app.clone());
    let (status, body) = consolidate(&router, &[&ids.0, &ids.1]).await;
    assert_summary_unavailable(status, &body, "llm empty");
    assert_nothing_consolidated(&app, &ids, "llm empty").await;
}

/// CONTROL — the same router consolidates when the model answers.
#[tokio::test]
async fn llm_answer_consolidates_4091_control() {
    let (_server, client) = mock_llm(ResponseTemplate::new(200).set_body_json(json!({
        "message": {
            "role": "assistant",
            "content": "AOM-101 hardened the sync_push retry path with backoff and jitter.",
        },
        "done": true,
    })))
    .await;
    let dir = scratch();
    let app = app_state(dir.path(), Some(client), Duration::from_secs(5));
    let ids = seed(&app).await;
    let router = router(app.clone());
    let (status, body) = consolidate(&router, &[&ids.0, &ids.1]).await;
    assert_eq!(status, StatusCode::CREATED, "control: {body}");
    assert!(
        body["summary"]
            .as_str()
            .is_some_and(|s| s.contains("AOM-101")),
        "control: the model's summary is the stored one: {body}"
    );
}
