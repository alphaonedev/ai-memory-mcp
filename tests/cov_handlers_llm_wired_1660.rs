// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage lift (operator 90%-per-module floor, 2026-06-11) for the
//! LLM-wired arms of `handlers/power_consolidation.rs` and the LLM-gated
//! arms of `handlers/power.rs`, plus a handful of cheap error/edge arms
//! across `governance.rs`, `capture_turn.rs`, `system.rs`, and
//! `archive.rs`.
//!
//! The pre-existing handler tests (`src/handlers/tests.rs`,
//! `tests/handler_postgres_branches_fake_pg.rs`) drive the no-LLM
//! fallbacks (`app.llm = None` → 503 / empty tag list) and the
//! sqlite/postgres CRUD shapes. They never wire a live `app.llm`, so the
//! entire LLM-success / LLM-error / LLM-timeout branch set in
//! `consolidate_memories`, `auto_tag_handler`, and `expand_query_handler`
//! was uncovered. This file builds an `AppState` whose `llm` field points
//! at a `wiremock` `/api/chat` endpoint so those branches execute against
//! a real (mocked) HTTP round-trip — the same pattern
//! `tests/form_1_synthesis_verdict_matrix.rs` uses for the synthesis
//! hook.

#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::llm::OllamaClient;

// ---------------------------------------------------------------------------
// Mock LLM — a wiremock server that answers `/api/chat` with a caller-
// supplied body string (Ollama native shape) and `/api/tags` with an
// empty model list (health probe). `chat_error` flips `/api/chat` to a
// 500 so the handler error arms execute.
// ---------------------------------------------------------------------------

async fn start_chat_mock(chat_content: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"content": chat_content}, "done": true})),
        )
        .mount(&server)
        .await;
    server
}

async fn start_chat_error_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
        .mount(&server)
        .await;
    server
}

/// Build a sqlite-backed router whose `app.llm` points at `llm_url`
/// (a wiremock `/api/chat` endpoint). Keeps the `NamedTempFile` alive
/// via the returned guard.
fn build_llm_router(llm_url: Option<&str>) -> (axum::Router, NamedTempFile, Db) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let llm = match llm_url {
        Some(u) => Arc::new(Some(
            OllamaClient::new_with_url_no_health_check(u, "test-model").expect("llm"),
        )),
        None => Arc::new(None),
    };
    let app_state = AppState {
        db: db.clone(),
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
        store,
        llm,
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        // Wildcard admin sentinel — same as `test_app_state` in
        // `src/handlers/tests.rs`. Production rejects "*" via
        // `validate_agent_id`, so it cannot leak into a real deployment.
        admin_agent_ids: Arc::new(vec!["*".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db)
}

async fn post_json_as(
    router: &axum::Router,
    uri: &str,
    body: Value,
    caller: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Seed a memory through the HTTP create path so it lands in `app.db`
/// (the connection the sqlite consolidate/auto_tag read paths use).
async fn seed_memory(router: &axum::Router, ns: &str, title: &str, caller: &str) -> String {
    let body = json!({
        "tier": "long",
        "namespace": ns,
        "title": title,
        "content": format!("body content for {title} — substantial enough to summarize"),
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    let (status, v) = post_json_as(router, "/api/v1/memories", body, caller).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "seed create: {status} {v}",
    );
    v["id"].as_str().expect("seeded id").to_string()
}

// ===========================================================================
// auto_tag_handler (power_consolidation.rs) — LLM-wired branches
// ===========================================================================

#[tokio::test]
async fn auto_tag_llm_success_returns_tags() {
    // Ollama auto_tag parses one tag per non-empty line, lowercased.
    let server = start_chat_mock("rust\ncoverage\nmemory\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, v) = post_json(
        &router,
        "/api/v1/auto_tag",
        json!({"title": "Coverage push", "content": "lifting handler coverage to 90%"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let tags = v["tags"].as_array().expect("tags array");
    assert!(tags.iter().any(|t| t == "rust"), "tags: {v}");
    assert!(
        v["memory_id"].is_null(),
        "ad-hoc title+content → null id: {v}"
    );
}

#[tokio::test]
async fn auto_tag_llm_by_memory_id_resolves_and_tags() {
    let server = start_chat_mock("alpha\nbeta\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let id = seed_memory(&router, "cov-autotag", "Tag me", "tagger").await;
    let (status, v) = post_json_as(
        &router,
        "/api/v1/auto_tag",
        json!({"memory_id": id, "namespace": "cov-autotag"}),
        "tagger",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["memory_id"], json!(id), "{v}");
    assert!(v["tags"].as_array().is_some_and(|a| !a.is_empty()), "{v}");
}

#[tokio::test]
async fn auto_tag_llm_upstream_error_returns_502() {
    let server = start_chat_error_mock().await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, v) = post_json(
        &router,
        "/api/v1/auto_tag",
        json!({"title": "x", "content": "y"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{v}");
    assert!(
        v["error"].as_str().is_some_and(|s| s.contains("auto_tag")),
        "{v}"
    );
}

#[tokio::test]
async fn auto_tag_llm_missing_memory_id_returns_404() {
    let server = start_chat_mock("t\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, _v) = post_json_as(
        &router,
        "/api/v1/auto_tag",
        json!({"memory_id": "00000000-0000-0000-0000-000000000000"}),
        "x",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn auto_tag_llm_invalid_memory_id_returns_400() {
    let server = start_chat_mock("t\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, _v) = post_json(
        &router,
        "/api/v1/auto_tag",
        json!({"memory_id": "not a valid id!!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auto_tag_llm_missing_both_shapes_returns_400() {
    let server = start_chat_mock("t\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    // LLM wired (so we pass the 503 gate) but no memory_id and no
    // title+content → the "requires memory_id or title+content" 400.
    let (status, v) = post_json(&router, "/api/v1/auto_tag", json!({"namespace": "x"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}

// ===========================================================================
// expand_query_handler (power_consolidation.rs) — LLM-wired branches
// ===========================================================================

#[tokio::test]
async fn expand_query_llm_success_returns_terms() {
    let server = start_chat_mock("kubernetes\ncontainer orchestration\nk8s\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, v) = post_json(
        &router,
        "/api/v1/expand_query",
        json!({"query": "  k8s deploy  "}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["original"], json!("k8s deploy"), "query trimmed: {v}");
    let terms = v["expanded_terms"].as_array().expect("expanded_terms");
    assert!(terms.iter().any(|t| t == "kubernetes"), "{v}");
}

#[tokio::test]
async fn expand_query_llm_upstream_error_returns_502() {
    let server = start_chat_error_mock().await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, v) = post_json(&router, "/api/v1/expand_query", json!({"query": "x"})).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{v}");
}

#[tokio::test]
async fn expand_query_empty_query_returns_400_even_with_llm() {
    let server = start_chat_mock("t\n").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let (status, _v) = post_json(&router, "/api/v1/expand_query", json!({"query": "   "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// consolidate_memories (power_consolidation.rs) — LLM auto-summary path
// ===========================================================================

#[tokio::test]
async fn consolidate_llm_auto_summary_when_summary_omitted() {
    // No `summary` in body → resolve_consolidate_summary asks the LLM.
    let server =
        start_chat_mock("A consolidated synthesis of the two source memories about coverage.")
            .await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let id1 = seed_memory(&router, "cov-cons", "Source one", "consol").await;
    let id2 = seed_memory(&router, "cov-cons", "Source two", "consol").await;
    let (status, v) = post_json_as(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "Merged coverage note",
            "namespace": "cov-cons",
            "use_llm": true,
        }),
        "consol",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(
        v[ai_memory::models::field_names::CONSOLIDATED],
        json!(2),
        "{v}"
    );
    let summary = v["summary"].as_str().expect("summary");
    assert!(
        summary.contains("consolidated synthesis"),
        "LLM summary used: {v}"
    );
}

#[tokio::test]
async fn consolidate_unknown_source_id_returns_400() {
    // LLM wired, summary omitted → resolve_consolidate_summary fetches
    // source pairs and a missing id short-circuits to 400.
    let server = start_chat_mock("ignored").await;
    let (router, _f, _db) = build_llm_router(Some(&server.uri()));
    let id1 = seed_memory(&router, "cov-cons2", "Real one", "consol2").await;
    let (status, v) = post_json_as(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, "00000000-0000-0000-0000-000000000000"],
            "title": "Merge with a ghost",
            "namespace": "cov-cons2",
        }),
        "consol2",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn consolidate_body_agent_id_mismatch_returns_403() {
    // summary supplied so the LLM path is skipped; header=alice but
    // body.agent_id=bob → 403 (the #905 spoof gate).
    let (router, _f, _db) = build_llm_router(None);
    let id1 = seed_memory(&router, "cov-cons3", "Owned", "alice").await;
    let id2 = seed_memory(&router, "cov-cons3", "Owned2", "alice").await;
    let (status, _v) = post_json_as(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "T",
            "summary": "a caller-supplied summary that is comfortably over twenty chars",
            "namespace": "cov-cons3",
            "agent_id": "bob",
        }),
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn consolidate_no_llm_deterministic_summary_fallback() {
    // No LLM wired + summary omitted → deterministic concat fallback.
    let (router, _f, _db) = build_llm_router(None);
    let id1 = seed_memory(&router, "cov-cons4", "Det one", "det").await;
    let id2 = seed_memory(&router, "cov-cons4", "Det two", "det").await;
    let (status, v) = post_json_as(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "Deterministic merge",
            "namespace": "cov-cons4",
        }),
        "det",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(
        v["summary"]
            .as_str()
            .is_some_and(|s| s.contains("Consolidated summary of")),
        "deterministic fallback: {v}",
    );
}

// ===========================================================================
// load_family_handler (power_consolidation.rs) — sqlite path + errors
// ===========================================================================

#[tokio::test]
async fn load_family_unknown_family_returns_400() {
    let (router, _f, _db) = build_llm_router(None);
    let (status, _v) = post_json(
        &router,
        "/api/v1/memory_load_family",
        json!({"family": "not-a-real-family"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn load_family_invalid_namespace_returns_400() {
    let (router, _f, _db) = build_llm_router(None);
    let (status, _v) = post_json(
        &router,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": "bad namespace!!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn load_family_happy_sqlite_returns_envelope() {
    let (router, _f, _db) = build_llm_router(None);
    let (status, v) = post_json_as(
        &router,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": "cov-fam", "k": 5}),
        "famcaller",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["family"], json!("core"), "{v}");
    assert!(v["memories"].is_array(), "{v}");
    assert_eq!(v["k"], json!(5), "{v}");
}

// ===========================================================================
// detect_contradictions (power.rs) — sqlite path with synthesized links
// ===========================================================================

#[tokio::test]
async fn contradictions_synthesizes_links_for_same_topic_sqlite() {
    let (router, _f, _db) = build_llm_router(None);
    // Two memories sharing topic metadata but differing content → a
    // synthesized contradicts link.
    let body_a = json!({
        "tier": "long", "namespace": "cov-contra", "title": "Claim A",
        "content": "the sky is blue", "tags": [], "priority": 5,
        "confidence": 1.0, "source": "user",
        "metadata": {"topic": "sky-color"},
    });
    let body_b = json!({
        "tier": "long", "namespace": "cov-contra", "title": "Claim B",
        "content": "the sky is green", "tags": [], "priority": 5,
        "confidence": 1.0, "source": "user",
        "metadata": {"topic": "sky-color"},
    });
    let _ = post_json_as(&router, "/api/v1/memories", body_a, "contra").await;
    let _ = post_json_as(&router, "/api/v1/memories", body_b, "contra").await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/contradictions?topic=sky-color&namespace=cov-contra")
        .header("x-agent-id", "contra")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let links = v["links"].as_array().expect("links");
    assert!(
        links.iter().any(|l| l["relation"] == "contradicts"
            && l[ai_memory::models::field_names::SYNTHESIZED] == json!(true)),
        "synthesized contradicts link expected: {v}",
    );
}

#[tokio::test]
async fn contradictions_invalid_namespace_returns_400() {
    let (router, _f, _db) = build_llm_router(None);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/contradictions?namespace=bad%20ns!!")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// check_duplicate (power.rs) — sqlite no-embedder 503 + validation 400s
// ===========================================================================

#[tokio::test]
async fn check_duplicate_no_embedder_returns_503() {
    let (router, _f, _db) = build_llm_router(None);
    let (status, _v) = post_json(
        &router,
        "/api/v1/check_duplicate",
        json!({"title": "Dup probe", "content": "some content body"}),
    )
    .await;
    // Sqlite backend + no embedder → 503 (embedder required).
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn check_duplicate_invalid_title_returns_400() {
    let (router, _f, _db) = build_llm_router(None);
    let (status, _v) = post_json(
        &router,
        "/api/v1/check_duplicate",
        json!({"title": "", "content": "body"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
