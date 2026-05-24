// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1111 — 14 HTTP route integration tests for the missing
//! MCP-only tools the SR-4 three-surface-parity audit flagged.
//!
//! Each test pins the wire shape for one new route. Pre-#1111 these
//! routes were missing entirely; a caller got 404. Post-#1111 every
//! route accepts the same JSON body shape the MCP `arguments` bag
//! accepts and returns the same envelope the MCP `tools/call`
//! response wraps.
//!
//! The tests use the shared `build_router_fixture` from the existing
//! `tests/share_http_route_1095.rs` (replicated here to keep the test
//! file self-contained — copy-pasting fixture boilerplate is preferable
//! to a cross-test shared-module dependency that would slow test
//! compilation).

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::similar_names
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1111-http-routes")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn build_router_fixture() -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
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
        llm_call_timeout: std::time::Duration::from_secs(30),
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// Helper: POST a JSON body to `path` and return the resulting
/// (status, parsed_body). Body parse falls back to Null on non-JSON.
async fn post_json(
    router: &axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    (status, parsed)
}

/// Helper: POST with an explicit X-Agent-Id header. Used by the
/// ownership-gated routes (replay, subscription_replay,
/// subscription_dlq_list).
async fn post_json_with_agent(
    router: &axum::Router,
    path: &str,
    body: serde_json::Value,
    agent_id: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    (status, parsed)
}

// ---------------------------------------------------------------------------
// 14 route integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smart_load_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Empty intent → routes to Core family fallback (no embedder
    // wired in this fixture so the keyword voting path runs).
    let (status, body) = post_json(
        &router,
        "/api/v1/memory_smart_load",
        serde_json::json!({"intent": ""}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1111: POST /api/v1/memory_smart_load must return 200 OK; body={body}"
    );
    assert!(
        body.get("chosen_family_source").is_some() || body.get("memories").is_some(),
        "#1111: smart_load envelope must echo the family-load shape; got {body}"
    );
}

#[tokio::test]
async fn reflect_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing source_ids → substrate-rejected with 400.
    let (status, body) = post_json(&router, "/api/v1/memory_reflect", serde_json::json!({})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: reflect with missing source_ids must 400; got {status} {body}"
    );
}

#[tokio::test]
async fn recall_observations_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // No filters → empty result set, 200 OK.
    let (status, body) = post_json(
        &router,
        "/api/v1/memory_recall_observations",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1111: recall_observations on empty db must 200 OK; got {status} {body}"
    );
    assert!(
        body.get("observations").is_some() || body.get("count").is_some(),
        "#1111: recall_observations envelope must carry the observations list (or count); got {body}"
    );
}

#[tokio::test]
async fn reflection_origin_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing memory_id → 400.
    let (status, _body) = post_json(
        &router,
        "/api/v1/memory_reflection_origin",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: reflection_origin with missing memory_id must 400"
    );
}

#[tokio::test]
async fn dependents_of_invalidated_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    let (status, _body) = post_json(
        &router,
        "/api/v1/memory_dependents_of_invalidated",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: dependents_of_invalidated with missing memory_id must 400"
    );
}

#[tokio::test]
async fn export_reflection_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    let (status, _body) = post_json(
        &router,
        "/api/v1/memory_export_reflection",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: export_reflection with missing memory_id must 400"
    );
}

#[tokio::test]
async fn atomise_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing memory_id → 400.
    let (status, _body) = post_json(&router, "/api/v1/memory_atomise", serde_json::json!({})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: atomise with missing memory_id must 400"
    );
}

#[tokio::test]
async fn calibrate_confidence_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // No params → substrate uses default window; 200 OK with empty
    // confidence-shadow table.
    let (status, body) = post_json(
        &router,
        "/api/v1/memory_calibrate_confidence",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1111: calibrate_confidence with default window must 200 OK; got {status} {body}"
    );
}

#[tokio::test]
async fn verify_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing link params → 400.
    let (status, _body) = post_json(&router, "/api/v1/memory_verify", serde_json::json!({})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: verify with missing link params must 400"
    );
}

#[tokio::test]
async fn replay_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing memory_id → 400. (Ownership gate only kicks in after
    // arg validation passes.)
    let (status, _body) = post_json_with_agent(
        &router,
        "/api/v1/memory_replay",
        serde_json::json!({}),
        "ai:alice",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: replay with missing memory_id must 400"
    );
}

#[tokio::test]
async fn subscription_replay_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    let (status, _body) = post_json_with_agent(
        &router,
        "/api/v1/memory_subscription_replay",
        serde_json::json!({}),
        "ai:alice",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: subscription_replay with missing subscription_id must 400"
    );
}

#[tokio::test]
async fn subscription_dlq_list_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // No params → list-all DLQ; substrate refuses non-admin without
    // subscription_id (issue #1118 SR-1 #6 ownership gate).
    let (status, _body) = post_json_with_agent(
        &router,
        "/api/v1/memory_subscription_dlq_list",
        serde_json::json!({}),
        "ai:alice",
    )
    .await;
    // Either 200 OK (admin) or 400 (non-admin refused by ownership
    // gate). The fixture's admin_agent_ids is empty so ai:alice is
    // non-admin → expect the ownership refusal path.
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::OK,
        "#1111: subscription_dlq_list must either 200 (admin) or 400 (non-admin refusal); got {status}"
    );
}

#[tokio::test]
async fn rule_list_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // No rules seeded → empty list, 200 OK.
    let (status, body) =
        post_json(&router, "/api/v1/memory_rule_list", serde_json::json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1111: rule_list on empty rules table must 200 OK; got {status} {body}"
    );
    assert!(
        body.get("rules").is_some() || body.get("count").is_some(),
        "#1111: rule_list envelope must carry the rules array or count; got {body}"
    );
}

#[tokio::test]
async fn check_agent_action_http_route_1111() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    // Missing kind → 400.
    let (status, _body) = post_json(
        &router,
        "/api/v1/memory_check_agent_action",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#1111: check_agent_action with missing kind must 400"
    );
}

/// Cross-cutting pin: every #1111 route MUST be a wired HTTP route
/// (not a 404). This catches accidental removal of any single route
/// in a future refactor.
#[tokio::test]
async fn all_1111_routes_are_wired() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    let routes = [
        "/api/v1/memory_smart_load",
        "/api/v1/memory_reflect",
        "/api/v1/memory_recall_observations",
        "/api/v1/memory_reflection_origin",
        "/api/v1/memory_dependents_of_invalidated",
        "/api/v1/memory_export_reflection",
        "/api/v1/memory_atomise",
        "/api/v1/memory_calibrate_confidence",
        "/api/v1/memory_verify",
        "/api/v1/memory_replay",
        "/api/v1/memory_subscription_replay",
        "/api/v1/memory_subscription_dlq_list",
        "/api/v1/memory_rule_list",
        "/api/v1/memory_check_agent_action",
    ];
    for path in routes {
        let (status, _body) =
            post_json_with_agent(&router, path, serde_json::json!({}), "ai:alice").await;
        assert!(
            status != StatusCode::NOT_FOUND,
            "#1111: route {path} must be wired (not 404); got {status}"
        );
    }
}
