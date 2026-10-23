// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7247 — CORS is deny-by-default.
//!
//! `build_router` layers `tower_http::cors::CorsLayer::new()` (src/lib.rs),
//! which allows no origin. The README used to call the layer "permissive";
//! this test pins the real posture so the docs and the code cannot drift
//! again: neither a cross-origin preflight nor a cross-origin simple
//! request may ever receive an `Access-Control-Allow-Origin` header.
//!
//! The fixture is copied from `tests/http_routes_1111.rs` (self-contained
//! fixture over a cross-test shared module, the same call that file makes).

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, header};
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const FOREIGN_ORIGIN: &str = "https://evil.example";

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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

#[tokio::test]
async fn cross_origin_preflight_gets_no_allow_origin_7247() {
    let (router, _f) = build_router_fixture();
    let req = Request::builder()
        .method("OPTIONS")
        .uri(ai_memory::handlers::routes::HEALTH)
        .header(header::ORIGIN, FOREIGN_ORIGIN)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "#7247: CorsLayer::new() allows no origin; a preflight from {FOREIGN_ORIGIN} must not \
         receive Access-Control-Allow-Origin, got {:?}",
        resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
}

#[tokio::test]
async fn cross_origin_simple_request_gets_no_allow_origin_7247() {
    let (router, _f) = build_router_fixture();
    let req = Request::builder()
        .method("GET")
        .uri(ai_memory::handlers::routes::HEALTH)
        .header(header::ORIGIN, FOREIGN_ORIGIN)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "#7247: a cross-origin GET must not receive Access-Control-Allow-Origin, got {:?}",
        resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
}
