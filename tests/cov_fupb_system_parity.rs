// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FUPB coverage — `src/handlers/system.rs` (capabilities accept-header
//! negotiation) + `src/handlers/parity.rs` (`resolve_caller_agent_id`
//! query-vs-header mismatch arm).
//!
//! system.rs: the existing fake-pg suite hits the default v3 + postgres
//! backend path, but not the explicit `Accept-Capabilities: v1` / `v2`
//! negotiation branches on a sqlite-backed daemon (the `accept` match's
//! non-default arm) nor the `db_schema_version` success path through the
//! SAL `schema_version()`.
//!
//! parity.rs: `resolve_caller_agent_id` accepts a `query` refinement slot
//! (the recall handler passes `as_agent` there). A query value that is
//! shape-valid but disagrees with the authenticated header-resolved id
//! must return `agent_id_query_header_mismatch` → 403. The existing recall
//! coverage only hits the shape-invalid (`as_agent` validation) 400 arm.

#![cfg(feature = "sal")]
#![allow(clippy::redundant_closure_for_method_calls)]

use std::sync::Arc;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

fn build_sqlite_router() -> axum::Router {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn get_with_header(
    router: &axum::Router,
    uri: &str,
    hdr: Option<(&str, &str)>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some((k, v)) = hdr {
        b = b.header(k, v);
    }
    let resp = router
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ---------------------------------------------------------------------------
// system.rs — capabilities accept-header negotiation on sqlite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capabilities_default_v3_on_sqlite() {
    let router = build_sqlite_router();
    let (status, v) = get_with_header(&router, "/api/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK);
    // sqlite backend surfaced + the live db_schema_version success path.
    assert_eq!(v["storage_backend"], json!("sqlite"));
    assert!(
        v["db_schema_version"].is_number(),
        "db_schema_version must be populated via SAL schema_version(); got {v}"
    );
    assert!(
        v["db_schema_version"].as_i64().unwrap_or(0) > 0,
        "a freshly-migrated sqlite store reports a positive schema version"
    );
}

#[tokio::test]
async fn capabilities_accept_v2_negotiation() {
    let router = build_sqlite_router();
    let (status, v) = get_with_header(
        &router,
        "/api/v1/capabilities",
        Some(("accept-capabilities", "v2")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "v2 negotiation must succeed; body={v}"
    );
    // Backend + schema fields are appended regardless of accept version.
    assert_eq!(v["storage_backend"], json!("sqlite"));
}

#[tokio::test]
async fn capabilities_accept_v1_negotiation() {
    let router = build_sqlite_router();
    let (status, v) = get_with_header(
        &router,
        "/api/v1/capabilities",
        Some(("accept-capabilities", "v1")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "v1 negotiation must succeed; body={v}"
    );
    assert_eq!(v["storage_backend"], json!("sqlite"));
}

// ---------------------------------------------------------------------------
// parity.rs — resolve_caller_agent_id query-vs-header mismatch arm
// ---------------------------------------------------------------------------

/// `POST /api/v1/recall` threads `body.as_agent` into the parity helper's
/// `query` refinement slot. A shape-valid `as_agent` that disagrees with
/// the `X-Agent-Id` header must surface the
/// `agent_id_query_header_mismatch` arm → 403.
#[tokio::test]
async fn recall_post_as_agent_mismatch_returns_403() {
    let router = build_sqlite_router();
    let body = json!({"context": "anything", "as_agent": "ai:viewer-bob"}).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:operator-alice")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "as_agent disagreeing with the authenticated header must 403; body={v}"
    );
    let err = v["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("query_header_mismatch") || err.contains("mismatch"),
        "error must tag the query/header mismatch; got {err:?}"
    );
}

/// GET twin — `?as_agent=` query param routed through the same slot.
#[tokio::test]
async fn recall_get_as_agent_mismatch_returns_403() {
    let router = build_sqlite_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/recall?context=hello&as_agent=ai:viewer-bob")
        .header("x-agent-id", "ai:operator-alice")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "GET as_agent mismatch must 403; body={v}"
    );
}

/// Matching `as_agent` + header must NOT trip the mismatch arm (200).
#[tokio::test]
async fn recall_post_as_agent_matching_header_ok() {
    let router = build_sqlite_router();
    let body = json!({"context": "anything", "as_agent": "ai:operator-alice"}).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:operator-alice")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "matching as_agent + header must pass the parity gate"
    );
}
