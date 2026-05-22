// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1095 — `POST /api/v1/share` HTTP route integration pin.
//!
//! Closes the SR-4 three-surface parity audit gap: `memory_share` was
//! MCP-only at v0.7.0 RC pre-#1095. This test pins the HTTP route's
//! wire shape so a future refactor that drops the route fails the
//! regression.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

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
        .join("issue-1095-share-http")
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// v0.7.0 #1095 — `POST /api/v1/share` MUST be a wired HTTP route.
///
/// Pre-#1095 the route was missing entirely; a wire caller got 404.
/// Post-#1095 the route wraps the substrate primitive and returns
/// the same envelope as the MCP tool.
#[tokio::test]
async fn share_http_route_copies_memory_into_shared_namespace_1095() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();

    // Seed a source memory to share.
    let seed_req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:alice")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "tier": "long",
                "namespace": "share-test-1095",
                "title": "shared-source",
                "content": "share me",
                "tags": [],
                "priority": 5,
            }))
            .unwrap(),
        ))
        .unwrap();
    let seed_resp = router.clone().oneshot(seed_req).await.unwrap();
    assert!(
        seed_resp.status().is_success(),
        "seed memory create must succeed; got {}",
        seed_resp.status()
    );
    let body_bytes = axum::body::to_bytes(seed_resp.into_body(), usize::MAX)
        .await
        .expect("read seed body");
    let seed_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse seed body");
    let source_id = seed_json["id"]
        .as_str()
        .expect("seed must return an id")
        .to_string();

    // Issue the share request.
    let share_req = Request::builder()
        .method("POST")
        .uri("/api/v1/share")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "source_memory_id": source_id,
                "target_agent_id": "ai:bob",
            }))
            .unwrap(),
        ))
        .unwrap();
    let share_resp = router.oneshot(share_req).await.unwrap();
    assert_eq!(
        share_resp.status(),
        StatusCode::OK,
        "#1095: POST /api/v1/share must return 200 OK on success"
    );
    let body_bytes = axum::body::to_bytes(share_resp.into_body(), usize::MAX)
        .await
        .expect("read share body");
    let share_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse share body");

    // Wire shape must match the MCP envelope (same fields, byte-equal).
    assert!(
        share_json["shared_memory_id"].is_string(),
        "#1095: share envelope must carry `shared_memory_id`"
    );
    assert_eq!(
        share_json["source_memory_id"], source_id,
        "#1095: share envelope must echo `source_memory_id`"
    );
    assert_eq!(
        share_json["target_agent_id"], "ai:bob",
        "#1095: share envelope must echo `target_agent_id`"
    );
    assert!(
        share_json["target_namespace"]
            .as_str()
            .unwrap_or("")
            .starts_with("_shared/"),
        "#1095: target_namespace must start with `_shared/` (MCP parity)"
    );
}

/// v0.7.0 #1095 — Validation errors surface as 400 with the
/// substrate's error string (e.g. invalid agent_id, missing source).
#[tokio::test]
async fn share_http_route_returns_400_on_invalid_input_1095() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/share")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "source_memory_id": "does-not-exist",
                "target_agent_id": "ai:bob",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "#1095: invalid input (missing source) must surface as 400"
    );
}
