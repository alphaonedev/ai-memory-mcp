// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1539 — `PUT /api/v1/agents/{id}/pubkey` route integration pin.
//!
//! Pre-#1539 there was NO HTTP/admin surface to bind an agent
//! attestation pubkey: attesting clients under
//! `REQUIRE_AGENT_ATTESTATION=1` needed an out-of-band DB write (the
//! do-1461 provisioning bound via ssh+psql on the region pg node).
//! This pins: admin gating, pubkey validation, the happy-path bind
//! through the SAL trait, and the unregistered-agent error shape.

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const ADMIN_CALLER: &str = "ai:ops-admin";
const TARGET_AGENT: &str = "ai:attesting-client";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1539-bind-pubkey")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn build_router_fixture() -> (axum::Router, NamedTempFile) {
    // Authenticated-deployment posture so admin header role-claims
    // resolve (#1570) — same as tests/share_http_route_1095.rs.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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
        admin_agent_ids: Arc::new(vec![ADMIN_CALLER.to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn register_target_agent(router: &axum::Router) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_CALLER)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "agent_id": TARGET_AGENT,
                "agent_type": "ai:test",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "agent registration must succeed; got {}",
        resp.status()
    );
}

fn valid_pubkey_b64() -> String {
    let dir = fresh_dir();
    // SAFETY-free key-dir override via the documented env knob is not
    // needed — `generate` takes no paths; the keypair lives in memory.
    let _ = dir;
    ai_memory::identity::keypair::generate("test-bind-1539")
        .expect("generate keypair")
        .public_base64()
}

fn put_pubkey(agent: &str, caller: &str, pubkey_b64: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/agents/{agent}/pubkey"))
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "pubkey_b64": pubkey_b64 })).unwrap(),
        ))
        .unwrap()
}

/// Happy path: admin binds a valid Ed25519 pubkey to a registered
/// agent → 200 `{bound:true}`.
#[tokio::test]
async fn bind_pubkey_route_happy_path_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(TARGET_AGENT, ADMIN_CALLER, &valid_pubkey_b64()))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin bind of a valid pubkey must return 200"
    );
    let body = axum::body::to_bytes(resp.into_body(), ai_memory::TEST_BODY_READ_CAP)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["bound"], serde_json::json!(true));
    assert_eq!(v["agent_id"], serde_json::json!(TARGET_AGENT));
}

/// Non-admin caller → 403 (the require_admin gate; generic body, no
/// allowlist probing).
#[tokio::test]
async fn bind_pubkey_route_requires_admin_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(
            TARGET_AGENT,
            "ai:not-an-admin",
            &valid_pubkey_b64(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin caller must be refused"
    );
}

/// Garbage pubkey → 400 before any store call.
#[tokio::test]
async fn bind_pubkey_route_rejects_invalid_pubkey_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();
    register_target_agent(&router).await;

    let resp = router
        .clone()
        .oneshot(put_pubkey(TARGET_AGENT, ADMIN_CALLER, "not-a-key"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid pubkey must be rejected with 400"
    );
}

/// Unregistered agent → the storage layer's typed error surfaces (the
/// bind pre-checks registration), not a silent 200.
#[tokio::test]
async fn bind_pubkey_route_unregistered_agent_errors_1539() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_fixture();

    let resp = router
        .clone()
        .oneshot(put_pubkey(
            "ai:never-registered",
            ADMIN_CALLER,
            &valid_pubkey_b64(),
        ))
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "binding to an unregistered agent must not succeed; got {}",
        resp.status()
    );
}
