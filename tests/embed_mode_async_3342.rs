// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3342 — HTTP sqlite-router pins for `embed_mode`.
//!
//! * `POST {embed_mode:"async"}` → 201 `embed_status: pending`
//! * unknown token → 400
//! * a Pending row is drainable by `run_embedding_backfill_on_store`
//!   without a daemon restart (the live-worker control)

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::Embed;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::CallerContext;

const TESTER: &str = "ai:embed-3342";

fn permissive_attestation() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn build_state(db_path: &std::path::Path) -> AppState {
    permissive_attestation();
    ai_memory::handlers::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
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
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("store")),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
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
        admin_agent_ids: Arc::new(vec![TESTER.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile, AppState) {
    let db_tmp = tempfile::NamedTempFile::new().expect("tmp");
    let _ = ai_memory::db::open(db_tmp.path()).expect("open");
    let state = build_state(db_tmp.path());
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (
        ai_memory::build_router(api_key_state, state.clone()),
        db_tmp,
        state,
    )
}

async fn post(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", TESTER)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

struct FixedEmb;

impl Embed for FixedEmb {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Ok(vec![0.01; 8])
    }
}

fn create_body(title: &str, mode: &str) -> Value {
    json!({
        "title": title,
        "content": "content body — long enough to satisfy validators",
        "namespace": "embed-3342",
        "tier": "long",
        "embed_mode": mode,
    })
}

#[tokio::test]
async fn http_embed_mode_async_returns_pending() {
    let (r, _t, _s) = sqlite_router();
    let (status, body) = post(&r, create_body("async-pending", "async")).await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["embed_status"], "pending");
    assert_eq!(body["embed_mode"], "async");
}

#[tokio::test]
async fn http_embed_mode_unknown_is_400() {
    let (r, _t, _s) = sqlite_router();
    let (status, body) = post(&r, create_body("async-bad", "nope")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("embed_mode"),
        "unknown token must name embed_mode: {body}"
    );
}

#[tokio::test]
async fn http_embed_mode_async_row_indexes_without_restart() {
    let (r, _t, state) = sqlite_router();
    let (status, body) = post(&r, create_body("async-drain", "async")).await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["embed_status"], "pending");

    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::EMBEDDING_BACKFILL);
    let pending = state
        .store
        .list_unembedded(&ctx, 16)
        .await
        .expect("list_unembedded");
    assert!(
        !pending.is_empty(),
        "async create must leave an unembedded row"
    );

    let written = ai_memory::store::run_embedding_backfill_on_store(
        state.store.as_ref(),
        &ctx,
        &FixedEmb,
        16,
    )
    .await;
    assert!(written >= 1, "backfill must write without a restart");

    let left = state
        .store
        .list_unembedded(&ctx, 16)
        .await
        .expect("list after backfill");
    assert!(
        left.is_empty(),
        "Pending row must be indexed without a daemon restart: {left:?}"
    );
}
