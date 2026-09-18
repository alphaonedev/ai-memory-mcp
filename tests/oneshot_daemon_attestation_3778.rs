// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3778 — the attestation posture of the in-process HTTP-direct surface is
//! DECLARED by the test that builds the router, never inherited from an
//! ambient environment or from a sibling test's process-global `Once`.
//!
//! `tests/integration.rs::OneshotDaemon` used to depend on a sibling having
//! called `common::free_port()` first (which pins the permissive opt-out for
//! the whole process); a filtered run failed at `create_memory` with
//! `ATTESTATION_FAILED` before the cell under test. That binary now declares
//! the opt-out in `OneshotDaemon::new`. This binary owns the OTHER half — the
//! CONTROL that the required posture still refuses an unsigned HTTP-direct
//! store — in its own process, under the env lock, because it must set the
//! variable to a STRICT value and the integration binary never may (#1609).

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

const API_KEY: &str = "attestation-3778";
const ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";

fn app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    );
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
        store,
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

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app,
    )
}

async fn unsigned_create(router: &axum::Router) -> (StatusCode, Value) {
    let body = json!({
        "namespace": "ns-3778",
        "title": "unsigned store",
        "content": "no signature on this write",
        "tier": "long",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("x-api-key", API_KEY)
        .header("x-agent-id", "ai:agent-3778")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// CONTROL: with attestation REQUIRED the unsigned HTTP-direct store is
/// refused `403 ATTESTATION_FAILED` — the posture the integration binary's
/// declared opt-out exists to switch OFF, proven live in its own process.
#[tokio::test]
async fn required_posture_refuses_an_unsigned_http_store_3778() {
    let _env = common::EnvVarGuard::set(ENV, "1".to_string());
    common::ensure_no_config_env();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let router = router(app_state(&dir.path().join("strict.db")));
    let (status, body) = unsigned_create(&router).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["code"],
        ai_memory::errors::error_codes::ATTESTATION_FAILED,
        "{body}"
    );
}

/// ALLOWED PATH: the documented opt-out (`=0`, what `OneshotDaemon::new` and
/// `cmd()` declare) lets the same unsigned store land `attest_level=claimed`.
#[tokio::test]
async fn declared_opt_out_admits_the_unsigned_http_store_3778() {
    let _env = common::EnvVarGuard::set(ENV, "0".to_string());
    common::ensure_no_config_env();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let router = router(app_state(&dir.path().join("permissive.db")));
    let (status, body) = unsigned_create(&router).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}
