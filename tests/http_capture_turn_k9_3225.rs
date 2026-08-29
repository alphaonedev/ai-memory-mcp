// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3225 — HTTP `POST /api/v1/capture_turn` must refuse a K9 namespace
//! Deny the same way MCP `memory_capture_turn` does. The lib-tier pin
//! lives in `src/handlers/tests.rs::http_capture_turn_respects_namespace_deny`
//! (sqlite). This binary is the live-postgres twin: same rule, postgres
//! SAL write path, `--include-ignored`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines, clippy::doc_markdown, clippy::expect_used)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::governance::{
    PermissionRule, RuleDecision, clear_active_permission_rules_for_test,
    set_active_permission_rules,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

async fn build_pg_router(url: &str) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    );
    let app_state = AppState {
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
        storage_backend: StorageBackend::Postgres,
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
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// Live-postgres twin of `http_capture_turn_respects_namespace_deny`.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn http_capture_turn_respects_namespace_deny() {
    let Some(url) = postgres_url() else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL unset — cannot run live-pg #3225 pin");
    };
    clear_active_permission_rules_for_test();
    set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: "secrets/*".to_string(),
        op: ai_memory::governance::Op::MemoryStore.as_str().to_string(),
        agent_pattern: "*".to_string(),
        decision: RuleDecision::Deny,
        reason: Some("no HTTP capture into secrets".to_string()),
    }]);

    let router = build_pg_router(&url).await;
    let ns = format!("secrets/ops-3225-{}", uuid::Uuid::new_v4());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/capture_turn")
        .header("content-type", "application/json")
        .header("x-agent-id", "alice")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "host_session_id": "sess-3225-pg",
                "host_turn_index": 0,
                "role": "user",
                "content": "secret operator directive",
                "namespace": ns
            }))
            .expect("body"),
        ))
        .expect("request");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    clear_active_permission_rules_for_test();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3225 pg: K9 Deny on capture_turn must be 403, got {status} {payload}"
    );
}
