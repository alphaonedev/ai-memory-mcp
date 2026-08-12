// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1924 (CWE-288) — END-TO-END proof that the HTTP write surface now routes
//! through the #1885 pre-event mandatory-hook-presence ENFORCEMENT gate.
//!
//! Pre-#1924 the gate was installed + consulted ONLY on the MCP stdio path;
//! the HTTP write handlers (POST /api/v1/memories, delete/promote/link/
//! consolidate/reflect) are a SEPARATE implementation that never routed through
//! `handle_store`, so `[hooks].enforce_mode = enforce` + `required_events =
//! ["pre_store"]` with no configured hook printed the boot banner / `doctor
//! --hooks` "WILL DENY" while every HTTP-routed write committed with NO hook
//! running — a total silent bypass on the network-facing surface.
//!
//! This test drives the REAL `create_memory` handler through the composed
//! router: it POSTs once with the gate NOT installed (write succeeds), then
//! installs the process gate in `enforce` mode with a required `pre_store`
//! event and NO configured hook, and POSTs again — the write is now DENIED with
//! HTTP 503. Isolated in its own integration-test binary because the gate is a
//! process-global `OnceLock` (first-writer-wins, non-resettable).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::hooks::{HookEnforceMode, HookEvent};

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn build_test_router() -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post_memories(router: &axum::Router, body: &Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn http_memory_store_denied_503_under_enforce_with_no_pre_store_hook() {
    let (router, _f) = build_test_router();
    let body = json!({
        "title": "gate probe",
        "content": "written via the HTTP create path",
        "namespace": "default",
    });

    // FAIL-BEFORE: gate not installed → the HTTP write is accepted.
    let before = post_memories(&router, &body).await;
    assert!(
        before.is_success(),
        "with no enforcement gate installed the HTTP write must succeed, got {before}"
    );

    // Install the process gate: enforce mode, `pre_store` REQUIRED, NO hooks.
    // This is the exact posture the boot banner / `doctor --hooks` advertise as
    // "WILL DENY".
    ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
        Vec::new(),
        HookEnforceMode::Enforce,
        vec![HookEvent::PreStore],
    );

    // PASS-AFTER: the SAME POST is now DENIED with 503 — the enforcement gate
    // fires on the HTTP write surface, closing the #1924 bypass.
    let after = post_memories(&router, &body).await;
    assert_eq!(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTP POST /api/v1/memories under enforce + required pre_store + no hook \
         must be DENIED with 503 (#1924), got {after}"
    );
}
