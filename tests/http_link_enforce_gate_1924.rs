// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1924 (CWE-288) — cover BOTH branches of the HTTP link handler's pre-event
//! enforcement-gate consult (`create_link` → `http_pre_event_gate(PreLink)`):
//! the allow path (no gate installed → the request proceeds past the consult)
//! and the deny path (`enforce_mode=enforce` + required `pre_link` + no hook →
//! the write is refused with 503 before any link is created). Isolated in its
//! own integration-test binary because the enforcement gate is a process-global
//! `OnceLock` (first-writer-wins, non-resettable).

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
        atomise_queue: None,
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

async fn post(router: &axum::Router, uri: &str, body: &Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn http_link_denied_503_under_enforce_with_no_pre_link_hook() {
    let (router, _f) = build_test_router();

    // Create two memories so a link request is otherwise well-formed.
    let a = post(
        &router,
        "/api/v1/memories",
        &json!({"title": "A", "content": "a", "namespace": "default"}),
    )
    .await;
    assert!(a.is_success(), "seed memory A must be created, got {a}");
    let b = post(
        &router,
        "/api/v1/memories",
        &json!({"title": "B", "content": "b", "namespace": "default"}),
    )
    .await;
    assert!(b.is_success(), "seed memory B must be created, got {b}");

    let link_body = json!({
        "source_id": "A",
        "target_id": "B",
        "relation": "related_to",
    });

    // ALLOW branch: gate not installed → the consult returns `Ok`, the handler
    // proceeds PAST the gate (it may then 200/400/404 on link specifics, but it
    // is NOT the gate's 503).
    let before = post(&router, "/api/v1/links", &link_body).await;
    assert_ne!(
        before,
        StatusCode::SERVICE_UNAVAILABLE,
        "with no enforcement gate the link consult must not deny; got {before}"
    );

    // Install the process gate: enforce, `pre_link` REQUIRED, NO hooks.
    ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
        Vec::new(),
        HookEnforceMode::Enforce,
        vec![HookEvent::PreLink],
    );

    // DENY branch: the SAME link request is now refused with 503 BEFORE any link
    // is created — the #1924 gate fires on the HTTP link write surface.
    let after = post(&router, "/api/v1/links", &link_body).await;
    assert_eq!(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "POST /api/v1/links under enforce + required pre_link + no hook must be \
         DENIED with 503 (#1924), got {after}"
    );
}
