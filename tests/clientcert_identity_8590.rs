// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8590: an active certificate binding must reach the legacy identity gate.
//! The unrelated enrolled key deliberately arms enforce mode. Neither the
//! shared transport key nor a claimed header proves the certificate's agent.

#![cfg(feature = "sal")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::mtls_agent_binding::{AgentBindingMode, ClientCertAgentBinding};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt as _;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

const SHARED_KEY: &str = "shared-transport-8590";
const ENROLLED_KEY: &str = "unrelated-agent-key-8590";
const ENROLLED_AGENT: &str = "ai:enrolled-8590";
const CERT_AGENT: &str = "ai:certificate-8590";
const OTHER_AGENT: &str = "ai:other-8590";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MISSING_MEMORY: &str = "/api/v1/memories/85908590-8590-4590-8590-859085908590";
const ADMIN_ROUTE: &str = "/api/v1/gc";

fn build_enforce_router() -> (axum::Router, TempDir) {
    build_router_with_store(None)
}

fn build_router_with_store(
    postgres: Option<Arc<dyn ai_memory::store::MemoryStore>>,
) -> (axum::Router, TempDir) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let root = PathBuf::from(".local-runs").join("identity-8590");
    std::fs::create_dir_all(&root).expect("scratch root");
    let dir = tempfile::tempdir_in(root).expect("scratch directory");
    let db_path = dir.path().join("memory.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let (store, storage_backend): (Arc<dyn ai_memory::store::MemoryStore>, _) = match postgres {
        Some(store) => (store, ai_memory::handlers::StorageBackend::Postgres),
        None => (
            Arc::new(
                ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
            ),
            ai_memory::handlers::StorageBackend::Sqlite,
        ),
    };

    let mut enrolled = HashMap::new();
    enrolled.insert(api_key_sha256_hex(ENROLLED_KEY), ENROLLED_AGENT.to_string());
    // v1.0.0 #3418 — the enrolled set is a LIVE registry, not a bare map.
    let enrolled =
        Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(enrolled));

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
        storage_backend,
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
        admin_agent_ids: Arc::new(vec![ENROLLED_AGENT.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Enforce,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: true,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Enforce,
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, dir)
}

fn request(path: &str, caller: &str, binding: Option<ClientCertAgentBinding>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", caller)
        .body(Body::empty())
        .expect("request");
    if let Some(binding) = binding {
        request.extensions_mut().insert(binding);
    }
    request
}

async fn check(router: axum::Router, request: Request<Body>, expected: StatusCode) {
    let response = router.oneshot(request).await.expect("router response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("response body");
    assert_eq!(
        status,
        expected,
        "response: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn mapped_certificate_shared_key_reaches_idor_route_8590() {
    let (router, _dir) = build_enforce_router();
    for (path, status) in [
        // An absent object must reach the ownership/store lookup and return
        // 404, rather than being refused by enforce_idor_identity with 403.
        (MISSING_MEMORY, StatusCode::NOT_FOUND),
        ("/api/v1/memories", StatusCode::OK),
    ] {
        let binding =
            ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), AgentBindingMode::Enforce);
        check(
            router.clone(),
            request(path, CERT_AGENT, Some(binding)),
            status,
        )
        .await;
    }
}

#[tokio::test]
async fn certificate_a_cannot_claim_agent_b_8590() {
    let (router, _dir) = build_enforce_router();
    let binding =
        ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), AgentBindingMode::Enforce);
    let response = router
        .oneshot(request(MISSING_MEMORY, OTHER_AGENT, Some(binding)))
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("response body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(
        json["code"],
        ai_memory::mtls_agent_binding::AGENT_ID_CERTIFICATE_MISMATCH
    );
}

#[tokio::test]
async fn missing_off_and_unmapped_bindings_do_not_elevate_8590() {
    let (router, _dir) = build_enforce_router();
    for binding in [
        None,
        Some(ClientCertAgentBinding::new(
            Some(CERT_AGENT.to_string()),
            AgentBindingMode::Off,
        )),
        Some(ClientCertAgentBinding::new(None, AgentBindingMode::Enforce)),
    ] {
        check(
            router.clone(),
            request(MISSING_MEMORY, CERT_AGENT, binding),
            StatusCode::FORBIDDEN,
        )
        .await;
    }
}

#[tokio::test]
async fn certificate_context_is_request_local_8590() {
    let (router, _dir) = build_enforce_router();
    let binding =
        ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), AgentBindingMode::Enforce);
    tokio::join!(
        check(
            router.clone(),
            request(MISSING_MEMORY, CERT_AGENT, Some(binding)),
            StatusCode::NOT_FOUND
        ),
        check(
            router.clone(),
            request(MISSING_MEMORY, CERT_AGENT, None),
            StatusCode::FORBIDDEN
        ),
    );
    check(
        router,
        request(MISSING_MEMORY, CERT_AGENT, None),
        StatusCode::FORBIDDEN,
    )
    .await;
}

#[tokio::test]
async fn resolver_requires_exact_caller_and_preserves_key_fallback_8590() {
    use ai_memory::handlers::identity_binding::{
        AuthLevel, EnrolledAgentKeys, IdentityHeaders, resolve_auth_level,
    };
    use axum::extract::FromRequestParts as _;
    let enrolled = EnrolledAgentKeys::from_map(HashMap::from([(
        api_key_sha256_hex(ENROLLED_KEY),
        ENROLLED_AGENT.to_string(),
    )]));
    let binding =
        ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), AgentBindingMode::Enforce);
    let (mut parts, _) = request(MISSING_MEMORY, CERT_AGENT, Some(binding)).into_parts();
    let headers = IdentityHeaders::from_request_parts(&mut parts, &())
        .await
        .expect("extract headers");
    assert_eq!(
        resolve_auth_level(&enrolled, &headers, CERT_AGENT),
        AuthLevel::KeyAuthenticated
    );
    assert_eq!(
        resolve_auth_level(&enrolled, &headers, OTHER_AGENT),
        AuthLevel::Claimed
    );
    // A wire-only copy carries no certificate proof, even with identical headers.
    let mut wire_only = IdentityHeaders::from(parts.headers);
    assert_eq!(
        resolve_auth_level(&enrolled, &wire_only, CERT_AGENT),
        AuthLevel::Claimed
    );
    wire_only.insert("x-api-key", ENROLLED_KEY.parse().expect("key header"));
    assert_eq!(
        resolve_auth_level(&enrolled, &wire_only, ENROLLED_AGENT),
        AuthLevel::KeyAuthenticated
    );
    assert_eq!(
        resolve_auth_level(&enrolled, &wire_only, CERT_AGENT),
        AuthLevel::Claimed
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_certificate_gate_parity_8590() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("SKIP postgres_certificate_gate_parity_8590: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let scratch = pg_barrier::ScratchDb::create(&url, "ai_memory_8590")
        .await
        .expect("scratch database");
    let store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
            .await
            .expect("PostgresStore"),
    );
    let (router, _dir) = build_router_with_store(Some(store.clone()));
    let binding =
        || ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), AgentBindingMode::Enforce);
    check(
        router.clone(),
        request(MISSING_MEMORY, CERT_AGENT, Some(binding())),
        StatusCode::NOT_FOUND,
    )
    .await;
    check(
        router.clone(),
        request("/api/v1/memories", CERT_AGENT, Some(binding())),
        StatusCode::OK,
    )
    .await;
    check(
        router.clone(),
        request(MISSING_MEMORY, OTHER_AGENT, Some(binding())),
        StatusCode::FORBIDDEN,
    )
    .await;
    for context in [
        None,
        Some(ClientCertAgentBinding::new(
            Some(CERT_AGENT.to_string()),
            AgentBindingMode::Off,
        )),
        Some(ClientCertAgentBinding::new(None, AgentBindingMode::Enforce)),
    ] {
        check(
            router.clone(),
            request(MISSING_MEMORY, CERT_AGENT, context),
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    check_certificate_admin(router.clone()).await;
    check_warn_rewrite(router.clone()).await;
    check_mixed_credentials(router.clone()).await;
    drop(router);
    drop(store);
    drop(scratch);
}

async fn check_certificate_admin(router: axum::Router) {
    for (agent, expected) in [
        (ENROLLED_AGENT, StatusCode::OK),
        (CERT_AGENT, StatusCode::FORBIDDEN),
    ] {
        let binding =
            ClientCertAgentBinding::new(Some(agent.to_string()), AgentBindingMode::Enforce);
        let mut req = request(ADMIN_ROUTE, agent, Some(binding));
        *req.method_mut() = axum::http::Method::POST;
        check(router.clone(), req, expected).await;
    }
}

#[tokio::test]
async fn certificate_admin_requires_allowlist_8590() {
    let (router, _dir) = build_enforce_router();
    check_certificate_admin(router).await;
}

async fn assert_certificate_principal(req: Request<Body>) {
    use ai_memory::handlers::identity_binding::{
        AuthLevel, EnrolledAgentKeys, IdentityHeaders, resolve_auth_level,
    };
    use axum::extract::FromRequestParts as _;
    let (mut parts, _) = req.into_parts();
    assert_eq!(parts.headers[ai_memory::HEADER_AGENT_ID], CERT_AGENT);
    let headers = IdentityHeaders::from_request_parts(&mut parts, &())
        .await
        .expect("extract rewritten certificate headers");
    let enrolled = EnrolledAgentKeys::from_map(HashMap::from([(
        api_key_sha256_hex(ENROLLED_KEY),
        ENROLLED_AGENT.to_string(),
    )]));
    assert_eq!(
        resolve_auth_level(&enrolled, &headers, CERT_AGENT),
        AuthLevel::KeyAuthenticated
    );
}

async fn check_warn_rewrite(router: axum::Router) {
    let make_request = || {
        request(
            MISSING_MEMORY,
            OTHER_AGENT,
            Some(ClientCertAgentBinding::new(
                Some(CERT_AGENT.to_string()),
                AgentBindingMode::Warn,
            )),
        )
    };
    let mut req = make_request();
    ai_memory::mtls_agent_binding::bind_request(&mut req).expect("warn rewrites the claim");
    assert_certificate_principal(req).await;
    check(router, make_request(), StatusCode::NOT_FOUND).await;
}

#[tokio::test]
async fn warn_rewrites_claim_and_reaches_key_authenticated_8590() {
    let (router, _dir) = build_enforce_router();
    check_warn_rewrite(router).await;
}

async fn check_mixed_credentials(router: axum::Router) {
    let make_request = |mode| {
        let binding = ClientCertAgentBinding::new(Some(CERT_AGENT.to_string()), mode);
        // The claim already matches the certificate: only key reconciliation
        // can reject this request, rather than the earlier claim check.
        let mut req = request(MISSING_MEMORY, CERT_AGENT, Some(binding));
        req.headers_mut()
            .insert("x-api-key", ENROLLED_KEY.parse().expect("key header"));
        req
    };
    let response = router
        .clone()
        .oneshot(make_request(AgentBindingMode::Enforce))
        .await
        .expect("mixed-credential response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .expect("refusal body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("refusal JSON");
    assert_eq!(
        json["code"],
        ai_memory::mtls_agent_binding::AGENT_ID_CERTIFICATE_MISMATCH
    );

    let mut req = make_request(AgentBindingMode::Warn);
    ai_memory::mtls_agent_binding::bind_request(&mut req).expect("bind certificate");
    assert!(
        ai_memory::mtls_agent_binding::reconcile_per_agent_key(&req, ENROLLED_AGENT)
            .expect("warn keeps certificate principal")
    );
    assert_certificate_principal(req).await;
    check(
        router.clone(),
        make_request(AgentBindingMode::Warn),
        StatusCode::NOT_FOUND,
    )
    .await;
    // The other agent's admin key cannot promote the certificate's principal.
    let mut req = make_request(AgentBindingMode::Warn);
    *req.uri_mut() = ADMIN_ROUTE.parse().expect("admin URI");
    *req.method_mut() = axum::http::Method::POST;
    check(router, req, StatusCode::FORBIDDEN).await;
}

#[tokio::test]
async fn conflicting_certificate_and_key_enforce_refuses_warn_preserves_certificate_8590() {
    let (router, _dir) = build_enforce_router();
    check_mixed_credentials(router).await;
}
