// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3638: a tenant may trigger policy enforcement, but may not read its private values.
#![cfg(feature = "sal")]

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const SHARED_KEY: &str = "issue-3638-transport-key";
const ATTACKER: &str = "ai:attacker";
const VICTIM: &str = "ai:victim";

fn build_router(
    backend: ai_memory::handlers::StorageBackend,
    supplied_store: Option<Arc<dyn MemoryStore>>,
    supplied_path: Option<&std::path::Path>,
) -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = supplied_path.unwrap_or(f.path()).to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = supplied_store.unwrap_or_else(|| {
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"))
    });
    let enrolled = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());

    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
        // Deliberately NOT alice/bob: an admin carve-out would mask the owner
        // gate this test is asserting.
        admin_agent_ids: Arc::new(vec!["ai:operator".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Advisory,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

fn req(method: &str, uri: &str, agent_id: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", SHARED_KEY);
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(v).expect("serialise body")))
            .expect("build request"),
        None => b.body(Body::empty()).expect("build request"),
    }
}

async fn call(router: &axum::Router, r: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(r).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn memory(owner: &str, namespace: &str, title: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        namespace: namespace.into(),
        title: title.into(),
        content: "issue 3638 regression".into(),
        metadata: json!({"agent_id": owner, "scope": "private"}),
        ..Memory::default()
    }
}

async fn exercise_private_policy_3638(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    sqlite_path: Option<&std::path::Path>,
) {
    let attacker = CallerContext::for_agent(ATTACKER);
    let victim = CallerContext::for_agent(VICTIM);
    let source = memory(ATTACKER, "attacker/sources", "readable source");
    store.store(&attacker, &source).await.expect("source");
    let mut standard = memory(VICTIM, "victim/standards", "private standard");
    let mut policy = ai_memory::models::GovernancePolicy::default();
    policy.core.max_reflection_depth = Some(0);
    standard.metadata["governance"] =
        serde_json::to_value(policy).expect("serialize complete policy");
    store.store(&victim, &standard).await.expect("standard");
    store
        .set_namespace_standard(&victim, "victim/private", &standard.id, None)
        .await
        .expect("bind standard");
    assert!(
        store.get(&attacker, &standard.id).await.is_err(),
        "private standard must remain unreadable"
    );
    assert!(store.get(&attacker, &source.id).await.is_ok());
    assert_eq!(
        store
            .resolve_governance_policy("victim/private")
            .await
            .expect("policy")
            .expect("bound policy")
            .effective_max_reflection_depth(),
        0
    );
    let (router, _file) = build_router(backend, Some(Arc::clone(&store)), sqlite_path);
    let (status, response) = call(&router, req("POST", "/api/v1/memory_reflect", Some(ATTACKER), Some(&json!({
        "source_ids": [source.id], "title": "probe", "content": "probe", "namespace": "victim/private"
    })))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        response["error"], "REFLECTION_DEPTH_EXCEEDED: reflection depth limit exceeded",
        "{response}"
    );
    assert!(!response.to_string().contains("victim/private"));
    assert!(!response.to_string().contains("max_reflection_depth"));
    assert!(
        store.get(&victim, &standard.id).await.is_ok(),
        "refusal must not mutate standard"
    );
}

#[tokio::test]
async fn issue_3638_sqlite_tenant_cannot_read_private_depth_cap() {
    let file = NamedTempFile::new().expect("sqlite file");
    let store = Arc::new(ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("sqlite"));
    exercise_private_policy_3638(store, StorageBackend::Sqlite, Some(file.path())).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_3638_postgres_tenant_cannot_read_private_depth_cap() {
    // Required: this regression must never report success without a live database.
    let url =
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("set fresh issue 3638 database URL");
    let store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("postgres"),
    );
    exercise_private_policy_3638(store, StorageBackend::Postgres, None).await;
}

#[tokio::test]
async fn issue_3638_sqlite_pending_response_hides_private_threshold() {
    let file = NamedTempFile::new().expect("sqlite file");
    let store = Arc::new(ai_memory::store::sqlite::SqliteStore::open(file.path()).expect("sqlite"));
    let attacker = CallerContext::for_agent(ATTACKER);
    let victim = CallerContext::for_agent(VICTIM);
    let source = memory(ATTACKER, "attacker/sources", "approval source");
    store.store(&attacker, &source).await.expect("source");
    let mut standard = memory(VICTIM, "victim/standards", "approval standard");
    standard.metadata["governance"] = json!({"require_approval_above_depth": 0});
    store.store(&victim, &standard).await.expect("standard");
    store
        .set_namespace_standard(&victim, "victim/private", &standard.id, None)
        .await
        .expect("bind standard");
    assert!(store.get(&attacker, &standard.id).await.is_err());
    let (router, _file) = build_router(StorageBackend::Sqlite, Some(store), Some(file.path()));
    let (status, response) = call(&router, req("POST", "/api/v1/memory_reflect", Some(ATTACKER), Some(&json!({
        "source_ids": [source.id], "title": "probe", "content": "probe", "namespace": "victim/private"
    })))).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["status"], "pending", "{response}");
    assert!(response["pending_id"].is_string(), "{response}");
    assert!(
        response.get("require_approval_above_depth").is_none(),
        "{response}"
    );
}
