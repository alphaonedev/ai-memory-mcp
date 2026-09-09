// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3381: the production HTTP auto-tag route enforces caller and substrate
//! visibility on SQLite and live PostgreSQL before any model request.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(feature = "sal-postgres")]
mod common;

const OWNER_AGENT: &str = "ai:auto-tag-owner-3381";
const OTHER_AGENT: &str = "ai:auto-tag-other-3381";

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
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
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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

/// The SAL handle, present only under `feature = "sal"`. Wrapping it in a
/// newtype keeps `app_state_with`'s signature identical across feature legs
/// (the default-feature build has no `MemoryStore` trait at all).
#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

/// Build a sqlite-backed `AppState` over a real on-disk DB. Under `sal` the
/// `SqliteStore` is opened against the SAME file as `app.db`, so both views
/// see the same rows (exactly what `bootstrap_serve` does).
fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

/// Build a postgres-backed `AppState`. `app.db` is a throwaway in-memory
/// sqlite — deliberately EMPTY, so any handler that reads it instead of
/// `app.store` returns nothing and the test fails loudly.
#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn memory(namespace: &str, scope: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        title: uuid::Uuid::new_v4().to_string(),
        content: "private test content".to_string(),
        tier: Tier::Mid,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": OWNER_AGENT, "scope": scope, "why_trace": "#3381 visibility regression fixture"}),
        tags: vec!["keep".to_string()],
        version: 1,
        ..Memory::default()
    }
}

async fn seed(app: &AppState, memory: &Memory) -> String {
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let caller = ai_memory::store::CallerContext::for_agent(OWNER_AGENT);
        return app
            .store
            .store(&caller, memory)
            .await
            .expect("seed PostgreSQL row");
    }
    let lock = app.db.lock().await;
    ai_memory::db::insert(&lock.0, memory).expect("seed SQLite row")
}

async fn stored(app: &AppState, id: &str) -> Memory {
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let caller = ai_memory::store::CallerContext::for_agent(OWNER_AGENT);
        return app
            .store
            .get(&caller, id)
            .await
            .expect("read PostgreSQL row");
    }
    let lock = app.db.lock().await;
    ai_memory::db::get(&lock.0, id).unwrap().unwrap()
}

async fn request(router: &axum::Router, id: &str, caller: Option<&str>) -> (StatusCode, Value) {
    request_with_key(router, id, caller, None).await
}

async fn request_with_key(
    router: &axum::Router,
    id: &str,
    caller: Option<&str>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/auto_tag")
        .header("content-type", "application/json");
    if let Some(caller) = caller {
        request = request.header("x-agent-id", caller);
    }
    if let Some(key) = key {
        request = request.header("x-api-key", key);
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(json!({"memory_id": id}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn check_visibility(mut app: AppState) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha\nbeta"}
        })))
        .mount(&server)
        .await;
    let llm =
        ai_memory::llm::OllamaClient::new_for_tests_without_probe(&server.uri(), "test-model")
            .unwrap();
    app.llm = Arc::new(ai_memory::reload::SwappableLlm::new(Some(llm)));
    let ordinary = seed(&app, &memory("autotag-3381", "private")).await;
    let substrate = seed(&app, &memory("_agents", "collective")).await;
    let collective = seed(&app, &memory("autotag-3381", "collective")).await;
    let before = stored(&app, &ordinary).await;
    let router = ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: app.enrolled_agent_keys.clone(),
            identity_mode: app.http_identity_mode,
        },
        app.clone(),
    );
    for (id, caller) in [
        (ordinary.as_str(), Some(OTHER_AGENT)),
        (ordinary.as_str(), None),
        (substrate.as_str(), Some(OWNER_AGENT)),
        (substrate.as_str(), Some(OTHER_AGENT)),
        (substrate.as_str(), None),
    ] {
        let (status, body) = request(&router, id, caller).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            body.get("tags").is_none(),
            "refusal must not return generated tags"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "denied reads must not egress"
    );
    for (id, caller) in [(&ordinary, OWNER_AGENT), (&collective, OTHER_AGENT)] {
        let (status, body) = request(&router, id, Some(caller)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tags"], json!(["alpha", "beta"]));
        assert_eq!(body["memory_id"], *id);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    let after = stored(&app, &ordinary).await;
    assert_eq!(
        after.tags, before.tags,
        "HTTP generates tags without persisting"
    );
    assert_eq!(after.version, before.version);
    let key = "auto-tag-3381-owner-test-key";
    let enrolled = Arc::new(
        ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(
            std::collections::HashMap::from([(
                ai_memory::handlers::identity_binding::api_key_sha256_hex(key),
                OWNER_AGENT.to_string(),
            )]),
        ),
    );
    app.enrolled_agent_keys = enrolled.clone();
    app.http_identity_mode = ai_memory::config::HttpIdentityMode::Enforce;
    let router = ai_memory::build_router(
        ApiKeyState {
            key: Some("auto-tag-3381-transport-test-key".to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: app.http_identity_mode,
        },
        app,
    );
    let (status, body) = request_with_key(
        &router,
        &ordinary,
        Some(OWNER_AGENT),
        Some("auto-tag-3381-transport-test-key"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "claimed identity must fail: {body}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    let (status, body) = request_with_key(&router, &ordinary, Some(OWNER_AGENT), Some(key)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key-bound owner must succeed: {body}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn sqlite_auto_tag_visibility_3381() {
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check_visibility(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_auto_tag_visibility_3381() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    check_visibility(postgres_app_state(&url).await).await;
}
