// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3383 — existing HTTP purge/GC authorization on both dispatched backends.

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

#[cfg(feature = "sal-postgres")]
mod common;

const OWNER_AGENT: &str = "ai:archive-owner-3383";
const OTHER_AGENT: &str = "ai:archive-other-3383";

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

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some("archive-test-key-3383".into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app,
    )
}

async fn request(
    router: &axum::Router,
    method: &str,
    uri: &str,
    caller: &str,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("x-api-key", "archive-test-key-3383")
                .header("x-agent-id", caller)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn seed(app: &AppState) {
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "http-archive-gc-3383".into(),
        title: uuid::Uuid::new_v4().to_string(),
        content: "expired owner fixture".into(),
        tier: Tier::Short,
        created_at: now.clone(),
        updated_at: now,
        expires_at: Some("2000-01-01T00:00:00+00:00".into()),
        metadata: json!({"agent_id": OWNER_AGENT, "scope":"private"}),
        ..Memory::default()
    };
    #[cfg(feature = "sal-postgres")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let caller = ai_memory::store::CallerContext::for_agent(OWNER_AGENT);
        app.store
            .store(&caller, &memory)
            .await
            .expect("seed pg expired row");
        return;
    }
    let lock = app.db.lock().await;
    ai_memory::db::insert(&lock.0, &memory).expect("seed sqlite expired row");
}

async fn check(mut app: AppState) {
    seed(&app).await;
    let closed = router(app.clone());
    assert_eq!(
        request(&closed, "POST", "/api/v1/gc", "ai:root").await.0,
        StatusCode::FORBIDDEN
    );
    app.admin_agent_ids = Arc::new(vec!["ai:root".into()]);
    let router = router(app);
    assert_eq!(
        request(&router, "POST", "/api/v1/gc", OTHER_AGENT).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = request(&router, "POST", "/api/v1/gc", "ai:root").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["expired_deleted"].as_u64().unwrap() >= 1,
        "refused calls must preserve the expired row: {body}"
    );
    let (status, body) = request(&router, "DELETE", "/api/v1/archive", OTHER_AGENT).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["purged"], 0, "non-owner cannot purge the archive");
    let (status, body) = request(&closed, "DELETE", "/api/v1/archive", "ai:root").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["purged"], 0, "empty allowlist cannot escalate");
    let (status, body) = request(&router, "DELETE", "/api/v1/archive", "ai:root").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["purged"].as_u64().unwrap() >= 1, "admin purge: {body}");
}

#[tokio::test]
async fn sqlite_http_purge_gc_authorization_3383() {
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    check(sqlite_app_state(&dir.path().join("memories.db"))).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_http_purge_gc_authorization_3383() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    check(postgres_app_state(&url).await).await;
}
