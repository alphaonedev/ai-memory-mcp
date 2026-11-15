// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8655: HTTP registration checks the same URL authority as the client.
//! No receiver is contacted. Both persistence adapters must refuse before writing.
#![cfg(feature = "sal")]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{AppState, Db, SubscribeBody};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;

mod common;

const CALLER: &str = "authority-parity-8655";
const BODY_LIMIT: usize = 64 * 1024;

fn fixture() -> (AppState, NamedTempFile) {
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
        llm_call_timeout: std::time::Duration::from_secs(
            ai_memory::config::DEFAULT_LLM_CALL_TIMEOUT_SECS,
        ),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
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
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (app_state, f)
}

async fn registration_cells(app: &AppState) {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", HeaderValue::from_static(CALLER));
    let mut urls: Vec<String> = ["10.0.0.1", "127.0.0.1", "[fd00::1]", "[::1]"]
        .iter()
        .map(|host| format!("https://{host}{}@public.example/hook", char::from(92)))
        .collect();
    urls.push("https://public.example/hook".to_string());
    for (index, url) in urls.iter().enumerate() {
        let expected = if index == urls.len() - 1 {
            StatusCode::CREATED
        } else {
            StatusCode::BAD_REQUEST
        };
        let response = ai_memory::handlers::subscribe(
            State(app.clone()),
            headers.clone(),
            Json(SubscribeBody {
                url: Some(url.clone()),
                events: Some("*".into()),
                secret: Some("fixture-hmac-8655".into()),
                namespace_filter: None,
                agent_filter: None,
                namespace: None,
                agent_id: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .expect("body");
        assert_eq!(
            status, expected,
            "#8655: backend {:?}, cell {index}",
            app.storage_backend
        );
        if expected == StatusCode::BAD_REQUEST {
            let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON refusal");
            let error = body["error"].as_str().expect("refusal reason");
            assert!(
                error.contains("loopback") || error.contains("private"),
                "address-class refusal"
            );
        }
    }
}

#[tokio::test]
async fn sqlite_registration_parser_parity_8655() {
    ai_memory::config::set_allow_loopback_webhooks(false);
    let (app, _keep) = fixture();
    registration_cells(&app).await;
    let db = app.db.lock().await;
    let rows = ai_memory::subscriptions::list(&db.0, Some(CALLER)).expect("list subscriptions");
    assert_eq!(rows.len(), 1, "only the public control is persisted");
    assert_eq!(
        rows[0].url, "https://public.example/hook",
        "stored control target"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_registration_parser_parity_8655() {
    let Some(url) = common::postgres_url() else {
        eprintln!("live Postgres cell requires AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    ai_memory::config::set_allow_loopback_webhooks(false);
    let scratch = common::pg_barrier::ScratchDb::create(&url, "authority8655")
        .await
        .expect("isolated database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("live Postgres store");
    let (mut app, _keep) = fixture();
    app.storage_backend = ai_memory::handlers::StorageBackend::Postgres;
    app.store = Arc::new(store);
    registration_cells(&app).await;
    let caller = ai_memory::store::CallerContext::for_agent(CALLER);
    let mut filter = ai_memory::store::Filter::default();
    filter.namespace = Some(format!("_subscriptions/{CALLER}"));
    let rows = app
        .store
        .list(&caller, &filter)
        .await
        .expect("list live subscriptions");
    assert_eq!(rows.len(), 1, "only the public control is persisted");
    assert_eq!(
        rows[0].metadata["url"], "https://public.example/hook",
        "stored control target"
    );
}
