// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3348 — HTTP parity for ambient substrate-namespace suppression.
//!
//! The router advertises `StorageBackend::Postgres` while its SAL handle is a
//! real `SqliteStore`. That established fake-PG pattern drives the production
//! Postgres-dispatch branches without an external service and, importantly,
//! returns rows that the HTTP layer must post-filter using the request's exact
//! namespace.

#![cfg(feature = "sal")]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const NEEDLE: &str = "http3348uniquepayload";
const CALLER: &str = "ai:me";
const OWN_INBOX: &str = "_messages/ai:me";
const OTHER_INBOX: &str = "_messages/ai:other";

struct Fixture {
    router: axum::Router,
    _file: NamedTempFile,
    ordinary: String,
    own_inbox: String,
    other_inbox: String,
    registry: String,
}

fn insert(conn: &rusqlite::Connection, namespace: &str, metadata: Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("#3348 {namespace}"),
        content: format!("{NEEDLE} in {namespace}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Memory::default()
    };
    let id = memory.id.clone();
    ai_memory::db::insert(conn, &memory).expect("seed #3348 HTTP row");
    id
}

fn fixture(storage_backend: StorageBackend) -> Fixture {
    let file = NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&path).expect("open DB");
    let ordinary = insert(
        &conn,
        "operator-memory",
        json!({"agent_id": CALLER, "scope": "private"}),
    );
    let own_inbox = insert(
        &conn,
        OWN_INBOX,
        json!({
            "agent_id": "ai:sender",
            "target_agent_id": CALLER,
            "scope": "private"
        }),
    );
    let other_inbox = insert(
        &conn,
        OTHER_INBOX,
        json!({
            "agent_id": "ai:sender",
            "target_agent_id": "ai:other",
            "scope": "private"
        }),
    );
    // Deliberately collective: ordinary scope visibility alone admits this row.
    let registry = insert(
        &conn,
        "_agents",
        json!({"agent_id": "ai:registry", "scope": "collective"}),
    );

    let db: Db = Arc::new(Mutex::new((
        conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SAL fake-PG store"),
    );
    let state = AppState {
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
    };
    let api_keys = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    Fixture {
        router: ai_memory::build_router(api_keys, state),
        _file: file,
        ordinary,
        own_inbox,
        other_inbox,
        registry,
    }
}

async fn get(router: &axum::Router, uri: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .body(Body::empty())
                .expect("GET request"),
        )
        .await
        .expect("GET response");
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("GET body");
    serde_json::from_slice(&bytes).expect("GET JSON")
}

async fn post_recall(router: &axum::Router, namespace: Option<&str>) -> Value {
    let mut body = json!({"context": NEEDLE, "limit": 50});
    if let Some(namespace) = namespace {
        body["namespace"] = json!(namespace);
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/recall")
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("recall body")))
                .expect("POST request"),
        )
        .await
        .expect("POST response");
    assert_eq!(response.status(), StatusCode::OK, "POST recall");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("POST body");
    serde_json::from_slice(&bytes).expect("POST JSON")
}

fn ids(response: &Value, key: &str) -> Vec<String> {
    response[key]
        .as_array()
        .expect("response row array")
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_string))
        .collect()
}

fn assert_ambient(ids: &[String], fixture: &Fixture, surface: &str) {
    assert!(
        ids.contains(&fixture.ordinary),
        "{surface}: ordinary caller-owned memory must remain readable; got {ids:?}"
    );
    for (label, id) in [
        ("own inbox", &fixture.own_inbox),
        ("other inbox", &fixture.other_inbox),
        ("collective registry", &fixture.registry),
    ] {
        assert!(
            !ids.contains(id),
            "{surface}: ambient read exposed {label}; got {ids:?}"
        );
    }
}

async fn assert_http_read_funnels_share_system_namespace_rule(fixture: &Fixture) {
    let list = get(&fixture.router, "/api/v1/memories?limit=50").await;
    assert_ambient(&ids(&list, "memories"), fixture, "list");

    let search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&limit=50"),
    )
    .await;
    assert_ambient(&ids(&search, "results"), fixture, "search");

    let recall_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&limit=50"),
    )
    .await;
    assert_ambient(&ids(&recall_get, "memories"), fixture, "GET recall");

    let recall_post = post_recall(&fixture.router, None).await;
    assert_ambient(&ids(&recall_post, "memories"), fixture, "POST recall");

    // Explicit namespace is the opt-in, but it never lifts owner/inbox
    // confinement. Drive every list/search/recall branch in both postures.
    let own_list = get(
        &fixture.router,
        "/api/v1/memories?namespace=_messages%2Fai%3Ame&limit=50",
    )
    .await;
    assert!(ids(&own_list, "memories").contains(&fixture.own_inbox));

    let own_search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&namespace=_messages%2Fai%3Ame&limit=50"),
    )
    .await;
    assert!(ids(&own_search, "results").contains(&fixture.own_inbox));

    let own_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&namespace=_messages%2Fai%3Ame&limit=50"),
    )
    .await;
    assert!(ids(&own_get, "memories").contains(&fixture.own_inbox));
    let own_post = post_recall(&fixture.router, Some(OWN_INBOX)).await;
    assert!(ids(&own_post, "memories").contains(&fixture.own_inbox));

    let other_list = get(
        &fixture.router,
        "/api/v1/memories?namespace=_messages%2Fai%3Aother&limit=50",
    )
    .await;
    assert!(!ids(&other_list, "memories").contains(&fixture.other_inbox));
    let other_search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&namespace=_messages%2Fai%3Aother&limit=50"),
    )
    .await;
    assert!(!ids(&other_search, "results").contains(&fixture.other_inbox));
    let other_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&namespace=_messages%2Fai%3Aother&limit=50"),
    )
    .await;
    assert!(!ids(&other_get, "memories").contains(&fixture.other_inbox));
    let other_post = post_recall(&fixture.router, Some(OTHER_INBOX)).await;
    assert!(!ids(&other_post, "memories").contains(&fixture.other_inbox));
}

#[tokio::test]
async fn fake_pg_http_read_funnels_share_system_namespace_rule_3348() {
    let fixture = fixture(StorageBackend::Postgres);
    assert_http_read_funnels_share_system_namespace_rule(&fixture).await;
}

#[tokio::test]
async fn direct_sqlite_http_read_funnels_share_system_namespace_rule_3348() {
    let fixture = fixture(StorageBackend::Sqlite);
    assert_http_read_funnels_share_system_namespace_rule(&fixture).await;
}
