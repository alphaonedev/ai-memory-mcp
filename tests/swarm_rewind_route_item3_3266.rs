// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Boids predator plan item 3, part 2 (#3266 / #3922, 5-agent vote `4d3ea1c5`,
//! ruling Q1) — `POST /api/v1/memory_swarm_rewind`, the admin-gated route that
//! makes the rewind reachable on a Postgres daemon. RED on the parent: the
//! route is not registered (404/405).
//!
//! In-process router (the `agents_post_caller_binding_3398` fixture shape).
//! Pinned per the ruling: a non-admin is refused; the SQLite lane reaches the
//! funnel; the Postgres lane reaches `PostgresStore`; the signed `swarm.rewind`
//! event's issuer is the SERVER-resolved admin principal.
#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::EnrolledAgentKeys;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::MemoryStore;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const ADMIN: &str = "ai:rewind-route-admin";
const BOB: &str = "ai:rewind-route-bob";
const KEY: &str = "rewind-route-shared-key";
const ROUTE: &str = "/api/v1/memory_swarm_rewind";

fn mem(ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

fn app_state_for(db: Db, store: Arc<dyn MemoryStore>, storage_backend: StorageBackend) -> AppState {
    AppState {
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
        http_identity_mode: HttpIdentityMode::default(),
    }
}

fn router_from(app_state: AppState) -> axum::Router {
    // An AUTHENTICATED deployment (api_key configured), the #1570 posture in
    // which an allowlisted `X-Agent-Id` is admitted as admin.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let api_key_state = ApiKeyState {
        key: Some(KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(EnrolledAgentKeys::empty()),
        identity_mode: HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn sqlite_router() -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    (
        router_from(app_state_for(db, store, StorageBackend::Sqlite)),
        f,
    )
}

fn post(agent_id: Option<&str>, body: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(ROUTE)
        .header(ai_memory::HEADER_API_KEY, KEY)
        .header("content-type", "application/json");
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    b.body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("build request")
}

async fn call(router: &axum::Router, r: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(r).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// root <- child (`derives_from`) seeded straight into the SQLite file.
fn seed_sqlite(db_path: &std::path::Path) -> (Memory, Memory) {
    let conn = ai_memory::db::open(db_path).expect("open");
    let (root, child) = (mem("route/ns", "root"), mem("route/ns", "child"));
    ai_memory::db::insert(&conn, &root).expect("insert root");
    ai_memory::db::insert(&conn, &child).expect("insert child");
    ai_memory::db::create_link(&conn, &child.id, &root.id, "derives_from").expect("edge");
    (root, child)
}

#[tokio::test]
async fn sqlite_non_admin_is_refused_3266() {
    let (router, f) = sqlite_router();
    let (root, child) = seed_sqlite(f.path());
    let (status, _) = call(&router, post(Some(BOB), &json!({"to": root.id}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a non-admin must be refused");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let st: String = conn
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = ?1",
            [&child.id],
            |r| r.get(0),
        )
        .expect("state");
    assert_eq!(st, "open", "a refused caller writes nothing");
}

#[tokio::test]
async fn sqlite_missing_to_is_a_bad_request_3266() {
    let (router, _f) = sqlite_router();
    let (status, body) = call(&router, post(Some(ADMIN), &json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "missing `to`: {body}");
}

#[tokio::test]
async fn sqlite_admin_rewind_reaches_the_funnel_and_signs_as_the_admin_3266() {
    let (router, f) = sqlite_router();
    let (root, child) = seed_sqlite(f.path());
    let (status, body) = call(&router, post(Some(ADMIN), &json!({"to": root.id}))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin rewind (RED on the parent: route absent): {body}"
    );
    assert_eq!(body["root_contaminated"], json!(true), "{body}");
    assert_eq!(body["descendants_stamped"], json!(1), "{body}");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let st: String = conn
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = ?1",
            [&child.id],
            |r| r.get(0),
        )
        .expect("state");
    assert_eq!(st, "contaminated");
    let issuer: String = conn
        .query_row(
            "SELECT agent_id FROM signed_events WHERE event_type = ?1 ORDER BY rowid DESC LIMIT 1",
            [ai_memory::signed_events::event_types::SWARM_REWIND],
            |r| r.get(0),
        )
        .expect("swarm.rewind event");
    assert_eq!(
        issuer, ADMIN,
        "issued_by is the server-resolved admin principal"
    );
}

#[cfg(feature = "sal-postgres")]
async fn pg_router(url: &str) -> (axum::Router, ai_memory::store::postgres::PostgresStore) {
    let pg = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .expect("connect postgres");
    let handle = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .expect("second handle for assertions");
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    (
        router_from(app_state_for(db, store, StorageBackend::Postgres)),
        handle,
    )
}

#[cfg(feature = "sal-postgres")]
async fn seed_pg(pg: &ai_memory::store::postgres::PostgresStore) -> (Memory, Memory) {
    let ns = format!("route-{}", uuid::Uuid::new_v4().simple());
    let ctx = ai_memory::store::CallerContext::for_agent("ai:tester");
    let (root, child) = (mem(&ns, "root"), mem(&ns, "child"));
    pg.store(&ctx, &root).await.expect("seed root");
    pg.store(&ctx, &child).await.expect("seed child");
    let link = ai_memory::models::MemoryLink {
        source_id: child.id.clone(),
        target_id: root.id.clone(),
        relation: ai_memory::models::MemoryLinkRelation::DerivesFrom,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    pg.link(&ctx, &link).await.expect("edge");
    (root, child)
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_admin_rewind_reaches_postgres_store_and_signs_as_the_admin_3266() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return;
    };
    let (router, pg) = pg_router(&url).await;
    let (root, child) = seed_pg(&pg).await;
    let (status, body) = call(&router, post(Some(ADMIN), &json!({"to": root.id}))).await;
    assert_eq!(status, StatusCode::OK, "pg admin rewind (not 501): {body}");
    assert_eq!(body["descendants_stamped"], json!(1), "{body}");
    let (st,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(&child.id)
        .fetch_one(pg.pool())
        .await
        .expect("state");
    assert_eq!(st, "contaminated", "the route reached PostgresStore");
    let (issuer,): (String,) =
        sqlx::query_as("SELECT agent_id FROM signed_events WHERE event_type = $1 AND id = $2")
            .bind(ai_memory::signed_events::event_types::SWARM_REWIND)
            .bind(body["signed_event_id"].as_str().expect("event id"))
            .fetch_one(pg.pool())
            .await
            .expect("event");
    assert_eq!(
        issuer, ADMIN,
        "issued_by is the server-resolved admin principal"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_non_admin_is_refused_3266() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return;
    };
    let (router, pg) = pg_router(&url).await;
    let (root, child) = seed_pg(&pg).await;
    let (status, _) = call(&router, post(Some(BOB), &json!({"to": root.id}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (st,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(&child.id)
        .fetch_one(pg.pool())
        .await
        .expect("state");
    assert_eq!(st, "open", "a refused caller writes nothing");
}
