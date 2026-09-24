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
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
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
/// #2044 per-agent api key enrolled for ADMIN (the `enforce` cells).
const ADMIN_KEY: &str = "rewind-route-admin-per-agent-key";
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
    app_state_with(
        db,
        store,
        storage_backend,
        HttpIdentityMode::default(),
        Arc::new(EnrolledAgentKeys::empty()),
    )
}

fn app_state_with(
    db: Db,
    store: Arc<dyn MemoryStore>,
    storage_backend: StorageBackend,
    mode: HttpIdentityMode,
    enrolled: Arc<EnrolledAgentKeys>,
) -> AppState {
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
        enrolled_agent_keys: enrolled,
        http_identity_mode: mode,
    }
}

fn router_from(app_state: AppState) -> axum::Router {
    let (mode, enrolled) = (
        app_state.http_identity_mode,
        Arc::clone(&app_state.enrolled_agent_keys),
    );
    // An AUTHENTICATED deployment (api_key configured), the #1570 posture in
    // which an allowlisted `X-Agent-Id` is admitted as admin.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let api_key_state = ApiKeyState {
        key: Some(KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
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
    post_with_key(KEY, agent_id, body)
}

fn post_with_key(api_key: &str, agent_id: Option<&str>, body: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(ROUTE)
        .header(ai_memory::HEADER_API_KEY, api_key)
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

/// On a FRESH database, parallel first-touch AGE label creation can defer one
/// `derives_from` edge's graph projection to the outbox and the (sync-mode
/// AGE) lineage walk then misses it — a pre-existing AGE-projection window,
/// not what these cells measure. One lineage is seeded serially first.
#[cfg(feature = "sal-postgres")]
async fn seed_pg(pg: &ai_memory::store::postgres::PostgresStore) -> (Memory, Memory) {
    static WARMED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    WARMED
        .get_or_init(|| async {
            seed_pg_rows(pg).await;
        })
        .await;
    seed_pg_rows(pg).await
}

#[cfg(feature = "sal-postgres")]
async fn seed_pg_rows(pg: &ai_memory::store::postgres::PostgresStore) -> (Memory, Memory) {
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

// ---- Attribution (f2r finding 2; GOD ruling on the issuer pin) ----
//
// WHY there is no wire-level "principal != header" cell: in this identity
// model `require_admin` resolves the caller from `X-Agent-Id` VERBATIM
// (`identity::resolve_http_agent_id`: validate, then `id.to_string()`), and a
// #2044 per-agent key only ATTESTS that header — under `enforce` a key bound
// to a different principal is refused; it never rebinds the principal. So on
// every ADMITTED path the resolved principal and the raw header are the same
// string, and a handler that read the header directly would be
// wire-indistinguishable. Stronger still (f2r, ITEM3-FINDING2-WITHDRAWN): the
// #2044 transport middleware REWRITES `X-Agent-Id` to the key-derived
// principal before any handler runs (`src/transport.rs`), so header-based
// resolution IS attested resolution by design. The limit is the identity
// model, not the test. What
// protects attribution is pinned instead: (1) structurally — the handler never
// reads the header and threads `is_admin` from the gate; (2) behaviourally —
// under `enforce` a spoofed admin header cannot obtain attribution.

/// Structural: the handler's ONLY identity input is `require_admin`'s return.
/// RED-first by injecting a header read into the handler source.
#[test]
fn handler_never_reads_the_agent_id_header_and_threads_is_admin_3266() {
    const SRC: &str = include_str!("../src/handlers/swarm_rewind_http.rs");
    let code: String = SRC
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // (i) the agent-id header by BOTH spellings, case-insensitively.
    let lower = code.to_ascii_lowercase();
    for needle in ["header_agent_id", "x-agent-id", "resolve_http_agent_id"] {
        assert!(
            !lower.contains(needle),
            "swarm_rewind_http.rs must not read the agent-id header itself (found `{needle}`); \
             the issuer is require_admin's return value only"
        );
    }
    // (ii) the POSITIVE shape: `headers` is used exactly once outside the
    // handler signature — as require_admin's argument. Deleting the gate
    // while keeping any stray `headers` use fails from both directions.
    let uses: Vec<&str> = code
        .lines()
        .filter(|l| {
            let t = l.trim();
            t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|w| w == "headers")
                && !t.starts_with("headers: HeaderMap")
        })
        .collect();
    assert_eq!(
        uses.len(),
        1,
        "`headers` must reach require_admin and nothing else; uses: {uses:?}"
    );
    assert!(
        uses[0].contains("require_admin(") && uses[0].contains("&headers"),
        "the single `headers` use must be the require_admin call: {uses:?}"
    );
    for (i, _) in code.match_indices("for_admin_checked(") {
        let args = &code[i..i + code[i..].find(')').expect("closing paren")];
        assert!(
            !args.trim_end().ends_with("true"),
            "for_admin_checked must take the threaded is_admin, never a literal: {args})"
        );
    }
    assert!(
        code.contains("Ok(c) => (c, true)"),
        "is_admin must be bound in the require_admin Ok arm (the #1062 typed dependency)"
    );
}

fn enforce_state(db: Db, store: Arc<dyn MemoryStore>, backend: StorageBackend) -> AppState {
    let mut map = std::collections::HashMap::new();
    map.insert(api_key_sha256_hex(ADMIN_KEY), ADMIN.to_string());
    app_state_with(
        db,
        store,
        backend,
        HttpIdentityMode::Enforce,
        Arc::new(EnrolledAgentKeys::from_map(map)),
    )
}

fn sqlite_enforce_router() -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    (
        router_from(enforce_state(db, store, StorageBackend::Sqlite)),
        f,
    )
}

fn sqlite_rewind_events(path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(path).expect("open");
    conn.query_row(
        "SELECT count(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::SWARM_REWIND],
        |r| r.get(0),
    )
    .expect("count")
}

/// #2044 under `enforce` (sqlite): the key-attested admin is the issuer; a
/// shared-key holder asserting the admin header is refused with zero writes.
#[tokio::test]
async fn sqlite_enforce_key_attested_admin_is_the_issuer_and_a_spoof_is_refused_3266() {
    let (router, f) = sqlite_enforce_router();
    let (root, child) = seed_sqlite(f.path());
    // Spoof first: the SHARED transport key cannot vouch for the admin name.
    let (status, _) = call(
        &router,
        post_with_key(KEY, Some(ADMIN), &json!({"to": root.id})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "shared-key admin-header spoof must be refused"
    );
    assert_eq!(
        sqlite_rewind_events(f.path()),
        0,
        "no swarm.rewind event from a spoof"
    );
    let conn = ai_memory::db::open(f.path()).expect("open");
    let st: String = conn
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = ?1",
            [&child.id],
            |r| r.get(0),
        )
        .expect("state");
    assert_eq!(st, "open", "a refused spoof writes nothing");
    // The key-attested admin succeeds and is the recorded issuer.
    let (status, body) = call(
        &router,
        post_with_key(ADMIN_KEY, Some(ADMIN), &json!({"to": root.id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let issuer: String = conn
        .query_row(
            "SELECT agent_id FROM signed_events WHERE event_type = ?1 ORDER BY rowid DESC LIMIT 1",
            [ai_memory::signed_events::event_types::SWARM_REWIND],
            |r| r.get(0),
        )
        .expect("event");
    assert_eq!(
        issuer, ADMIN,
        "issued_by is the key-attested admin principal"
    );
}

/// #2044 under `enforce` (Postgres): same two halves on the PG arm.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_enforce_key_attested_admin_is_the_issuer_and_a_spoof_is_refused_3266() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return;
    };
    let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect");
    let handle = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("handle");
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    let router = router_from(enforce_state(db, store, StorageBackend::Postgres));
    let (root, child) = seed_pg(&handle).await;
    // Scoped to THIS cell's root, not a global event count (a sibling PG cell
    // signs as the same ADMIN in parallel on the shared database). The event
    // and the root's `contamination.rewind` marker commit in ONE transaction,
    // so "this root carries no rewind marker" is exactly "no swarm.rewind
    // event was committed for this root".
    let root_rewound = |h: &ai_memory::store::postgres::PostgresStore, id: String| {
        let pool = h.pool().clone();
        async move {
            let (marker,): (Option<serde_json::Value>,) = sqlx::query_as(
                "SELECT metadata->'contamination'->'rewind' FROM memories WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("root marker");
            marker == Some(json!(true))
        }
    };
    let (status, _) = call(
        &router,
        post_with_key(KEY, Some(ADMIN), &json!({"to": root.id})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "shared-key admin-header spoof must be refused"
    );
    assert!(
        !root_rewound(&handle, root.id.clone()).await,
        "no swarm.rewind committed for this root by a spoof"
    );
    let (st,): (String,) = sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(&child.id)
        .fetch_one(handle.pool())
        .await
        .expect("state");
    assert_eq!(st, "open", "a refused spoof writes nothing");
    let (status, body) = call(
        &router,
        post_with_key(ADMIN_KEY, Some(ADMIN), &json!({"to": root.id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (issuer,): (String,) =
        sqlx::query_as("SELECT agent_id FROM signed_events WHERE event_type = $1 AND id = $2")
            .bind(ai_memory::signed_events::event_types::SWARM_REWIND)
            .bind(body["signed_event_id"].as_str().expect("event id"))
            .fetch_one(handle.pool())
            .await
            .expect("event");
    assert_eq!(
        issuer, ADMIN,
        "issued_by is the key-attested admin principal"
    );
    assert!(
        root_rewound(&handle, root.id.clone()).await,
        "non-vacuity: the admitted rewind DOES mark this root"
    );
}
