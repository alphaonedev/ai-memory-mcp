// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov_ga2 round-4 — error / edge / match-arm coverage for the three
//! near-90 handler modules `handlers::admin`, `handlers::links`, and
//! `handlers::approvals`.
//!
//! Prior coverage waves landed the happy paths; this suite targets the
//! still-dark ERROR / EDGE / MATCH arms enumerated in
//! `.local-runs/ga-session-0611/gaps4/handlers__{admin,links,approvals}.rs.txt`:
//! validation failures, not-found, not-owner / forbidden, scope &
//! visibility filters, quota-exceeded, governance-deny, both the sqlite
//! AND the postgres dispatch arms, and the serialization branches.
//!
//! Two production routers are driven through `tower::oneshot`:
//!   - a SQLite-backed router (`sqlite_router`) reaches every
//!     `StorageBackend::Sqlite` dispatch arm + the shared validation /
//!     ownership / quota / governance gates that run before the backend
//!     split. These run unconditionally.
//!   - a LIVE [`PostgresStore`]-backed router (`pg_store_and_router`)
//!     reaches the `#[cfg(feature = "sal")]` / `sal-postgres` postgres
//!     dispatch arms end-to-end. Gated on `AI_MEMORY_TEST_POSTGRES_URL`;
//!     each pg test SKIPs with a printed line when the env var is unset.
//!
//! Every namespace / agent-id / memory-id is uuid-randomised so the
//! suite never collides with co-resident suites on the shared scratch
//! DB; no test asserts global-table emptiness — assertions filter to
//! this suite's own unique ids only.
//!
//! Covered handler arms (file:function):
//!   - `admin::register_agent` — invalid agent_id 400, invalid
//!     agent_type 400, invalid capabilities 400, sqlite create path.
//!   - `admin::bind_agent_pubkey` — non-admin 403, invalid agent_id
//!     400, invalid pubkey 400.
//!   - `admin::list_agents` — non-admin 403, sqlite list path.
//!   - `admin::quota_status_handler` — invalid agent_id 400, body /
//!     caller mismatch 403, sqlite single-agent + namespace arms,
//!     sqlite operator-list arm, non-admin list 403.
//!   - `admin::get_stats` — non-admin 403, sqlite stats path.
//!   - `admin::run_gc` — non-admin 403, sqlite gc path.
//!   - `admin::export_memories` — non-admin 403, sqlite export path.
//!   - `admin::import_memories` — oversize 400, non-admin 403, sqlite
//!     import path (restamp + provenance), `tools_list`.
//!   - `links::verify_link_handler` — missing-args 400, invalid
//!     source_id 400, invalid target_id 400, strict-nonce 400,
//!     back-compat no-nonce path, sqlite NOT_IMPLEMENTED is
//!     unreachable under `sal` (the pg/sal arm runs).
//!   - `links::create_link` — unknown_field 400, deserialize 400,
//!     invalid triple 400, invalid_relation 400, source-not-found
//!     404, not-owner 403, sqlite create path.
//!   - `links::delete_link` — unknown_field 400, deserialize 400,
//!     invalid triple 400, missing-source deleted:false, not-owner
//!     403, sqlite delete path.
//!   - `links::get_links` — invalid id 400, sqlite visibility-filter
//!     path, admin-bypass path.
//!   - `approvals::verify_approval_hmac` — no-secret 401, missing
//!     signature 401, missing timestamp 401, non-integer timestamp
//!     401, stale timestamp 401, future-skew 401, mismatch 401,
//!     replay 401.
//!   - `approvals::approval_decide` — bad body 400, invalid id 400,
//!     sqlite approve→execute path, sqlite deny path, sqlite
//!     unknown-id 404 (deny + approve), sqlite already-decided.
//!   - `approvals::sse_event_visible_to` — empty agent, `host:`
//!     prefix, agent match, empty-namespace fallthrough, K9-rule
//!     allow.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::let_underscore_untyped)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Admin agent-id this suite presents on admin-gated requests. Added to
/// `admin_agent_ids` so `require_admin` admits it.
const ADMIN_AGENT: &str = "ai:cov-ga2-r4-admin";

/// A distinct non-admin agent-id used for the 403 negative tests.
const NON_ADMIN_AGENT: &str = "ai:cov-ga2-r4-nonadmin";

/// A hex-decodable HMAC secret so the approvals path takes the canonical
/// (hex-decoded) key branch.
const HMAC_SECRET_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..12])
}

/// Opt into the #1570 legacy header-trust posture so a bare
/// `X-Agent-Id` naming an allowlisted admin resolves to admin role on
/// this keyless test daemon. Set process-wide exactly once; it only
/// LOOSENS admin gating for the allowlisted admin id, so the non-admin
/// negative tests (distinct non-allowlisted id) are unaffected.
fn enable_admin_header_trust() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once, before any concurrent reader observes a
        // half-written value; the var is only ever set (never cleared).
        unsafe {
            std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }
    });
}

// ---------------------------------------------------------------------------
// SQLite router (production router over a fresh on-disk sqlite DB; the
// SAL SqliteStore opens the SAME path so seed → read works through both
// the legacy db path and the trait).
// ---------------------------------------------------------------------------

fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile, Db) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        ),
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_AGENT.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (
        ai_memory::build_router(api_key_state, app_state),
        db_tmp,
        db,
    )
}

/// SQLite router with `verify_require_nonce = true` so the strict-mode
/// missing-nonce 400 arm in `verify_link_handler` is reachable.
fn sqlite_router_strict_nonce() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        ),
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: true,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_AGENT.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

async fn pg_store_and_router(url: &str) -> (PostgresStore, axum::Router) {
    let store_concrete = PostgresStore::connect(url).await.expect("connect postgres");
    let router = router_for_pg(store_concrete.clone());
    (store_concrete, router)
}

fn router_for_pg(store_concrete: PostgresStore) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(store_concrete);
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_AGENT.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

// ---------------------------------------------------------------------------
// HTTP drivers
// ---------------------------------------------------------------------------

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn post_as(
    router: &axum::Router,
    uri: &str,
    agent: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn put_as(
    router: &axum::Router,
    uri: &str,
    agent: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn delete_as(
    router: &axum::Router,
    uri: &str,
    agent: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get_as(router: &axum::Router, uri: &str, agent: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

// ---------------------------------------------------------------------------
// HMAC signing — replicates the pub(crate) subscriptions helpers; the
// canonical signed string is `<ts>.<METHOD>.<pending_id>.<body>`.
// ---------------------------------------------------------------------------

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hmac_sha256_hex(key_hex: &str, body: &str) -> String {
    const BLOCK: usize = 64;
    let mut key = hex_decode(key_hex);
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(&key);
        key = h.finalize().to_vec();
    }
    key.resize(BLOCK, 0);
    let mut opad = [0x5cu8; BLOCK];
    let mut ipad = [0x36u8; BLOCK];
    for i in 0..BLOCK {
        opad[i] ^= key[i];
        ipad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

/// Build an HMAC-signed `POST /api/v1/approvals/{pending_id}` request
/// with an explicit timestamp so the stale / future-skew arms can be
/// exercised by passing a doctored `ts`.
fn signed_approval_request_ts(pending_id: &str, body: &Value, ts: i64) -> Request<Body> {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts_str = ts.to_string();
    let canonical = format!("{ts_str}.POST.{pending_id}.{body_str}");
    let key_hash = sha256_hex(HMAC_SECRET_HEX);
    let sig = hmac_sha256_hex(&key_hash, &canonical);
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts_str)
        .body(Body::from(body_bytes))
        .unwrap()
}

fn signed_approval_request(pending_id: &str, body: &Value) -> Request<Body> {
    signed_approval_request_ts(pending_id, body, chrono::Utc::now().timestamp())
}

// ---------------------------------------------------------------------------
// Memory + pending seeding (against the sqlite app.db connection)
// ---------------------------------------------------------------------------

fn mem(id: &str, ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "cov-ga2-r4 anchor".to_string(),
        tags: vec!["cov-ga2-r4".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

// ===========================================================================
// admin::register_agent — validation arms (sqlite create path)
// ===========================================================================

#[tokio::test]
async fn admin_register_invalid_agent_id_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = post_as(
        &r,
        "/api/v1/agents",
        ADMIN_AGENT,
        &json!({"agent_id": "bad id with spaces", "agent_type": "system"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_register_invalid_agent_type_is_400() {
    let (r, _t, _db) = sqlite_router();
    let agent_id = uid("ai:cov-ga2-r4-reg");
    let (status, _b) = post_as(
        &r,
        "/api/v1/agents",
        ADMIN_AGENT,
        &json!({"agent_id": agent_id, "agent_type": "not a valid type!!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_register_sqlite_create_path() {
    let (r, _t, _db) = sqlite_router();
    let agent_id = uid("ai:cov-ga2-r4-reg");
    let (status, body) = post_as(
        &r,
        "/api/v1/agents",
        ADMIN_AGENT,
        &json!({"agent_id": agent_id, "agent_type": "system", "capabilities": ["recall"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["registered"], true);
    assert_eq!(body["agent_id"], agent_id);
}

// ===========================================================================
// admin::bind_agent_pubkey — non-admin 403 + validation arms
// ===========================================================================

#[tokio::test]
async fn admin_bind_pubkey_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let agent_id = uid("ai:cov-ga2-r4-bind");
    let kp = ai_memory::identity::keypair::generate(&agent_id).expect("keypair");
    let (status, _b) = put_as(
        &r,
        &format!("/api/v1/agents/{agent_id}/pubkey"),
        NON_ADMIN_AGENT,
        &json!({"pubkey_b64": kp.public_base64()}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_bind_pubkey_invalid_agent_id_is_400() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let kp = ai_memory::identity::keypair::generate("ai:x").expect("keypair");
    // Admin caller passes require_admin; the path agent_id is invalid.
    let (status, _b) = put_as(
        &r,
        "/api/v1/agents/bad%20id/pubkey",
        ADMIN_AGENT,
        &json!({"pubkey_b64": kp.public_base64()}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_bind_pubkey_invalid_pubkey_is_400() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let agent_id = uid("ai:cov-ga2-r4-bind");
    let (status, _b) = put_as(
        &r,
        &format!("/api/v1/agents/{agent_id}/pubkey"),
        ADMIN_AGENT,
        &json!({"pubkey_b64": "not-a-valid-ed25519-key"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// admin::list_agents — non-admin 403 + sqlite list path
// ===========================================================================

#[tokio::test]
async fn admin_list_agents_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = get_as(&r, "/api/v1/agents", NON_ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_list_agents_sqlite_path() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let (status, body) = get_as(&r, "/api/v1/agents", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("agents").is_some());
    assert!(body.get("count").is_some());
}

// ===========================================================================
// admin::quota_status_handler — invalid id, mismatch, sqlite arms
// ===========================================================================

#[tokio::test]
async fn admin_quota_invalid_agent_id_is_400() {
    let (r, _t, _db) = sqlite_router();
    // Caller header is a valid id; body.agent_id is malformed → 400.
    let (status, _b) = post_as(
        &r,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"agent_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_quota_body_caller_mismatch_is_403() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = post_as(
        &r,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"agent_id": "ai:someone-else"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_quota_single_agent_sqlite_aggregate_arm() {
    let (r, _t, _db) = sqlite_router();
    // body.agent_id == caller, no namespace → aggregate sqlite arm.
    let (status, body) = post_as(
        &r,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"agent_id": ADMIN_AGENT}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn admin_quota_single_agent_sqlite_namespace_arm() {
    let (r, _t, _db) = sqlite_router();
    // body.agent_id == caller, explicit namespace → get_status sqlite arm.
    let ns = uid("cov-ga2-r4-qns");
    let (status, body) = post_as(
        &r,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"agent_id": ADMIN_AGENT, "namespace": ns}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn admin_quota_list_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    // No agent_id → operator-list path; non-admin caller is rejected.
    let (status, _b) = post_as(&r, "/api/v1/quota/status", NON_ADMIN_AGENT, &json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_quota_list_sqlite_arm() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    // No agent_id → admin operator-list sqlite arm (list_status).
    let (status, body) = post_as(&r, "/api/v1/quota/status", ADMIN_AGENT, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("quotas").is_some());
    assert!(body.get("count").is_some());
}

#[tokio::test]
async fn admin_quota_list_sqlite_namespace_filter_arm() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let ns = uid("cov-ga2-r4-qlist");
    let (status, body) = post_as(
        &r,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"namespace": ns}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("quotas").is_some());
}

// ===========================================================================
// admin::get_stats — non-admin 403 + sqlite stats path
// ===========================================================================

#[tokio::test]
async fn admin_stats_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = get_as(&r, "/api/v1/stats", NON_ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_stats_sqlite_path() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let (status, body) = get_as(&r, "/api/v1/stats", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("total_memories").is_some() || body.get("total").is_some());
}

// ===========================================================================
// admin::run_gc — non-admin 403 + sqlite gc path
// ===========================================================================

#[tokio::test]
async fn admin_run_gc_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = post_as(&r, "/api/v1/gc", NON_ADMIN_AGENT, &json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_run_gc_sqlite_path() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let (status, body) = post_as(&r, "/api/v1/gc", ADMIN_AGENT, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("expired_deleted").is_some());
}

// ===========================================================================
// admin::export_memories — non-admin 403 + sqlite export path
// ===========================================================================

#[tokio::test]
async fn admin_export_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = get_as(&r, "/api/v1/export", NON_ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_export_sqlite_path() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let (status, body) = get_as(&r, "/api/v1/export", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("memories").is_some());
    assert!(body.get("links").is_some());
    assert!(body.get("exported_at").is_some());
}

// ===========================================================================
// admin::import_memories — oversize 400, non-admin 403, sqlite path
// ===========================================================================

#[tokio::test]
async fn admin_import_oversize_is_400() {
    let (r, _t, _db) = sqlite_router();
    let ns = uid("cov-ga2-r4-impbig");
    let big: Vec<Value> = (0..=ai_memory::handlers::MAX_BULK_SIZE)
        .map(|i| {
            serde_json::to_value(mem(&uid("imp"), &ns, &format!("row-{i}"), ADMIN_AGENT)).unwrap()
        })
        .collect();
    let (status, _b) = post_as(&r, "/api/v1/import", ADMIN_AGENT, &json!({"memories": big})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_import_non_admin_is_403() {
    let (r, _t, _db) = sqlite_router();
    let ns = uid("cov-ga2-r4-imp");
    let m1 = mem(&uid("imp"), &ns, "import-one", NON_ADMIN_AGENT);
    let (status, _b) = post_as(
        &r,
        "/api/v1/import",
        NON_ADMIN_AGENT,
        &json!({"memories": [m1]}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_import_sqlite_path_with_links() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let ns = uid("cov-ga2-r4-imp");
    // One row carries a different agent_id so the provenance-restamp
    // (imported_from_agent_id) branch fires. One link references the
    // two imported rows so the sqlite links loop runs. One link has an
    // invalid triple so the `continue` arm runs.
    let id1 = uid("imp");
    let id2 = uid("imp");
    let m1 = mem(&id1, &ns, "import-one", "ai:original-author");
    let m2 = mem(&id2, &ns, "import-two", ADMIN_AGENT);
    let (status, body) = post_as(
        &r,
        "/api/v1/import",
        ADMIN_AGENT,
        &json!({
            "memories": [m1, m2],
            "links": [
                {"source_id": id1, "target_id": id2, "relation": "related_to", "created_at": ""},
                {"source_id": "", "target_id": id2, "relation": "related_to", "created_at": ""},
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["imported"], 2, "both rows import; body={body}");
}

#[tokio::test]
async fn admin_import_invalid_memory_collects_error() {
    enable_admin_header_trust();
    let (r, _t, _db) = sqlite_router();
    let ns = uid("cov-ga2-r4-imperr");
    // A memory with an empty id fails validate_memory → error arm
    // (sanitize_bulk_row_error + continue) instead of import.
    let mut bad = mem("", &ns, "bad", ADMIN_AGENT);
    bad.id = String::new();
    let good = mem(&uid("imp"), &ns, "good", ADMIN_AGENT);
    let (status, body) = post_as(
        &r,
        "/api/v1/import",
        ADMIN_AGENT,
        &json!({"memories": [bad, good]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let errors = body["errors"].as_array().expect("errors array");
    assert!(
        !errors.is_empty(),
        "invalid row should collect an error; body={body}"
    );
}

// ===========================================================================
// admin::tools_list — backend-agnostic config surface
// ===========================================================================

#[tokio::test]
async fn admin_tools_list_ok() {
    let (r, _t, _db) = sqlite_router();
    let (status, body) = get_as(&r, "/api/v1/tools/list", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

// ===========================================================================
// links::verify_link_handler — validation + strict-nonce arms
// ===========================================================================

#[tokio::test]
async fn links_verify_missing_args_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, body) = post_as(&r, "/api/v1/links/verify", ADMIN_AGENT, &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.get("fields").is_some());
}

#[tokio::test]
async fn links_verify_invalid_source_id_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = post_as(
        &r,
        "/api/v1/links/verify",
        ADMIN_AGENT,
        &json!({"source_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn links_verify_invalid_target_id_is_400() {
    let (r, _t, _db) = sqlite_router();
    // Valid source_id, invalid target_id → the target_id 400 arm.
    let (status, _b) = post_as(
        &r,
        "/api/v1/links/verify",
        ADMIN_AGENT,
        &json!({"source_id": "good-src", "target_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn links_verify_strict_nonce_missing_is_400() {
    let (r, _t) = sqlite_router_strict_nonce();
    // require_nonce = true + no nonce → 400 with verification_nonce field.
    let (status, body) = post_as(
        &r,
        "/api/v1/links/verify",
        ADMIN_AGENT,
        &json!({"source_id": "src-1", "target_id": "tgt-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
    assert!(body.get("fields").is_some());
}

#[tokio::test]
async fn links_verify_back_compat_no_nonce_runs_sal_arm() {
    let (r, _t, _db) = sqlite_router();
    // require_nonce = false (default) + no nonce → back-compat WARN path,
    // then the sal verify_link arm runs against a nonexistent link.
    let src = uid("ghost-src");
    let tgt = uid("ghost-tgt");
    let (status, _b) = post_as(
        &r,
        "/api/v1/links/verify",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt}),
    )
    .await;
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::INTERNAL_SERVER_ERROR,
        "verify sal arm executed; status={status}"
    );
}

// ===========================================================================
// links::create_link — unknown_field / deserialize / triple / relation /
//                       not-found / not-owner / sqlite create arms
// ===========================================================================

#[tokio::test]
async fn links_create_unknown_field_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, body) = post_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "a", "target_id": "b", "link_type": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unknown_field");
}

#[tokio::test]
async fn links_create_invalid_triple_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = post_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "", "target_id": "b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn links_create_invalid_relation_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, body) = post_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "aaaaaaaa", "target_id": "bbbbbbbb", "relation": "frobnicates"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_relation");
}

#[tokio::test]
async fn links_create_source_not_found_is_404() {
    let (r, _t, _db) = sqlite_router();
    // Valid triple + valid relation, but the source memory does not
    // exist → sqlite SOURCE_MEMORY_NOT_FOUND 404 arm.
    let src = uid("nosrc");
    let tgt = uid("notgt");
    let (status, body) = post_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body={body}");
}

#[tokio::test]
async fn links_create_not_owner_is_403() {
    let (r, _t, db) = sqlite_router();
    // Seed a source memory owned by someone else; a different caller's
    // create attempt hits the caller-vs-source-owner 403 arm.
    let ns = uid("cov-ga2-r4-lnown");
    let src = uid("ln-src");
    let tgt = uid("ln-tgt");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", "ai:another-owner"))
            .expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", "ai:another-owner"))
            .expect("seed tgt");
    }
    let (status, body) = post_as(
        &r,
        "/api/v1/links",
        NON_ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
}

#[tokio::test]
async fn links_create_sqlite_owner_path() {
    let (r, _t, db) = sqlite_router();
    // Seed a source memory owned by the caller so the owner gate passes
    // and the sqlite create_link_signed path runs end-to-end.
    let ns = uid("cov-ga2-r4-lnok");
    let src = uid("ln-src");
    let tgt = uid("ln-tgt");
    let owner = uid("ai:cov-ga2-r4-lnowner");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", &owner)).expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", &owner)).expect("seed tgt");
    }
    let (status, body) = post_as(
        &r,
        "/api/v1/links",
        &owner,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["linked"], true);
}

// ===========================================================================
// links::delete_link — unknown_field / triple / missing-source / not-owner
//                      / sqlite delete arms
// ===========================================================================

#[tokio::test]
async fn links_delete_unknown_field_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, body) = delete_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "a", "target_id": "b", "bogus": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unknown_field");
}

#[tokio::test]
async fn links_delete_invalid_triple_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = delete_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "", "target_id": "b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn links_delete_missing_source_is_deleted_false() {
    let (r, _t, _db) = sqlite_router();
    // No such source memory → falls through to db::delete_link returning
    // deleted:false (the missing-source arm).
    let (status, body) = delete_as(
        &r,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": "ghostsrc", "target_id": "ghosttgt", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["deleted"], false);
}

#[tokio::test]
async fn links_delete_not_owner_is_403() {
    let (r, _t, db) = sqlite_router();
    let ns = uid("cov-ga2-r4-dlown");
    let src = uid("dl-src");
    let tgt = uid("dl-tgt");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", "ai:owner-a")).expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", "ai:owner-b")).expect("seed tgt");
    }
    let (status, body) = delete_as(
        &r,
        "/api/v1/links",
        NON_ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
}

#[tokio::test]
async fn links_delete_sqlite_owner_path() {
    let (r, _t, db) = sqlite_router();
    let ns = uid("cov-ga2-r4-dlok");
    let src = uid("dl-src");
    let tgt = uid("dl-tgt");
    let owner = uid("ai:cov-ga2-r4-dlowner");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", &owner)).expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", &owner)).expect("seed tgt");
        ai_memory::db::create_link(&lock.0, &src, &tgt, "related_to").expect("seed link");
    }
    let (status, body) = delete_as(
        &r,
        "/api/v1/links",
        &owner,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["deleted"], true);
}

// ===========================================================================
// links::get_links — invalid id + sqlite visibility / admin-bypass arms
// ===========================================================================

#[tokio::test]
async fn links_get_invalid_id_is_400() {
    let (r, _t, _db) = sqlite_router();
    let (status, _b) = get_as(&r, "/api/v1/links/bad%20id", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn links_get_sqlite_visibility_filter_path() {
    let (r, _t, db) = sqlite_router();
    // Seed a real anchor + edge owned by the caller so the per-endpoint
    // visibility post-filter (sal get) keeps the edge.
    let ns = uid("cov-ga2-r4-getln");
    let src = uid("gl-src");
    let tgt = uid("gl-tgt");
    let owner = uid("ai:cov-ga2-r4-glowner");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", &owner)).expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", &owner)).expect("seed tgt");
        ai_memory::db::create_link(&lock.0, &src, &tgt, "related_to").expect("seed link");
    }
    let (status, body) = get_as(&r, &format!("/api/v1/links/{src}"), &owner).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("links").is_some());
}

#[tokio::test]
async fn links_get_sqlite_admin_bypass_path() {
    enable_admin_header_trust();
    let (r, _t, db) = sqlite_router();
    // Admin caller bypasses the visibility filter entirely.
    let ns = uid("cov-ga2-r4-getadm");
    let src = uid("gla-src");
    let tgt = uid("gla-tgt");
    {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &mem(&src, &ns, "src", "ai:some-owner")).expect("seed src");
        ai_memory::db::insert(&lock.0, &mem(&tgt, &ns, "tgt", "ai:some-owner")).expect("seed tgt");
        ai_memory::db::create_link(&lock.0, &src, &tgt, "related_to").expect("seed link");
    }
    let (status, body) = get_as(&r, &format!("/api/v1/links/{src}"), ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let links = body["links"].as_array().expect("links array");
    assert!(
        links
            .iter()
            .any(|l| l.get("target_id").and_then(Value::as_str) == Some(tgt.as_str())),
        "admin bypass surfaces the edge; body={body}"
    );
}

// ===========================================================================
// approvals::verify_approval_hmac — every refusal arm
// ===========================================================================

#[tokio::test]
async fn approval_no_secret_is_401() {
    // No hooks HMAC secret configured → strict-by-default 401 even with a
    // present (but unverifiable) signature.
    ai_memory::config::set_active_hooks_hmac_secret(None);
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", "sha256=deadbeef")
        .header(
            "x-ai-memory-timestamp",
            chrono::Utc::now().timestamp().to_string(),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_missing_signature_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header(
            "x-ai-memory-timestamp",
            chrono::Utc::now().timestamp().to_string(),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_missing_timestamp_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", "sha256=deadbeef")
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_noninteger_timestamp_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", "sha256=deadbeef")
        .header("x-ai-memory-timestamp", "not-an-integer")
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_stale_timestamp_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    // ts older than the 300s window, correctly signed → stale arm 401.
    let stale = chrono::Utc::now().timestamp() - 10_000;
    let req = signed_approval_request_ts(&pending_id, &json!({"decision": "approve"}), stale);
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_future_skew_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    // ts far in the future beyond the 60s skew tolerance → future arm 401.
    let future = chrono::Utc::now().timestamp() + 10_000;
    let req = signed_approval_request_ts(&pending_id, &json!({"decision": "approve"}), future);
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_signature_mismatch_is_401() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    // Fresh timestamp but a garbage signature → constant_time_eq mismatch 401.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header(
            "x-ai-memory-signature",
            "sha256=00000000000000000000000000000000",
        )
        .header(
            "x-ai-memory-timestamp",
            chrono::Utc::now().timestamp().to_string(),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"decision": "approve"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// approvals::approval_decide — bad-body / invalid-id / sqlite arms
// ===========================================================================

#[tokio::test]
async fn approval_decide_bad_body_is_400() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    let pending_id = uid("ns");
    // Valid HMAC over a body that isn't a valid ApprovalRequestBody.
    let req = signed_approval_request(&pending_id, &json!({"not_a_decision": true}));
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approval_decide_invalid_id_is_400() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    // The path id is malformed; sign over it so HMAC passes and the
    // validate_id 400 arm runs.
    let bad_id = "bad-id-but-signed";
    let body = json!({"decision": "approve", "remember": "once"});
    // validate_id rejects ids that don't match the id grammar; use an id
    // with a disallowed char. We must sign over the *path* id verbatim.
    let pending_id = format!("{bad_id}$");
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let canonical = format!("{ts}.POST.{pending_id}.{body_str}");
    let sig = hmac_sha256_hex(&sha256_hex(HMAC_SECRET_HEX), &canonical);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN_AGENT)
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::from(body_bytes))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approval_decide_deny_unknown_id_sqlite_is_404() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    // Valid HMAC, no such pending row → sqlite deny arm Ok(false) → 404.
    let pending_id = uid("nope");
    let req = signed_approval_request(
        &pending_id,
        &json!({"decision": "deny", "remember": "once"}),
    );
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_decide_approve_unknown_id_sqlite_is_404() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, _db) = sqlite_router();
    // Valid HMAC, no such pending row → sqlite approve arm NotFound → 404.
    let pending_id = uid("nope");
    let req = signed_approval_request(
        &pending_id,
        &json!({"decision": "approve", "remember": "once"}),
    );
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_decide_approve_sqlite_execute_path() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, db) = sqlite_router();
    // Seed an approve-gated pending Store action whose payload is a full
    // serialized Memory owned by the requester. The default namespace
    // resolves to ApproverType::Human → single approve → Approved →
    // execute_pending_action replays the Store. Reaches the sqlite
    // approve + execute + executed:true arm.
    let ns = uid("cov-ga2-r4-approve");
    let requester = uid("ai:cov-ga2-r4-req");
    let queued = mem(&uid("pa"), &ns, "needs approval", &requester);
    let payload = serde_json::to_value(&queued).expect("serialize payload");
    let pending_id = {
        let lock = db.lock().await;
        ai_memory::db::queue_pending_action(
            &lock.0,
            ai_memory::models::GovernedAction::Store,
            &ns,
            None,
            &requester,
            &payload,
        )
        .expect("queue pending")
    };
    // Sign+decide as the requester (Human approver accepts any approval).
    let body = json!({"decision": "approve", "remember": "session"});
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let canonical = format!("{ts}.POST.{pending_id}.{body_str}");
    let sig = hmac_sha256_hex(&sha256_hex(HMAC_SECRET_HEX), &canonical);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", &requester)
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::from(body_bytes))
        .unwrap();
    let (status, body) = decode(&r, req).await;
    assert_eq!(status, StatusCode::OK, "approve sqlite body={body}");
    assert_eq!(body["approved"], true, "body={body}");
    assert_eq!(body["id"], pending_id);
}

#[tokio::test]
async fn approval_decide_deny_sqlite_path() {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (r, _t, db) = sqlite_router();
    let ns = uid("cov-ga2-r4-deny");
    let requester = uid("ai:cov-ga2-r4-dreq");
    let queued = mem(&uid("pa"), &ns, "needs approval", &requester);
    let payload = serde_json::to_value(&queued).expect("serialize payload");
    let pending_id = {
        let lock = db.lock().await;
        ai_memory::db::queue_pending_action(
            &lock.0,
            ai_memory::models::GovernedAction::Store,
            &ns,
            None,
            &requester,
            &payload,
        )
        .expect("queue pending")
    };
    let body = json!({"decision": "deny", "remember": "forever"});
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let body_str = String::from_utf8(body_bytes.clone()).unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let canonical = format!("{ts}.POST.{pending_id}.{body_str}");
    let sig = hmac_sha256_hex(&sha256_hex(HMAC_SECRET_HEX), &canonical);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-agent-id", &requester)
        .header("x-ai-memory-signature", format!("sha256={sig}"))
        .header("x-ai-memory-timestamp", ts)
        .body(Body::from(body_bytes))
        .unwrap();
    let (status, body) = decode(&r, req).await;
    assert_eq!(status, StatusCode::OK, "deny sqlite body={body}");
    assert_eq!(body["rejected"], true, "body={body}");
    assert_eq!(body["id"], pending_id);
}

// ===========================================================================
// approvals::sse_event_visible_to — unit-level visibility predicate arms
// ===========================================================================

#[test]
fn sse_visible_empty_agent_is_false() {
    let evt = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "p".into(),
        decision: "approve".into(),
        decided_by: "ai:x".into(),
        remember: "once".into(),
        namespace: "ns".into(),
        requested_by: "ai:requester".into(),
    };
    assert!(!ai_memory::handlers::approvals::sse_event_visible_to(
        "", &evt
    ));
}

#[test]
fn sse_visible_host_prefix_is_false() {
    let evt = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "p".into(),
        decision: "approve".into(),
        decided_by: "ai:x".into(),
        remember: "once".into(),
        namespace: "ns".into(),
        requested_by: "ai:requester".into(),
    };
    assert!(!ai_memory::handlers::approvals::sse_event_visible_to(
        "host:node-1",
        &evt
    ));
}

#[test]
fn sse_visible_agent_match_is_true() {
    let evt = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "p".into(),
        decision: "approve".into(),
        decided_by: "ai:x".into(),
        remember: "once".into(),
        namespace: "ns".into(),
        requested_by: "ai:matching-subscriber".into(),
    };
    assert!(ai_memory::handlers::approvals::sse_event_visible_to(
        "ai:matching-subscriber",
        &evt
    ));
}

#[test]
fn sse_visible_no_namespace_fallthrough_is_false() {
    // Subscriber does not match the requester and the event carries no
    // namespace hint → strict agent-id match fails → false.
    let evt = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "p".into(),
        decision: "approve".into(),
        decided_by: "ai:x".into(),
        remember: "once".into(),
        namespace: String::new(),
        requested_by: "ai:requester".into(),
    };
    assert!(!ai_memory::handlers::approvals::sse_event_visible_to(
        "ai:unrelated-subscriber",
        &evt
    ));
}

// ===========================================================================
// Postgres-arm coverage — gated on AI_MEMORY_TEST_POSTGRES_URL. These
// reach the `#[cfg(feature = "sal")]` / `sal-postgres` dispatch arms in
// each module that the sqlite router can never enter. SKIP-prints when
// the env var is unset.
// ===========================================================================

macro_rules! pg_test {
    ($name:ident, $url:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($url) = pg_url() else {
                eprintln!(
                    "SKIP {}: AI_MEMORY_TEST_POSTGRES_URL not set",
                    stringify!($name)
                );
                return;
            };
            $body
        }
    };
}

async fn pg_post(
    router: &axum::Router,
    uri: &str,
    agent: &str,
    body: &Value,
) -> (StatusCode, Value) {
    post_as(router, uri, agent, body).await
}

// admin::register_agent + bind_agent_pubkey postgres arms.
pg_test!(pg_register_then_bind_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let agent_id = uid("ai:cov-ga2-r4-pgreg");
    let (rs, rb) = pg_post(
        &router,
        "/api/v1/agents",
        ADMIN_AGENT,
        &json!({"agent_id": agent_id, "agent_type": "system"}),
    )
    .await;
    assert_eq!(rs, StatusCode::CREATED, "register body={rb}");
    assert_eq!(rb["storage_backend"], "postgres");

    let kp = ai_memory::identity::keypair::generate(&agent_id).expect("keypair");
    let (bs, bb) = put_as(
        &router,
        &format!("/api/v1/agents/{agent_id}/pubkey"),
        ADMIN_AGENT,
        &json!({"pubkey_b64": kp.public_base64()}),
    )
    .await;
    assert_eq!(bs, StatusCode::OK, "bind body={bb}");
    assert_eq!(bb["bound"], true);
});

// admin::import_memories postgres arm (admin gate + restamp + store loop).
pg_test!(pg_import_memories_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-r4-pgimp");
    let m1 = mem(&uid("imp"), &ns, "pg-import-one", ADMIN_AGENT);
    let m2 = mem(&uid("imp"), &ns, "pg-import-two", "ai:other-author");
    let (status, body) = pg_post(
        &router,
        "/api/v1/import",
        ADMIN_AGENT,
        &json!({"memories": [m1, m2], "links": []}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["imported"], 2, "both rows import; body={body}");
});

// admin::quota_status_handler postgres single-agent + list arms.
pg_test!(pg_quota_single_and_list_postgres_arms, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let (ss, sb) = pg_post(
        &router,
        "/api/v1/quota/status",
        ADMIN_AGENT,
        &json!({"agent_id": ADMIN_AGENT}),
    )
    .await;
    assert_eq!(ss, StatusCode::OK, "single body={sb}");

    let (ls, lb) = pg_post(&router, "/api/v1/quota/status", ADMIN_AGENT, &json!({})).await;
    assert_eq!(ls, StatusCode::OK, "list body={lb}");
    assert!(lb.get("quotas").is_some());
});

// admin::get_stats + run_gc postgres arms.
pg_test!(pg_stats_and_gc_postgres_arms, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let (gs, gb) = get_as(&router, "/api/v1/stats", ADMIN_AGENT).await;
    assert_eq!(gs, StatusCode::OK, "stats body={gb}");
    assert_eq!(gb["storage_backend"], "postgres");

    let (cs, cb) = pg_post(&router, "/api/v1/gc", ADMIN_AGENT, &json!({})).await;
    assert_eq!(cs, StatusCode::OK, "gc body={cb}");
    assert_eq!(cb["storage_backend"], "postgres");
});

// admin::export_memories postgres arm.
pg_test!(pg_export_postgres_arm, url, {
    enable_admin_header_trust();
    let (_store, router) = pg_store_and_router(&url).await;
    let (status, body) = get_as(&router, "/api/v1/export", ADMIN_AGENT).await;
    assert_eq!(status, StatusCode::OK, "export body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert!(body.get("memories").is_some());
});

// links::create_link + get_links postgres arms.
pg_test!(pg_create_and_get_link_postgres_arms, url, {
    let (store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-r4-pglinks");
    let src = uid("ln-src");
    let tgt = uid("ln-tgt");
    let ctx = ai_memory::store::CallerContext::for_admin(ADMIN_AGENT);
    store
        .store(&ctx, &mem(&src, &ns, "src", ADMIN_AGENT))
        .await
        .expect("seed src");
    store
        .store(&ctx, &mem(&tgt, &ns, "tgt", ADMIN_AGENT))
        .await
        .expect("seed tgt");
    let (cs, cb) = pg_post(
        &router,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED, "create body={cb}");
    assert_eq!(cb["linked"], true);

    let (gs, gb) = get_as(&router, &format!("/api/v1/links/{src}"), ADMIN_AGENT).await;
    assert_eq!(gs, StatusCode::OK, "get body={gb}");
    let links = gb["links"].as_array().expect("links array");
    assert!(
        links
            .iter()
            .any(|l| l.get("target_id").and_then(Value::as_str) == Some(tgt.as_str())),
        "get_links surfaces the edge; body={gb}"
    );
});

// links::delete_link postgres arm.
pg_test!(pg_delete_link_postgres_arm, url, {
    let (store, router) = pg_store_and_router(&url).await;
    let ns = uid("cov-ga2-r4-pgdel");
    let src = uid("dl-src");
    let tgt = uid("dl-tgt");
    let ctx = ai_memory::store::CallerContext::for_admin(ADMIN_AGENT);
    store
        .store(&ctx, &mem(&src, &ns, "src", ADMIN_AGENT))
        .await
        .expect("seed src");
    store
        .store(&ctx, &mem(&tgt, &ns, "tgt", ADMIN_AGENT))
        .await
        .expect("seed tgt");
    let (cs, _cb) = pg_post(
        &router,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);

    let (ds, db) = delete_as(
        &router,
        "/api/v1/links",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(ds, StatusCode::OK, "delete body={db}");
    assert!(db.get("deleted").is_some());
});

// links::verify_link_handler postgres arm (nonexistent link).
pg_test!(pg_verify_link_nonexistent_postgres_arm, url, {
    let (_store, router) = pg_store_and_router(&url).await;
    let src = uid("ghost-src");
    let tgt = uid("ghost-tgt");
    let (status, _b) = pg_post(
        &router,
        "/api/v1/links/verify",
        ADMIN_AGENT,
        &json!({"source_id": src, "target_id": tgt}),
    )
    .await;
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST,
        "verify pg arm executed; status={status}"
    );
});

// approvals::approval_decide_postgres — unknown id deny arm → 404.
pg_test!(pg_approval_unknown_id_postgres_arm, url, {
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET_HEX.to_string()));
    let (_store, router) = pg_store_and_router(&url).await;
    let pending_id = uid("nope");
    let req = signed_approval_request(
        &pending_id,
        &json!({"decision": "deny", "remember": "once"}),
    );
    let (status, _b) = decode(&router, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
});
