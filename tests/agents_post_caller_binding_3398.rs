// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3398 — `POST /api/v1/agents` had NEITHER an admin gate NOR a
//! caller-vs-`agent_id` binding, while its `GET` twin is admin-gated (#946).
//!
//! ## The hole
//!
//! `db::register_agent` and the postgres `_agents` write are UPSERTS on the
//! roster row, so any authenticated caller could POST
//! `{agent_id: "<victim>", agent_type: "human", capabilities: ["TAMPERED"]}`
//! and overwrite another agent's entry — including an admin's own
//! `agent_type` / `capabilities`. The admin-gated `GET /api/v1/agents` then
//! served the forgery as authoritative roster truth: the read side was locked
//! and the write side was open, so the lock only guaranteed that a *reader*
//! was an admin, never that what they read was written by one. Same class as
//! MCP #3372 (re-register overwrite) and #3362 (`_agents` writable).
//!
//! ## The control
//!
//! A caller may register or refresh ONLY its own resolved identity; touching
//! another principal's entry goes through the canonical `require_admin` gate
//! (not a second copy of its allowlist + #1570 authn-trust + #2044
//! key-attestation logic), and the refusal is audited.
//!
//! ## Wire-shape parity, same route
//!
//! The two backend arms hand-rolled their own response objects and had
//! DRIFTED: SQLite emitted `registered: true`, PostgreSQL did not. Both now
//! derive from one `register_agent_response` projection, so a client keying off
//! that field sees the same acknowledgement from either backend. Fixed by
//! sharing the projection, NOT by patching postgres to resemble sqlite.
//!
//! ## What this pins — DENIED and ALLOWED, both backends
//!
//! DENIED: a non-admin cross-register is 403 AND the victim's roster row is
//! byte-unchanged (the refusal precedes the upsert). ALLOWED: self-register,
//! and an admin managing another agent. Plus `registered: true` on both
//! backends.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::EnrolledAgentKeys;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

mod common;

const ADMIN: &str = "ai:roster-admin";
const ALICE: &str = "ai:roster-alice";
const MALLORY: &str = "ai:roster-mallory";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("agents-post-binding-3398");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Opt into the #1570 legacy header-trust posture so a bare `X-Agent-Id`
/// naming the allowlisted admin resolves to the admin role on these keyless
/// test daemons. It only LOOSENS admin gating, so it never weakens the DENIED
/// assertions below — those use a non-allowlisted id.
fn enable_admin_header_trust() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once, before any concurrent reader observes a
        // half-written value; never cleared for the binary's lifetime.
        unsafe {
            std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }
    });
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
        enrolled_agent_keys: enrolled,
        http_identity_mode: HttpIdentityMode::default(),
    }
}

fn router_from(app_state: AppState, enrolled: Arc<EnrolledAgentKeys>) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn sqlite_router() -> (axum::Router, NamedTempFile) {
    enable_admin_header_trust();
    ai_memory::handlers::admin_role::mark_request_authn_configured(false);
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
    let enrolled = Arc::new(EnrolledAgentKeys::empty());
    (
        router_from(
            app_state_for(db, store, StorageBackend::Sqlite, Arc::clone(&enrolled)),
            enrolled,
        ),
        f,
    )
}

fn req(method: &str, uri: &str, agent_id: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(v).expect("serialise")))
            .expect("build request"),
        None => b.body(Body::empty()).expect("build request"),
    }
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

fn register_body(agent_id: &str, agent_type: &str, caps: &[&str]) -> Value {
    json!({
        "agent_id": agent_id,
        "agent_type": agent_type,
        "capabilities": caps,
    })
}

/// The roster entry for `agent_id` as the admin-gated `GET` serves it.
async fn roster_entry(router: &axum::Router, agent_id: &str) -> Option<Value> {
    let (status, v) = call(router, req("GET", "/api/v1/agents", Some(ADMIN), None)).await;
    assert_eq!(status, StatusCode::OK, "admin list must succeed: {v}");
    v["agents"]
        .as_array()?
        .iter()
        .find(|a| a["agent_id"].as_str() == Some(agent_id))
        .cloned()
}

// ---------------------------------------------------------------------------
// sqlite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_cross_register_by_a_non_admin_is_refused_and_leaves_the_roster_intact() {
    // THE regression, denied half.
    let _dir = fresh_dir();
    let (router, _f) = sqlite_router();

    // Alice registers herself — the legitimate roster entry.
    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(ALICE),
            Some(&register_body(ALICE, "ai:generic", &["read"])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "self-register must work: {v}");

    // Mallory tries to overwrite Alice's entry with a forged type + caps.
    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(MALLORY),
            Some(&register_body(ALICE, "human", &["TAMPERED"])),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-admin may not register another principal: {v}"
    );

    // ...and the refusal precedes the upsert: the roster is byte-unchanged.
    let entry = roster_entry(&router, ALICE)
        .await
        .expect("alice's roster entry");
    assert_eq!(
        entry["agent_type"].as_str(),
        Some("ai:generic"),
        "the victim's agent_type must not be mutated: {entry}"
    );
    let caps: Vec<&str> = entry["capabilities"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        caps,
        vec!["read"],
        "the victim's capabilities must not be mutated: {entry}"
    );
}

#[tokio::test]
async fn sqlite_self_register_is_allowed_and_acknowledges_with_registered_true() {
    // ALLOWED half + the wire-shape field the postgres arm used to omit.
    let _dir = fresh_dir();
    let (router, _f) = sqlite_router();

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(ALICE),
            Some(&register_body(ALICE, "ai:generic", &["read", "write"])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["registered"], json!(true), "{v}");
    assert_eq!(v["agent_id"].as_str(), Some(ALICE), "{v}");
    assert!(v["id"].is_string(), "{v}");
}

#[tokio::test]
async fn sqlite_admin_may_register_another_agent() {
    // ALLOWED half — the admin escape hatch the issue asks for, so operators
    // can still manage the roster.
    let _dir = fresh_dir();
    let (router, _f) = sqlite_router();

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(ADMIN),
            Some(&register_body(ALICE, "ai:generic", &["read"])),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an admin may manage another agent's entry: {v}"
    );
    assert_eq!(v["registered"], json!(true), "{v}");
}

#[tokio::test]
async fn sqlite_body_validation_still_precedes_the_binding() {
    // A malformed body is still a 400, not a 403 — the caller's own input is
    // diagnosed before the authz decision, preserving the shipped contract.
    let _dir = fresh_dir();
    let (router, _f) = sqlite_router();

    let (status, _v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(MALLORY),
            Some(&register_body("has whitespace", "ai:generic", &[])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// postgres — same route, same projection
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
async fn pg_router(url: &str) -> axum::Router {
    enable_admin_header_trust();
    ai_memory::handlers::admin_role::mark_request_authn_configured(false);
    let store_concrete = ai_memory::store::postgres::PostgresStore::connect(url)
        .await
        .expect("connect postgres");
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(store_concrete);
    let enrolled = Arc::new(EnrolledAgentKeys::empty());
    router_from(
        app_state_for(db, store, StorageBackend::Postgres, Arc::clone(&enrolled)),
        enrolled,
    )
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_self_register_emits_the_same_registered_field_as_sqlite() {
    // THE wire-shape parity fix: pre-#3398 the postgres arm's hand-rolled
    // object omitted `registered`, so a client keying off it saw every
    // postgres-backed registration as un-acknowledged.
    let Some(url) = common::postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (no live postgres tier)");
        return;
    };
    let router = pg_router(&url).await;
    let agent = format!("ai:roster-pg-{}", uuid::Uuid::new_v4().simple());

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(&agent),
            Some(&register_body(&agent, "ai:generic", &["read"])),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(
        v["registered"],
        json!(true),
        "postgres must acknowledge with the same field sqlite does: {v}"
    );
    assert_eq!(v["agent_id"].as_str(), Some(agent.as_str()), "{v}");
    assert_eq!(
        v["storage_backend"].as_str(),
        Some("postgres"),
        "the house backend marker is preserved: {v}"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_cross_register_by_a_non_admin_is_refused() {
    // DENIED half on the second backend — the gate sits ahead of the backend
    // dispatch, so it must fire identically.
    let Some(url) = common::postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (no live postgres tier)");
        return;
    };
    let router = pg_router(&url).await;
    let victim = format!("ai:roster-pg-victim-{}", uuid::Uuid::new_v4().simple());

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/agents",
            Some(MALLORY),
            Some(&register_body(&victim, "human", &["TAMPERED"])),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-admin may not register another principal on postgres either: {v}"
    );
}
