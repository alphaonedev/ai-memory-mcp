// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3456 (security-high, v1.0.0) — `POST /api/v1/import` must enforce the
//! destination namespace's governance standard on BOTH backends.
//!
//! F-A2A1.5 (#705) gated the postgres branch of `import_memories` because an
//! imported row is a Store action and must be gated by the destination
//! namespace's standard. The sqlite branch was never followed up: its loop was
//! `restamp -> validate -> db::insert` with no
//! `consult_pre_governance_decision_gate` and no
//! `enforce_governance_action(GovernedAction::Store)`. So the SAME admin
//! request against a sqlite-backed daemon bypassed a `write: Deny` /
//! `write: Approve` standard entirely, while the postgres-backed daemon refused
//! it or parked it pending — a backend-dependent authorization outcome for one
//! wire call. The sqlite envelope also had no `pending` field, so an `Approve`
//! standard was not even expressible on that backend.
//!
//! This is import-specific rather than a sqlite-wide gap: every sibling sqlite
//! write funnel already gates (`handlers::create`, `handlers::bulk`, MCP
//! `memory_store`). `db::insert` does consult the substrate
//! `GOVERNANCE_PRE_WRITE` hook, but that is the operator-signed SUBSTRATE
//! layer — a different control from the namespace STANDARD decision.
//!
//! Coverage, DENIED and ALLOWED, on BOTH lanes:
//!
//! * sqlite lane — `StorageBackend::Sqlite` (the `db::enforce_governance` +
//!   `db::insert` branch).
//! * postgres lane — `StorageBackend::Postgres`, driving the SAL
//!   `store.enforce_governance_action` branch over an `SqliteStore` handle
//!   (which delegates to the same `db::enforce_governance` evaluator), the
//!   `handler_postgres_branches_fake_pg` harness pattern.
//!
//! The DENIED/ALLOWED pair is deliberately the SAME policy — `write:
//! Registered` — flipped only by whether the caller is a registered agent, so
//! a pass cannot be an accident of some unrelated admission path.

#![cfg(feature = "sal")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, PermissionsMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{
    ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier, default_metadata,
};

const ADMIN: &str = "ops:admin";
/// The namespace standard is owned by a DIFFERENT principal than the importing
/// admin on purpose. Under `write: Approve` the namespace-standard OWNER
/// auto-allows (#3292 M6, sqlite<->pg parity), so a standard owned by the
/// importer would take the auto-allow arm and never reach the pending queue —
/// making `approve_standard_parks_pending` vacuous.
const STANDARD_OWNER: &str = "ops:standards";
const GOVERNED_NS: &str = "gov3456";

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, std::path::PathBuf) {
    // #1570 — model an AUTHENTICATED deployment so the admin `X-Agent-Id`
    // role-claim is honoured; the #1570 secure default is pinned by
    // `tests/admin_header_trust_1570.rs` in its own process.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    // The governance gate short-circuits to Allow under `Off` and only logs
    // under `Advisory`; a test binary that never installs a mode falls back to
    // `Advisory`. Production boot resolves `enforce` by default, so pin it.
    ai_memory::config::set_active_permissions_mode(PermissionsMode::Enforce);

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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

/// Seed a governance standard memory carrying `policy` and bind it to
/// `GOVERNED_NS`.
fn bind_standard(db_path: &std::path::Path, policy: &GovernancePolicy) {
    let conn = ai_memory::db::open(db_path).expect("reopen for standard");
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            Value::String(STANDARD_OWNER.to_string()),
        );
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(policy).expect("serialize policy"),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: GOVERNED_NS.to_string(),
        title: format!("standard for {GOVERNED_NS} {}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    let standard_id = ai_memory::db::insert(&conn, &standard).expect("insert standard");
    ai_memory::db::set_namespace_standard(&conn, GOVERNED_NS, &standard_id, None)
        .expect("bind namespace standard");
}

fn policy_with_write(level: GovernanceLevel) -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: level,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    }
}

fn register_admin(db_path: &std::path::Path) {
    let conn = ai_memory::db::open(db_path).expect("reopen for register");
    ai_memory::storage::register_agent(&conn, ADMIN, "nhi", &[]).expect("register admin");
}

async fn import_as_admin(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json")
        .header("x-agent-id", ADMIN)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn row(id: &str, title: &str) -> Value {
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: GOVERNED_NS.to_string(),
        title: title.to_string(),
        content: "an imported body".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        metadata: json!({ "agent_id": ADMIN }),
        ..Memory::default()
    };
    serde_json::to_value(&mem).expect("serialize row")
}

fn stored(db_path: &std::path::Path, id: &str) -> Option<Memory> {
    let conn: Connection = ai_memory::db::open(db_path).expect("reopen for readback");
    ai_memory::db::get(&conn, id).expect("db::get")
}

// ---------------------------------------------------------------------------
// DENIED — a governed namespace refuses an unregistered caller's import
// ---------------------------------------------------------------------------

async fn governed_namespace_denies(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    bind_standard(&db_path, &policy_with_write(GovernanceLevel::Registered));
    // The admin is deliberately NOT registered, so `write: Registered` denies.
    let id = uuid::Uuid::new_v4().to_string();

    let (status, body) =
        import_as_admin(&router, json!({ "memories": [row(&id, "denied row")] })).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["imported"],
        json!(0),
        "a governed namespace must refuse the row: {body}"
    );
    assert!(
        body["errors"].as_array().is_some_and(|e| e.iter().any(|m| m
            .as_str()
            .is_some_and(|s| s.contains("not a registered agent")))),
        "the refusal must name the governance reason: {body}"
    );
    assert!(
        stored(&db_path, &id).is_none(),
        "a governance-denied row must never be persisted"
    );
}

#[tokio::test]
async fn sqlite_import_governed_namespace_denies_3456() {
    governed_namespace_denies(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_governed_namespace_denies_3456() {
    governed_namespace_denies(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// ALLOWED — the SAME policy admits once the caller satisfies it
// ---------------------------------------------------------------------------

async fn governed_namespace_allows(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    bind_standard(&db_path, &policy_with_write(GovernanceLevel::Registered));
    register_admin(&db_path);
    let id = uuid::Uuid::new_v4().to_string();

    let (status, body) =
        import_as_admin(&router, json!({ "memories": [row(&id, "allowed row")] })).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["imported"],
        json!(1),
        "a caller who satisfies the standard must be admitted: {body}"
    );
    assert!(
        body["errors"].as_array().is_some_and(Vec::is_empty),
        "an admitted row must produce no row error: {body}"
    );
    let stored = stored(&db_path, &id).expect("the admitted row must be persisted");
    assert_eq!(stored.title, "allowed row");
}

#[tokio::test]
async fn sqlite_import_governed_namespace_allows_3456() {
    governed_namespace_allows(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_governed_namespace_allows_3456() {
    governed_namespace_allows(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// PENDING — an `Approve` standard is now EXPRESSIBLE on the sqlite envelope
// ---------------------------------------------------------------------------

async fn approve_standard_parks_pending(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    bind_standard(&db_path, &policy_with_write(GovernanceLevel::Approve));
    register_admin(&db_path);
    let id = uuid::Uuid::new_v4().to_string();

    let (status, body) =
        import_as_admin(&router, json!({ "memories": [row(&id, "pending row")] })).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["imported"], json!(0), "{body}");
    let pending = body["pending"]
        .as_array()
        .expect("the sqlite envelope must carry `pending` (#3456)");
    assert_eq!(pending.len(), 1, "{body}");
    assert_eq!(pending[0]["id"].as_str(), Some(id.as_str()), "{body}");
    assert_eq!(
        pending[0]["namespace"].as_str(),
        Some(GOVERNED_NS),
        "{body}"
    );
    assert!(
        pending[0]["pending_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the parked row must carry a pending_id the caller can drive: {body}"
    );
    assert!(
        stored(&db_path, &id).is_none(),
        "a row awaiting approval must not be live"
    );
}

#[tokio::test]
async fn sqlite_import_approve_standard_parks_pending_3456() {
    approve_standard_parks_pending(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_approve_standard_parks_pending_3456() {
    approve_standard_parks_pending(StorageBackend::Postgres).await;
}

// ---------------------------------------------------------------------------
// Control — an UNGOVERNED namespace is unaffected (no new refusal surface)
// ---------------------------------------------------------------------------

async fn ungoverned_namespace_is_unchanged(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    // No standard bound: the fail-closed ungoverned refusal is opt-in via
    // `AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE=1`, which this test
    // does NOT set, so the row must still land exactly as before #3456.
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) =
        import_as_admin(&router, json!({ "memories": [row(&id, "ungoverned row")] })).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["imported"], json!(1), "{body}");
    assert!(stored(&db_path, &id).is_some());
}

#[tokio::test]
async fn sqlite_import_ungoverned_namespace_unchanged_3456() {
    ungoverned_namespace_is_unchanged(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_import_ungoverned_namespace_unchanged_3456() {
    ungoverned_namespace_is_unchanged(StorageBackend::Postgres).await;
}
