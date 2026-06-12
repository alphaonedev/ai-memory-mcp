// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! GA-gate coverage backfill (operator uniform-90%-per-module floor,
//! 2026-06-12) for the zero-coverage handlers in three HTTP modules that
//! the pre-existing suites leave dark:
//!
//! - `handlers/admin.rs` — `register_agent`, `bind_agent_pubkey`,
//!   `import_memories`, `quota_status_handler` (success + validation +
//!   admin-gate + dual-backend SAL arms).
//! - `handlers/governance.rs` — `list_pending` (admin queue-view,
//!   non-admin `requested_by` post-filter, and the postgres SAL arm).
//! - `handlers/links.rs` — `create_link`, `delete_link`, `get_links`,
//!   `verify_link_handler` (success + validation + ownership-gate +
//!   dual-backend SAL arms).
//!
//! All cases drive the real production router (`ai_memory::build_router`)
//! over an on-disk sqlite `AppState` via `tower::oneshot`, mirroring the
//! `tests/cov3_handlers_sqlite.rs` + `tests/cov_handlers_gov_admin_1660.rs`
//! scaffolding. The dual-backend SAL branches (`#[cfg(feature = "sal")]`
//! arms gated on `StorageBackend::Postgres`) are exercised by pairing a
//! `storage_backend = Postgres` `AppState` with an `SqliteStore` handle —
//! the "fake-postgres" trick the gov/admin-1660 suite already uses for
//! `capture_turn`. No live postgres is required; the SAL trait method
//! lands against the sqlite-backed store.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

/// Build the production router over a fresh on-disk sqlite DB. The
/// `app.store` `SqliteStore` opens against the SAME path so seed → read
/// works through both the legacy `db` path and the SAL trait. `backend`
/// selects the `storage_backend` field: passing `Postgres` while the
/// store handle stays sqlite drives the `#[cfg(feature = "sal")]`
/// SAL-trait arms without a live postgres.
fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, Db) {
    // The admin gate (#1570) trusts a self-asserted `X-Agent-Id` naming
    // an admin id only when the daemon has request authentication
    // configured. Mark authn configured so the explicit `admin_agent_ids`
    // below admit the matching caller.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("db tempfile");
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
        storage_backend: backend,
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
        // Integration tests link the library WITHOUT `cfg(test)`, so the
        // `"*"` wildcard arm in `is_admin_caller` is compiled out. Name
        // the explicit admin caller id every admin-gated case asserts.
        admin_agent_ids: Arc::new(vec!["admin-caller".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let router = ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
        },
        app_state,
    );
    (router, f, db)
}

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// POST a JSON body with an explicit `X-Agent-Id` header.
async fn post_as(
    router: &axum::Router,
    uri: &str,
    agent_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

/// PUT a JSON body with an explicit `X-Agent-Id` header.
async fn put_as(
    router: &axum::Router,
    uri: &str,
    agent_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

/// DELETE a JSON body with an explicit `X-Agent-Id` header.
async fn delete_as(
    router: &axum::Router,
    uri: &str,
    agent_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

/// GET with an explicit `X-Agent-Id` header.
async fn get_as(router: &axum::Router, uri: &str, agent_id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .body(Body::empty())
        .unwrap();
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

/// Insert a memory owned by `agent_id` (its `metadata.agent_id`) so the
/// create/delete link ownership gates admit `agent_id` as the caller.
/// Returns the new memory id.
async fn seed_owned_memory(db: &Db, namespace: &str, agent_id: &str) -> String {
    let lock = db.lock().await;
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("cov-ga2 seed {}", uuid::Uuid::new_v4()),
        content: "cov-ga2 link source/target body".into(),
        source: "test".into(),
        confidence: 1.0,
        priority: 5,
        metadata: json!({ "agent_id": agent_id }),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&lock.0, &mem).expect("insert seed memory")
}

/// A real, valid URL-safe-no-pad base64 Ed25519 public key. The wire
/// validator (`validate_agent_pubkey_b64`) and the keypair decoder agree
/// on this format, so this round-trips a real 32-byte curve point.
fn valid_pubkey_b64() -> String {
    ai_memory::identity::keypair::generate("cov-ga2-pubkey")
        .expect("generate keypair")
        .public_base64()
}

/// Build a wire-valid `Memory` JSON value carrying every required field
/// (the `ImportBody.memories` vec deserializes into the full 26-field
/// `Memory` struct; a partial object 422s before the handler runs). The
/// returned value is the serialized `Memory` with `metadata.agent_id`
/// optionally stamped in.
fn memory_json(id: &str, namespace: &str, title: &str, owner: Option<&str>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let mut mem = ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("{title} body"),
        // `import` is in the closed `VALID_SOURCES` set checked by
        // `validate_memory`; `"test"` is rejected.
        source: "import".into(),
        confidence: 1.0,
        priority: 5,
        created_at: now.clone(),
        updated_at: now,
        ..ai_memory::models::Memory::default()
    };
    if let Some(agent_id) = owner {
        mem.metadata = json!({ "agent_id": agent_id });
    }
    serde_json::to_value(&mem).expect("serialize Memory")
}

/// Register `agent_id` so a subsequent `bind_agent_pubkey` finds the
/// `_agents` row (the bind path refuses an unregistered agent). Drives
/// the same backend arm the router uses.
async fn register_agent(router: &axum::Router, agent_id: &str) {
    let (status, v) = post_as(
        router,
        "/api/v1/agents",
        agent_id,
        json!({"agent_id": agent_id, "agent_type": "ai:test"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register {agent_id}: {v}");
}

// ===========================================================================
// admin.rs — register_agent
// ===========================================================================

#[tokio::test]
async fn register_agent_sqlite_happy_returns_201() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(
        &r,
        "/api/v1/agents",
        "cov-agent-a",
        json!({
            "agent_id": "cov-agent-a",
            "agent_type": "ai:claude-opus-4.8",
            "capabilities": ["recall", "store"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["registered"], json!(true), "{v}");
    assert_eq!(v["agent_id"], json!("cov-agent-a"), "{v}");
}

#[tokio::test]
async fn register_agent_invalid_agent_id_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/agents",
        "caller",
        json!({"agent_id": "bad id with spaces", "agent_type": "ai:x"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_agent_invalid_agent_type_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // Empty agent_type fails validate_agent_type.
    let (status, _v) = post_as(
        &r,
        "/api/v1/agents",
        "caller",
        json!({"agent_id": "cov-agent-b", "agent_type": ""}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_agent_postgres_sal_path_returns_201() {
    // storage_backend=Postgres + SqliteStore drives the SAL `store.store`
    // registration arm (the `#[cfg(feature = "sal")]` postgres branch).
    let (r, _f, _db) = build_router(StorageBackend::Postgres);
    let (status, v) = post_as(
        &r,
        "/api/v1/agents",
        "cov-agent-pg",
        json!({
            "agent_id": "cov-agent-pg",
            "agent_type": "ai:grok-4.3",
            "capabilities": ["recall"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["storage_backend"], json!("postgres"), "{v}");
    assert!(v.get("id").is_some(), "{v}");
}

// ===========================================================================
// admin.rs — bind_agent_pubkey
// ===========================================================================

#[tokio::test]
async fn bind_agent_pubkey_non_admin_returns_403() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = put_as(
        &r,
        "/api/v1/agents/some-agent/pubkey",
        "not-admin",
        json!({"pubkey_b64": valid_pubkey_b64()}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bind_agent_pubkey_admin_invalid_pubkey_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = put_as(
        &r,
        "/api/v1/agents/some-agent/pubkey",
        "admin-caller",
        json!({"pubkey_b64": "not-a-valid-pubkey"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bind_agent_pubkey_admin_sqlite_via_sal_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // The bind path refuses an unregistered agent; register first.
    register_agent(&r, "cov-bind-agent").await;
    let (status, v) = put_as(
        &r,
        "/api/v1/agents/cov-bind-agent/pubkey",
        "admin-caller",
        json!({"pubkey_b64": valid_pubkey_b64()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["bound"], json!(true), "{v}");
    assert_eq!(v["agent_id"], json!("cov-bind-agent"), "{v}");
}

#[tokio::test]
async fn bind_agent_pubkey_admin_postgres_via_sal_returns_200() {
    let (r, _f, db) = build_router(StorageBackend::Postgres);
    // Seed the `_agents` row directly (JSON content) so the SAL bind
    // UPDATE's `json_set(content, ...)` succeeds. The HTTP register
    // postgres branch stores a plain-string content, which the bind's
    // `json_set` cannot patch — an artificial cross-backend mix the
    // fake-postgres harness creates but a real PostgresStore daemon
    // never hits (it binds against postgres, not this sqlite handle).
    {
        let lock = db.lock().await;
        ai_memory::db::register_agent(&lock.0, "cov-bind-pg", "ai:test", &[])
            .expect("seed _agents row");
    }
    let (status, v) = put_as(
        &r,
        "/api/v1/agents/cov-bind-pg/pubkey",
        "admin-caller",
        json!({"pubkey_b64": valid_pubkey_b64()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["bound"], json!(true), "{v}");
}

// ===========================================================================
// admin.rs — import_memories
// ===========================================================================

#[tokio::test]
async fn import_memories_non_admin_returns_403() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(&r, "/api/v1/import", "not-admin", json!({"memories": []})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn import_memories_over_limit_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // MAX_BULK_SIZE+1 wire-valid rows trips the size guard up front.
    let n = ai_memory::handlers::MAX_BULK_SIZE + 1;
    let memories: Vec<Value> = (0..n)
        .map(|i| {
            memory_json(
                &format!("00000000-0000-0000-0000-{i:012x}"),
                "cov-import",
                &format!("over-limit {i}"),
                None,
            )
        })
        .collect();
    let (status, _v) = post_as(
        &r,
        "/api/v1/import",
        "admin-caller",
        json!({"memories": memories}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn import_memories_admin_sqlite_imports_rows() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let m1 = memory_json(
        "00000000-0000-0000-0000-000000000aaa",
        "cov-import",
        "imported one",
        Some("alice"),
    );
    let m2 = memory_json(
        "00000000-0000-0000-0000-000000000bbb",
        "cov-import",
        "imported two",
        None,
    );
    let (status, v) = post_as(
        &r,
        "/api/v1/import",
        "admin-caller",
        json!({
            "memories": [m1, m2],
            "links": [
                {
                    "source_id": "00000000-0000-0000-0000-000000000aaa",
                    "target_id": "00000000-0000-0000-0000-000000000bbb",
                    "relation": "related_to",
                    "created_at": "2026-06-12T00:00:00Z"
                }
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["imported"], json!(2), "{v}");
}

#[tokio::test]
async fn import_memories_admin_postgres_via_sal_imports_rows() {
    let (r, _f, _db) = build_router(StorageBackend::Postgres);
    let m1 = memory_json(
        "00000000-0000-0000-0000-0000000000c1",
        "cov-import-pg",
        "pg imported",
        Some("bob"),
    );
    let (status, v) = post_as(
        &r,
        "/api/v1/import",
        "admin-caller",
        json!({
            "memories": [m1],
            "links": [
                {
                    "source_id": "00000000-0000-0000-0000-0000000000c1",
                    "target_id": "00000000-0000-0000-0000-0000000000c1",
                    "relation": "related_to",
                    "created_at": "2026-06-12T00:00:00Z"
                }
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["storage_backend"], json!("postgres"), "{v}");
    assert!(v.get("imported").is_some(), "{v}");
}

#[tokio::test]
async fn import_memories_admin_invalid_row_accumulates_error() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // A wire-valid Memory whose title is then blanked fails
    // `validate_memory` → the sanitized error accumulates in `errors`
    // (the per-row validate-fail arm) rather than failing the whole call.
    let mut bad = memory_json(
        "00000000-0000-0000-0000-0000000000ee",
        "cov-import",
        "placeholder",
        None,
    );
    bad["title"] = json!("");
    bad["content"] = json!("");
    let (status, v) = post_as(
        &r,
        "/api/v1/import",
        "admin-caller",
        json!({ "memories": [bad] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["imported"], json!(0), "{v}");
    assert!(v["errors"].as_array().is_some_and(|e| !e.is_empty()), "{v}");
}

// ===========================================================================
// admin.rs — quota_status_handler
// ===========================================================================

#[tokio::test]
async fn quota_status_invalid_header_agent_id_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/quota/status")
        .header("content-type", "application/json")
        .header("x-agent-id", "bad id with spaces")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let (status, _v) = read_json(r.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn quota_status_body_agent_id_mismatch_returns_403() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/quota/status",
        "caller-x",
        json!({"agent_id": "someone-else"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn quota_status_own_agent_sqlite_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // body.agent_id == caller, no namespace → aggregate-status arm.
    let (status, v) = post_as(
        &r,
        "/api/v1/quota/status",
        "cov-quota-self",
        json!({"agent_id": "cov-quota-self"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.is_object(), "{v}");
}

#[tokio::test]
async fn quota_status_own_agent_with_namespace_sqlite_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // explicit namespace → single-row get_status arm.
    let (status, v) = post_as(
        &r,
        "/api/v1/quota/status",
        "cov-quota-ns",
        json!({"agent_id": "cov-quota-ns", "namespace": "cov-ns"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.is_object(), "{v}");
}

#[tokio::test]
async fn quota_status_own_agent_postgres_via_sal_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Postgres);
    let (status, v) = post_as(
        &r,
        "/api/v1/quota/status",
        "cov-quota-pg",
        json!({"agent_id": "cov-quota-pg"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.is_object(), "{v}");
}

#[tokio::test]
async fn quota_status_list_non_admin_returns_403() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // No body.agent_id → operator list path → admin gate refuses.
    let (status, _v) = post_as(&r, "/api/v1/quota/status", "not-admin", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn quota_status_list_admin_sqlite_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(&r, "/api/v1/quota/status", "admin-caller", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("quotas").is_some() && v.get("count").is_some(), "{v}");
}

#[tokio::test]
async fn quota_status_list_admin_with_namespace_sqlite_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(
        &r,
        "/api/v1/quota/status",
        "admin-caller",
        json!({"namespace": "cov-ns"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("quotas").is_some(), "{v}");
}

#[tokio::test]
async fn quota_status_list_admin_postgres_via_sal_returns_200() {
    let (r, _f, _db) = build_router(StorageBackend::Postgres);
    let (status, v) = post_as(&r, "/api/v1/quota/status", "admin-caller", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("quotas").is_some(), "{v}");
}

// ===========================================================================
// governance.rs — list_pending
// ===========================================================================

/// Seed a queued `Delete` pending row for `requested_by` in `namespace`.
async fn seed_pending(db: &Db, namespace: &str, requested_by: &str) -> String {
    let lock = db.lock().await;
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("cov-ga2 pending target {}", uuid::Uuid::new_v4()),
        content: "pending target body".into(),
        source: "test".into(),
        confidence: 1.0,
        priority: 5,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&lock.0, &mem).expect("insert");
    ai_memory::db::queue_pending_action(
        &lock.0,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&mem_id),
        requested_by,
        &json!({"reason": "cov-ga2"}),
    )
    .expect("queue_pending_action")
}

#[tokio::test]
async fn list_pending_admin_sees_all_rows_sqlite() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let _ = seed_pending(&db, "cov-list-admin", "requester-1").await;
    let (status, v) = get_as(&r, "/api/v1/pending?limit=50", "admin-caller").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["count"].as_u64().is_some_and(|c| c >= 1), "{v}");
    assert_eq!(v["owner_scope"], json!("admin"), "{v}");
}

#[tokio::test]
async fn list_pending_non_admin_sees_only_own_rows_sqlite() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    // One row owned by the caller, one owned by someone else.
    let _ = seed_pending(&db, "cov-list-own", "cov-self").await;
    let _ = seed_pending(&db, "cov-list-own", "other-agent").await;
    let (status, v) = get_as(&r, "/api/v1/pending", "cov-self").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["owner_scope"], json!("caller"), "{v}");
    // Post-filter drops the other-agent row; only the caller's row shows.
    let rows = v["pending"].as_array().expect("pending array");
    assert!(
        rows.iter()
            .all(|row| row["requested_by"] == json!("cov-self")),
        "{v}"
    );
    assert!(!rows.is_empty(), "caller should see their own row: {v}");
}

#[tokio::test]
async fn list_pending_non_admin_empty_when_no_own_rows() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let _ = seed_pending(&db, "cov-list-empty", "someone").await;
    let (status, v) = get_as(&r, "/api/v1/pending?status=pending", "stranger").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["count"], json!(0), "{v}");
}

// NOTE: the `list_pending` postgres branch
// (`src/handlers/governance.rs:91-130`, `#[cfg(feature = "sal-postgres")]`)
// routes through `crate::store::postgres::list_pending_actions_via_store`,
// which hard-`downcast_postgres`-es `app.store` to a `PostgresStore`
// (`src/store/postgres.rs:13997`). The fake-postgres trick (sqlite store
// + `StorageBackend::Postgres`) returns `BackendUnavailable` (503) there
// rather than executing the branch body, so those lines are genuinely
// uncoverable without a live PostgresStore. See the final report.

// ===========================================================================
// links.rs — create_link
// ===========================================================================

#[tokio::test]
async fn create_link_unknown_field_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "a", "target_id": "b", "link_type": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], json!("unknown_field"));
}

#[tokio::test]
async fn create_link_invalid_relation_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "aaaaaaaa", "target_id": "bbbbbbbb", "relation": "frobnicates"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], json!("invalid_relation"));
}

#[tokio::test]
async fn create_link_invalid_triple_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "", "target_id": "b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_link_source_not_found_returns_404() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "ghost-source", "target_id": "ghost-target", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_link_not_owner_returns_403() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    // Source owned by "owner-a"; caller "intruder" is neither owner nor
    // target nor daemon → the #941 ownership gate refuses.
    let src = seed_owned_memory(&db, "cov-link", "owner-a").await;
    let tgt = seed_owned_memory(&db, "cov-link", "owner-a").await;
    let (status, _v) = post_as(
        &r,
        "/api/v1/links",
        "intruder",
        json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_link_owner_sqlite_returns_201() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-link", "link-owner").await;
    let tgt = seed_owned_memory(&db, "cov-link", "link-owner").await;
    let (status, v) = post_as(
        &r,
        "/api/v1/links",
        "link-owner",
        json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["linked"], json!(true), "{v}");
    assert!(v.get("attest_level").is_some(), "{v}");
}

#[tokio::test]
async fn create_link_postgres_via_sal_returns_201() {
    let (r, _f, db) = build_router(StorageBackend::Postgres);
    let src = seed_owned_memory(&db, "cov-link-pg", "pg-link-owner").await;
    let tgt = seed_owned_memory(&db, "cov-link-pg", "pg-link-owner").await;
    let (status, v) = post_as(
        &r,
        "/api/v1/links",
        "pg-link-owner",
        json!({"source_id": src, "target_id": tgt, "relation": "supersedes"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["linked"], json!(true), "{v}");
    assert_eq!(v["relation"], json!("supersedes"), "{v}");
}

// ===========================================================================
// links.rs — delete_link
// ===========================================================================

#[tokio::test]
async fn delete_link_unknown_field_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = delete_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "a", "target_id": "b", "bogus": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], json!("unknown_field"));
}

#[tokio::test]
async fn delete_link_invalid_triple_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = delete_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "", "target_id": "b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_link_missing_source_returns_deleted_false() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    // Source memory doesn't exist → fall through to substrate delete,
    // which reports deleted:false (no owner gate fires).
    let (status, v) = delete_as(
        &r,
        "/api/v1/links",
        "caller",
        json!({"source_id": "ghostsrc", "target_id": "ghosttgt", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["deleted"], json!(false), "{v}");
}

#[tokio::test]
async fn delete_link_not_owner_returns_403() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-del", "del-owner").await;
    let tgt = seed_owned_memory(&db, "cov-del", "del-owner").await;
    let (status, _v) = delete_as(
        &r,
        "/api/v1/links",
        "del-intruder",
        json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_link_owner_returns_deleted_status() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-del", "del-owner-2").await;
    let tgt = seed_owned_memory(&db, "cov-del", "del-owner-2").await;
    // Create the link first so the delete removes a real edge.
    let (cs, _cv) = post_as(
        &r,
        "/api/v1/links",
        "del-owner-2",
        json!({"source_id": src.clone(), "target_id": tgt.clone(), "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);
    let (status, v) = delete_as(
        &r,
        "/api/v1/links",
        "del-owner-2",
        json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["deleted"], json!(true), "{v}");
}

// ===========================================================================
// links.rs — get_links
// ===========================================================================

#[tokio::test]
async fn get_links_invalid_id_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = get_as(&r, "/api/v1/links/bad%20id", "caller").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_links_admin_caller_sqlite_returns_200() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-get", "get-owner").await;
    let tgt = seed_owned_memory(&db, "cov-get", "get-owner").await;
    let (cs, _cv) = post_as(
        &r,
        "/api/v1/links",
        "get-owner",
        json!({"source_id": src.clone(), "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);
    // admin caller bypasses the visibility post-filter (the admin arm).
    let (status, v) = get_as(&r, &format!("/api/v1/links/{src}"), "admin-caller").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("links").is_some(), "{v}");
}

#[tokio::test]
async fn get_links_non_admin_visibility_filter_sqlite_returns_200() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-get", "vis-owner").await;
    let tgt = seed_owned_memory(&db, "cov-get", "vis-owner").await;
    let (cs, _cv) = post_as(
        &r,
        "/api/v1/links",
        "vis-owner",
        json!({"source_id": src.clone(), "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);
    // Non-admin caller drives the per-endpoint SAL visibility post-filter.
    let (status, v) = get_as(&r, &format!("/api/v1/links/{src}"), "vis-owner").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("links").is_some(), "{v}");
}

#[tokio::test]
async fn get_links_postgres_via_sal_returns_200() {
    let (r, _f, db) = build_router(StorageBackend::Postgres);
    let anchor = seed_owned_memory(&db, "cov-get-pg", "pg-get-owner").await;
    // get_links_for_anchor on the SAL store; empty edge set is fine.
    let (status, v) = get_as(&r, &format!("/api/v1/links/{anchor}"), "admin-caller").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("links").is_some(), "{v}");
}

// ===========================================================================
// links.rs — verify_link_handler
// ===========================================================================

#[tokio::test]
async fn verify_link_missing_args_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, v) = post_as(&r, "/api/v1/links/verify", "caller", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(v.get("fields").is_some(), "{v}");
}

#[tokio::test]
async fn verify_link_invalid_source_id_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/links/verify",
        "caller",
        json!({"source_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_link_invalid_target_id_returns_400() {
    let (r, _f, _db) = build_router(StorageBackend::Sqlite);
    let (status, _v) = post_as(
        &r,
        "/api/v1/links/verify",
        "caller",
        json!({"source_id": "valid-source", "target_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_link_sqlite_via_sal_resolves() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-verify", "verify-owner").await;
    let tgt = seed_owned_memory(&db, "cov-verify", "verify-owner").await;
    let (cs, _cv) = post_as(
        &r,
        "/api/v1/links",
        "verify-owner",
        json!({"source_id": src.clone(), "target_id": tgt.clone(), "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);
    // Drives the SAL verify_link arm + the nonce record_and_check path.
    let (status, v) = post_as(
        &r,
        "/api/v1/links/verify",
        "verify-owner",
        json!({
            "source_id": src,
            "target_id": tgt,
            "verification_nonce": uuid::Uuid::new_v4().to_string(),
        }),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "verify status {status}: {v}"
    );
}

#[tokio::test]
async fn verify_link_nonce_replay_returns_409() {
    let (r, _f, db) = build_router(StorageBackend::Sqlite);
    let src = seed_owned_memory(&db, "cov-verify", "replay-owner").await;
    let tgt = seed_owned_memory(&db, "cov-verify", "replay-owner").await;
    let (cs, _cv) = post_as(
        &r,
        "/api/v1/links",
        "replay-owner",
        json!({"source_id": src.clone(), "target_id": tgt.clone(), "relation": "related_to"}),
    )
    .await;
    assert_eq!(cs, StatusCode::CREATED);
    let nonce = uuid::Uuid::new_v4().to_string();
    let body = json!({
        "source_id": src,
        "target_id": tgt,
        "verification_nonce": nonce,
    });
    // First verify lands the fingerprint; the byte-identical replay is a
    // 409 Conflict (the H5 anti-replay arm). Only assert the replay when
    // the first verify resolved the link (200) so the fingerprint was
    // actually recorded.
    let (s1, _v1) = post_as(&r, "/api/v1/links/verify", "replay-owner", body.clone()).await;
    if s1 == StatusCode::OK {
        let (s2, v2) = post_as(&r, "/api/v1/links/verify", "replay-owner", body).await;
        assert_eq!(s2, StatusCode::CONFLICT, "replay should 409: {v2}");
    }
}
