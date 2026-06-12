// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage lift (operator 90%-per-module floor, 2026-06-11) for the
//! happy-path + edge arms of `handlers/governance.rs`,
//! `handlers/capture_turn.rs`, and `handlers/admin.rs` that the
//! pre-existing suites leave dark.
//!
//! The in-file `src/handlers/tests.rs` exercises the
//! `approve_pending` / `reject_pending` HMAC gate, the unknown-id 404,
//! and the invalid-agent-id 400 — but NOT the `ApproveOutcome::Approved`
//! → `execute_pending_action` success arm, the `Ok(true)` reject arm, or
//! `list_pending`. `tests/k10_approval_http.rs` covers the *new* K10
//! `/api/v1/approvals/{id}` route, not the legacy
//! `/api/v1/pending/{id}/{approve,reject}` pair these handlers serve.
//! This file drives those sqlite-branch success paths against a real
//! seeded `pending_actions` row, plus a fake-postgres `capture_turn`
//! round-trip and a few admin gate arms.

#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_closure_for_method_calls)]
// `HMAC_LOCK` is a process-global serialisation guard held across the
// approve/reject request `await` so the K7 HMAC secret can't be flipped
// mid-request by a sibling test — the same idiom (and same allow) as
// `tests/k10_approval_postgres_dispatch_1618.rs`.
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

mod common;

/// The legacy `approve_pending` / `reject_pending` handlers verify HMAC
/// against the process-global `set_active_hooks_hmac_secret`. Serialise
/// these tests so one test's secret cannot flip out from under another's
/// in-flight request (same idiom as `src/handlers/tests.rs::
/// APPROVE_HMAC_TEST_LOCK`).
static HMAC_LOCK: StdMutex<()> = StdMutex::new(());

const TEST_SECRET: &str = "cov-gov-1660-secret";

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, Db) {
    // The admin-gate (#1570) treats a self-asserted `X-Agent-Id` naming
    // an admin id as trusted ONLY when the daemon has request
    // authentication configured (or the header-trust escape hatch is
    // set). Mark authn configured so the `admin_agent_ids = ["*"]`
    // wildcard sentinel admits the caller — the same posture the in-file
    // `test_app_state` scaffold establishes via
    // `install_security_bypass_for_legacy_tests`.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
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
        // `"*"` wildcard arm in `is_admin_caller` is compiled out (it is
        // `#[cfg(test)]`-gated per #980). Enumerate the explicit admin
        // caller ids these tests assert against instead.
        admin_agent_ids: Arc::new(vec!["admin-caller".to_string(), "lister".to_string()]),
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

/// K7-style `(timestamp, signature)` for an approve/reject body, mirroring
/// `src/handlers/tests.rs::sign_approve_body`.
fn sign_approve(secret: &str, method: &str, pending_id: &str, body: &[u8]) -> (String, String) {
    let ts = chrono::Utc::now().timestamp().to_string();
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let sig = common::sign_canonical(secret, &ts, method, pending_id, body_str);
    (ts, format!("sha256={sig}"))
}

/// Seed a memory + a queued `Delete` pending row targeting it (the
/// delete branch of `execute_pending_action` only needs a valid
/// `memory_id`). Returns the pending id.
async fn seed_delete_pending(db: &Db, namespace: &str, requested_by: &str) -> String {
    let lock = db.lock().await;
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: "cov-gov-target".into(),
        content: "pending-delete target body".into(),
        source: "test".into(),
        confidence: 1.0,
        priority: 5,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&lock.0, &mem).expect("insert memory");
    let payload = json!({"reason": "cov-gov-1660"});
    ai_memory::db::queue_pending_action(
        &lock.0,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&mem_id),
        requested_by,
        &payload,
    )
    .expect("queue_pending_action")
}

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn signed_post(
    router: &axum::Router,
    uri: &str,
    pending_id: &str,
    agent_id: &str,
) -> (StatusCode, Value) {
    let (ts, sig) = sign_approve(TEST_SECRET, "POST", pending_id, b"");
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .header("x-ai-memory-timestamp", ts)
        .header("x-ai-memory-signature", sig)
        .body(Body::empty())
        .unwrap();
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

// ===========================================================================
// governance.rs — approve_pending / reject_pending sqlite happy paths
// ===========================================================================

#[tokio::test]
async fn approve_pending_executes_delete_and_returns_200() {
    let _guard = HMAC_LOCK.lock().unwrap();
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, _f, db) = build_router(StorageBackend::Sqlite);
    let pending_id = seed_delete_pending(&db, "cov-gov-approve", "approver").await;
    let (status, v) = signed_post(
        &router,
        &format!("/api/v1/pending/{pending_id}/approve"),
        &pending_id,
        "approver",
    )
    .await;
    ai_memory::config::set_active_hooks_hmac_secret(None);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["approved"], json!(true), "{v}");
    assert_eq!(v["executed"], json!(true), "{v}");
    assert_eq!(
        v[ai_memory::models::field_names::DECIDED_BY],
        json!("approver"),
        "{v}"
    );
}

#[tokio::test]
async fn reject_pending_marks_rejected_and_returns_200() {
    let _guard = HMAC_LOCK.lock().unwrap();
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, _f, db) = build_router(StorageBackend::Sqlite);
    let pending_id = seed_delete_pending(&db, "cov-gov-reject", "rejecter").await;
    let (status, v) = signed_post(
        &router,
        &format!("/api/v1/pending/{pending_id}/reject"),
        &pending_id,
        "rejecter",
    )
    .await;
    ai_memory::config::set_active_hooks_hmac_secret(None);
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["rejected"], json!(true), "{v}");
    assert_eq!(
        v[ai_memory::models::field_names::DECIDED_BY],
        json!("rejecter"),
        "{v}"
    );
}

#[tokio::test]
async fn list_pending_admin_sees_seeded_row_sqlite() {
    let (router, _f, db) = build_router(StorageBackend::Sqlite);
    let _ = seed_delete_pending(&db, "cov-gov-list", "lister").await;
    // admin_agent_ids = ["*"] in build_router → the "lister" caller is
    // treated as admin and sees the queue (owner_scope=admin).
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/pending?limit=50")
        .header("x-agent-id", "lister")
        .body(Body::empty())
        .unwrap();
    let (status, v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["count"].as_u64().is_some_and(|c| c >= 1), "{v}");
    assert_eq!(
        v[ai_memory::models::field_names::OWNER_SCOPE],
        json!("admin"),
        "{v}"
    );
}

#[tokio::test]
async fn approve_pending_invalid_id_format_returns_400() {
    let _guard = HMAC_LOCK.lock().unwrap();
    ai_memory::config::set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let bad = "not a valid id!!";
    let (ts, sig) = sign_approve(TEST_SECRET, "POST", bad, b"");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/pending/not%20a%20valid%20id%21%21/approve")
        .header("x-agent-id", "approver")
        .header("x-ai-memory-timestamp", ts)
        .header("x-ai-memory-signature", sig)
        .body(Body::empty())
        .unwrap();
    let (status, _v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    ai_memory::config::set_active_hooks_hmac_secret(None);
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// capture_turn.rs — fake-postgres SAL round-trip + agent-id resolve error
// ===========================================================================

#[tokio::test]
async fn capture_turn_fake_pg_sal_path_creates_then_dedups() {
    // storage_backend=Postgres with an SqliteStore handle drives the
    // `#[cfg(feature="sal")]` SAL `capture_turn_idempotent` arm.
    let (router, _f, _db) = build_router(StorageBackend::Postgres);
    let body = json!({
        "host_session_id": "cov-pg-sess",
        "host_turn_index": 0,
        "role": "user",
        "content": "L4 capture via the postgres-claiming SAL path",
    });
    let mk = |b: &Value| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/capture_turn")
            .header("content-type", "application/json")
            .header("x-agent-id", "pg-l4")
            .body(Body::from(serde_json::to_vec(b).unwrap()))
            .unwrap()
    };
    let (s1, v1) = read_json(router.clone().oneshot(mk(&body)).await.unwrap()).await;
    assert_eq!(s1, StatusCode::CREATED, "fresh L4 capture: {v1}");
    assert_eq!(v1["dedup_hit"], json!(false), "{v1}");
    let id = v1["memory_id"].as_str().expect("memory_id").to_string();
    // Idempotent replay → 200 dedup_hit:true, same id.
    let (s2, v2) = read_json(router.clone().oneshot(mk(&body)).await.unwrap()).await;
    assert_eq!(s2, StatusCode::OK, "replay: {v2}");
    assert_eq!(v2["dedup_hit"], json!(true), "{v2}");
    assert_eq!(v2["memory_id"], json!(id), "{v2}");
}

#[tokio::test]
async fn capture_turn_invalid_agent_id_header_returns_400() {
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let body = json!({
        "host_session_id": "cov-badid",
        "host_turn_index": 0,
        "role": "user",
        "content": "x",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/capture_turn")
        .header("content-type", "application/json")
        .header("x-agent-id", "bad id with spaces!!")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// admin.rs — register_agent sqlite happy path + bind_pubkey + run_gc
// ===========================================================================

#[tokio::test]
async fn register_agent_sqlite_happy_returns_201() {
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let body = json!({
        "agent_id": "cov-agent-1",
        "agent_type": "ai:claude-opus-4.7",
        "capabilities": ["recall", "store"],
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/agents")
        .header("content-type", "application/json")
        .header("x-agent-id", "cov-agent-1")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "register: {status} {v}",
    );
}

#[tokio::test]
async fn run_gc_admin_returns_200_sqlite() {
    // admin_agent_ids=["*"] → caller passes the admin gate.
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("content-type", "application/json")
        .header("x-agent-id", "admin-caller")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let (status, v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn export_memories_admin_returns_200_sqlite() {
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/export")
        .header("x-agent-id", "admin-caller")
        .body(Body::empty())
        .unwrap();
    let (status, v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(
        v.get("memories").is_some() || v.get("count").is_some(),
        "{v}"
    );
}

#[tokio::test]
async fn get_stats_admin_returns_200_sqlite() {
    let (router, _f, _db) = build_router(StorageBackend::Sqlite);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/stats")
        .header("x-agent-id", "admin-caller")
        .body(Body::empty())
        .unwrap();
    let (status, _v) = read_json(router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}
