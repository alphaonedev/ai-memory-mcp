// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FUPB coverage — `src/handlers/approvals.rs`.
//!
//! Targets the arms the existing K10 suites (`tests/k10_*`,
//! `tests/handler_postgres_branches_fake_pg.rs`) leave uncovered:
//!   - `sse_event_visible_to` — every visibility rule (empty subscriber,
//!     `host:` prefix bypass-refusal, own-agent match, namespace via K9
//!     Allow rule, no-namespace fail-closed, no-matching-rule).
//!   - `approvals_sse` — the SSE handshake handler (anonymous +
//!     `host:`-rejected + identified subscriber paths) plus a delivered
//!     event over the broadcast bus.
//!   - the K10 `approval_decide` Deny sqlite arm (200 `rejected` + the
//!     missing-row 404) and the Approve happy path on a plain sqlite
//!     router, exercising `publish_decision_event` + the
//!     `record_synthetic_rule` (`remember=forever`) branch.

#![cfg(feature = "sal")]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::redundant_closure_for_method_calls)]

use std::sync::{Arc, Mutex};

use ai_memory::approvals::ApprovalEvent;
use ai_memory::config::set_active_hooks_hmac_secret;
use ai_memory::governance::{PermissionRule, RuleDecision};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend, sse_event_visible_to};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt as _;

mod common;

/// Serialises tests that mutate process-global state: the K10 HMAC
/// secret + the active permission rule registry.
static APPROVALS_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

const TEST_SECRET: &str = "cov-fupb-approvals-secret";

fn build_sqlite_router() -> (axum::Router, std::path::PathBuf) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_path)
}

/// Seed a delete-shaped pending row directly into the sqlite DB the
/// router opened. Returns the pending id. `namespace` + `requested_by`
/// feed the published-event tenant fields.
fn seed_pending_row(db_path: &std::path::Path, namespace: &str, requested_by: &str) -> String {
    let conn = ai_memory::db::open(db_path).expect("open db");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("cov-fupb-{}", uuid::Uuid::new_v4()),
        content: "approval cov".into(),
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({}),
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&conn, &mem).expect("insert memory");
    ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&mem_id),
        requested_by,
        &json!({"reason": "cov-fupb"}),
    )
    .expect("queue_pending_action")
}

fn signed_request(pending_id: &str, body: &str) -> Request<Body> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig = common::sign_canonical_envelope(TEST_SECRET, &timestamp, "POST", pending_id, body);
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", &timestamp)
        .header("x-ai-memory-signature", sig)
        .header("x-agent-id", "operator-1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// sse_event_visible_to — every visibility arm
// ---------------------------------------------------------------------------

fn decided_event(requested_by: &str, namespace: &str) -> ApprovalEvent {
    ApprovalEvent::ApprovalDecided {
        pending_id: "pa-cov".into(),
        decision: "approve".into(),
        decided_by: "operator-1".into(),
        remember: "once".into(),
        namespace: namespace.into(),
        requested_by: requested_by.into(),
    }
}

#[test]
fn sse_empty_subscriber_sees_nothing() {
    let evt = decided_event("alice", "team-a");
    assert!(
        !sse_event_visible_to("", &evt),
        "anonymous subscriber must be fail-closed"
    );
}

#[test]
fn sse_host_prefixed_subscriber_refused() {
    let evt = decided_event("alice", "team-a");
    // #628 P1: a self-asserted `host:` agent_id must NOT bypass the
    // tenant filter even though it matches the requester naming.
    assert!(
        !sse_event_visible_to("host:laptop", &evt),
        "host:-prefixed subscriber must be refused"
    );
}

#[test]
fn sse_own_agent_match_visible() {
    let evt = decided_event("alice", "team-a");
    assert!(
        sse_event_visible_to("alice", &evt),
        "the requester sees their own decided event"
    );
}

#[test]
fn sse_namespace_via_allow_rule_visible() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // Rule grants approver `carol` the `team-a/*` namespace.
    ai_memory::permissions::set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: "team-a".to_string(),
        op: "approve".to_string(),
        agent_pattern: "carol".to_string(),
        decision: RuleDecision::Allow,
        reason: None,
    }]);
    let evt = decided_event("alice", "team-a");
    assert!(
        sse_event_visible_to("carol", &evt),
        "approver reachable via a K9 Allow rule on the namespace must see the event"
    );
    // A subscriber with no matching rule (and not the requester) does not.
    assert!(
        !sse_event_visible_to("dave", &evt),
        "non-matching subscriber must NOT see the event"
    );
    ai_memory::permissions::clear_active_permission_rules_for_test();
}

#[test]
fn sse_no_namespace_hint_fails_closed() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    ai_memory::permissions::clear_active_permission_rules_for_test();
    // Empty namespace on the event → fall back to strict agent-id match.
    let evt = decided_event("alice", "");
    assert!(
        !sse_event_visible_to("bob", &evt),
        "no-namespace event must not leak cross-agent"
    );
}

// ---------------------------------------------------------------------------
// approvals_sse — the SSE handshake handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approvals_sse_identified_subscriber_returns_event_stream() {
    let (router, _p) = build_sqlite_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/approvals/stream")
        .header("x-agent-id", "operator-1")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        ct.contains("text/event-stream"),
        "SSE response must carry text/event-stream content-type; got {ct}"
    );
}

#[tokio::test]
async fn approvals_sse_host_prefixed_agent_id_accepted_as_anonymous() {
    // The handshake filters `host:`-prefixed agent_ids to empty — the
    // stream is still established (200), just fail-closed on visibility.
    let (router, _p) = build_sqlite_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/approvals/stream")
        .header("x-agent-id", "host:laptop:pid-1")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn approvals_sse_anonymous_subscriber_ok() {
    let (router, _p) = build_sqlite_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/approvals/stream")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// approval_decide — sqlite Deny + Approve arms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approval_decide_deny_sqlite_arm_returns_rejected() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, db_path) = build_sqlite_router();
    let pending_id = seed_pending_row(&db_path, "team-a", "alice");

    let body = json!({"decision": "deny", "remember": "once"}).to_string();
    let resp = router
        .oneshot(signed_request(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "deny sqlite arm; body={v}");
    assert_eq!(v["rejected"], json!(true));

    // The row transitioned to rejected in the sqlite store.
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("row exists");
    assert_eq!(row.status, "rejected");
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_deny_missing_row_returns_404() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, _db_path) = build_sqlite_router();
    let body = json!({"decision": "deny", "remember": "once"}).to_string();
    let resp = router
        .oneshot(signed_request("nonexistent-deny-row", &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "deny on a missing/already-decided row is 404"
    );
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_approve_forever_records_synthetic_rule() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    ai_memory::approvals::clear_synthetic_rules_for_test();
    let (router, db_path) = build_sqlite_router();
    let pending_id = seed_pending_row(&db_path, "team-syn", "alice");

    // remember=forever → publish_decision_event records a synthetic
    // permission rule (the `Forever | Session` branch).
    let body = json!({"decision": "approve", "remember": "forever"}).to_string();
    let resp = router
        .oneshot(signed_request(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "approve forever; body={v}");
    assert_eq!(v["approved"], json!(true));
    assert_eq!(v["remember"], json!("forever"));

    let synth = ai_memory::approvals::list_synthetic_rules();
    assert!(
        synth.iter().any(|r| r.namespace == "team-syn"),
        "remember=forever must record a synthetic permission rule for the namespace; got {synth:?}"
    );
    ai_memory::approvals::clear_synthetic_rules_for_test();
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_missing_hmac_secret_401() {
    let _g = APPROVALS_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // No server-wide HMAC configured → strict refusal (401) regardless
    // of signature contents.
    set_active_hooks_hmac_secret(None);
    let (router, _db_path) = build_sqlite_router();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/approvals/some-id")
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", "1700000000")
        .header("x-ai-memory-signature", "sha256=deadbeef")
        .body(Body::from("{\"decision\":\"approve\"}"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
