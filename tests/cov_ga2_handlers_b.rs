// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! GA2 coverage backfill (batch B) — oracle-STRONG HTTP-router coverage
//! for three under-covered handler modules:
//!
//!   - `handlers/hook_subscribers` — `get_inbox`, the namespace-standard
//!     set / get / clear surfaces (path + query-string + postgres SAL
//!     branches incl. `merge_governance_fields_http`), and
//!     `session_start`.
//!   - `handlers/approvals` — `approval_decide` (sqlite approve / deny /
//!     404 / validation arms), `approval_decide_postgres` (fake-pg SAL
//!     dispatch), the HMAC verifier + `record_hmac_nonce` replay cache,
//!     `default_remember`, `publish_decision_event`, `approvals_sse` +
//!     `sse_event_visible_to`.
//!   - `handlers/http` — `maybe_auto_tag` (the no-LLM degradation arm,
//!     reached through `create_memory`) and `get_with_visibility_retry`
//!     (the postgres `promote_memory` path).
//!
//! Methodology: codegraph-directed reachability + oracle-STRONG
//! assertions (status, response state, persisted side-effects, error
//! envelopes). Every test drives the real production router
//! (`ai_memory::build_router`) via `tower::oneshot`.
//!
//! The postgres SAL-dispatch arms are reached with NO live postgres by
//! the "fake-pg" harness pattern (mirrors
//! `tests/k10_approval_postgres_dispatch_1618.rs`): a router whose
//! `storage_backend = Postgres` but whose `app.store` is a real
//! tempfile-backed `SqliteStore`. The handler's
//! `matches!(app.storage_backend, Postgres)` branch then dispatches
//! through the SAL trait against the sqlite-backed store, executing the
//! postgres code path end-to-end. The live-postgres variants are gated
//! on `AI_MEMORY_TEST_POSTGRES_URL` and skip when unset.
//!
//! Structural exceptions (genuinely unreachable from an integration
//! crate, recorded — not faked):
//!   - `handlers/http::maybe_detect_conflicts` (`src/handlers/http.rs:183`)
//!     and `handlers/http::fetch_namespace_candidates`
//!     (`src/handlers/http.rs:260`) are `#[allow(dead_code)]` — their
//!     call sites into `create_memory` are not yet wired (issue #519) —
//!     AND are private (`async fn` / module-private). Only the in-crate
//!     `#[cfg(test)]` `cov897_*` unit tests reach them; an external test
//!     crate cannot, so they are out of scope for this integration file.
//!   - The LLM-success and LLM-timeout arms of
//!     `handlers/http::maybe_auto_tag` require a live LLM service. CI has
//!     pg + AGE but no LLM, so only the no-LLM short-circuit arm is
//!     reachable here.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex as AsyncMutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl, set_active_hooks_hmac_secret};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

mod common;

/// Serialises every test in this binary. Two pieces of process-global
/// state are exercised: the K10 HMAC secret (`set_active_hooks_hmac_secret`)
/// and the approvals broadcast bus / synthetic-rule registry. Serial
/// execution keeps both deterministic across the multi-step
/// seed -> POST -> assert flows. Same idiom as `tests/k10_approval_http.rs`.
static GA2_LOCK: Mutex<()> = Mutex::new(());

const HMAC_SECRET: &str = "cov-ga2-handlers-b-secret";

// ---------------------------------------------------------------------------
// Harness — sqlite router (over a real on-disk DB) and the fake-pg router.
// ---------------------------------------------------------------------------

fn app_state_for(
    db: Db,
    store: Arc<dyn ai_memory::store::MemoryStore>,
    backend: StorageBackend,
) -> AppState {
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(AsyncMutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    }
}

/// Production router over a fresh on-disk sqlite DB. The legacy `app.db`
/// connection and the SAL `SqliteStore` open the SAME path so a seed via
/// either surface is visible through the other.
fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(AsyncMutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = app_state_for(db, store, StorageBackend::Sqlite);
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

/// "Fake-pg" router: `storage_backend = Postgres` but `app.store` is a
/// real tempfile-backed `SqliteStore` DISJOINT from the scratch
/// `:memory:` legacy `app.db`. Reaches the postgres SAL-dispatch arms
/// with no live postgres. Returns the router plus the store's backing
/// path so a test can seed rows the SAL branch will read.
fn fake_pg_router() -> (axum::Router, std::path::PathBuf) {
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(AsyncMutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
    let store_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
    );
    let app_state = app_state_for(db, store, StorageBackend::Postgres);
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (
        ai_memory::build_router(api_key_state, app_state),
        store_path,
    )
}

const AGENT: &str = "ai:cov-ga2-b";

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", AGENT)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn delete_req(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-agent-id", AGENT)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Build a K10-signed `POST /api/v1/approvals/{id}` request bound to the
/// canonical `(timestamp, "POST", pending_id, body)` envelope.
fn signed_approval(pending_id: &str, body: &str) -> Request<Body> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig = common::sign_canonical_envelope(HMAC_SECRET, &timestamp, "POST", pending_id, body);
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

/// Seed a memory + a delete-shaped pending row directly into a sqlite DB
/// at `path` (the SAL store backing file OR the sqlite router DB).
/// Mirrors `tests/k10_approval_http.rs::seed_pending_row_via_db`.
fn seed_pending_row(path: &std::path::Path, namespace: &str, requested_by: &str) -> String {
    let conn = ai_memory::db::open(path).expect("open backing file");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("ga2-pending-{}", uuid::Uuid::new_v4()),
        content: "ga2 pending fixture body".into(),
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
        &json!({"reason": "ga2-test"}),
    )
    .expect("queue_pending_action")
}

// ===========================================================================
// hook_subscribers — get_inbox
// ===========================================================================

#[tokio::test]
async fn inbox_sqlite_empty_returns_200_envelope() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/inbox").await;
    assert_eq!(status, StatusCode::OK);
    // The owner echoes the authenticated X-Agent-Id; messages is empty.
    assert_eq!(body["agent_id"], json!(AGENT));
    assert_eq!(body["count"], json!(0));
    assert_eq!(body["messages"], json!([]));
}

#[tokio::test]
async fn inbox_query_agent_mismatch_is_403() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // ?agent_id= disagrees with the authenticated X-Agent-Id header.
    let (status, _b) = get(&r, "/api/v1/inbox?agent_id=ai:someone-else").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "claimed agent_id != header owner must 403"
    );
}

#[tokio::test]
async fn inbox_query_agent_match_is_200() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // ?agent_id= equal to the header owner passes the gate.
    let (status, body) = get(
        &r,
        &format!("/api/v1/inbox?agent_id={AGENT}&unread_only=true"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent_id"], json!(AGENT));
    assert_eq!(
        body[ai_memory::models::field_names::UNREAD_ONLY],
        json!(true)
    );
}

#[tokio::test]
async fn inbox_populated_via_notify_round_trips() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // alice sends bob a message; bob reads his inbox and sees it.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notify")
        .header("content-type", "application/json")
        .header("x-agent-id", "alice")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "target_agent_id": "bob",
                "title": "hello-bob",
                "payload": "a notify message body for the inbox round trip",
            }))
            .unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::CREATED);

    let bob_req = Request::builder()
        .method("GET")
        .uri("/api/v1/inbox")
        .header("x-agent-id", "bob")
        .body(Body::empty())
        .unwrap();
    let (status, body) = decode(&r, bob_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent_id"], json!("bob"));
    assert_eq!(body["count"], json!(1));
    // `handle_notify` resolves the sender through `resolve_agent_id`,
    // which derives an `ai:alice@<host>:pid-…` form from the bare
    // header value — assert the substring rather than an exact match.
    let from = body["messages"][0]["from"].as_str().unwrap_or_default();
    assert!(
        from.contains("alice"),
        "sender should carry alice; got {from}"
    );
    assert_eq!(body["messages"][0]["title"], json!("hello-bob"));
    assert_eq!(body["messages"][0]["read"], json!(false));
}

#[tokio::test]
async fn inbox_postgres_branch_empty_envelope() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _p) = fake_pg_router();
    let (status, body) = get(&r, "/api/v1/inbox").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["agent_id"], json!(AGENT));
    // The postgres branch stamps storage_backend and an unread_count.
    assert_eq!(
        body[ai_memory::models::field_names::STORAGE_BACKEND],
        json!("postgres")
    );
    assert_eq!(body["unread_count"], json!(0));
    assert_eq!(body["messages"], json!([]));
}

// ===========================================================================
// hook_subscribers — namespace standard set / get / clear (sqlite)
// ===========================================================================

#[tokio::test]
async fn namespace_standard_set_get_clear_sqlite() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    let ns = "ga2-ns-sqlite";

    // POST without id auto-seeds a placeholder standard; governance blob
    // is layered into the standard memory's metadata.
    let (status, body) = post_json(
        &r,
        &format!("/api/v1/namespaces/{ns}/standard"),
        json!({"governance": {"write": "any", "promote": "any", "delete": "owner"}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "set body={body}");

    // GET via the Db path returns the resolved standard.
    let (status, body) = get(&r, &format!("/api/v1/namespaces/{ns}/standard")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get(ai_memory::models::field_names::STANDARD_ID)
            .is_some(),
        "get standard envelope must carry a standard_id key: {body}"
    );

    // DELETE clears it.
    let (status, body) = delete_req(&r, &format!("/api/v1/namespaces/{ns}/standard")).await;
    assert_eq!(status, StatusCode::OK, "clear body={body}");
}

#[tokio::test]
async fn namespace_standard_qs_form_sqlite() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    let ns = "ga2-ns-qs";

    // The path-less /namespaces POST shape carries the namespace in body.
    let (status, _b) = post_json(
        &r,
        "/api/v1/namespaces",
        json!({"namespace": ns, "governance": {"write": "registered"}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // GET /namespaces?namespace=ns resolves the just-set standard.
    let (status, body) = get(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get(ai_memory::models::field_names::STANDARD_ID)
            .is_some()
    );

    // DELETE /namespaces?namespace=ns clears it.
    let (status, _b) = delete_req(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn namespace_standard_qs_missing_namespace_is_400() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // DELETE with no ?namespace= hits the NAMESPACE_REQUIRED arm.
    let (status, _b) = delete_req(&r, "/api/v1/namespaces").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn namespace_standard_set_invalid_governance_is_400() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // A governance blob whose typed shape is invalid (bad enum level) is
    // rejected by the validation arm.
    let (status, _b) = post_json(
        &r,
        "/api/v1/namespaces/ga2-bad-gov/standard",
        json!({"governance": {"write": "not-a-valid-level"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// hook_subscribers — namespace standard postgres branches (fake-pg)
// ===========================================================================

#[tokio::test]
async fn namespace_standard_postgres_set_get_clear_and_merge() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _p) = fake_pg_router();
    let ns = "ga2-ns-pg";

    // First set: auto-seed a placeholder + layer the governance policy
    // into metadata.governance via the postgres SAL branch.
    let (status, body) = post_json(
        &r,
        &format!("/api/v1/namespaces/{ns}/standard"),
        json!({"governance": {"write": "owner", "promote": "owner", "delete": "owner"}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "pg set body={body}");
    assert_eq!(
        body[ai_memory::models::field_names::STORAGE_BACKEND],
        json!("postgres")
    );
    let standard_id = body[ai_memory::models::field_names::STANDARD_ID]
        .as_str()
        .expect("standard_id present")
        .to_string();

    // Second set with the SAME id + a fresh governance key exercises
    // merge_governance_fields_http (existing keys survive, new keys
    // merge in) and the ownership-gate no-op for the same caller.
    let (status, body) = post_json(
        &r,
        &format!("/api/v1/namespaces/{ns}/standard"),
        json!({"id": standard_id, "governance": {"promote": "approve"}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "pg merge set body={body}");

    // GET (qs form) on the postgres branch, non-inherit.
    let (status, body) = get(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body[ai_memory::models::field_names::STORAGE_BACKEND],
        json!("postgres")
    );
    assert_eq!(body["resolved_namespace"], json!(ns));

    // GET with inherit=true exercises the chain-walk arm.
    let (status, body) = get(
        &r,
        &format!("/api/v1/namespaces?namespace={ns}/child&inherit=true"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("chain").is_some(),
        "inherit form returns a chain array: {body}"
    );
    assert!(body.get("standards").is_some());

    // DELETE on the postgres branch.
    let (status, body) = delete_req(&r, &format!("/api/v1/namespaces/{ns}/standard")).await;
    assert_eq!(status, StatusCode::OK, "pg clear body={body}");
    assert_eq!(body["cleared"], json!(true));
    assert_eq!(
        body[ai_memory::models::field_names::STORAGE_BACKEND],
        json!("postgres")
    );
}

#[tokio::test]
async fn namespace_standard_postgres_clear_missing_is_404() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _p) = fake_pg_router();
    // Clearing a namespace that has no namespace_meta row hits the
    // postgres `Ok(false)` -> 404 arm.
    let (status, _b) = delete_req(&r, "/api/v1/namespaces/ga2-never-set/standard").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn namespace_standard_postgres_get_unset_returns_null_envelope() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _p) = fake_pg_router();
    // Non-inherit GET on a namespace with no standard -> Ok(None) ->
    // null-standard_id 200 envelope on the postgres branch.
    let (status, body) = get(&r, "/api/v1/namespaces?namespace=ga2-pg-unset").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body[ai_memory::models::field_names::STORAGE_BACKEND],
        json!("postgres")
    );
    assert_eq!(
        body[ai_memory::models::field_names::STANDARD_ID],
        Value::Null
    );
}

// ===========================================================================
// hook_subscribers — session_start
// ===========================================================================

#[tokio::test]
async fn session_start_ok_stamps_session_id() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"namespace": "ga2-session", "limit": 5, "agent_id": "ai:cov-ga2-b"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    // session_id is stamped, and the supplied agent_id is echoed back.
    assert!(body.get("session_id").and_then(Value::as_str).is_some());
    assert_eq!(body["agent_id"], json!("ai:cov-ga2-b"));
}

#[tokio::test]
async fn session_start_invalid_agent_id_is_400() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"agent_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_start_body_header_agent_mismatch_is_400() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // X-Agent-Id header (AGENT) disagrees with the body-supplied agent_id.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/session/start")
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(
            serde_json::to_vec(&json!({"agent_id": "ai:different-from-header"})).unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_start_no_agent_id_synthesizes_caller() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // No header, no body agent_id -> caller is a synthesized anonymous id.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/session/start")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let (status, body) = decode(&r, req).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("session_id").and_then(Value::as_str).is_some());
}

// ===========================================================================
// approvals — approval_decide (sqlite) + HMAC verifier + record_hmac_nonce
// ===========================================================================

#[tokio::test]
async fn approval_decide_approve_sqlite_executes() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");

    // Omitting `remember` exercises default_remember() -> "once".
    let body = json!({"decision": "approve"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "body={v}");
    assert_eq!(v["approved"], json!(true));
    assert_eq!(v["executed"], json!(true));
    assert_eq!(v["remember"], json!("once"), "default_remember -> once");

    // Side-effect: the pending row transitioned in the DB.
    let conn = ai_memory::db::open(t.path()).expect("reopen");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("row exists");
    assert_eq!(row.status, "approved");
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_deny_sqlite_publishes_synthetic_rule() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");

    // remember=forever drives the publish_decision_event synthetic-rule arm.
    let body = json!({"decision": "deny", "remember": "forever"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "body={v}");
    assert_eq!(v["rejected"], json!(true));
    assert_eq!(v["remember"], json!("forever"));

    let conn = ai_memory::db::open(t.path()).expect("reopen");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("row exists");
    assert_eq!(row.status, "rejected");
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_unknown_id_sqlite_is_404() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, _t) = sqlite_router();
    // Valid id shape, but no such pending row -> NotFound 404 arm.
    let pending_id = "pa-does-not-exist";
    let body = json!({"decision": "approve", "remember": "once"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(pending_id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_missing_signature_is_401() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");
    let body = json!({"decision": "approve"}).to_string();
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_no_server_secret_is_401() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(None);
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");
    let body = json!({"decision": "approve"}).to_string();
    // Even a well-formed signature -> 401 when no server secret is set.
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approval_decide_stale_timestamp_is_401() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");
    let body = json!({"decision": "approve"}).to_string();
    // A timestamp far outside the 300s replay window -> stale -> 401.
    let stale_ts = (chrono::Utc::now().timestamp() - 10_000).to_string();
    let sig = common::sign_canonical_envelope(HMAC_SECRET, &stale_ts, "POST", &pending_id, &body);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", &stale_ts)
        .header("x-ai-memory-signature", sig)
        .header("x-agent-id", "operator-1")
        .body(Body::from(body))
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_nonce_replay_is_401() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, t) = sqlite_router();
    let pending_id = seed_pending_row(t.path(), "scratch", "alice");
    let body = json!({"decision": "approve"}).to_string();
    // Build ONE signed request and replay it byte-for-byte. The first
    // call consumes the row (approved); the SECOND replays the exact same
    // signature, which record_hmac_nonce rejects as a single-use replay.
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig = common::sign_canonical_envelope(HMAC_SECRET, &timestamp, "POST", &pending_id, &body);
    let make = || {
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/approvals/{pending_id}"))
            .header("content-type", "application/json")
            .header("x-ai-memory-timestamp", &timestamp)
            .header("x-ai-memory-signature", &sig)
            .header("x-agent-id", "operator-1")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let first = r.clone().oneshot(make()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK, "first decide must succeed");
    let second = r.clone().oneshot(make()).await.unwrap();
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "replayed signature must be rejected by the nonce cache"
    );
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_invalid_id_shape_is_400() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, _t) = sqlite_router();
    // An id with a space fails validate_id AFTER passing HMAC. The
    // path segment is percent-encoded (`bad%20id`) so the URI builder
    // accepts it; axum decodes it to `bad id`, which the handler binds
    // into the HMAC canonical and then rejects at validate_id. We sign
    // the DECODED form so the signature is valid for the bound id.
    let decoded_id = "bad id";
    let body = json!({"decision": "approve"}).to_string();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig = common::sign_canonical_envelope(HMAC_SECRET, &timestamp, "POST", decoded_id, &body);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/approvals/bad%20id")
        .header("content-type", "application/json")
        .header("x-ai-memory-timestamp", &timestamp)
        .header("x-ai-memory-signature", sig)
        .header("x-agent-id", "operator-1")
        .body(Body::from(body))
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    set_active_hooks_hmac_secret(None);
}

// ===========================================================================
// approvals — approval_decide_postgres (fake-pg SAL dispatch)
// ===========================================================================

#[tokio::test]
async fn approval_decide_postgres_approve_dispatches_to_store() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, store_path) = fake_pg_router();
    let pending_id = seed_pending_row(&store_path, "scratch", "alice");

    let body = json!({"decision": "approve", "remember": "session"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "pg approve body={v}");
    assert_eq!(v["approved"], json!(true));
    assert_eq!(v["executed"], json!(true));
    assert_eq!(v["remember"], json!("session"));

    // The row transitioned in the SAL store's backing file, NOT the
    // scratch app.db — proving the postgres branch dispatched to the store.
    let conn = ai_memory::db::open(&store_path).expect("reopen store file");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("row in SAL store");
    assert_eq!(row.status, "approved");
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_postgres_deny_dispatches_to_store() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, store_path) = fake_pg_router();
    let pending_id = seed_pending_row(&store_path, "scratch", "alice");

    let body = json!({"decision": "deny", "remember": "once"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "pg deny body={v}");
    assert_eq!(v["rejected"], json!(true));

    let conn = ai_memory::db::open(&store_path).expect("reopen store file");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("row in SAL store");
    assert_eq!(row.status, "rejected");
    set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn approval_decide_postgres_missing_id_is_404() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let (r, _p) = fake_pg_router();
    // No such pending row in the SAL store -> deny path's pending_decide
    // returns Ok(false) -> 404.
    let pending_id = "pa-pg-missing";
    let body = json!({"decision": "deny", "remember": "once"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(pending_id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    set_active_hooks_hmac_secret(None);
}

/// Live-postgres variant of `approval_decide_postgres`. Skips when
/// `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn approval_decide_live_postgres_missing_id_is_404() {
    use ai_memory::store::MemoryStore;
    use ai_memory::store::postgres::PostgresStore;

    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(url) = common::postgres_url() else {
        eprintln!(
            "SKIP approval_decide_live_postgres_missing_id_is_404: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
    let db: Db = Arc::new(AsyncMutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    let app_state = app_state_for(db, store, StorageBackend::Postgres);
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let r = ai_memory::build_router(api_key_state, app_state);

    let pending_id = format!("pa-live-missing-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let body = json!({"decision": "approve", "remember": "once"}).to_string();
    let resp = r
        .clone()
        .oneshot(signed_approval(&pending_id, &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "missing pending id on live postgres must 404"
    );
    set_active_hooks_hmac_secret(None);
}

// ===========================================================================
// approvals — approvals_sse + sse_event_visible_to
// ===========================================================================

#[tokio::test]
async fn approvals_sse_emits_visible_event_to_matching_subscriber() {
    use http_body_util::BodyExt as _;
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();

    // Subscribe as "operator" so the event (requested_by="operator") is
    // visible per sse_event_visible_to's agent-id match arm.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/approvals/stream")
        .header("accept", "text/event-stream")
        .header("x-agent-id", "operator")
        .body(Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    // Fire an approval_requested event on the bus after the subscriber
    // attaches (broadcast channels never replay history).
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let pending_id = ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Store,
        "ns-ga2-sse",
        None,
        "operator",
        &json!({"title": "x", "content": "y", "namespace": "ns-ga2-sse"}),
    )
    .expect("queue_pending_action");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        ai_memory::subscriptions::dispatch_approval_requested(
            &conn,
            &pending_id,
            std::path::Path::new(":memory:"),
        );
    });

    let mut buf = Vec::new();
    let read = async {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(bytes) = frame.data_ref() {
                        buf.extend_from_slice(bytes);
                        if String::from_utf8_lossy(&buf).contains("approval_requested") {
                            return Ok::<(), String>(());
                        }
                    }
                }
                Some(Err(e)) => return Err(format!("body error: {e}")),
                None => return Err("body ended before event".into()),
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), read)
        .await
        .expect("SSE timeout")
        .expect("SSE read");
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("event: approval_requested"),
        "subscriber must receive the visible event; got: {text}"
    );
}

#[tokio::test]
async fn sse_event_visible_to_oracle_matrix() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let evt = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "pa-vis".into(),
        decision: "approve".into(),
        decided_by: "operator".into(),
        remember: "once".into(),
        namespace: "ga2-vis".into(),
        requested_by: "alice".into(),
    };
    // Empty subscriber -> fail-closed.
    assert!(!ai_memory::handlers::sse_event_visible_to("", &evt));
    // host:-prefixed self-asserted id -> fail-closed (privilege-escalation guard).
    assert!(!ai_memory::handlers::sse_event_visible_to(
        "host:anything",
        &evt
    ));
    // The originating requester sees their own event.
    assert!(ai_memory::handlers::sse_event_visible_to("alice", &evt));
    // An unrelated agent with no matching permission rule does not.
    assert!(!ai_memory::handlers::sse_event_visible_to(
        "ai:stranger",
        &evt
    ));
}

// ===========================================================================
// http — maybe_auto_tag (no-LLM arm via create_memory) +
//        get_with_visibility_retry (postgres promote path)
// ===========================================================================

#[tokio::test]
async fn create_memory_no_llm_yields_no_auto_tags() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _t) = sqlite_router();
    // No operator tags + long-enough content + non-internal namespace,
    // but the keyword-tier router has no llm_model and no LLM client, so
    // maybe_auto_tag short-circuits to no tags. The 201 response must
    // carry NO `auto_tags` key.
    let (status, body) = post_json(
        &r,
        "/api/v1/memories",
        json!({
            "title": "ga2 auto-tag probe",
            "content": "this content is comfortably longer than the fifty character auto-tag gate threshold",
            "namespace": "ga2-autotag",
            "agent_id": AGENT,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert!(
        body.get("auto_tags").is_none(),
        "no LLM wired -> no auto_tags in the create response: {body}"
    );
    assert!(body.get("id").and_then(Value::as_str).is_some());
}

#[tokio::test]
async fn promote_postgres_uses_visibility_retry() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, store_path) = fake_pg_router();
    // Seed a memory directly in the SAL store so the postgres promote
    // path (which calls get_with_visibility_retry) resolves it.
    let conn = ai_memory::db::open(&store_path).expect("open store file");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: "ga2-promote".into(),
        title: "ga2-promote-target".into(),
        content: "a memory to be promoted via the postgres branch".into(),
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({"agent_id": AGENT, "scope": "shared"}),
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&conn, &mem).expect("insert memory");
    drop(conn);

    let (status, body) =
        post_json(&r, &format!("/api/v1/memories/{mem_id}/promote"), json!({})).await;
    // The promote resolves the row through get_with_visibility_retry and
    // jumps it to long tier (200 OK with the promoted shape).
    assert_eq!(status, StatusCode::OK, "promote body={body}");
    assert_eq!(body["id"], json!(mem_id));

    // Side-effect: the row's tier advanced to long in the SAL store.
    let conn = ai_memory::db::open(&store_path).expect("reopen store file");
    let got = ai_memory::db::get(&conn, &mem_id)
        .expect("get")
        .expect("row exists");
    assert_eq!(got.tier, ai_memory::models::Tier::Long);
}

#[tokio::test]
async fn promote_postgres_unknown_id_is_404() {
    let _g = GA2_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (r, _p) = fake_pg_router();
    // A well-formed id with no backing row exhausts the visibility-retry
    // budget and surfaces 404.
    let (status, _b) = post_json(
        &r,
        "/api/v1/memories/ga2-promote-missing/promote",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
