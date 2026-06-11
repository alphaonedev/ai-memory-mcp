// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1618 — `POST /api/v1/approvals/{pending_id}` (K10) per-backend
//! dispatch.
//!
//! Pre-#1618 the K10 approval handler unconditionally locked `app.db`
//! — on a postgres-backed daemon that is the empty in-memory scratch
//! sqlite `bootstrap_serve` opens — so every HMAC-valid approval was
//! refused as "not found" and never touched the real store, even
//! though the endpoint is allow-listed in the postgres gate
//! (`approvals_decide_path`, `postgres_gate.rs`).
//!
//! Pins:
//!   - Dispatch (fake-pg harness): `storage_backend = Postgres` with a
//!     DISJOINT SAL store — the pending row exists ONLY in the SAL
//!     store, never in `app.db`. Approve and deny must both land on
//!     the SAL store (200), proving the handler routed through the
//!     trait rather than the scratch `app.db` (pre-#1618: 403).
//!   - Live postgres (skip-if-env-unset): a missing pending id on a
//!     real `PostgresStore` surfaces `StoreError::NotFound` → 404
//!     (pre-#1618 the scratch-sqlite path returned 403 Rejected).

#![cfg(feature = "sal")]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::redundant_closure_for_method_calls)]

use std::sync::Arc;
use std::sync::Mutex;

use ai_memory::config::set_active_hooks_hmac_secret;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt as _;

mod common;

/// Serialises the tests in this binary — the K10 HMAC secret is
/// process-global state (`set_active_hooks_hmac_secret`). Same idiom
/// as `tests/k10_approval_http.rs`.
static K10_PG_DISPATCH_LOCK: Mutex<()> = Mutex::new(());

const TEST_SECRET: &str = "k10-pg-dispatch-1618-secret";

/// Build a router claiming `storage_backend = Postgres` whose SAL
/// store is a tempfile-backed `SqliteStore` DISJOINT from the scratch
/// `:memory:` legacy `app.db`. A pending row seeded into the SAL
/// store's backing file is therefore reachable ONLY through the trait
/// dispatch path — the load-bearing property this regression test
/// pins.
fn build_disjoint_fake_pg_router() -> (axum::Router, std::path::PathBuf) {
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
    let store_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
    );
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
    (
        ai_memory::build_router(api_key_state, app_state),
        store_path,
    )
}

/// Seed a memory + a delete-shaped pending row directly into the SAL
/// store's backing sqlite file (NOT into the daemon's scratch
/// `app.db`). Mirrors `tests/k10_approval_http.rs::seed_pending_row_via_db`.
fn seed_pending_row_in_store(store_path: &std::path::Path, requested_by: &str) -> String {
    let conn = ai_memory::db::open(store_path).expect("open store backing file");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "scratch".to_string(),
        title: format!("k10-1618-{}", uuid::Uuid::new_v4()),
        content: "from #1618 dispatch test".into(),
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
        "scratch",
        Some(&mem_id),
        requested_by,
        &json!({"reason": "k10-1618-test"}),
    )
    .expect("queue_pending_action")
}

fn signed_approval_request(pending_id: &str, body: &str) -> Request<Body> {
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

/// Approve must reach the SAL store (where the row lives) — 200 with
/// the K10 wire shape — and transition the row to `approved` in the
/// store's backing file. Pre-#1618 the handler consulted only the
/// scratch `app.db` (row absent) and refused with 403.
#[tokio::test]
async fn approve_dispatches_to_sal_store_on_postgres_backend_1618() {
    let _g = K10_PG_DISPATCH_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, store_path) = build_disjoint_fake_pg_router();
    let pending_id = seed_pending_row_in_store(&store_path, "alice");

    let body = json!({"decision": "approve", "remember": "once"}).to_string();
    let resp = router
        .clone()
        .oneshot(signed_approval_request(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "#1618 — approve must dispatch to the SAL store on a postgres-backed daemon; got {status} body={v}"
    );
    assert_eq!(v["approved"], json!(true));
    assert_eq!(v["executed"], json!(true));
    assert_eq!(v["remember"], json!("once"));

    // The row transitioned in the SAL store's backing file.
    let conn = ai_memory::db::open(&store_path).expect("reopen store backing file");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("pending row exists in SAL store");
    assert_eq!(
        row.status, "approved",
        "row must transition in the SAL store"
    );
    set_active_hooks_hmac_secret(None);
}

/// Deny mirrors approve: `pending_decide(false)` on the SAL store →
/// 200 `{"rejected": true, ...}`. Pre-#1618 the scratch `app.db` had
/// no such row → 404.
#[tokio::test]
async fn deny_dispatches_to_sal_store_on_postgres_backend_1618() {
    let _g = K10_PG_DISPATCH_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, store_path) = build_disjoint_fake_pg_router();
    let pending_id = seed_pending_row_in_store(&store_path, "alice");

    let body = json!({"decision": "deny", "remember": "once"}).to_string();
    let resp = router
        .clone()
        .oneshot(signed_approval_request(&pending_id, &body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "#1618 — deny must dispatch to the SAL store on a postgres-backed daemon; got {status} body={v}"
    );
    assert_eq!(v["rejected"], json!(true));

    let conn = ai_memory::db::open(&store_path).expect("reopen store backing file");
    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get_pending_action")
        .expect("pending row exists in SAL store");
    assert_eq!(
        row.status, "rejected",
        "row must transition in the SAL store"
    );
    set_active_hooks_hmac_secret(None);
}

/// Live postgres (skip-if-env-unset): a missing pending id surfaces
/// `StoreError::NotFound` from `governance_approve_with_consensus` →
/// 404 on the K10 wire. Pre-#1618 the request fell through to the
/// scratch sqlite and returned 403 Rejected.
#[cfg(feature = "sal-postgres")]
mod live_pg {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn approvals_decide_missing_id_returns_404_on_live_postgres_1618() {
        let Some(url) = common::postgres_url() else {
            eprintln!("skipping approvals_decide_missing_id_returns_404_on_live_postgres_1618");
            return;
        };
        let _g = K10_PG_DISPATCH_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));

        let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(&url)
                .await
                .expect("connect postgres adapter"),
        );
        let scratch =
            ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            scratch,
            std::path::PathBuf::from(":memory:"),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
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
        let router = ai_memory::build_router(api_key_state, app_state);

        let bogus = uuid::Uuid::new_v4().to_string();
        let body = json!({"decision": "approve", "remember": "once"}).to_string();
        let resp = router
            .clone()
            .oneshot(signed_approval_request(&bogus, &body))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "#1618 — missing pending id on live postgres must be 404 (StoreError::NotFound), not the pre-fix scratch-sqlite 403"
        );
        set_active_hooks_hmac_secret(None);
    }
}

/// #1620 — sqlite twin of the missing-pending-id 404: the legacy
/// sqlite path used to collapse "no such row" into the policy-refusal
/// 403 bucket (`ApproveOutcome::Rejected`) while postgres returned 404
/// for the same probe. Post-#1620 both backends 404 via the typed
/// `ApproveOutcome::NotFound`.
#[tokio::test]
async fn pending_approve_missing_id_returns_404_on_sqlite_1620() {
    use tower::ServiceExt as _;
    let _g = K10_PG_DISPATCH_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    set_active_hooks_hmac_secret(Some(TEST_SECRET.to_string()));
    let (router, _store_path) = {
        // Reuse the harness builder but point the gate at a SQLITE
        // backend: build a plain sqlite router the same way the
        // attestation integration tests do.
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let db_path = f.path().to_path_buf();
        let _ = ai_memory::db::open(&db_path).expect("db::open");
        // Leak the tempfile guard so the DB outlives this block.
        std::mem::forget(f);
        let conn = ai_memory::db::open(&db_path).expect("reopen");
        let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
            conn,
            db_path.clone(),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        );
        let app_state = ai_memory::handlers::AppState {
            db,
            embedder: std::sync::Arc::new(None),
            vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            federation: std::sync::Arc::new(None),
            tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: std::sync::Arc::new(None),
            active_keypair: std::sync::Arc::new(None),
            family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
            store,
            llm: std::sync::Arc::new(None),
            auto_tag_model: std::sync::Arc::new(None),
            llm_call_timeout: std::time::Duration::from_secs(30),
            replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
            verify_require_nonce: false,
            federation_nonce_cache: std::sync::Arc::new(
                ai_memory::identity::replay::FederationNonceCache::default(),
            ),
            autonomous_hooks: false,
            recall_scope: std::sync::Arc::new(None),
            deferred_audit_queue: std::sync::Arc::new(None),
            admin_agent_ids: std::sync::Arc::new(Vec::new()),
            rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
            resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
            runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
            max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        };
        let api_key_state = ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
        };
        (ai_memory::build_router(api_key_state, app_state), db_path)
    };

    // The decide surfaces are K10-HMAC gated; reuse the signed helper
    // (it targets /api/v1/approvals/{id} — the approval_decide sqlite
    // branch this case pins).
    let body = serde_json::json!({"decision": "approve", "remember": "once"}).to_string();
    let resp = router
        .oneshot(signed_approval_request("does-not-exist-1620", &body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::NOT_FOUND,
        "#1620: missing pending id on sqlite must be 404 (was 403)"
    );
}
