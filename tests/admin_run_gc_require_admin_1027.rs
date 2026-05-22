// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1027 + #1107 — `POST /api/v1/gc` `require_admin` gate
//! integration pin.
//!
//! The #1027 close-comment cited a full lib test sweep as the gate
//! verification but did not point at a specific regression test. The
//! audit-lens follow-up #1107 (SR-6 #3) flagged the missing
//! integration pin: no test POSTs to `/api/v1/gc` as a non-admin
//! caller and asserts 403 FORBIDDEN.
//!
//! This file pins the wire-level admin gate so a future refactor that
//! drops the `require_admin` call (or moves it past a side-effecting
//! branch) fails this regression.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1027-run-gc-admin")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build an HTTP test fixture with the supplied admin allowlist.
fn build_router_with_admin_allowlist(admins: Vec<String>) -> (axum::Router, NamedTempFile) {
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
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admins),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// v0.7.0 #1027 + #1107 — A non-admin caller MUST get 403 FORBIDDEN.
///
/// Pre-#1027 the handler logged the caller to the forensic chain but
/// accepted ANY API-key holder (no admin allowlist membership). An
/// attacker with the shared API key could force-purge mid-tier-expired
/// rows across tenants. The fix added `require_admin` which now
/// gates the entire side-effect path.
#[tokio::test]
async fn run_gc_route_returns_403_for_non_admin_caller_1027() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_with_admin_allowlist(vec!["ai:operator-alice".to_string()]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-agent-id", "ai:not-admin")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#1027: non-admin POST /api/v1/gc must be denied with 403 \
         FORBIDDEN before any state change"
    );
}

/// v0.7.0 #1027 + #1107 — An admin caller (in the allowlist) must
/// pass the gate and receive a 200 response. This is the positive
/// control that pins the gate is not over-restrictive.
#[tokio::test]
async fn run_gc_route_accepts_admin_caller_1027() {
    let _dir = fresh_dir();
    let (router, _f) = build_router_with_admin_allowlist(vec!["ai:operator-alice".to_string()]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-agent-id", "ai:operator-alice")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#1027: admin POST /api/v1/gc must pass the require_admin gate \
         and reach the GC executor (200 OK)"
    );
}
