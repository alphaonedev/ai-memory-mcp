// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2044 (v1.0.0, #2032-A) — ROUTE-LEVEL regression pins for per-agent-key
//! identity binding, driving real Axum routes end-to-end through
//! `build_router` (the middleware + handler + `require_admin` wiring), not just
//! the gate primitives (`tests/http_per_agent_key_binding_2044.rs`).
//!
//!   * **M1 (admin spoof)** — a shared-transport-key caller presenting a
//!     configured admin `X-Agent-Id` on `POST /api/v1/gc` is refused under
//!     `enforce`; the same admin presenting their enrolled per-agent key passes.
//!   * **H1 (bulk-read IDOR)** — a shared-key caller presenting a victim
//!     `X-Agent-Id` on the BULK read surface (`GET /api/v1/memories`) is refused
//!     under `enforce` BEFORE the visibility filter; the enrolled per-agent key
//!     for that principal passes.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::admin_role::is_admin_caller_trusted;
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "shared-transport-key";
const ALICE_KEY: &str = "alice-per-agent-key";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("issue-2044-route-gate");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build a router in `enforce` mode with `alice` enrolled both as an admin and
/// as the owner of the `ALICE_KEY` per-agent api-key. The shared transport key
/// (`SHARED_KEY`) authenticates transport but resolves to NO per-agent principal.
fn build_enforce_router() -> (axum::Router, AppState, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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

    let mut enrolled = HashMap::new();
    enrolled.insert(api_key_sha256_hex(ALICE_KEY), "alice".to_string());
    let enrolled = Arc::new(enrolled);

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
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["alice".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Enforce,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Enforce,
    };
    let router = ai_memory::build_router(api_key_state, app_state.clone());
    (router, app_state, f)
}

// ---------------------------------------------------------------------------
// M1 — admin spoof via shared key, route-level.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m1_run_gc_shared_key_admin_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    // Shared transport key + a configured admin X-Agent-Id — the M1 spoof.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "alice")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#2044 M1: a shared-key caller asserting admin X-Agent-Id must be \
         refused under enforce (Claimed, not key-attested)"
    );
}

#[tokio::test]
async fn m1_run_gc_per_agent_key_admin_passes() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    // alice's enrolled per-agent key → middleware binds X-Agent-Id=alice, the
    // gate sees KeyAuthenticated, require_admin admits → 200.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-api-key", ALICE_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#2044: alice's enrolled per-agent key must pass the admin gate"
    );
}

// ---------------------------------------------------------------------------
// H1 — bulk-read IDOR via shared key, route-level.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h1_list_memories_shared_key_victim_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    // Shared transport key + a victim X-Agent-Id on the BULK read surface — the
    // H1 cross-tenant enumeration lever. Refused BEFORE the visibility filter.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/memories")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "victim")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#2044 H1: a shared-key caller asserting a victim X-Agent-Id must be \
         refused on the bulk-read surface under enforce"
    );
}

#[tokio::test]
async fn h1_list_memories_per_agent_key_passes() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    // alice's enrolled per-agent key → bound + key-attested → 200 (her own view).
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/memories")
        .header("x-api-key", ALICE_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#2044: alice's enrolled per-agent key must pass the bulk-read gate"
    );
}

#[tokio::test]
async fn h1_search_shared_key_victim_spoof_is_403_under_enforce() {
    // #2095 MINOR — the SEARCH bulk-read surface (GET /api/v1/search) shares the
    // same self-asserted-X-Agent-Id → visibility filter as list/recall.
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/search?q=anything")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "victim")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#2044 H1: shared-key victim-spoof on search must 403 under enforce"
    );
}

#[tokio::test]
async fn h1_recall_shared_key_victim_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/recall?context=anything")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "victim")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#2044 H1: shared-key victim-spoof on recall must 403 under enforce"
    );
}

// ---------------------------------------------------------------------------
// M1 (#2093) — the SECOND admin predicate `is_admin_caller_trusted`, consumed
// by 8 read+destructive admin surfaces (purge_archive, forget-adjacent, kg /
// power / governance / links admin branches). This is a bool gate (not a
// 403-returning one): under `enforce` a forged shared-key admin must resolve to
// NOT-trusted so the handler downgrades to caller-scope (no cross-tenant admin
// bypass — e.g. no cross-tenant archive purge). One predicate guards all 8
// sites, so this direct test is the load-bearing guarantee for every one.
// ---------------------------------------------------------------------------

fn headers_with_key(api_key: &str, agent_id: &str) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert("x-api-key", api_key.parse().unwrap());
    h.insert("x-agent-id", agent_id.parse().unwrap());
    h
}

#[tokio::test]
async fn m1_2093_is_admin_caller_trusted_refuses_shared_key_admin_under_enforce() {
    let _dir = fresh_dir();
    let (_router, app, _f) = build_enforce_router();

    // Shared transport key + a forged admin X-Agent-Id → Claimed → NOT trusted
    // under enforce. This is the #2093 fix: pre-fix this returned `true` (the
    // base #1570 gate passed because api_key is configured), letting a shared-key
    // caller pass the destructive purge_archive / forget admin branches.
    let shared = headers_with_key(SHARED_KEY, "alice");
    assert!(
        !is_admin_caller_trusted(&app, &shared, "alice"),
        "#2093: a shared-key caller asserting an admin id must NOT be trusted \
         under enforce (Claimed, not key-attested)"
    );

    // alice's enrolled per-agent key acting as alice → KeyAuthenticated → trusted.
    let keyed = headers_with_key(ALICE_KEY, "alice");
    assert!(
        is_admin_caller_trusted(&app, &keyed, "alice"),
        "#2093: alice's enrolled per-agent key must be trusted for admin"
    );

    // A non-allowlisted caller is never trusted regardless of key.
    assert!(
        !is_admin_caller_trusted(&app, &keyed, "bob"),
        "non-allowlisted caller is never admin-trusted"
    );
}

#[tokio::test]
async fn m1_2093_purge_archive_shared_key_admin_does_not_403_but_downgrades() {
    // Route-level pin for the DESTRUCTIVE surface (DELETE /api/v1/archive). The
    // predicate DOWNGRADES (not 403s), so a forged shared-key admin gets a normal
    // 200 that ran in CALLER scope (no cross-tenant purge) — the security
    // property is the absence of the admin bypass, pinned directly above. Here we
    // assert the route stays functional (no crash / no spurious 403) under the
    // new gate.
    let _dir = fresh_dir();
    let (router, _app, _f) = build_enforce_router();
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/archive?older_than_days=3650")
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "alice")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#2093: purge_archive downgrades a forged shared-key admin to caller \
         scope (200, caller-scoped purge), it does not 403"
    );
}
