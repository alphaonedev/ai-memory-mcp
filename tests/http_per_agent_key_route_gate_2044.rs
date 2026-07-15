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
fn build_enforce_router() -> (axum::Router, NamedTempFile) {
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
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

// ---------------------------------------------------------------------------
// M1 — admin spoof via shared key, route-level.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m1_run_gc_shared_key_admin_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    let (router, _f) = build_enforce_router();
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
    let (router, _f) = build_enforce_router();
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
    let (router, _f) = build_enforce_router();
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
    let (router, _f) = build_enforce_router();
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
async fn h1_recall_shared_key_victim_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    let (router, _f) = build_enforce_router();
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
