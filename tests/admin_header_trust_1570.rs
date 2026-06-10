// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1570 (H6) — admin role must NOT be granted from a bare
//! self-asserted `X-Agent-Id` header on an UNAUTHENTICATED deployment.
//!
//! Pre-#1570, `require_admin` resolved the caller from the wire
//! `X-Agent-Id` header and checked the string against the
//! `[admin].agent_ids` allowlist with no binding of identity to any
//! credential. On a deployment with no `api_key` configured, ANY wire
//! caller could mint admin by typing a configured admin id into the
//! header and dump the corpus (`GET /api/v1/export`), enumerate agents,
//! etc.
//!
//! Post-#1570 the gate honors the header role-claim only when
//! (a) request authentication is configured (`api_key` — the
//! middleware then guarantees the credential was presented), or
//! (b) the operator explicitly opted into the legacy posture via
//! `AI_MEMORY_ADMIN_HEADER_TRUST=1`.
//!
//! This binary runs in its own process so the process-global
//! authn marker + env flag start in the secure default (unset).
//! The three postures are asserted in ONE sequential test because
//! both knobs are process-global.

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

const ADMIN_ID: &str = "ai:operator-alice";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1570-admin-header-trust")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build an HTTP test fixture with `ADMIN_ID` on the admin allowlist
/// and NO `api_key` configured (the unauthenticated default install).
fn build_router() -> (axum::Router, NamedTempFile) {
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
        admin_agent_ids: Arc::new(vec![ADMIN_ID.to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn gc_status_with_admin_header(router: axum::Router) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-agent-id", ADMIN_ID)
        .body(Body::empty())
        .unwrap();
    router.oneshot(req).await.unwrap().status()
}

/// The three #1570 postures, asserted sequentially because the authn
/// marker and the env flag are process-global:
///
/// 1. Secure default — no `api_key`, flag off: a bare `X-Agent-Id`
///    naming a configured admin id gets 403.
/// 2. Operator escape hatch — `AI_MEMORY_ADMIN_HEADER_TRUST=1`
///    restores the legacy trust-the-header posture (200).
/// 3. Authenticated deployment — request authn configured (`api_key` at
///    boot): the header role-claim is honored (200).
#[tokio::test]
async fn bare_admin_header_is_refused_by_default_1570() {
    let _dir = fresh_dir();

    // Posture 1 — secure default: allowlisted NAME alone must not
    // mint admin on an unauthenticated deployment.
    let (router, _f) = build_router();
    assert_eq!(
        gc_status_with_admin_header(router).await,
        StatusCode::FORBIDDEN,
        "#1570: bare X-Agent-Id naming an admin id must be 403 on an \
         unauthenticated deployment (no api_key, trust flag off)"
    );

    // Posture 2 — explicit legacy opt-in via the env escape hatch.
    // SAFETY: single-threaded with respect to readers of this env var
    // (this binary's only test), mirroring the suite's set_var precedent.
    unsafe {
        std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
    }
    let (router, _f2) = build_router();
    assert_eq!(
        gc_status_with_admin_header(router).await,
        StatusCode::OK,
        "#1570: AI_MEMORY_ADMIN_HEADER_TRUST=1 must restore the legacy \
         header-trust posture"
    );
    unsafe {
        std::env::remove_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
    }

    // Re-pin the secure default after removing the flag (guards
    // against env-read caching regressions).
    let (router, _f3) = build_router();
    assert_eq!(
        gc_status_with_admin_header(router).await,
        StatusCode::FORBIDDEN,
        "#1570: removing the trust flag must restore the secure default"
    );

    // Posture 3 — authenticated deployment: request authn configured
    // at boot (api_key). The middleware would have enforced the key on
    // every request; the header role-claim is honored again.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let (router, _f4) = build_router();
    assert_eq!(
        gc_status_with_admin_header(router).await,
        StatusCode::OK,
        "#1570: with request authn configured the allowlisted caller \
         must pass the gate"
    );
    ai_memory::handlers::admin_role::mark_request_authn_configured(false);
}
