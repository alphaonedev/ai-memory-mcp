// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #957 — `export_memories` admin-role gate regression
//! (security-critical, v0.7.0 SHIP-blocker).
//!
//! Pre-#957 the `GET /api/v1/export` handler took NO headers,
//! accepted no caller-identity input, and:
//!
//! - Postgres branch: called `app.store.export_memories()` →
//!   SAL-side `for_agent("export")` → returned the full corpus.
//! - Sqlite branch: called `db::export_all(&lock.0)` directly →
//!   returned the full corpus.
//!
//! The legacy `api_key_auth` middleware passes through when
//! `api_key` is unset (the default install — see #946 RCA), so
//! the endpoint was OPEN by default. Even WITH `api_key`, no
//! per-caller role check distinguished an admin from any other
//! caller; any authenticated caller could dump every memory
//! across every owner, every namespace, every scope (including
//! `scope=private`) plus every link.
//!
//! The fix:
//!
//! 1. Handler signature gains `headers: HeaderMap`.
//! 2. The shared admin role gate
//!    (`handlers::admin_role::require_admin`) resolves the
//!    caller from `X-Agent-Id`, audits the role decision via
//!    `governance::audit::record_decision`, and short-circuits
//!    non-admin callers with `403 Forbidden` + a sanitised
//!    `{"error": "admin role required"}` body.
//! 3. Admin callers (those whose `agent_id` matches
//!    `[admin].agent_ids` in `config.toml`) reach the unchanged
//!    full-fidelity backup path.
//!
//! These tests pin the contract on the sqlite path:
//!
//! 1. `non_admin_caller_gets_403_957` — bob (not in allowlist)
//!    gets 403 with the sanitised error body. No corpus payload.
//! 2. `admin_caller_gets_full_corpus_957` — admin (in allowlist)
//!    gets 200 with `{memories, links, count, exported_at}`.
//! 3. `missing_agent_id_header_gets_403_957` — request with no
//!    `X-Agent-Id` header is rejected (the fallback caller
//!    `anonymous:...` cannot be in any admin allowlist).
//! 4. `empty_allowlist_rejects_every_caller_957` — when no
//!    `[admin].agent_ids` is configured (the v0.7.0 default),
//!    every caller is rejected — the safe-by-default posture
//!    closes the open-corpus surface.
//! 5. `error_body_is_sanitised_957` — the 403 body does NOT
//!    leak the allowlist configuration nor the caller's
//!    resolved identity.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

fn seed_memory(db_path: &std::path::Path, owner: &str, namespace: &str) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}"),
        content: format!("private body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner, "scope": "private"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
}

#[allow(clippy::too_many_lines)]
fn build_router_fixture_with_admin(
    db_path: &std::path::Path,
    admin_ids: Vec<String>,
) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
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
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn export_as(router: &axum::Router, caller: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri("/api/v1/export");
    if let Some(c) = caller {
        builder = builder.header("x-agent-id", c);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn non_admin_caller_gets_403_957() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "secrets-957/a");
    seed_memory(db_path, "carol", "secrets-957/c");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    // Bob is authenticated (X-Agent-Id present) but NOT in the
    // operator-configured `[admin].agent_ids` allowlist.
    let (status, body) = export_as(&router, Some("bob")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#957: non-admin caller MUST be rejected with 403; got body={body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("admin role required"),
        "#957: rejection body MUST be sanitised; got body={body}"
    );
    // The corpus MUST NOT leak in the rejection payload.
    assert!(
        body.get("memories").is_none(),
        "#957: 403 body MUST NOT carry the corpus; got body={body}"
    );
}

#[tokio::test]
async fn admin_caller_gets_full_corpus_957() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "secrets-957/a");
    seed_memory(db_path, "carol", "secrets-957/c");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let (status, body) = export_as(&router, Some("ops:admin")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#957: admin caller MUST receive 200; got body={body}"
    );
    let count = body["count"].as_u64().unwrap_or(0);
    assert_eq!(
        count, 2,
        "#957: admin export MUST round-trip every row regardless of scope; got body={body}"
    );
    assert!(
        body["memories"].is_array(),
        "#957: admin export MUST carry the `memories` array; got body={body}"
    );
}

#[tokio::test]
async fn missing_agent_id_header_gets_403_957() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "secrets-957/a");

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    // No X-Agent-Id header — the fallback caller (`anonymous:...`)
    // cannot match any admin allowlist entry.
    let (status, body) = export_as(&router, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#957: missing X-Agent-Id MUST be rejected with 403; got body={body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("admin role required"),
        "#957: rejection body MUST be sanitised; got body={body}"
    );
}

#[tokio::test]
async fn empty_allowlist_rejects_every_caller_957() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "secrets-957/a");

    // Default-empty admin allowlist — the v0.7.0 safe-by-default
    // posture per the `pm-v3` operator addendum. Every caller must
    // be rejected including would-be admin-looking ids.
    let router = build_router_fixture_with_admin(db_path, vec![]);
    for caller in &["ops:admin", "bob", "alice", "root"] {
        let (status, body) = export_as(&router, Some(caller)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#957: empty allowlist MUST reject every caller (got {status} for {caller}); body={body}"
        );
        assert_eq!(
            body["error"].as_str(),
            Some("admin role required"),
            "#957: rejection body MUST be sanitised; got body={body}"
        );
    }
}

#[tokio::test]
async fn error_body_is_sanitised_957() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_memory(db_path, "alice", "secrets-957/a");

    let router =
        build_router_fixture_with_admin(db_path, vec!["ops:admin".into(), "ops:other".into()]);
    let (status, body) = export_as(&router, Some("attacker")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The rejection body MUST be exactly the sanitised generic
    // shape: it MUST NOT leak the allowlist configuration nor the
    // caller's resolved identity. If a future regression added a
    // diagnostic field carrying the configured allowlist or the
    // caller string, this assertion would fail.
    assert_eq!(
        body,
        json!({"error": "admin role required"}),
        "#957: rejection body MUST be the sanitised constant shape; got body={body}"
    );
}
