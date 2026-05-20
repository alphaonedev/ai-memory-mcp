// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #942 — search_memories + forget_memories caller-vs-row-owner
//! gates (security-high, Track A QC sweep 2026-05-20).
//!
//! Pre-fix:
//! - `search_memories` had NO `headers` parameter; the postgres branch
//!   hardcoded `CallerContext { agent_id: "ai:http", ... }` so the SAL
//!   visibility filter saw every caller as the same synthetic
//!   principal → effectively no per-tenant filtering.
//! - The sqlite branch took `?as_agent=` from the query string ONLY;
//!   callers who didn't bother got unfiltered search.
//! - `forget_memories` sqlite called `db::forget` with no caller —
//!   any caller could bulk-delete by namespace+pattern+tier.
//!
//! Fix:
//! - search: header param added, CallerContext threads the real
//!   resolved id, sqlite fallback for `as_agent` uses the X-Agent-Id
//!   header when the query param is absent.
//! - forget: admin-only gate via `handlers::admin_role::require_admin`
//!   (same pattern as #957 export_memories) — substrate refactor for
//!   a per-row caller-filter on forget is bigger than the QC sweep
//!   budget; admin-only is the right semantic for a destructive bulk
//!   operation.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

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

fn seed_memory(
    db_path: &std::path::Path,
    owner: &str,
    namespace: &str,
    title: &str,
    content: &str,
) -> String {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-942".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    ai_memory::db::insert(&conn, &mem).expect("db::insert");
    id
}

fn build_router_fixture(db_path: &std::path::Path, admin_agents: Vec<String>) -> axum::Router {
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
        admin_agent_ids: Arc::new(admin_agents),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn forget_as(router: &axum::Router, caller: &str, namespace: &str) -> (StatusCode, Value) {
    let body = json!({"namespace": namespace, "pattern": "secret"});
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/forget")
        .header("x-agent-id", caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn non_admin_cannot_forget_memories_942() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _alice_id = seed_memory(
        tmp.path(),
        "ai:alice",
        "942/forget",
        "secret-alice",
        "alice owns this",
    );
    // No admin allowlist.
    let router = build_router_fixture(tmp.path(), Vec::new());
    let (status, _body) = forget_as(&router, "ai:bob", "942/forget").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin bob must NOT be able to forget memories"
    );
}

#[tokio::test]
async fn admin_can_forget_memories_942() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _alice_id = seed_memory(
        tmp.path(),
        "ai:alice",
        "942/forget-admin",
        "secret-admin-alice",
        "alice owns this",
    );
    let router = build_router_fixture(tmp.path(), vec!["ai:operator".to_string()]);
    let (status, _body) = forget_as(&router, "ai:operator", "942/forget-admin").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin caller in allowlist can forget"
    );
}
