// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #944 — `GET /api/v1/kg/timeline` caller-vs-source-owner
//! gate regression (security-high, Track A QC sweep 2026-05-20).
//!
//! Pre-#944 the HTTP handler `src/handlers/kg.rs::kg_timeline` took
//! NO `headers: HeaderMap` parameter. Any authenticated caller could
//! `GET /api/v1/kg/timeline?source_id=<id>&since=&until=&limit=` and
//! the substrate `db::kg_timeline` (sqlite) / `kg_timeline_via_store`
//! (postgres) would return the full link-event projection
//! (`target_id`, `relation`, `valid_from`, `valid_until`,
//! `observed_by`, `title`, `target_namespace`) for the given source
//! regardless of which agent owns the source memory. Cross-tenant
//! info-leak on the temporal-graph read surface.
//!
//! The fix mirrors the #938 `kg_invalidate` owner gate
//! (commit `54706eeed`, same file) and the #937 `delete_memory`
//! shape (commit `a582bdc5b`):
//!
//! 1. Handler takes `headers: HeaderMap`, resolves the caller via
//!    `crate::handlers::parity::resolve_caller_agent_id`.
//! 2. Handler fetches the source memory + compares `metadata.agent_id`
//!    to the caller. Permitted: source-owner, inbox carve-out
//!    (`metadata.target_agent_id == caller`), legacy `"daemon"`
//!    sentinel, or legacy unowned (empty `metadata.agent_id`) rows.
//! 3. Cross-tenant attempts return HTTP 403 + `{error, owner, caller,
//!    source_id}` envelope and DO NOT return the timeline rows.
//! 4. Missing source memory returns HTTP 404 with `{found: false,
//!    source_id, error}`.
//!
//! Tests:
//!
//! 1. `bob_cannot_read_alice_timeline_944` — alice owns a source
//!    memory and a `:related_to` edge from it; bob's GET returns
//!    HTTP 403 and the response body does NOT contain the timeline
//!    rows.
//! 2. `owner_can_read_own_timeline_944` — alice's GET against her
//!    own source returns HTTP 200 + the events array (count >= 1).
//! 3. `missing_source_returns_404_944` — GET against a non-existent
//!    source returns HTTP 404 (canonical missing-source envelope,
//!    not a 500, not an empty 200).
//! 4. `inbox_target_can_read_timeline_944` — when the source memory
//!    is a `_inbox/<recipient>` row, the recipient can read its
//!    timeline (same semantic as `store::is_visible_to_caller`).

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

/// Insert a memory with the supplied owner + optional inbox-target
/// metadata, returning its id.
fn seed_memory(
    db_path: &std::path::Path,
    owner: &str,
    namespace: &str,
    extra_meta: &Value,
) -> String {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = json!({"agent_id": owner});
    if let Some(extra) = extra_meta.as_object()
        && let Some(obj) = metadata.as_object_mut()
    {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}-{}", &id[..8]),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-944".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
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
    id
}

/// Create a `:related_to` link between two seeded memories.
fn seed_link(db_path: &std::path::Path, source_id: &str, target_id: &str, relation: &str) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    ai_memory::db::create_link(&conn, source_id, target_id, relation).expect("create_link seed");
}

#[allow(clippy::too_many_lines)]
fn build_router_fixture(db_path: &std::path::Path) -> axum::Router {
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
        admin_agent_ids: Arc::new(Vec::new()),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn timeline_as(router: &axum::Router, caller: &str, source_id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/kg/timeline?source_id={source_id}"))
        .header("x-agent-id", caller)
        .body(Body::empty())
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
async fn bob_cannot_read_alice_timeline_944() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let alice_src = seed_memory(db_path, "alice", "shared-944/a", &json!({}));
    let alice_tgt = seed_memory(db_path, "alice", "shared-944/a", &json!({}));
    seed_link(db_path, &alice_src, &alice_tgt, "related_to");

    let router = build_router_fixture(db_path);
    let (status, body) = timeline_as(&router, "bob", &alice_src).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#944: bob (non-owner) MUST be refused with HTTP 403; body={body}"
    );
    assert_eq!(
        body["caller"].as_str(),
        Some("bob"),
        "#944: 403 envelope must echo the rejected caller; body={body}"
    );
    assert_eq!(
        body["owner"].as_str(),
        Some("alice"),
        "#944: 403 envelope must echo the source's recorded owner; body={body}"
    );
    assert!(
        body.get("events").is_none(),
        "#944: 403 response MUST NOT leak the events array; body={body}"
    );
}

#[tokio::test]
async fn owner_can_read_own_timeline_944() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let alice_src = seed_memory(db_path, "alice", "shared-944/b", &json!({}));
    let alice_tgt = seed_memory(db_path, "alice", "shared-944/b", &json!({}));
    seed_link(db_path, &alice_src, &alice_tgt, "related_to");

    let router = build_router_fixture(db_path);
    let (status, body) = timeline_as(&router, "alice", &alice_src).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#944 owner-exemption: alice MUST be able to read her own timeline; body={body}"
    );
    let events = body.get("events").and_then(|v| v.as_array());
    assert!(
        events.is_some_and(|a| !a.is_empty()),
        "#944: owner GET must return a non-empty events array; body={body}"
    );
}

#[tokio::test]
async fn missing_source_returns_404_944() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Seed a memory but never create the queried source so the gate's
    // pre-check hits the "source not found" branch.
    let _ = seed_memory(db_path, "alice", "shared-944/c", &json!({}));
    let bogus_src = uuid::Uuid::new_v4().to_string();

    let router = build_router_fixture(db_path);
    let (status, body) = timeline_as(&router, "alice", &bogus_src).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#944: missing source MUST surface as HTTP 404 (not 500, not 403); body={body}"
    );
    assert_eq!(
        body["found"].as_bool(),
        Some(false),
        "#944: 404 envelope must carry found=false for wire-compat; body={body}"
    );
}

#[tokio::test]
async fn inbox_target_can_read_timeline_944() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Carol sent alice an inbox-style memory: sender = carol,
    // target_agent_id = alice. Alice is the legitimate reader of
    // edges anchored to her own inbox row.
    let inbox_src = seed_memory(
        db_path,
        "carol",
        "_inbox/alice",
        &json!({"target_agent_id": "alice"}),
    );
    let alice_tgt = seed_memory(db_path, "alice", "shared-944/d", &json!({}));
    seed_link(db_path, &inbox_src, &alice_tgt, "related_to");

    let router = build_router_fixture(db_path);
    let (status, body) = timeline_as(&router, "alice", &inbox_src).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#944 inbox carve-out: alice (target) MUST be able to read edges anchored to her inbox row; body={body}"
    );
    let events = body.get("events").and_then(|v| v.as_array());
    assert!(
        events.is_some_and(|a| !a.is_empty()),
        "#944 inbox carve-out: target GET must return a non-empty events array; body={body}"
    );
}
