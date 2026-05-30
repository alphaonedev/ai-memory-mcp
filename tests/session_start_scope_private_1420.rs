// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v0.7.0 #1420 — regression pin for the `memory_session_start`
//! cross-agent visibility leak (6-agent code+security review reviewer
//! 3 finding F3.3, memory `cd28329a`).
//!
//! Pre-fix `handle_session_start` forwarded `db::list`'s un-filtered
//! result to the caller. Bob calling the MCP tool or HTTP endpoint
//! in Alice's namespace got back her `scope=private` rows. HTTP
//! `list_memories` post-filtered with `is_visible_to_caller`
//! (`src/handlers/memories_query.rs:181-185`) but session_start was
//! added later and missed the post-filter.
//!
//! ## What this test pins
//!
//! - **Cross-agent leak refused (MCP)** — Bob's MCP call with caller=bob
//!   does NOT see Alice's scope=default-private row.
//! - **Cross-agent leak refused (HTTP)** — Bob's HTTP call with
//!   `X-Agent-Id: bob` does NOT see Alice's scope=default-private row.
//! - **Owner sees own row (MCP)** — Alice's MCP call with caller=alice
//!   DOES see her own row.
//! - **Owner sees own row (HTTP)** — Alice's HTTP call with body
//!   `agent_id=alice` DOES see her own row.
//! - **Public row visible to anyone (MCP)** — `scope=public` rows
//!   bypass the gate.
//! - **Body/header agreement** — supplying both with mismatch returns
//!   400 (mirrors `#910` write-surface norm).

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

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn seed_memory(
    db_path: &std::path::Path,
    owner: &str,
    namespace: &str,
    title: &str,
    scope_public: bool,
) -> String {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = json!({ "agent_id": owner });
    if scope_public && let Some(obj) = metadata.as_object_mut() {
        obj.insert("scope".to_string(), json!("public"));
    }
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-1420".to_string(),
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
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("db::insert");
    id
}

fn build_router(db_path: &std::path::Path) -> axum::Router {
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
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
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

async fn post_json_with_header(
    router: &axum::Router,
    path: &str,
    body: &Value,
    x_agent: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(a) = x_agent {
        req = req.header("X-Agent-Id", a);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP cross-agent leak refused
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_session_start_does_not_leak_alice_private_row_to_bob() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _alice_row = seed_memory(tmp.path(), "alice", "ns-1420-leak", "alice-private", false);

    let router = build_router(tmp.path());
    let (status, resp) = post_json_with_header(
        &router,
        "/api/v1/session/start",
        &json!({ "namespace": "ns-1420-leak", "limit": 50 }),
        Some("bob"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status}: {resp}");
    let mems = resp["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        0,
        "bob must NOT see alice's scope=default-private row; got: {mems:?}"
    );
}

#[tokio::test]
async fn http_session_start_owner_sees_own_row() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _row = seed_memory(tmp.path(), "alice", "ns-1420-owner", "alice-private", false);

    let router = build_router(tmp.path());
    let (status, resp) = post_json_with_header(
        &router,
        "/api/v1/session/start",
        &json!({ "namespace": "ns-1420-owner", "limit": 50 }),
        Some("alice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mems = resp["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "alice DOES see her own private row; got: {mems:?}"
    );
    assert_eq!(mems[0]["title"].as_str(), Some("alice-private"));
}

#[tokio::test]
async fn http_session_start_public_row_visible_to_anyone() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let _row = seed_memory(tmp.path(), "alice", "ns-1420-pub", "alice-public", true);

    let router = build_router(tmp.path());
    let (status, resp) = post_json_with_header(
        &router,
        "/api/v1/session/start",
        &json!({ "namespace": "ns-1420-pub", "limit": 50 }),
        Some("bob"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mems = resp["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "bob sees alice's scope=public row; got: {mems:?}"
    );
    assert_eq!(mems[0]["title"].as_str(), Some("alice-public"));
}

#[tokio::test]
async fn http_session_start_body_header_mismatch_returns_400() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let router = build_router(tmp.path());
    let (status, resp) = post_json_with_header(
        &router,
        "/api/v1/session/start",
        &json!({ "agent_id": "alice" }),
        Some("bob"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {status}: {resp}");
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("agent_id body parameter does not match"),
        "error mentions mismatch: {resp}"
    );
}

#[tokio::test]
async fn http_session_start_body_agent_id_acts_as_caller_when_no_header() {
    // Pre-#1420 contract: agent_id can come from body OR header. When
    // body is the sole source (no header), it acts as the caller for
    // the post-list visibility filter.
    let tmp = NamedTempFile::new().expect("tempfile");
    let _row = seed_memory(
        tmp.path(),
        "alice",
        "ns-1420-body-only",
        "alice-private",
        false,
    );

    let router = build_router(tmp.path());
    let (status, resp) = post_json_with_header(
        &router,
        "/api/v1/session/start",
        &json!({ "namespace": "ns-1420-body-only", "agent_id": "alice", "limit": 50 }),
        None, // no X-Agent-Id header
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mems = resp["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        1,
        "body-only agent_id acts as caller; got: {mems:?}"
    );
}

// MCP-path direct calls would require `handle_session_start` to be
// `pub` — it's `pub(crate)` per the v0.7.0 D1.6 #987 family. The
// HTTP tests above exercise the same `handle_session_start` body
// end-to-end (`hook_subscribers::session_start` calls into it).
// MCP-stdio coverage of the same fix lands via the in-crate
// `mcp::session_start::tests::*` unit tests (under `cfg(test)`
// in the lib target).
