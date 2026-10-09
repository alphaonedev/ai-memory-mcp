// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3415 (umbrella #6050) — the HTTP "low cluster", pinned at the wire:
//!
//! 1. `POST /api/v1/gc?dry_run=true` COUNTS the expired rows and deletes
//!    nothing (the MCP `memory_gc` twin honours `dry_run`; pre-fix the HTTP
//!    handler took no query at all and swept silently).
//! 2. A JSON body the extractor rejects answers with the daemon's JSON error
//!    envelope (`{"error": ...}`) instead of axum's `text/plain` rejection,
//!    on every `Json`-extracted route (sampled here on `POST /api/v1/recall`).
//! 3. `GET /api/v1/pending?status=<unknown>` is `400` with `fields:
//!    ["status"]` instead of a `200` that matches nothing.
//!
//! The router fixture mirrors `tests/admin_run_gc_require_admin_1027.rs`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const ADMIN: &str = "ai:operator-3415";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3415-http-low-cluster")
}

fn fresh_dir() -> TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build an authenticated-deployment router with `ADMIN` allowlisted.
/// Returns the router plus the backing sqlite path.
fn build_router() -> (axum::Router, NamedTempFile) {
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// Insert one short-tier memory whose `expires_at` is already in the past
/// (a GC candidate) and return its id.
fn seed_expired_memory(db_path: &std::path::Path) -> String {
    let conn = ai_memory::db::open(db_path).expect("open for seed");
    let now = chrono::Utc::now();
    let created = (now - chrono::Duration::hours(12)).to_rfc3339();
    let expired = (now - chrono::Duration::hours(1)).to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Short,
        namespace: "gc3415".to_string(),
        title: "expired row".to_string(),
        content: "this row expired an hour ago".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: created.clone(),
        updated_at: created,
        last_accessed_at: None,
        expires_at: Some(expired),
        metadata: serde_json::json!({"agent_id": ADMIN}),
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
        lifecycle_state: LifecycleState::Open,
    };
    ai_memory::db::insert(&conn, &mem).expect("insert expired row")
}

fn row_exists(db_path: &std::path::Path, id: &str) -> bool {
    let conn = ai_memory::db::open(db_path).expect("open for probe");
    ai_memory::db::get(&conn, id).expect("get").is_some()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "body is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn content_type(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// (1) `?dry_run=true` counts the expired rows and deletes nothing; the
/// control sweep without it deletes them.
#[tokio::test]
async fn http_gc_dry_run_counts_without_deleting_3415() {
    let _dir = fresh_dir();
    let (router, f) = build_router();
    let id = seed_expired_memory(f.path());
    assert!(row_exists(f.path(), &id), "seed row present");

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc?dry_run=true")
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["dry_run"], serde_json::json!(true), "{body}");
    assert_eq!(
        body["collected"],
        serde_json::json!(1),
        "#3415: dry run reports the one expired row: {body}"
    );
    assert!(
        row_exists(f.path(), &id),
        "#3415: dry_run=true must not delete the expired row"
    );

    // Control: the real sweep removes it and reports it.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/gc")
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["expired_deleted"], serde_json::json!(1), "{body}");
    assert!(
        !row_exists(f.path(), &id),
        "control: the real sweep deletes"
    );
}

/// (2) A body the JSON extractor rejects (wrong type, malformed JSON)
/// answers with the JSON error envelope, never `text/plain`.
#[tokio::test]
async fn http_json_body_rejection_is_a_json_envelope_3415() {
    let _dir = fresh_dir();
    let (router, _f) = build_router();

    // Type error (`context` must be a string): axum's default is a
    // text/plain 422.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("x-agent-id", ADMIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"context": 5}"#))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "rejection is a 4xx: {}",
        resp.status()
    );
    let ct = content_type(&resp);
    assert!(
        ct.starts_with("application/json"),
        "#3415: a body rejection must carry the JSON envelope, got content-type {ct:?}"
    );
    let body = body_json(resp).await;
    assert!(
        body["error"].is_string(),
        "#3415: envelope carries `error`: {body}"
    );

    // Malformed JSON: same envelope.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("x-agent-id", ADMIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"context": "#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
    let ct = content_type(&resp);
    assert!(
        ct.starts_with("application/json"),
        "#3415: malformed-JSON rejection must carry the JSON envelope, got {ct:?}"
    );
    let body = body_json(resp).await;
    assert!(body["error"].is_string(), "{body}");
}

/// (3) An unknown `?status=` on `/pending` is a `400` naming the field;
/// a known status still lists.
#[tokio::test]
async fn http_pending_unknown_status_is_400_3415() {
    let _dir = fresh_dir();
    let (router, _f) = build_router();

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/pending?status=bogus")
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "#3415: an unknown status filter is a client error, not an empty 200"
    );
    let body = body_json(resp).await;
    assert!(body["error"].is_string(), "{body}");
    assert_eq!(body["fields"], serde_json::json!(["status"]), "{body}");

    // Control: a known status lists (empty queue → count 0).
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/pending?status=pending")
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["count"], serde_json::json!(0), "{body}");
}
