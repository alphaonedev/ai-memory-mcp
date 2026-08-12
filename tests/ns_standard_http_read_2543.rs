// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v1.0.0 #2543 — HTTP GET namespace-standard explicit-fetch visibility gate.
//!
//! Residual of #959 / #2537: MCP injection and `memory_namespace_get_standard`
//! route through `lookup_namespace_standard` + `is_visible_to_caller`, but the
//! HTTP surfaces
//!
//! - `GET /api/v1/namespaces?namespace=`
//! - `GET /api/v1/namespaces/{ns}/standard`
//!
//! previously passed `caller=None` (sqlite) / `CallerContext::for_admin`
//! (postgres), so any agent who could name a namespace received title +
//! content of a default-private standard body.
//!
//! Pins:
//! - bob cannot read alice's private cross-namespace-bound standard body
//! - honesty marker is count-only (`standards_withheld`), no id/owner leak
//! - CONTROL: shared-scope standard remains fetchable
//! - CONTROL: owner can still read their own private standard

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

const SECRET: &str = "CLASSIFIED-ALICE-HTTP-2543";
const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
const VICTIM_NS: &str = "t2543-victim";
const TENANT_NS: &str = "t2543-tenant";

fn seed_memory(
    conn: &rusqlite::Connection,
    id: &str,
    namespace: &str,
    owner: &str,
    scope: Option<&str>,
    content: &str,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        ai_memory::META_KEY_AGENT_ID.to_string(),
        json!(owner.to_string()),
    );
    if let Some(s) = scope {
        metadata.insert(ai_memory::META_KEY_SCOPE.to_string(), json!(s.to_string()));
    }
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: id.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2543".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::Value::Object(metadata),
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
    ai_memory::db::insert(conn, &mem).expect("insert");
}

fn seed_cross_namespace_bind(conn: &rusqlite::Connection, scope: Option<&str>) {
    seed_memory(
        conn,
        "alice-std-2543",
        VICTIM_NS,
        ALICE,
        scope,
        &format!("needle {SECRET}"),
    );
    ai_memory::db::set_namespace_standard(conn, TENANT_NS, "alice-std-2543", None)
        .expect("bind standard");
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn get_standard_qs(router: &axum::Router, ns: &str, agent: &str) -> (StatusCode, String) {
    let uri = format!("/api/v1/namespaces?namespace={ns}");
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("X-Agent-Id", agent)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn get_standard_path(router: &axum::Router, ns: &str, agent: &str) -> (StatusCode, String) {
    let uri = format!("/api/v1/namespaces/{ns}/standard");
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("X-Agent-Id", agent)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn http_qs_withholds_private_cross_namespace_standard_2543() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, None);
    }
    let router = build_router(tmp.path());

    let (status, body) = get_standard_qs(&router, TENANT_NS, BOB).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert!(
        !body.contains(SECRET),
        "#2543 LEAK (HTTP qs): bob received alice's private standard body. response={body}"
    );
    assert!(
        !body.contains("alice-std-2543"),
        "#2543 existence oracle: withheld id must not appear. response={body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["standards_withheld"].as_u64(), Some(1), "got {body}");
    assert!(
        parsed.get("standard_id").is_none()
            || parsed["standard_id"].is_null()
            || parsed["standard_id"] == json!(null),
        "standard_id must be null when withheld; got {body}"
    );
}

#[tokio::test]
async fn http_path_withholds_private_cross_namespace_standard_2543() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, None);
    }
    let router = build_router(tmp.path());

    let (status, body) = get_standard_path(&router, TENANT_NS, BOB).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert!(
        !body.contains(SECRET),
        "#2543 LEAK (HTTP path): bob received alice's private standard body. response={body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["standards_withheld"].as_u64(), Some(1), "got {body}");
}

#[tokio::test]
async fn http_qs_shared_standard_still_readable_2543() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, Some("shared"));
    }
    let router = build_router(tmp.path());

    let (status, body) = get_standard_qs(&router, TENANT_NS, BOB).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert!(
        body.contains(SECRET),
        "CONTROL: shared-policy standard must remain fetchable; got {body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed["standard_id"].as_str(),
        Some("alice-std-2543"),
        "got {body}"
    );
    assert!(
        parsed.get("standards_withheld").is_none(),
        "nothing withheld for shared; got {body}"
    );
}

#[tokio::test]
async fn http_qs_owner_can_read_own_private_standard_2543() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, None);
    }
    let router = build_router(tmp.path());

    let (status, body) = get_standard_qs(&router, TENANT_NS, ALICE).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert!(
        body.contains(SECRET),
        "CONTROL: owner must still read their private standard; got {body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed["standard_id"].as_str(),
        Some("alice-std-2543"),
        "got {body}"
    );
}
