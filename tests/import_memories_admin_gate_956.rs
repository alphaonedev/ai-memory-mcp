// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #956 — `import_memories` admin-role gate + provenance restamp.

#![allow(clippy::needless_pass_by_value)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn body_memory(id: &str, namespace: &str, metadata: Value) -> Value {
    json!({
        "id": id, "tier": "long", "namespace": namespace,
        "title": "imported-row-956", "content": "imported-content-956",
        "tags": [], "priority": 5, "confidence": 1.0, "source": "import",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "last_accessed_at": null, "expires_at": null,
        "metadata": metadata, "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn import_as(
    router: &axum::Router,
    caller: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/import")
        .header("content-type", "application/json");
    if let Some(c) = caller {
        builder = builder.header("x-agent-id", c);
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn read_metadata(db_path: &std::path::Path, id: &str) -> Option<Value> {
    let conn = ai_memory::db::open(db_path).ok()?;
    let mem = ai_memory::db::get(&conn, id).ok()??;
    Some(mem.metadata)
}

#[tokio::test]
async fn non_admin_caller_gets_403_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let mem_id = "11111111-1111-4111-8111-111111111111";
    let body =
        json!({"memories": [body_memory(mem_id, "import-956/a", json!({"agent_id": "alice"}))]});
    let (status, payload) = import_as(&router, Some("bob"), body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={payload}");
    assert_eq!(payload["error"].as_str(), Some("admin role required"));
    assert!(read_metadata(db_path, mem_id).is_none());
}

#[tokio::test]
async fn admin_caller_can_import_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let mem_id = "22222222-2222-4222-8222-222222222222";
    let body = json!({"memories": [body_memory(mem_id, "import-956/b", json!({"agent_id": "ops:admin"}))]});
    let (status, payload) = import_as(&router, Some("ops:admin"), body).await;
    assert_eq!(status, StatusCode::OK, "body={payload}");
    assert_eq!(payload["imported"], 1);
}

#[tokio::test]
async fn missing_agent_id_header_gets_403_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let body = json!({"memories": [body_memory("33333333-3333-4333-8333-333333333333", "import-956/c", json!({"agent_id": "alice"}))]});
    let (status, payload) = import_as(&router, None, body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={payload}");
    assert_eq!(payload["error"].as_str(), Some("admin role required"));
}

#[tokio::test]
async fn empty_allowlist_rejects_every_caller_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec![]);
    for caller in &["ops:admin", "bob", "alice", "root"] {
        let body = json!({"memories": [body_memory("44444444-4444-4444-8444-000000000000", "import-956/d", json!({}))]});
        let (status, payload) = import_as(&router, Some(caller), body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "caller={caller} body={payload}"
        );
        assert_eq!(payload["error"].as_str(), Some("admin role required"));
    }
}

#[tokio::test]
async fn error_body_is_sanitised_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router =
        build_router_fixture_with_admin(db_path, vec!["ops:admin".into(), "ops:other".into()]);
    let body = json!({"memories": [body_memory("55555555-5555-4555-8555-555555555555", "import-956/e", json!({"agent_id": "alice"}))]});
    let (status, payload) = import_as(&router, Some("attacker"), body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(payload, json!({"error": "admin role required"}));
}

#[tokio::test]
async fn admin_import_restamps_agent_id_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let mem_id = "66666666-6666-4666-8666-666666666666";
    let body = json!({"memories": [body_memory(mem_id, "import-956/restamp", json!({
        "agent_id": "alice", "scope": "private", "other_field": "preserved",
    }))]});
    let (status, payload) = import_as(&router, Some("ops:admin"), body).await;
    assert_eq!(status, StatusCode::OK, "body={payload}");
    assert_eq!(payload["imported"], 1);
    let meta = read_metadata(db_path, mem_id).expect("persisted memory");
    assert_eq!(meta["agent_id"].as_str(), Some("ops:admin"), "meta={meta}");
    assert_eq!(
        meta["imported_from_agent_id"].as_str(),
        Some("alice"),
        "meta={meta}"
    );
    assert_eq!(meta["scope"].as_str(), Some("private"));
    assert_eq!(meta["other_field"].as_str(), Some("preserved"));
}

#[tokio::test]
async fn admin_import_preserves_when_body_matches_caller_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let mem_id = "77777777-7777-4777-8777-777777777777";
    let body = json!({"memories": [body_memory(mem_id, "import-956/identical", json!({"agent_id": "ops:admin"}))]});
    let (status, payload) = import_as(&router, Some("ops:admin"), body).await;
    assert_eq!(status, StatusCode::OK, "body={payload}");
    assert_eq!(payload["imported"], 1);
    let meta = read_metadata(db_path, mem_id).expect("persisted memory");
    assert_eq!(meta["agent_id"].as_str(), Some("ops:admin"));
    assert!(meta.get("imported_from_agent_id").is_none(), "meta={meta}");
}

#[tokio::test]
async fn admin_import_metadata_absent_agent_id_stamps_caller_956() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let mem_id = "88888888-8888-4888-8888-888888888888";
    let body =
        json!({"memories": [body_memory(mem_id, "import-956/missing", json!({"tag": "x"}))]});
    let (status, payload) = import_as(&router, Some("ops:admin"), body).await;
    assert_eq!(status, StatusCode::OK, "body={payload}");
    assert_eq!(payload["imported"], 1);
    let meta = read_metadata(db_path, mem_id).expect("persisted memory");
    assert_eq!(meta["agent_id"].as_str(), Some("ops:admin"));
    assert!(meta.get("imported_from_agent_id").is_none(), "meta={meta}");
    assert_eq!(meta["tag"].as_str(), Some("x"));
}
