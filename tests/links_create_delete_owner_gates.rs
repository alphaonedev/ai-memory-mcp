// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #939 + #941 — link create/delete sqlite caller-vs-source-
//! memory-owner gates (security-high, Track A QC sweep 2026-05-20).

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
        source: "test-link-gate".to_string(),
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
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn post_link_as(
    router: &axum::Router,
    caller: &str,
    source_id: &str,
    target_id: &str,
) -> (StatusCode, Value) {
    let body = json!({"source_id": source_id, "target_id": target_id, "relation": "related_to"});
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/links")
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

async fn delete_link_as(
    router: &axum::Router,
    caller: &str,
    source_id: &str,
    target_id: &str,
) -> (StatusCode, Value) {
    let body = json!({"source_id": source_id, "target_id": target_id, "relation": "related_to"});
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/links")
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
async fn bob_cannot_create_link_rooted_at_alice_memory_941() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_src = seed_memory(tmp.path(), "ai:alice", "link-gate/test", &json!({}));
    let target = seed_memory(tmp.path(), "ai:alice", "link-gate/test", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, _body) = post_link_as(&router, "ai:bob", &alice_src, &target).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "bob must NOT be able to create a link rooted at alice's source memory"
    );
}

#[tokio::test]
async fn owner_can_create_own_link_941() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_src = seed_memory(tmp.path(), "ai:alice", "link-gate/own", &json!({}));
    let target = seed_memory(tmp.path(), "ai:alice", "link-gate/own", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = post_link_as(&router, "ai:alice", &alice_src, &target).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "alice owns the source → link allowed: {body}"
    );
}

#[tokio::test]
async fn bob_cannot_delete_alice_link_939() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_src = seed_memory(tmp.path(), "ai:alice", "link-gate/del", &json!({}));
    let alice_tgt = seed_memory(tmp.path(), "ai:alice", "link-gate/del", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (s1, _) = post_link_as(&router, "ai:alice", &alice_src, &alice_tgt).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _) = delete_link_as(&router, "ai:bob", &alice_src, &alice_tgt).await;
    assert_eq!(
        s2,
        StatusCode::FORBIDDEN,
        "bob owns neither endpoint → must NOT delete"
    );
}

#[tokio::test]
async fn either_endpoint_owner_can_delete_link_939() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_src = seed_memory(tmp.path(), "ai:alice", "link-gate/del2", &json!({}));
    let bob_tgt = seed_memory(tmp.path(), "ai:bob", "link-gate/del2", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (s1, _) = post_link_as(&router, "ai:alice", &alice_src, &bob_tgt).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _) = delete_link_as(&router, "ai:bob", &alice_src, &bob_tgt).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "bob owns the target → symmetric severance permitted"
    );
}
