// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #937 — `DELETE /api/v1/memories/{id}` sqlite path
//! caller-vs-row-owner gate regression (security-high, Track A QC
//! sweep 2026-05-20).
//!
//! Pre-fix the sqlite branch ran governance enforcement
//! (`db::enforce_governance`) but skipped the explicit caller-vs-row-
//! owner check that #930 added to update + promote. When governance
//! is unconfigured (the default), `enforce_governance` returns Allow
//! and the path is wide open — any caller could delete any memory
//! regardless of `metadata.agent_id`.
//!
//! Fix mirrors the #930 / #938 / #940 / #939+#941 gate shape: after
//! resolving the caller, compare to `mem.metadata.agent_id` BEFORE
//! the governance call. 403 on mismatch. Inbox carve-out + legacy
//! "daemon" sentinel + legacy unowned rows pass.

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
        source: "test-937".to_string(),
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
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn delete_as(router: &axum::Router, caller: &str, id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/memories/{id}"))
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
async fn bob_cannot_delete_alice_memory_937() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_id = seed_memory(tmp.path(), "ai:alice", "delete-gate/test", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, _body) = delete_as(&router, "ai:bob", &alice_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "bob must NOT be able to delete alice's memory"
    );

    // Confirm row still exists after the rejected delete.
    let conn = ai_memory::db::open(tmp.path()).expect("reopen");
    let still_exists = ai_memory::db::get(&conn, &alice_id).expect("get").is_some();
    assert!(
        still_exists,
        "memory must still exist after rejected delete"
    );
}

#[tokio::test]
async fn owner_can_delete_own_memory_937() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let alice_id = seed_memory(tmp.path(), "ai:alice", "delete-gate/own", &json!({}));
    let router = build_router_fixture(tmp.path());
    let (status, body) = delete_as(&router, "ai:alice", &alice_id).await;
    assert_eq!(status, StatusCode::OK, "alice owns row → delete OK: {body}");
}

#[tokio::test]
async fn inbox_target_can_delete_inbox_message_937() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let inbox_id = seed_memory(
        tmp.path(),
        "ai:alice",
        "_inbox/ai:bob",
        &json!({"target_agent_id": "ai:bob"}),
    );
    let router = build_router_fixture(tmp.path());
    let (status, body) = delete_as(&router, "ai:bob", &inbox_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bob is the inbox target → delete OK: {body}"
    );
}
