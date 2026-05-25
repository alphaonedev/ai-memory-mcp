// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #959 — `GET /api/v1/links/{id}` visibility post-filter
//! regression coverage.
//!
//! Pre-fix `get_links` returned every link anchored at the requested
//! memory id regardless of whether either endpoint memory was
//! scope=private owned by a different agent. An attacker who knew or
//! guessed a victim's memory id could enumerate that memory's
//! outgoing graph topology.
//!
//! The fix resolves the caller from `X-Agent-Id`, then drops any
//! edge whose `source_id` OR `target_id` row is not visible to the
//! caller. Admin callers (per `is_admin_caller`) bypass the filter.

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

fn build_router(admin_ids: Vec<String>) -> (axum::Router, NamedTempFile, String, String) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let alice_id = uuid::Uuid::new_v4().to_string();
    let bob_id = uuid::Uuid::new_v4().to_string();
    let alice = Memory {
        id: alice_id.clone(),
        tier: Tier::Long,
        namespace: "ns-959".to_string(),
        title: "alice-private-row".to_string(),
        content: "alice body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "alice", "scope": "private"}),
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
    let bob = Memory {
        id: bob_id.clone(),
        tier: Tier::Long,
        namespace: "ns-959".to_string(),
        title: "bob-public-row".to_string(),
        content: "bob body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "bob", "scope": "collective"}),
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
    ai_memory::db::insert(&conn, &alice).expect("insert alice");
    ai_memory::db::insert(&conn, &bob).expect("insert bob");

    // Edge bob → alice (alice is scope=private, so bob's outbound
    // edge MUST be hidden from non-owners).
    ai_memory::db::create_link(&conn, &bob_id, &alice_id, "related_to").expect("create link");

    let conn2 = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(Mutex::new((
        conn2,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, alice_id, bob_id)
}

async fn get_links_as(router: &axum::Router, anchor_id: &str, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/links/{anchor_id}"))
        .header("x-agent-id", caller)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn get_links_blocks_cross_tenant_edge_to_private_endpoint_959() {
    // Edge bob→alice (alice scope=private). Charlie (third party)
    // anchors the lookup at bob (which is collective + readable) and
    // pre-fix would see the edge surface alice's private id.
    let (router, _f, _alice_id, bob_id) = build_router(Vec::new());
    let (status, body) = get_links_as(&router, &bob_id, "charlie").await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let links = body["links"].as_array().expect("links array");
    assert!(
        links.is_empty(),
        "#959: charlie must NOT see edge to alice's scope=private endpoint, got body={body}"
    );
}

#[tokio::test]
async fn get_links_owner_can_see_own_edges_959() {
    let (router, _f, alice_id, _bob_id) = build_router(Vec::new());
    // Alice anchors at her own memory; she's the owner → sees the edge.
    let (status, body) = get_links_as(&router, &alice_id, "alice").await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let links = body["links"].as_array().expect("links array");
    assert_eq!(
        links.len(),
        1,
        "#959 owner-exemption: alice MUST see edge to her own row, got body={body}"
    );
}

#[tokio::test]
async fn get_links_admin_bypass_959() {
    let (router, _f, alice_id, _bob_id) = build_router(vec!["ops:admin".to_string()]);
    let (status, body) = get_links_as(&router, &alice_id, "ops:admin").await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let links = body["links"].as_array().expect("links array");
    assert_eq!(
        links.len(),
        1,
        "#959 admin-bypass: admin MUST see edges across tenants, got body={body}"
    );
}
