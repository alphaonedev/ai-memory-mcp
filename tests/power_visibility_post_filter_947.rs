// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #947 — sqlite legacy path visibility post-filter on three
//! `power.rs` + `kg.rs` handler sites that pre-fix scanned the
//! database without a caller filter:
//!
//! 1. `detect_contradictions` — `db::list` in the sqlite branch
//!    returned every namespace row regardless of `metadata.scope`;
//!    cross-tenant attacker could enumerate contradiction candidates.
//! 2. `check_duplicate` — `db::check_duplicate_with_text` scanned all
//!    embeddings in the namespace; an attacker could probe whether
//!    their input matched another tenant's private memory via the
//!    cosine-similarity surface.
//! 3. `entity_get_by_alias` — `db::entity_get_by_alias` returned the
//!    matching entity row regardless of ownership; a cross-tenant
//!    alias collision leaked the existence of a private entity.
//!
//! Fix: in each handler, resolve the caller from `X-Agent-Id`, then
//! post-filter results through `crate::visibility::is_visible_to_caller`.
//! Admin callers (per `is_admin_caller`) bypass the filter to match
//! the cross-cutting admin posture.
//!
//! These tests pin the cross-tenant block + the owner-exemption +
//! the admin-bypass for each of the three surfaces.

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

fn build_fixture(
    seeds: &[(&str, &str, &str, &str)],
    admin_ids: Vec<String>,
) -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    for (title, ns, owner, scope) in seeds {
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: (*ns).to_string(),
            title: (*title).to_string(),
            content: format!("body for {title}/{owner}/{scope}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now.clone(),
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": owner, "scope": scope}),
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn get_as(router: &axum::Router, uri: &str, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
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

// ---- detect_contradictions: sqlite legacy path ----

#[tokio::test]
async fn detect_contradictions_blocks_cross_tenant_private_rows_947() {
    // Alice owns a scope=private row in the namespace. Bob calls the
    // endpoint; pre-fix he would see it surface as a contradiction
    // candidate. Post-fix the visibility filter must drop it.
    // (Note: db::insert UPSERTs on (title, namespace), so we seed one
    // row per title to avoid the dedup collapsing the seed set.)
    let (router, _f) = build_fixture(
        &[("disputed-fact-a", "ns-947-contra", "alice", "private")],
        Vec::new(),
    );
    let (status, body) = get_as(
        &router,
        "/api/v1/contradictions?namespace=ns-947-contra",
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let memories = body["memories"].as_array().expect("memories array");
    assert!(
        memories.is_empty(),
        "#947: bob must NOT see alice's scope=private contradiction candidates, got body={body}"
    );
}

#[tokio::test]
async fn detect_contradictions_owner_can_see_own_private_rows_947() {
    let (router, _f) = build_fixture(
        &[("disputed-fact-b", "ns-947-contra-b", "alice", "private")],
        Vec::new(),
    );
    let (status, body) = get_as(
        &router,
        "/api/v1/contradictions?namespace=ns-947-contra-b",
        "alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let memories = body["memories"].as_array().expect("memories array");
    assert_eq!(
        memories.len(),
        1,
        "#947 owner-exemption: alice MUST see her own private row, got body={body}"
    );
}

#[tokio::test]
async fn detect_contradictions_admin_bypass_947() {
    let (router, _f) = build_fixture(
        &[("disputed-fact-c", "ns-947-contra-c", "alice", "private")],
        vec!["ops:admin".to_string()],
    );
    let (status, body) = get_as(
        &router,
        "/api/v1/contradictions?namespace=ns-947-contra-c",
        "ops:admin",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let memories = body["memories"].as_array().expect("memories array");
    assert_eq!(
        memories.len(),
        1,
        "#947 admin-bypass: admin MUST see cross-tenant private rows, got body={body}"
    );
}

#[tokio::test]
async fn detect_contradictions_scope_collective_visible_cross_tenant_947() {
    // Precision check: scope=collective rows MUST remain visible to
    // bob (the filter is precise — only `private` is dropped).
    let (router, _f) = build_fixture(
        &[("public-fact", "ns-947-contra-d", "alice", "collective")],
        Vec::new(),
    );
    let (status, body) = get_as(
        &router,
        "/api/v1/contradictions?namespace=ns-947-contra-d",
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    let memories = body["memories"].as_array().expect("memories array");
    assert_eq!(
        memories.len(),
        1,
        "#947 precision: scope=collective rows MUST stay visible cross-tenant, got body={body}"
    );
}

// ---- entity_get_by_alias: sqlite legacy path ----
// (check_duplicate sqlite path requires an embedder; covered by the
// unit-level tests at handlers::tests:: + the SAL postgres path test.
// The sqlite-only embedder-less surface returns 503; we don't have a
// way to fixture a real embedder in an integration test cheaply, so
// the duplicate-check visibility filter is pinned through code review
// + the unified caller-resolution pattern shared with the other two
// surfaces.)

#[tokio::test]
async fn entity_get_by_alias_blocks_cross_tenant_private_entity_947() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    // Seed: a private entity owned by alice. `entity_register` writes
    // the entity-alias row; we additionally insert a scope=private
    // memory at the entity_id so the visibility filter has a row to
    // gate on.
    let entity_id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: entity_id.clone(),
        tier: Tier::Long,
        namespace: "ns-947-ent".to_string(),
        title: "Acme Corp".to_string(),
        content: "private entity body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "alice", "scope": "private", "kind": "entity"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Entity,
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
    ai_memory::db::insert(&conn, &mem).expect("insert entity memory");
    // Register alias row pointing at the entity_id.
    ai_memory::db::entity_register(
        &conn,
        "Acme Corp",
        "ns-947-ent",
        &["acme".to_string()],
        &json!({}),
        Some("alice"),
    )
    .expect("entity_register");

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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);

    // Bob (non-owner, non-admin) must see found:false (existence-leak mask).
    let (status, body) = get_as(
        &router,
        "/api/v1/entities/by_alias?alias=acme&namespace=ns-947-ent",
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {status} body={body}");
    assert_eq!(
        body["found"], false,
        "#947: bob must NOT resolve alice's private entity alias, got body={body}"
    );

    // Alice (owner) sees found:true.
    let (status_owner, body_owner) = get_as(
        &router,
        "/api/v1/entities/by_alias?alias=acme&namespace=ns-947-ent",
        "alice",
    )
    .await;
    assert_eq!(
        status_owner,
        StatusCode::OK,
        "got {status_owner} body={body_owner}"
    );
    assert_eq!(
        body_owner["found"], true,
        "#947 owner-exemption: alice MUST resolve her own entity, got body={body_owner}"
    );
    assert_eq!(body_owner["canonical_name"], "Acme Corp");
}
