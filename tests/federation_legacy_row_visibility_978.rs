// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on the regression we pin.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

//! v0.7.0 #978 — federation `/sync/since` legacy-row visibility gate.
//!
//! Pre-#978 the `has_ownership_signal` carve-out in
//! `src/handlers/federation_sync_since.rs:107-115` projected any row
//! that lacked BOTH `metadata.scope` AND `metadata.agent_id` through
//! the federation pull UNCHANGED, on the rationale that pre-v0.7-era
//! rows had no NHI-ownership signals to filter against. That carve-out
//! was the cross-tenant leak surface: a memory written by the operator
//! (or via legacy CLI without `agent_id`) leaked to every federated
//! peer matching the namespace allowlist, regardless of whether the
//! row content was intended for that peer to see.
//!
//! Post-#978 the substrate runs every row through
//! `crate::visibility::is_visible_to_caller`, with ONE named
//! operator-explicit escape hatch: `metadata.federation_share == true`.
//! Operators migrating legacy peers stamp the flag on rows that
//! SHOULD federate; everything else default-denies.
//!
//! The existing `AI_MEMORY_FED_SYNC_TRUST_PEER=1` full-dump escape
//! hatch (`scope_status: "legacy_bypass"`) keeps working for legacy
//! peers that demand the pre-#978 wire shape — covered by
//! `g_issue_239_sync_scope::case_3_no_allowlist_with_bypass_is_full_dump`.
//!
//! This file pins the new semantics specifically:
//!
//! 1. Legacy row (no scope + no agent_id + no federation_share flag)
//!    in an allowlisted namespace → EXCLUDED from response (the leak
//!    surface this issue closes).
//! 2. Legacy row + `federation_share=true` → INCLUDED (operator opt-in).
//! 3. `federation_share=true` is strict-bool — `"true"` (string) or
//!    `1` (int) do NOT bypass; only the literal JSON `true`.
//! 4. Owner-signed scope=private row + peer caller==owner → INCLUDED.
//! 5. Inbox-target row + peer caller==target_agent_id → INCLUDED.
//! 6. Scope=shared row → INCLUDED (post-#948 canonical shareable shape).
//! 7. `excluded_for_scope_private` counter reflects the new gate.

use ai_memory::models::ConfidenceSource;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"),
        )
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(None),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

async fn seed_with_metadata(
    db: &ai_memory::handlers::Db,
    ns: &str,
    title: &str,
    metadata: serde_json::Value,
) {
    let lock = db.lock().await;
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ns.into(),
        title: title.into(),
        content: "x".into(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "user".into(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&lock.0, &mem).expect("seed insert");
}

fn reset_env() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

async fn sync_since_body(router: axum::Router, peer_id: &str) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/sync/since")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer_id,
        )
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "sync_since must always 200");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn set_peer1_allowlist(ns_glob: &str) {
    let allowlist = format!(r#"{{ "peer-1": {{ "allowed_namespaces": ["{ns_glob}"] }} }}"#);
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            allowlist,
        );
    }
}

/// 1. Legacy row (no scope, no agent_id, no federation_share flag) in
///    an allowlisted namespace MUST be excluded. This is the leak the
///    issue closes.
#[tokio::test]
async fn legacy_unauthored_row_excluded_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("legacy/*");
    let (router, db) = build_router_with_db();
    seed_with_metadata(
        &db,
        "legacy/operator-seed",
        "legacy",
        ai_memory::models::default_metadata(),
    )
    .await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        0,
        "pre-#978 leak: legacy unauthored row MUST NOT project to a peer that hasn't been granted owner / inbox-target / federation_share consent. Got: {body:?}",
    );
    // The `excluded_for_scope_private` counter pins the new gate as
    // the rejector (separate from the namespace-allowlist
    // `excluded_for_scope` counter).
    assert_eq!(
        body["excluded_for_scope_private"], 1,
        "the visibility gate (not the namespace allowlist) must reject the legacy row",
    );
}

/// 2. Legacy row + `federation_share = true` opt-in MUST be projected.
///    Operator-explicit consent overrides the default-deny.
#[tokio::test]
async fn federation_share_opt_in_projects_legacy_row_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("legacy/*");
    let (router, db) = build_router_with_db();
    let mut md = ai_memory::models::default_metadata();
    if let Some(o) = md.as_object_mut() {
        o.insert(
            "federation_share".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    seed_with_metadata(&db, "legacy/operator-seed", "shared-legacy", md).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        1,
        "operator-explicit federation_share=true MUST opt the legacy row into projection. Got: {body:?}",
    );
}

/// 3. `federation_share` is strict-bool. `"true"` (string) and `1`
///    (integer) do NOT count as opt-in; only the literal JSON `true`.
///    Catches a class of mistakes where the operator writes the flag
///    via a templating layer that emits stringified booleans.
#[tokio::test]
async fn federation_share_is_strict_bool_only_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("legacy/*");
    let (router, db) = build_router_with_db();
    // String "true" — must NOT count as opt-in.
    let mut md_string = ai_memory::models::default_metadata();
    if let Some(o) = md_string.as_object_mut() {
        o.insert(
            "federation_share".to_string(),
            serde_json::Value::String("true".to_string()),
        );
    }
    seed_with_metadata(&db, "legacy/string-flag", "string-true", md_string).await;
    // Integer 1 — must NOT count as opt-in.
    let mut md_int = ai_memory::models::default_metadata();
    if let Some(o) = md_int.as_object_mut() {
        o.insert(
            "federation_share".to_string(),
            serde_json::Value::Number(1u64.into()),
        );
    }
    seed_with_metadata(&db, "legacy/int-flag", "int-1", md_int).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        0,
        "string \"true\" and integer 1 MUST NOT pass federation_share strict-bool check. Got: {body:?}",
    );
}

/// 4. Owner-signed scope=private row + peer caller == owner MUST be
///    projected. Pin that the visibility gate continues to honour the
///    canonical owner-match path.
#[tokio::test]
async fn owner_signed_private_row_projects_to_owner_peer_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("ops/*");
    let (router, db) = build_router_with_db();
    let metadata = serde_json::json!({
        "scope": "private",
        "agent_id": "peer-1",
    });
    seed_with_metadata(&db, "ops/private-to-peer-1", "owner-row", metadata).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        1,
        "owner-match: scope=private + agent_id=peer-1 MUST project to peer-1. Got: {body:?}",
    );
}

/// 5. Inbox-target row + peer caller == target_agent_id MUST be
///    projected. The inbox carve-out (private-by-default with the
///    target stamped on the row) is the canonical
///    sender-to-recipient channel and must continue working
///    post-#978.
#[tokio::test]
async fn inbox_target_row_projects_to_target_peer_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("_inbox/*");
    let (router, db) = build_router_with_db();
    let metadata = serde_json::json!({
        "scope": "private",
        "agent_id": "sender",
        "target_agent_id": "peer-1",
    });
    seed_with_metadata(&db, "_inbox/peer-1", "inbox-row", metadata).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        1,
        "inbox-target: scope=private + target_agent_id=peer-1 MUST project to peer-1. Got: {body:?}",
    );
}

/// 6. Scope=shared row (post-#948 canonical shareable shape) MUST be
///    projected regardless of caller. Pin that the explicit shared
///    scope continues to satisfy the visibility predicate.
#[tokio::test]
async fn shared_scope_row_projects_to_any_peer_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("shared/*");
    let (router, db) = build_router_with_db();
    let metadata = serde_json::json!({"scope": "shared"});
    seed_with_metadata(&db, "shared/announcement", "shared-row", metadata).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        1,
        "scope=shared row MUST project to any allowlisted peer. Got: {body:?}",
    );
}

/// 7. Non-owner peer cross-tenant write attempt: scope=private row
///    with agent_id=alice MUST NOT project to peer-1 (which is bob).
///    Pin the canonical cross-tenant deny.
#[tokio::test]
async fn private_row_owned_by_other_does_not_project_978() {
    let env_guard = ENV_LOCK.lock().await;
    reset_env();
    set_peer1_allowlist("alice/*");
    let (router, db) = build_router_with_db();
    let metadata = serde_json::json!({
        "scope": "private",
        "agent_id": "alice",
    });
    seed_with_metadata(&db, "alice/secret", "alice-row", metadata).await;
    let body = sync_since_body(router, "peer-1").await;
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
    drop(env_guard);
    let mems = body["memories"].as_array().unwrap();
    assert_eq!(
        mems.len(),
        0,
        "scope=private + agent_id=alice MUST NOT project to peer-1. Got: {body:?}",
    );
    assert_eq!(
        body["excluded_for_scope_private"], 1,
        "the visibility gate must reject the non-owner-targeted private row",
    );
}
