// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v1.0.0 #2719 (CB-6 / 2704-F1, CWE-284) — HTTP+sqlite `clear_namespace_standard`
//! ownership gate.
//!
//! ## The exploit this file pins
//!
//! `clear_namespace_standard_inner`'s sqlite arm passed only `{namespace}` into
//! `handle_namespace_clear_standard`, so its `identity_claimed` probe
//! (`params.agent_id` present + non-empty) was FALSE and the entire #1777 owner
//! gate + #2545 unresolvable-refusal block was SKIPPED:
//!
//! ```text
//! DELETE /api/v1/namespaces/<alice-ns>/standard  X-Agent-Id: ai:mallory
//!   -> 200 cleared, alice's namespace_meta row DELETED (silent authz bypass) —
//!      dropping the #2503 severed floor and re-opening the #2545 attack on the
//!      network surface for ANY api-key/keyless caller.
//! ```
//!
//! The sibling SET path (`set_namespace_standard_inner`) threads the resolved
//! caller into its MCP params; the fix mirrors that so the same #1777 + #2545
//! gates run on CLEAR. A keyless caller resolves to a non-empty anonymous id, so
//! `identity_claimed` is true and the gate refuses a foreign clear of a named
//! owner's standard while an owner clear still succeeds.
//!
//! Pins:
//! - REFUSED: a foreign named caller (`ai:mallory`) cannot clear alice's standard
//! - REFUSED: a keyless caller (no `X-Agent-Id`) cannot clear alice's standard
//! - the `namespace_meta` binding survives every refused clear
//! - CONTROL: the OWNER (`ai:alice`) can still clear their own standard

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const ALICE: &str = "ai:alice-2719";
const MALLORY: &str = "ai:mallory-2719";
const NS: &str = "t2719-alice-ns";

fn seed_owned_standard(conn: &rusqlite::Connection) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        ai_memory::META_KEY_AGENT_ID.to_string(),
        serde_json::json!(ALICE),
    );
    metadata.insert(
        ai_memory::META_KEY_SCOPE.to_string(),
        serde_json::json!("shared"),
    );
    let mem = Memory {
        id: "alice-std-2719".to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "alice-std-2719".to_string(),
        content: "alice's governance standard (2719)".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2719".to_string(),
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
    ai_memory::db::insert(conn, &mem).expect("insert standard memory");
    ai_memory::db::set_namespace_standard(conn, NS, "alice-std-2719", None).expect("bind standard");
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
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
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
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// DELETE /api/v1/namespaces/{ns}/standard with an optional `X-Agent-Id`.
async fn delete_standard(
    router: &axum::Router,
    ns: &str,
    agent: Option<&str>,
) -> (StatusCode, String) {
    let uri = format!("/api/v1/namespaces/{ns}/standard");
    let mut builder = Request::builder().method("DELETE").uri(&uri);
    if let Some(a) = agent {
        builder = builder.header("X-Agent-Id", a);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Read the raw binding straight from `namespace_meta` (bypasses the HTTP
/// visibility/withholding layers).
fn bound_standard_id(db_path: &std::path::Path, ns: &str) -> Option<String> {
    let conn = ai_memory::db::open(db_path).expect("reopen for raw read");
    ai_memory::db::get_namespace_standard(&conn, ns).expect("get_namespace_standard")
}

#[tokio::test]
async fn foreign_caller_cannot_clear_owned_standard_2719() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_owned_standard(&conn);
    }
    let router = build_router(tmp.path());

    // THE #2545 ATTACK on the sqlite network surface: mallory (a foreign named
    // caller) deletes alice's namespace standard. Pre-fix this returned 200 +
    // cleared:true. It must be REFUSED (400 via the #1777 gate).
    let (status, body) = delete_standard(&router, NS, Some(MALLORY)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#2719: a foreign caller must NOT clear alice's owned namespace standard; got {status}: {body}"
    );
    assert_eq!(
        bound_standard_id(tmp.path(), NS).as_deref(),
        Some("alice-std-2719"),
        "#2719: the namespace_meta binding must survive the refused clear; body={body}"
    );
}

#[tokio::test]
async fn keyless_caller_cannot_clear_owned_standard_2719() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_owned_standard(&conn);
    }
    let router = build_router(tmp.path());

    // A keyless caller (no X-Agent-Id at all) resolves to a non-empty anonymous
    // id, so `identity_claimed` is true and the gate refuses the clear.
    let (status, body) = delete_standard(&router, NS, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#2719: a keyless caller must NOT clear alice's owned namespace standard; got {status}: {body}"
    );
    assert_eq!(
        bound_standard_id(tmp.path(), NS).as_deref(),
        Some("alice-std-2719"),
        "#2719: the namespace_meta binding must survive the refused keyless clear; body={body}"
    );
}

#[tokio::test]
async fn owner_can_still_clear_own_standard_2719() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_owned_standard(&conn);
    }
    let router = build_router(tmp.path());

    // CONTROL: alice (the recorded owner) can still clear her own standard.
    let (status, body) = delete_standard(&router, NS, Some(ALICE)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CONTROL: the owner must still be able to clear their standard; got {status}: {body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed["cleared"],
        Value::Bool(true),
        "CONTROL: owner clear must report cleared:true; got {body}"
    );
    assert_eq!(
        bound_standard_id(tmp.path(), NS),
        None,
        "CONTROL: the namespace_meta binding must be gone after the owner clear; body={body}"
    );
}
