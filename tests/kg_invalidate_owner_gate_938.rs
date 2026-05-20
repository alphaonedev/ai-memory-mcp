// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #938 — `POST /api/v1/kg/invalidate` caller-vs-source-owner
//! gate regression (security-high, Track A QC sweep 2026-05-20).
//!
//! Pre-#938 the HTTP handler `src/handlers/kg.rs::kg_invalidate` took
//! NO `headers` parameter. Any authenticated caller could POST
//! `{source_id, target_id, relation, valid_until?}` and the substrate
//! `db::invalidate_link` (sqlite) / `kg_invalidate_via_store`
//! (postgres) would mark the matching (source, target, relation)
//! triple invalidated regardless of which agent owns the source
//! memory. Cross-tenant temporal-graph forgery: any caller could
//! mark another tenant's `:supersedes` / `:contradicts` / governance
//! edges invalid by setting `valid_until = now()`, hiding
//! contradictions and supersession chains.
//!
//! The fix mirrors the #930 namespace-set-standard / #936
//! archive-purge gate shape:
//!
//! 1. Handler takes `headers: HeaderMap`, resolves the caller via
//!    `crate::handlers::parity::resolve_caller_agent_id` (the canonical
//!    X-Agent-Id ladder shared by every v0.7.0 post-#874 HTTP handler).
//! 2. Handler fetches the source memory and compares `metadata.agent_id`
//!    to the caller via the `check_kg_invalidate_owner` helper.
//!    Allowed: source-owner, inbox carve-out
//!    (`metadata.target_agent_id == caller`), legacy `"daemon"`
//!    sentinel, or legacy unowned (empty `metadata.agent_id`) rows.
//! 3. Cross-tenant attempts return HTTP 403 + `{error, owner, caller,
//!    source_id}` envelope and DO NOT touch the link row.
//! 4. Missing source memory returns 404 with the canonical
//!    `{found: false, ...}` envelope (existence is a precondition for
//!    any anchor-edge invalidation; the caller is already
//!    authenticated so the 404 is not an existence leak).
//!
//! Tests:
//!
//! 1. `bob_cannot_invalidate_alice_link_938` — alice owns a source
//!    memory and a `:related_to` edge from it; bob's POST returns
//!    HTTP 403 and the link's `valid_until` remains NULL.
//! 2. `owner_can_invalidate_own_link_938` — alice's POST against her
//!    own link returns HTTP 200 + `found: true` and the link's
//!    `valid_until` is now stamped.
//! 3. `missing_source_returns_404_938` — POST against a non-existent
//!    source returns HTTP 404 (mirrors the canonical missing-source
//!    envelope, not a 500).
//! 4. `inbox_target_can_invalidate_938` — when the source memory is
//!    a `_inbox/<recipient>` row (`metadata.target_agent_id` set), the
//!    recipient can invalidate edges anchored to it (same semantic
//!    as `store::is_visible_to_caller`).

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

/// Insert a memory with the supplied owner + optional inbox-target
/// metadata, returning its id. Mirrors `seed_archived` from the #936
/// regression fixture, scaled down to "live memory" rather than the
/// archive table.
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
        source: "test-938".to_string(),
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
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
    id
}

/// Create a `:related_to` link between two seeded memories.
fn seed_link(db_path: &std::path::Path, source_id: &str, target_id: &str, relation: &str) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    ai_memory::db::create_link(&conn, source_id, target_id, relation).expect("create_link seed");
}

/// Inspect `(source, target, relation)`'s `valid_until` column. Returns
/// `None` when the row doesn't exist OR `valid_until` is NULL, so the
/// callers can assert on both "row absent" and "row not invalidated".
fn link_valid_until(
    db_path: &std::path::Path,
    source_id: &str,
    target_id: &str,
    relation: &str,
) -> Option<String> {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row(
        "SELECT valid_until FROM memory_links
         WHERE source_id = ?1 AND target_id = ?2 AND relation = ?3",
        rusqlite::params![source_id, target_id, relation],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

#[allow(clippy::too_many_lines)]
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn invalidate_as(
    router: &axum::Router,
    caller: &str,
    source_id: &str,
    target_id: &str,
    relation: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "source_id": source_id,
        "target_id": target_id,
        "relation": relation,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/kg/invalidate")
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
async fn bob_cannot_invalidate_alice_link_938() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let alice_src = seed_memory(db_path, "alice", "shared-938/a", &json!({}));
    let alice_tgt = seed_memory(db_path, "alice", "shared-938/a", &json!({}));
    seed_link(db_path, &alice_src, &alice_tgt, "related_to");
    assert!(
        link_valid_until(db_path, &alice_src, &alice_tgt, "related_to").is_none(),
        "#938 setup: link must start with valid_until = NULL"
    );

    let router = build_router_fixture(db_path);
    let (status, body) = invalidate_as(&router, "bob", &alice_src, &alice_tgt, "related_to").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#938: bob (non-owner) MUST be refused with HTTP 403; body={body}"
    );
    assert_eq!(
        body["caller"].as_str(),
        Some("bob"),
        "#938: 403 envelope must echo the rejected caller; body={body}"
    );
    assert_eq!(
        body["owner"].as_str(),
        Some("alice"),
        "#938: 403 envelope must echo the source's recorded owner; body={body}"
    );
    assert!(
        link_valid_until(db_path, &alice_src, &alice_tgt, "related_to").is_none(),
        "#938: link valid_until MUST remain NULL after bob's refused POST"
    );
}

#[tokio::test]
async fn owner_can_invalidate_own_link_938() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let alice_src = seed_memory(db_path, "alice", "shared-938/b", &json!({}));
    let alice_tgt = seed_memory(db_path, "alice", "shared-938/b", &json!({}));
    seed_link(db_path, &alice_src, &alice_tgt, "related_to");

    let router = build_router_fixture(db_path);
    let (status, body) =
        invalidate_as(&router, "alice", &alice_src, &alice_tgt, "related_to").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#938 owner-exemption: alice MUST be able to invalidate her own link; body={body}"
    );
    assert_eq!(
        body["found"].as_bool(),
        Some(true),
        "#938: owner POST must surface found=true; body={body}"
    );
    assert!(
        link_valid_until(db_path, &alice_src, &alice_tgt, "related_to").is_some(),
        "#938: link valid_until MUST be stamped after alice's owner POST"
    );
}

#[tokio::test]
async fn missing_source_returns_404_938() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Seed only the target; the source is never created so the owner
    // gate's pre-check hits the "source not found" branch.
    let target = seed_memory(db_path, "alice", "shared-938/c", &json!({}));
    let bogus_src = uuid::Uuid::new_v4().to_string();

    let router = build_router_fixture(db_path);
    let (status, body) = invalidate_as(&router, "alice", &bogus_src, &target, "related_to").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#938: missing source MUST surface as HTTP 404 (not 500, not 403); body={body}"
    );
    assert_eq!(
        body["found"].as_bool(),
        Some(false),
        "#938: 404 envelope must carry found=false for wire-compat; body={body}"
    );
}

#[tokio::test]
async fn inbox_target_can_invalidate_938() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Carol sent alice an inbox-style memory: sender = carol,
    // target_agent_id = alice. Alice is the legitimate
    // reader/invalidator of edges anchored to her own inbox row
    // (mirrors the `store::is_visible_to_caller` carve-out for
    // `_inbox/<recipient>`).
    let inbox_src = seed_memory(
        db_path,
        "carol",
        "_inbox/alice",
        &json!({"target_agent_id": "alice"}),
    );
    let alice_tgt = seed_memory(db_path, "alice", "shared-938/d", &json!({}));
    seed_link(db_path, &inbox_src, &alice_tgt, "related_to");

    let router = build_router_fixture(db_path);
    let (status, body) =
        invalidate_as(&router, "alice", &inbox_src, &alice_tgt, "related_to").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#938 inbox carve-out: alice (target) MUST be able to invalidate edges anchored to her inbox row; body={body}"
    );
    assert_eq!(
        body["found"].as_bool(),
        Some(true),
        "#938 inbox carve-out: target POST must surface found=true; body={body}"
    );
    assert!(
        link_valid_until(db_path, &inbox_src, &alice_tgt, "related_to").is_some(),
        "#938 inbox carve-out: link valid_until MUST be stamped after target's POST"
    );
}
