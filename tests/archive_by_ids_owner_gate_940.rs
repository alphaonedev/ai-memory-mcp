// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #940 — `archive_by_ids` (sqlite branch) caller-vs-row-owner
//! gate regression (security-high, v0.7.0 SHIP-blocker).
//!
//! Pre-#940 the HTTP handler at
//! `src/handlers/archive.rs::archive_by_ids` (sqlite branch) called
//! the owner-blind `db::archive_memory(&lock.0, id, ...)` with no
//! caller. Any authenticated HTTP caller could bulk-archive any
//! other owner's live rows via:
//!
//! ```text
//! POST /api/v1/archive  {"ids": [...]}
//! ```
//!
//! The pair (restore + bulk-archive) gives an attacker a denial-of-
//! service primitive: archive a victim's live working set out from
//! under them, optionally restore later.
//!
//! The postgres SAL branch was already QC-P1-fixed (2026-05-20) to
//! pass `CallerContext::for_agent(caller)`; the sqlite branch is
//! closed by routing through the new caller-scoped helper
//! `db::archive_memory_for_caller(conn, id, reason, caller)`. A
//! non-owner id surfaces in the `missing` response slot (same shape
//! as a row that wasn't live locally) so the surface cannot be used
//! to probe other owners' live ids.
//!
//! Tests:
//!
//! 1. `bob_cannot_archive_alice_live_row_940` — alice owns a live
//!    row; bob's bulk-archive attempt returns the row in `missing`
//!    and the row remains in `memories`.
//! 2. `owner_can_archive_own_live_row_940` — alice can bulk-archive
//!    her own row; it moves from `memories` to `archived_memories`.
//! 3. `mixed_batch_only_archives_owner_rows_940` — bob runs a batch
//!    with one of his own ids + one of alice's; only bob's lands in
//!    `archived`, alice's lands in `missing`, alice's row is intact.
//! 4. `inbox_target_can_archive_inbox_row_940` — alice can archive
//!    a live inbox row whose `metadata.target_agent_id == "alice"`
//!    (mirrors the `is_visible_to_caller` carve-out).

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

/// Insert one live memory with the supplied owner + metadata.
/// Returns the row id.
fn seed_live(
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
        title: format!("seed-{owner}"),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
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
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
    id
}

fn live_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count live")
}

fn archive_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count archived")
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
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn archive_as(
    router: &axum::Router,
    caller: &str,
    ids: &[&str],
    reason: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({"ids": ids});
    if let Some(r) = reason
        && let Some(obj) = body.as_object_mut()
    {
        obj.insert("reason".into(), json!(r));
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/archive")
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
async fn bob_cannot_archive_alice_live_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let id = seed_live(db_path, "alice", "shared-940/a", &json!({}));
    assert_eq!(live_row_count(db_path), 1);
    assert_eq!(archive_row_count(db_path), 0);

    let router = build_router_fixture(db_path);
    let (status, body) = archive_as(&router, "bob", &[&id], None).await;
    assert_eq!(status, StatusCode::OK, "archive body: {body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "#940: bob (non-owner) MUST NOT archive alice's row; body={body}"
    );
    let archived = body["archived"].as_array().expect("archived array");
    assert!(
        archived.is_empty(),
        "#940: archived MUST be empty for non-owner bulk-archive attempt; body={body}"
    );
    let missing = body["missing"].as_array().expect("missing array");
    assert_eq!(
        missing.len(),
        1,
        "#940: alice's id MUST surface in `missing` (same shape as not-live-locally); body={body}"
    );
    assert_eq!(missing[0].as_str(), Some(id.as_str()));
    assert_eq!(
        live_row_count(db_path),
        1,
        "#940: alice's live row MUST still exist after bob's bulk-archive attempt"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#940: no archived row MUST be created by bob's attempt"
    );
}

#[tokio::test]
async fn owner_can_archive_own_live_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let id = seed_live(db_path, "alice", "shared-940/b", &json!({}));
    assert_eq!(live_row_count(db_path), 1);

    let router = build_router_fixture(db_path);
    let (status, body) = archive_as(&router, "alice", &[&id], Some("own-archive-940")).await;
    assert_eq!(status, StatusCode::OK, "archive body: {body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(1),
        "#940 owner-exemption: alice MUST be able to archive her own row; body={body}"
    );
    assert_eq!(
        live_row_count(db_path),
        0,
        "#940: alice's row MUST be moved out of memories after owner archive"
    );
    assert_eq!(
        archive_row_count(db_path),
        1,
        "#940: alice's row MUST land in archived_memories after owner archive"
    );
}

#[tokio::test]
async fn mixed_batch_only_archives_owner_rows_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let alice_id = seed_live(db_path, "alice", "shared-940/a", &json!({}));
    let bob_id = seed_live(db_path, "bob", "shared-940/b", &json!({}));
    assert_eq!(live_row_count(db_path), 2);

    let router = build_router_fixture(db_path);
    // Bob attempts to archive his own row + alice's row in one batch.
    let (status, body) = archive_as(&router, "bob", &[&bob_id, &alice_id], Some("mixed-940")).await;
    assert_eq!(status, StatusCode::OK, "archive body: {body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(1),
        "#940: only bob's own row may land in archived; body={body}"
    );
    let archived: Vec<&str> = body["archived"]
        .as_array()
        .expect("archived array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(archived, vec![bob_id.as_str()]);
    let missing: Vec<&str> = body["missing"]
        .as_array()
        .expect("missing array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(missing, vec![alice_id.as_str()]);
    // Alice's live row remains intact.
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let alice_present: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM memories WHERE id = ?1",
            [&alice_id],
            |r| r.get(0),
        )
        .expect("count alice");
    assert!(
        alice_present,
        "#940: alice's row MUST remain live after bob's mixed batch"
    );
    // Bob's row is archived.
    let bob_archived: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM archived_memories WHERE id = ?1",
            [&bob_id],
            |r| r.get(0),
        )
        .expect("count bob");
    assert!(
        bob_archived,
        "#940: bob's own row MUST move to archived in the mixed batch"
    );
}

#[tokio::test]
async fn inbox_target_can_archive_inbox_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Carol sent alice an inbox message; the live row carries
    // `metadata.agent_id = "carol"` (sender) and
    // `metadata.target_agent_id = "alice"` (recipient). Alice is the
    // legitimate reader/archiver of her own inbox per the
    // `is_visible_to_caller` carve-out.
    let id = seed_live(
        db_path,
        "carol",
        "_inbox/alice",
        &json!({"target_agent_id": "alice"}),
    );
    assert_eq!(live_row_count(db_path), 1);

    let router = build_router_fixture(db_path);
    let (status, body) = archive_as(&router, "alice", &[&id], Some("inbox-tidy-940")).await;
    assert_eq!(status, StatusCode::OK, "archive body: {body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(1),
        "#940 inbox carve-out: alice (target) MUST be able to archive her own inbox row; body={body}"
    );
    assert_eq!(
        live_row_count(db_path),
        0,
        "#940: inbox row MUST move out of memories after target archive"
    );
    assert_eq!(
        archive_row_count(db_path),
        1,
        "#940: inbox row MUST land in archived_memories after target archive"
    );
}
