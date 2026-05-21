// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #940 — `archive_restore` (sqlite branch) caller-vs-row-owner
//! gate regression (security-high, v0.7.0 SHIP-blocker).
//!
//! Pre-#940 the HTTP handler at
//! `src/handlers/archive.rs::restore_archive` (sqlite branch) called
//! the owner-blind `db::restore_archived(&lock.0, &id)` with no
//! caller. Any authenticated HTTP caller could restore any other
//! owner's archived rows back into the live working set via:
//!
//! ```text
//! POST /api/v1/archive/{id}/restore
//! ```
//!
//! The postgres SAL branch was already QC-P1-fixed (2026-05-20) to
//! pass `CallerContext::for_agent(caller)`; the sqlite branch is
//! closed by routing through the new caller-scoped helper
//! `db::restore_archived_for_caller(conn, id, caller)`. Non-owner
//! attempts return 404 (not 403) so the surface cannot be used to
//! enumerate other owners' archived ids — mirrors the #927
//! `get_memory` posture.
//!
//! Tests:
//!
//! 1. `bob_cannot_restore_alice_archived_row_940` — alice archives a
//!    row; bob's `POST /api/v1/archive/{id}/restore` returns 404 and
//!    the row remains in `archived_memories`.
//! 2. `owner_can_restore_own_archived_row_940` — alice can restore
//!    her own archived row; the row returns to `memories`.
//! 3. `inbox_target_can_restore_inbox_row_940` — inbox rows
//!    (`metadata.target_agent_id == recipient`) are restorable by
//!    the recipient even though the sender stamps `metadata.agent_id`
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

/// Insert one memory and then archive it so the row lands in
/// `archived_memories` with the supplied metadata. Returns the row id.
fn seed_archived(
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
    let moved =
        ai_memory::db::archive_memory(&conn, &id, Some("test-940")).expect("archive_memory");
    assert!(moved, "archive_memory must return true on live row");
    id
}

fn archive_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count archived")
}

fn live_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count live")
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn restore_as(router: &axum::Router, caller: &str, id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/archive/{id}/restore"))
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
async fn bob_cannot_restore_alice_archived_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let id = seed_archived(db_path, "alice", "shared-940/a", &json!({}));
    assert_eq!(archive_row_count(db_path), 1);
    assert_eq!(live_row_count(db_path), 0);

    let router = build_router_fixture(db_path);
    let (status, body) = restore_as(&router, "bob", &id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "#940: bob (non-owner) MUST get 404 on restore attempt; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        1,
        "#940: alice's archived row MUST still be present after bob's failed restore"
    );
    assert_eq!(
        live_row_count(db_path),
        0,
        "#940: alice's row MUST NOT be restored into the live set by bob"
    );
}

#[tokio::test]
async fn owner_can_restore_own_archived_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    let id = seed_archived(db_path, "alice", "shared-940/b", &json!({}));
    assert_eq!(archive_row_count(db_path), 1);

    let router = build_router_fixture(db_path);
    let (status, body) = restore_as(&router, "alice", &id).await;
    assert_eq!(status, StatusCode::OK, "restore body: {body}");
    assert_eq!(
        body["restored"].as_bool(),
        Some(true),
        "#940 owner-exemption: alice MUST be able to restore her own row; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#940: archived row MUST be gone after owner restore"
    );
    assert_eq!(
        live_row_count(db_path),
        1,
        "#940: row MUST land in the live set after owner restore"
    );
}

#[tokio::test]
async fn inbox_target_can_restore_inbox_row_940() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Carol sent alice an inbox message; the row carries
    // `metadata.agent_id = "carol"` (the sender) and
    // `metadata.target_agent_id = "alice"` (the recipient). The
    // `is_visible_to_caller` carve-out treats this as alice-readable
    // / alice-restorable.
    let id = seed_archived(
        db_path,
        "carol",
        "_inbox/alice",
        &json!({"target_agent_id": "alice"}),
    );
    assert_eq!(archive_row_count(db_path), 1);

    let router = build_router_fixture(db_path);
    let (status, body) = restore_as(&router, "alice", &id).await;
    assert_eq!(status, StatusCode::OK, "restore body: {body}");
    assert_eq!(
        body["restored"].as_bool(),
        Some(true),
        "#940 inbox carve-out: alice (target) MUST be able to restore her own inbox row; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#940: inbox-target carve-out MUST restore the recipient's view"
    );
    assert_eq!(
        live_row_count(db_path),
        1,
        "#940: inbox row MUST land in the live set after target restore"
    );
}
