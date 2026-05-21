// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Issue #936 — `archive_purge` caller-vs-row-owner gate regression
//! (security-critical, v0.7.0 SHIP-blocker).
//!
//! Pre-#936 the postgres SAL trait method `archive_purge(older_than_days)`
//! took NO caller argument and the HTTP handler at
//! `src/handlers/archive.rs::purge_archive` ran an unconstrained DELETE
//! against `archived_memories`. Any authenticated caller could destroy
//! every owner's archived corpus via:
//!
//! ```text
//! DELETE /api/v1/archive?older_than_days=N
//! ```
//!
//! The fix:
//!
//! 1. SAL trait `archive_purge` now requires `&CallerContext`.
//! 2. Adapters (sqlite + postgres) constrain the DELETE to rows whose
//!    `metadata.agent_id` matches the caller (with the inbox-target
//!    carve-out: `metadata.target_agent_id == caller` is also
//!    purgeable). Admin callers (`ctx.bypass_visibility == true`)
//!    skip the filter — the legitimate operator full-wipe path.
//! 3. Handler resolves the caller from `X-Agent-Id`, audits the
//!    role decision, then routes through the owner-scoped variant
//!    by default. Admin/operator path reserved for
//!    `[admin].agent_ids` allowlist members.
//!
//! These tests pin the contract on the sqlite path (the postgres
//! branch is covered by the trait-level dispatch in the
//! `tests/g*_postgres_*` integration tests when a live PG instance
//! is available; the in-process sqlite path is the wire-level
//! regression surface).
//!
//! Tests:
//!
//! 1. `bob_cannot_purge_alice_rows_936` — alice archives a row;
//!    bob's `DELETE /api/v1/archive` returns `{purged: 0}` and
//!    alice's row remains.
//! 2. `owner_can_purge_own_archived_rows_936` — alice archives a
//!    row, alice's `DELETE /api/v1/archive` returns `{purged: 1}`.
//! 3. `non_admin_caller_does_not_get_admin_owner_scope_936` —
//!    the response includes `owner_scope: "caller"` for non-admins.
//! 4. `admin_caller_can_purge_cross_tenant_936` — when the caller's
//!    `agent_id` is in `admin_agent_ids`, the DELETE is owner-blind
//!    and the response includes `owner_scope: "admin"`.
//! 5. `inbox_target_carve_out_purgeable_by_recipient_936` — inbox
//!    rows (`metadata.target_agent_id == caller`) are purgeable
//!    by the recipient even when the sender is a different agent
//!    (mirrors the `is_visible_to_caller` semantic).

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
/// `archived_memories` with the supplied metadata.
fn seed_archived(db_path: &std::path::Path, owner: &str, namespace: &str, extra_meta: &Value) {
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
    // Move into archived_memories with a fresh `archived_at`.
    let moved =
        ai_memory::db::archive_memory(&conn, &id, Some("test-936")).expect("archive_memory");
    assert!(moved, "archive_memory must return true on live row");
}

/// Count rows in `archived_memories` (used to verify state after
/// the purge).
fn archive_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count archived")
}

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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn purge_as(router: &axum::Router, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/archive")
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
async fn bob_cannot_purge_alice_rows_936() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_archived(db_path, "alice", "shared-936/a", &json!({}));
    assert_eq!(
        archive_row_count(db_path),
        1,
        "seed must land 1 archived row"
    );

    let router = build_router_fixture_with_admin(db_path, vec![]);
    let (status, body) = purge_as(&router, "bob").await;
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert_eq!(
        body["purged"].as_u64(),
        Some(0),
        "#936: bob (non-owner, non-admin) MUST NOT destroy alice's archived rows; body={body}"
    );
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("caller"),
        "#936: non-admin response must declare owner_scope=caller; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        1,
        "#936: archived row MUST still exist after bob's failed purge"
    );
}

#[tokio::test]
async fn owner_can_purge_own_archived_rows_936() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_archived(db_path, "alice", "shared-936/b", &json!({}));
    assert_eq!(
        archive_row_count(db_path),
        1,
        "seed must land 1 archived row"
    );

    let router = build_router_fixture_with_admin(db_path, vec![]);
    let (status, body) = purge_as(&router, "alice").await;
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert_eq!(
        body["purged"].as_u64(),
        Some(1),
        "#936 owner-exemption: alice MUST be able to purge her own archived rows; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#936: archived row MUST be gone after alice's own purge"
    );
}

#[tokio::test]
async fn non_admin_caller_does_not_get_admin_owner_scope_936() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Mixed deployment — alice's + carol's rows in the archive.
    seed_archived(db_path, "alice", "mixed-936/a", &json!({}));
    seed_archived(db_path, "carol", "mixed-936/c", &json!({}));
    assert_eq!(archive_row_count(db_path), 2);

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    // Non-admin caller — even though an admin allowlist is configured,
    // bob is not in it.
    let (status, body) = purge_as(&router, "bob").await;
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert_eq!(
        body["purged"].as_u64(),
        Some(0),
        "#936: non-admin bob MUST NOT touch alice's or carol's rows; body={body}"
    );
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("caller"),
        "#936: non-admin allowlist-miss MUST resolve to owner_scope=caller; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        2,
        "#936: cross-tenant rows MUST be intact after non-admin attempt"
    );
}

#[tokio::test]
async fn admin_caller_can_purge_cross_tenant_936() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    seed_archived(db_path, "alice", "mixed-936/a", &json!({}));
    seed_archived(db_path, "carol", "mixed-936/c", &json!({}));
    assert_eq!(archive_row_count(db_path), 2);

    let router = build_router_fixture_with_admin(db_path, vec!["ops:admin".into()]);
    let (status, body) = purge_as(&router, "ops:admin").await;
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert_eq!(
        body["purged"].as_u64(),
        Some(2),
        "#936 admin-bypass: ops:admin in allowlist MUST be able to purge cross-tenant; body={body}"
    );
    assert_eq!(
        body["owner_scope"].as_str(),
        Some("admin"),
        "#936: allowlist-hit MUST resolve to owner_scope=admin; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#936: admin-bypass purge MUST land both rows in the destructive path"
    );
}

#[tokio::test]
async fn inbox_target_carve_out_purgeable_by_recipient_936() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path();
    // Carol sent alice an inbox message; the row lives in alice's
    // `_inbox/alice` namespace with `metadata.agent_id = "carol"`
    // (the sender) and `metadata.target_agent_id = "alice"` (the
    // recipient). The `is_visible_to_caller` carve-out treats this
    // as alice-readable / alice-purgeable per the
    // `MemoryStore::archive_purge` doc-comment.
    seed_archived(
        db_path,
        "carol",
        "_inbox/alice",
        &json!({"target_agent_id": "alice"}),
    );
    assert_eq!(archive_row_count(db_path), 1);

    let router = build_router_fixture_with_admin(db_path, vec![]);
    let (status, body) = purge_as(&router, "alice").await;
    assert_eq!(status, StatusCode::OK, "purge body: {body}");
    assert_eq!(
        body["purged"].as_u64(),
        Some(1),
        "#936 inbox carve-out: alice (target) MUST be able to purge her own inbox row; body={body}"
    );
    assert_eq!(
        archive_row_count(db_path),
        0,
        "#936: inbox-target carve-out MUST purge the recipient's view"
    );
}
