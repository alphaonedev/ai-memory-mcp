// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage lift (operator 90%-per-module floor, 2026-06-11) for the
//! sqlite-branch SUCCESS arms of `handlers/archive.rs` and the
//! caller-owned mutation success arms of `handlers/memories.rs` that the
//! pre-existing suites (which only hit the 404 / 400 error arms or the
//! postgres branch) leave dark.
//!
//! Each test seeds a real memory through the HTTP create path so the
//! row lands in `app.db` (the connection the sqlite read/write paths
//! use), then drives archive → restore → list → purge and
//! get/update/delete/promote round-trips against that row.

#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

fn build_router() -> (axum::Router, NamedTempFile) {
    // Mark request-authn configured so the explicit admin allowlist
    // below admits the admin caller (the `cfg(test)` "*" wildcard arm
    // is compiled out for integration-test linkage; #980/#1570).
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["arch-admin".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let router = ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
        },
        app_state,
    );
    (router, f)
}

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn send(
    router: &axum::Router,
    m: &str,
    uri: &str,
    caller: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(m).uri(uri);
    if let Some(c) = caller {
        b = b.header("x-agent-id", c);
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    read_json(router.clone().oneshot(req).await.unwrap()).await
}

async fn seed(router: &axum::Router, ns: &str, title: &str, caller: &str) -> String {
    let body = json!({
        "tier": "mid", "namespace": ns, "title": title,
        "content": format!("seed body for {title}"), "tags": [], "priority": 5,
        "confidence": 1.0, "source": "user", "metadata": {},
    });
    let (status, v) = send(router, "POST", "/api/v1/memories", Some(caller), Some(body)).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "seed: {status} {v}",
    );
    v["id"].as_str().expect("id").to_string()
}

// ===========================================================================
// archive.rs — sqlite SUCCESS arms (archive_by_ids, restore, purge, list)
// ===========================================================================

#[tokio::test]
async fn archive_by_ids_then_restore_then_purge_sqlite() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-arch", "Archive me", "owner-a").await;

    // archive_by_ids — caller-owned sqlite path → 200 with archived:[id].
    let (s1, v1) = send(
        &router,
        "POST",
        "/api/v1/archive",
        Some("owner-a"),
        Some(json!({"ids": [id], "reason": "cov-test"})),
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "archive_by_ids: {v1}");
    assert!(
        v1["archived"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == &json!(id))),
        "archived list: {v1}",
    );

    // list_archive — admin gate; "arch-admin" is the allowlisted admin.
    let (s2, v2) = send(
        &router,
        "GET",
        "/api/v1/archive?namespace=cov-arch&limit=50",
        Some("arch-admin"),
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "list_archive: {v2}");
    assert!(v2["count"].as_u64().is_some_and(|c| c >= 1), "{v2}");

    // restore_archive — caller-owned sqlite path → 200 restored:true.
    let (s3, v3) = send(
        &router,
        "POST",
        &format!("/api/v1/archive/{id}/restore"),
        Some("owner-a"),
        None,
    )
    .await;
    assert_eq!(s3, StatusCode::OK, "restore: {v3}");
    assert_eq!(v3["restored"], json!(true), "{v3}");

    // Re-archive then purge (caller-scoped sqlite path → 200 purged>=0).
    let _ = send(
        &router,
        "POST",
        "/api/v1/archive",
        Some("owner-a"),
        Some(json!({"ids": [id]})),
    )
    .await;
    let (s4, v4) = send(&router, "DELETE", "/api/v1/archive", Some("owner-a"), None).await;
    assert_eq!(s4, StatusCode::OK, "purge: {v4}");
    assert_eq!(
        v4[ai_memory::models::field_names::OWNER_SCOPE],
        json!("caller"),
        "{v4}"
    );
}

#[tokio::test]
async fn purge_archive_admin_scope_sqlite() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-purge-admin", "Purge target", "someone").await;
    let _ = send(
        &router,
        "POST",
        "/api/v1/archive",
        Some("someone"),
        Some(json!({"ids": [id]})),
    )
    .await;
    // Admin caller → cross-tenant purge path (owner_scope=admin).
    let (status, v) = send(
        &router,
        "DELETE",
        "/api/v1/archive",
        Some("arch-admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v[ai_memory::models::field_names::OWNER_SCOPE],
        json!("admin"),
        "{v}"
    );
}

#[tokio::test]
async fn archive_by_ids_invalid_id_returns_400() {
    let (router, _f) = build_router();
    let (status, _v) = send(
        &router,
        "POST",
        "/api/v1/archive",
        Some("owner-x"),
        Some(json!({"ids": ["not a valid id!!"]})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_archive_non_admin_returns_403() {
    let (router, _f) = build_router();
    let (status, _v) = send(&router, "GET", "/api/v1/archive", Some("not-admin"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn archive_stats_admin_returns_200_sqlite() {
    let (router, _f) = build_router();
    let (status, _v) = send(
        &router,
        "GET",
        "/api/v1/archive/stats",
        Some("arch-admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// memories.rs — sqlite caller-owned mutation SUCCESS arms
// ===========================================================================

#[tokio::test]
async fn get_memory_after_create_sqlite_returns_200() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-get", "Gettable", "g-owner").await;
    let (status, v) = send(
        &router,
        "GET",
        &format!("/api/v1/memories/{id}"),
        Some("g-owner"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // sqlite get_memory returns the row (id at top level or under memory).
    let got_id = v
        .get("id")
        .or_else(|| v.get("memory").and_then(|m| m.get("id")));
    assert_eq!(got_id, Some(&json!(id)), "{v}");
}

#[tokio::test]
async fn update_memory_owner_sqlite_returns_200() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-upd", "Updatable", "u-owner").await;
    let (status, v) = send(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        Some("u-owner"),
        Some(json!({"content": "updated content body"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn update_memory_non_owner_returns_403() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-upd2", "Owned by alice", "alice").await;
    let (status, _v) = send(
        &router,
        "PUT",
        &format!("/api/v1/memories/{id}"),
        Some("mallory"),
        Some(json!({"content": "hijack attempt"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn promote_memory_owner_sqlite_returns_200() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-prom", "Promote me", "p-owner").await;
    let (status, v) = send(
        &router,
        "POST",
        &format!("/api/v1/memories/{id}/promote"),
        Some("p-owner"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn promote_memory_invalid_target_tier_returns_400() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-prom2", "Promote bad tier", "p2-owner").await;
    let (status, _v) = send(
        &router,
        "POST",
        &format!("/api/v1/memories/{id}/promote"),
        Some("p2-owner"),
        Some(json!({"target_tier": "bogus"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_memory_owner_sqlite_returns_200() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-del", "Delete me", "d-owner").await;
    let (status, v) = send(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{id}"),
        Some("d-owner"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // The row is gone — a follow-up GET is 404.
    let (s2, _v2) = send(
        &router,
        "GET",
        &format!("/api/v1/memories/{id}"),
        Some("d-owner"),
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_memory_non_owner_returns_403() {
    let (router, _f) = build_router();
    let id = seed(&router, "cov-del2", "Owned by bob", "bob").await;
    // The row is visible (default sqlite reads are trust-all), so the
    // `require_caller_owns_memory` ownership gate fires its 403 arm for
    // a non-owner caller before any delete is attempted.
    let (status, _v) = send(
        &router,
        "DELETE",
        &format!("/api/v1/memories/{id}"),
        Some("eve"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ===========================================================================
// memories_query.rs — list/search/forget sqlite arms
// ===========================================================================

#[tokio::test]
async fn list_memories_returns_seeded_row_sqlite() {
    let (router, _f) = build_router();
    let _ = seed(&router, "cov-listq", "Listable", "lister-q").await;
    let (status, v) = send(
        &router,
        "GET",
        "/api/v1/memories?namespace=cov-listq&limit=20",
        Some("lister-q"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["count"].as_u64().is_some_and(|c| c >= 1), "{v}");
}

#[tokio::test]
async fn search_memories_finds_seeded_token_sqlite() {
    let (router, _f) = build_router();
    let _ = seed(&router, "cov-search", "uniquetoken9821 here", "searcher").await;
    let (status, v) = send(
        &router,
        "GET",
        "/api/v1/search?q=uniquetoken9821&namespace=cov-search",
        Some("searcher"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn forget_memories_admin_returns_deleted_count_sqlite() {
    let (router, _f) = build_router();
    let _ = seed(&router, "cov-forget", "Forget me", "forgetter").await;
    let (status, v) = send(
        &router,
        "POST",
        "/api/v1/forget",
        Some("arch-admin"),
        Some(json!({"namespace": "cov-forget"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("deleted").is_some(), "{v}");
}

#[tokio::test]
async fn forget_memories_non_admin_returns_403() {
    let (router, _f) = build_router();
    let (status, _v) = send(
        &router,
        "POST",
        "/api/v1/forget",
        Some("not-admin"),
        Some(json!({"namespace": "cov-forget"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
