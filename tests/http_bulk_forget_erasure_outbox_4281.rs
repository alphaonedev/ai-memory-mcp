// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4281 (WP-ERASURE #6048, #2446 residual) — the HTTP bulk forget
//! (`POST /api/v1/forget`, `handlers::memories_query::forget_memories`) must
//! queue every erased id for federated fan-out through the SAME #2446
//! erasure outbox the MCP `memory_forget` and CLI `forget` funnels use.
//!
//! Pre-fix the handler deleted locally and queued NOTHING, so a GDPR bulk
//! erasure was honoured on this node only: every peer kept the rows, kept
//! serving them, and could LWW-resurrect them. The single-id HTTP delete
//! fans out (`broadcast_delete_quorum`); the bulk verb did not.
//!
//! Drives the production router (`ai_memory::build_router`) over an on-disk
//! sqlite `AppState` via `tower::oneshot`. The drainability marker is
//! stamped the way a federated sqlite-backed `serve` boot stamps it
//! (`erasure_outbox::mark_federation_drainable`), and the assertion reads
//! the pending sentinel rows exactly as `tests/federation_erasure_replication_2446.rs`
//! does.

#![cfg(feature = "sal")]
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::erasure_outbox::{
    ALL_PEERS_SENTINEL_PEER_ID, mark_federation_drainable,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};

const NS: &str = "http-bulk-forget-4281";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("http-bulk-forget-erasure-outbox-4281")
}

fn build_router(db_path: &Path) -> (axum::Router, Db) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("open for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db: db.clone(),
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["admin-caller".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(
        ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app_state,
    );
    (router, db)
}

async fn post_as(
    router: &axum::Router,
    uri: &str,
    agent_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn sample(id: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("#4281 bulk forget probe body for {title}"),
        source: "test".into(),
        confidence: 1.0,
        priority: 5,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "admin-caller" }),
        ..Memory::default()
    }
}

/// Every PENDING erasure-outbox sentinel row's memory id, sorted.
fn pending_sentinel_ids(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id FROM federation_push_dlq \
             WHERE peer_id = ?1 AND replayed_at IS NULL ORDER BY memory_id",
        )
        .expect("prepare sentinel query");
    stmt.query_map(rusqlite::params![ALL_PEERS_SENTINEL_PEER_ID], |r| {
        r.get::<_, String>(0)
    })
    .expect("query sentinels")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect sentinels")
}

/// The defect cell: a drainable (federated) sqlite deployment, an admin
/// bulk forget over the namespace → every forgotten id has a pending
/// erasure-outbox sentinel row, exactly as the MCP / CLI forgets leave.
#[tokio::test]
async fn http_bulk_forget_queues_an_erasure_outbox_row_per_forgotten_id_4281() {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("forget-4281.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        ai_memory::db::insert(&conn, &sample("4281-fgt-a", "forget me a")).expect("seed a");
        ai_memory::db::insert(&conn, &sample("4281-fgt-b", "forget me b")).expect("seed b");
        // Stamp the drainability marker exactly as a federated, sqlite-backed
        // `serve` boot does (the #2446 contract): erasures on this database
        // queue for fan-out while it exists.
        mark_federation_drainable(&conn, 1).expect("stamp drainability marker");
    }
    let (router, db) = build_router(&db_path);

    let (status, v) = post_as(
        &router,
        "/api/v1/forget",
        "admin-caller",
        json!({ "namespace": NS }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["deleted"], json!(2), "both rows erased locally: {v}");

    let lock = db.lock().await;
    let live: i64 = lock
        .0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [NS],
            |r| r.get(0),
        )
        .expect("count live");
    assert_eq!(live, 0, "the local forget stands");
    let ids = pending_sentinel_ids(&lock.0);
    assert_eq!(
        ids,
        vec!["4281-fgt-a".to_string(), "4281-fgt-b".to_string()],
        "#4281: the HTTP bulk forget must queue an erasure-outbox row for EVERY forgotten id \
         (pre-fix it queued NOTHING, so peers kept the rows)"
    );
}

/// The bound (mirrors `unconfigured_deployment_erasure_succeeds_and_queues_nothing_2446`):
/// with no drainability marker the forget still succeeds and queues nothing,
/// so an unfederated deployment pays nothing for the fix.
#[tokio::test]
async fn http_bulk_forget_on_an_undrainable_deployment_queues_nothing_4281() {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("forget-4281-undrainable.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        ai_memory::db::insert(&conn, &sample("4281-local-a", "local only a")).expect("seed a");
    }
    let (router, db) = build_router(&db_path);

    let (status, v) = post_as(
        &router,
        "/api/v1/forget",
        "admin-caller",
        json!({ "namespace": NS }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["deleted"], json!(1), "{v}");

    let lock = db.lock().await;
    assert!(
        pending_sentinel_ids(&lock.0).is_empty(),
        "no drainability marker ⇒ zero outbox rows"
    );
}
