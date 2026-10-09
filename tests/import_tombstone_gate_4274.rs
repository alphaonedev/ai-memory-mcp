// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4274 (WP-ERASURE #6048) — `POST /api/v1/import` must honour the forget
//! covenant: an id with a signed FORGET tombstone (#1821 / G30) is SKIPPED
//! with a per-row reason, never re-admitted live beside its own tombstone.
//!
//! The v2 portability import (`src/portability/import.rs`) and the v1 CLI
//! import (`src/cli/io.rs`) both gate on `storage::memory_is_tombstoned`;
//! the HTTP admin import did not, so an admin re-import of an older export
//! RESURRECTED a forgotten memory (the #2208 class on a third surface).
//!
//! Drives the production router (`ai_memory::build_router`) over an on-disk
//! sqlite `AppState` via `tower::oneshot`, mirroring
//! `tests/cov_ga2_handlers_a.rs`.

#![cfg(feature = "sal")]
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};

const NS: &str = "import-tombstone-4274";

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("import-tombstone-gate-4274")
}

/// Build the production router over a fresh on-disk sqlite DB under
/// `.local-runs/` (project hard rule: never `/tmp`).
fn build_router() -> (axum::Router, tempfile::TempDir, Db) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("import-4274.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
    (router, dir, db)
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
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("#4274 import tombstone probe body for {title}"),
        // `import` is in the closed `VALID_SOURCES` set `validate_memory`
        // checks; `"test"` is rejected.
        source: "import".into(),
        confidence: 1.0,
        priority: 5,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "admin-caller" }),
        ..Memory::default()
    }
}

async fn live_exists(db: &Db, id: &str) -> bool {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT COUNT(*) > 0 FROM memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("probe live row")
}

/// Cell 1 (the defect) + cell 2 (control) in ONE import call: the bundle
/// carries a forgotten id and a never-seen id. The forgotten id stays
/// ABSENT and the report says so per row; the control id is imported.
#[tokio::test]
async fn http_import_skips_a_forget_tombstoned_id_and_imports_the_control_4274() {
    let (router, _dir, db) = build_router();
    let forgotten = sample("00000000-0000-0000-0000-00000000f0f0", "forgotten row");
    let control = sample("00000000-0000-0000-0000-00000000c0c0", "control row");

    // Seed the row, then HARD-delete it: `db::delete` writes the signed
    // forget tombstone (`tombstone_and_erase`, #3192) and erases the row.
    let tombstoned = {
        let lock = db.lock().await;
        ai_memory::db::insert(&lock.0, &forgotten).expect("seed");
        assert!(ai_memory::db::delete(&lock.0, &forgotten.id).expect("hard delete"));
        ai_memory::db::memory_is_tombstoned(&lock.0, &forgotten.id).expect("probe")
    };
    assert!(
        tombstoned,
        "fixture: the hard delete must leave a forget tombstone"
    );

    let (status, v) = post_as(
        &router,
        "/api/v1/import",
        "admin-caller",
        json!({
            "memories": [
                serde_json::to_value(&forgotten).unwrap(),
                serde_json::to_value(&control).unwrap(),
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The forget covenant holds: the tombstoned id is NOT live again.
    assert!(
        !live_exists(&db, &forgotten.id).await,
        "#4274: a forget-tombstoned id must not be re-admitted by the HTTP import; got {v}"
    );
    // The control id IS imported (the gate is per-row, not whole-import).
    assert!(
        live_exists(&db, &control.id).await,
        "control row must import: {v}"
    );
    assert_eq!(
        v["imported"],
        json!(1),
        "exactly the control row counts: {v}"
    );

    // The report names the skipped row and the reason.
    let errors = v["errors"].as_array().cloned().unwrap_or_default();
    let names_tombstone = errors.iter().any(|e| {
        e.as_str()
            .is_some_and(|s| s.contains(&forgotten.id) && s.to_lowercase().contains("tombstone"))
    });
    assert!(
        names_tombstone,
        "#4274: the import report must carry a per-row tombstone reason for {}: {v}",
        forgotten.id
    );
}
