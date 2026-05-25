// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Test scaffold only — relax a few pedantic lints around the
// router/fixture boilerplate so the test body reads cleanly.
#![allow(clippy::too_many_lines)]
// `body_blob` is a column name we deliberately reference verbatim in
// the docstrings; backticks would add visual noise.
#![allow(clippy::doc_markdown)]

//! Regression test for issue #1261 — `src/handlers/skills.rs`
//! `skill_list_route` / `skill_get_route` / `skill_compose_route`
//! 500-paths previously forwarded the raw `rusqlite::Error` string
//! (which leaks SQL fragments like `SELECT id, namespace, name, ...`)
//! straight onto the HTTP wire. This test forces an `Err` from the
//! substrate (by DROP-ing the `skills` table out from under the open
//! connection) and asserts the wire response is the sanitized generic
//! `{"error": "internal server error"}` shape — no SQL fragments,
//! no rusqlite verbiage.

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use std::path::PathBuf;
use tempfile::TempDir;
use tower::ServiceExt as _;

// ---------------------------------------------------------------------------
// Fixture helpers (mirror `tests/skill_cli_http_parity.rs`).
// ---------------------------------------------------------------------------

fn fresh_db() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    let _conn = ai_memory::db::open(&path).expect("db::open");
    (dir, path)
}

fn build_router_with_db_path(db_path: &std::path::Path) -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(db_path).expect("open db");
    let path = db_path.to_path_buf();
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"),
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
        admin_agent_ids: std::sync::Arc::new(vec!["ops:admin".to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db)
}

async fn read_body_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, v)
}

/// Drop the `skills` table on the router's shared connection so the
/// `skill_list` substrate's `prepare()` call fails with a rusqlite
/// "no such table" error — exactly the class of error #1261 wants
/// sanitized.
async fn drop_skills_table(db: &ai_memory::handlers::Db) {
    let guard = db.lock().await;
    guard
        .0
        .execute_batch("DROP TABLE IF EXISTS skills;")
        .expect("drop skills table");
}

/// Seed a real skill row, then corrupt its `body_blob` so zstd
/// decompression fails. `skill_get` + `skill_compose` swallow the
/// "no such table" error into a 404 (so dropping the table doesn't
/// hit the 500 path); but a corrupted body_blob bypasses the
/// `query_row(...).ok()` early-out and surfaces a non-"skill not found"
/// substrate error — which is the 500 path #1261 sanitizes.
fn minimal_skill_md(name: &str) -> String {
    format!(
        "---\nnamespace: testns\nname: {name}\ndescription: A demo skill for sanitize tests.\n---\n\nBody for {name}.\n"
    )
}

fn seed_skill_with_corrupted_body(db_path: &std::path::Path, name: &str) -> String {
    let conn = ai_memory::db::open(db_path).unwrap();
    let v = ai_memory::mcp::handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md(name)}),
        None,
    )
    .expect("seed skill");
    let id = v["id"].as_str().unwrap().to_string();
    // Replace the valid zstd-encoded body with random non-zstd bytes so
    // the substrate's `zstd::decode_all` call fails. The handler then
    // returns `Err("zstd decompress body: ...")` which the route
    // currently forwards onto the wire — exactly what #1261 sanitizes.
    let bogus_body: Vec<u8> = vec![0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9];
    conn.execute(
        "UPDATE skills SET body_blob = ?1 WHERE id = ?2",
        rusqlite::params![bogus_body, id],
    )
    .expect("update body_blob");
    id
}

/// Tokens that confirm the substrate's rusqlite/zstd error string was
/// forwarded unchanged onto the wire. We MUST NOT see any of these in
/// the post-#1261 response body.
const SQL_FRAGMENTS: &[&str] = &[
    "SELECT",
    "skills",
    "FROM",
    "WHERE",
    "no such table",
    "skill_list prepare",
    "skill_list query",
    "rusqlite",
    "zstd decompress",
    "Unknown frame descriptor",
];

#[tokio::test]
async fn skill_list_route_500_sanitized_no_sql_fragments() {
    let (_dir, db_path) = fresh_db();
    let (router, db) = build_router_with_db_path(&db_path);
    drop_skills_table(&db).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/skill/list")
        .header("x-agent-id", "ops:admin")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expected 500 on substrate error; got body: {v}"
    );
    let body_str = serde_json::to_string(&v).expect("serialize");
    for fragment in SQL_FRAGMENTS {
        assert!(
            !body_str.to_lowercase().contains(&fragment.to_lowercase()),
            "#1261 — wire response MUST NOT contain SQL fragment {fragment:?}; got body: {body_str}"
        );
    }
    assert_eq!(
        v["error"],
        json!("internal server error"),
        "#1261 — sanitized wire response MUST equal {{\"error\":\"internal server error\"}}; got: {v}"
    );
}

#[tokio::test]
async fn skill_get_route_500_sanitized_no_sql_fragments() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill_with_corrupted_body(&db_path, "sanitize-get");
    let (router, _db) = build_router_with_db_path(&db_path);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/skill/{id}"))
        .header("x-agent-id", "ops:admin")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expected 500 on substrate error; got body: {v}"
    );
    let body_str = serde_json::to_string(&v).expect("serialize");
    for fragment in SQL_FRAGMENTS {
        assert!(
            !body_str.to_lowercase().contains(&fragment.to_lowercase()),
            "#1261 — wire response MUST NOT contain SQL fragment {fragment:?}; got body: {body_str}"
        );
    }
    assert_eq!(
        v["error"],
        json!("internal server error"),
        "#1261 — sanitized wire response MUST equal {{\"error\":\"internal server error\"}}; got: {v}"
    );
}

#[tokio::test]
async fn skill_compose_route_500_sanitized_no_sql_fragments() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill_with_corrupted_body(&db_path, "sanitize-compose");
    let (router, _db) = build_router_with_db_path(&db_path);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/skill/{id}/compose"))
        .header("content-type", "application/json")
        .header("x-agent-id", "ops:admin")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expected 500 on substrate error; got body: {v}"
    );
    let body_str = serde_json::to_string(&v).expect("serialize");
    for fragment in SQL_FRAGMENTS {
        assert!(
            !body_str.to_lowercase().contains(&fragment.to_lowercase()),
            "#1261 — wire response MUST NOT contain SQL fragment {fragment:?}; got body: {body_str}"
        );
    }
    assert_eq!(
        v["error"],
        json!("internal server error"),
        "#1261 — sanitized wire response MUST equal {{\"error\":\"internal server error\"}}; got: {v}"
    );
}
