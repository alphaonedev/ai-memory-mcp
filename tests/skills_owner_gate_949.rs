// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows: test scaffolding only; pedantic lints with no
// behavioural impact in test code.
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! Issue #949 — admin-role gate on every skill HTTP route
//! (MEDIUM-severity, v0.7.0 QC sweep, 2026-05-20).
//!
//! Pre-#949 none of the 7 `/api/v1/skill/*` routes accepted a
//! `HeaderMap`, resolved the caller, or applied any cross-tenant
//! gate. Skills are executable artefacts (SKILL.md + resources +
//! signing surface); the supply-chain attack surface is broader than
//! a memory row:
//!
//! - register / promote / compose: WRITE surfaces that mint or
//!   re-mint executable capabilities. Cross-tenant write = forged
//!   provenance on a skill that other agents will subsequently
//!   activate.
//! - export: WRITES to the daemon-host filesystem (target_folder
//!   resolved on the daemon, written under the daemon user).
//! - list / get / resource: READ surfaces that exfiltrate skill
//!   bodies, manifests, and resource blobs.
//!
//! The fix lands an admin-only gate on every route via the shared
//! `handlers::admin_role::require_admin` helper (same shape #957
//! `export_memories` and #946 `list_agents` use). This file pins the
//! contract on every route × {non-admin caller, missing header,
//! empty allowlist, admin caller, sanitised body} matrix.
//!
//! Per-route contract pinned here:
//!
//! 1. `non_admin_caller_gets_403_on_register_949`
//! 2. `non_admin_caller_gets_403_on_list_949`
//! 3. `non_admin_caller_gets_403_on_get_949`
//! 4. `non_admin_caller_gets_403_on_resource_949`
//! 5. `non_admin_caller_gets_403_on_export_949`
//! 6. `non_admin_caller_gets_403_on_promote_949`
//! 7. `non_admin_caller_gets_403_on_compose_949`
//! 8. `missing_agent_id_header_gets_403_on_every_route_949`
//! 9. `empty_allowlist_rejects_every_caller_on_every_route_949`
//! 10. `admin_caller_can_register_949`
//! 11. `admin_caller_can_list_949`
//! 12. `admin_caller_can_get_949`
//! 13. `error_body_is_sanitised_949`

use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn minimal_skill_md(name: &str) -> String {
    format!(
        "---\nnamespace: testns-949\nname: {name}\ndescription: A demo skill for #949 gate tests.\n---\n\nBody for {name}.\n"
    )
}

fn fresh_db() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    let _conn = ai_memory::db::open(&path).expect("db::open");
    (dir, path)
}

#[allow(clippy::too_many_lines)]
fn build_router_with_admin(db_path: &std::path::Path, admin_ids: Vec<String>) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("open db");
    let path = db_path.to_path_buf();
    let db: Db = Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)));
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
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// Seed a skill directly via the MCP substrate (bypassing the gated
/// HTTP route so we have a known id for the per-route checks).
fn seed_skill(db_path: &std::path::Path, name: &str) -> String {
    let conn = ai_memory::db::open(db_path).unwrap();
    let v = ai_memory::mcp::handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md(name)}),
        None,
    )
    .expect("seed skill");
    v["id"].as_str().unwrap().to_string()
}

async fn read_body_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, v)
}

/// Build a per-route request. `agent_id=None` => no `X-Agent-Id`
/// header (synthetic `anonymous:...` caller, which can never match an
/// admin allowlist). `agent_id=Some("x")` stamps `X-Agent-Id: x`.
fn build_req(
    method: Method,
    uri: &str,
    agent_id: Option<&str>,
    body: Option<&Value>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = agent_id {
        b = b.header("x-agent-id", c);
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    let payload = body.map_or_else(Body::empty, |v| Body::from(serde_json::to_vec(v).unwrap()));
    b.body(payload).unwrap()
}

/// Per-route table. Each entry describes one of the 7 skill routes:
/// (label, method, uri-template, optional body).
/// `{id}` placeholder is replaced with a seeded skill id.
fn route_table(seeded_id: &str) -> Vec<(&'static str, Method, String, Option<Value>)> {
    let register_body = json!({"inline_skill": minimal_skill_md("gated-register")});
    // Project hard-rule: no agent-created files under /tmp. The 403
    // path SHOULD never touch this folder because the gate rejects
    // before the substrate runs; still, point at a path that would
    // fail safely (non-existent) on any accidental fall-through.
    let export_body = json!({"target_folder": "./.local-runs/should-never-write-949"});
    let promote_body = json!({
        "name": "gated-promote",
        "description": "should never run",
    });
    let compose_body = json!({"budget_tokens": 2000});
    vec![
        (
            "register",
            Method::POST,
            "/api/v1/skill/register".to_string(),
            Some(register_body),
        ),
        (
            "list",
            Method::GET,
            "/api/v1/skill/list?namespace=testns-949".to_string(),
            None,
        ),
        (
            "get",
            Method::GET,
            format!("/api/v1/skill/{seeded_id}"),
            None,
        ),
        (
            "resource",
            Method::GET,
            format!("/api/v1/skill/{seeded_id}/resource?path=scripts/x.sh"),
            None,
        ),
        (
            "export",
            Method::POST,
            format!("/api/v1/skill/{seeded_id}/export"),
            Some(export_body),
        ),
        (
            "promote",
            Method::POST,
            format!("/api/v1/skill/{seeded_id}/promote"),
            Some(promote_body),
        ),
        (
            "compose",
            Method::POST,
            format!("/api/v1/skill/{seeded_id}/compose"),
            Some(compose_body),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Per-route non-admin → 403 tests
// ---------------------------------------------------------------------------

async fn assert_route_rejects(
    router: &axum::Router,
    label: &str,
    method: Method,
    uri: &str,
    body: Option<&Value>,
    caller: Option<&str>,
) {
    let req = build_req(method, uri, caller, body);
    let resp = router.clone().oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#949 {label}: non-admin caller MUST be rejected with 403; got body={v}"
    );
    assert_eq!(
        v["error"].as_str(),
        Some("admin role required"),
        "#949 {label}: rejection body MUST be sanitised; got body={v}"
    );
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_register_949() {
    let (_dir, db_path) = fresh_db();
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let body = json!({"inline_skill": minimal_skill_md("attacker-skill")});
    assert_route_rejects(
        &router,
        "register",
        Method::POST,
        "/api/v1/skill/register",
        Some(&body),
        Some("bob"),
    )
    .await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_list_949() {
    let (_dir, db_path) = fresh_db();
    let _id = seed_skill(&db_path, "seeded-for-list");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    assert_route_rejects(
        &router,
        "list",
        Method::GET,
        "/api/v1/skill/list?namespace=testns-949",
        None,
        Some("bob"),
    )
    .await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_get_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-for-get");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = format!("/api/v1/skill/{id}");
    assert_route_rejects(&router, "get", Method::GET, &uri, None, Some("bob")).await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_resource_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-for-resource");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = format!("/api/v1/skill/{id}/resource?path=scripts/x.sh");
    assert_route_rejects(&router, "resource", Method::GET, &uri, None, Some("bob")).await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_export_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-for-export");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = format!("/api/v1/skill/{id}/export");
    let body = json!({"target_folder": "./.local-runs/should-never-write-949"});
    assert_route_rejects(
        &router,
        "export",
        Method::POST,
        &uri,
        Some(&body),
        Some("bob"),
    )
    .await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_promote_949() {
    let (_dir, db_path) = fresh_db();
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = "/api/v1/skill/no-such-reflection/promote";
    let body = json!({"name": "p", "description": "d"});
    assert_route_rejects(
        &router,
        "promote",
        Method::POST,
        uri,
        Some(&body),
        Some("bob"),
    )
    .await;
}

#[tokio::test]
async fn non_admin_caller_gets_403_on_compose_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-for-compose");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = format!("/api/v1/skill/{id}/compose");
    let body = json!({"budget_tokens": 1000});
    assert_route_rejects(
        &router,
        "compose",
        Method::POST,
        &uri,
        Some(&body),
        Some("bob"),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Cross-cutting: missing X-Agent-Id → 403 on every route.
// The fallback caller (`anonymous:req-<uuid>`) cannot match any admin
// allowlist entry, so omitting the header MUST land 403.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_agent_id_header_gets_403_on_every_route_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-no-header");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    for (label, method, uri, body) in route_table(&id) {
        assert_route_rejects(&router, label, method, &uri, body.as_ref(), None).await;
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting: empty allowlist (v0.7.0 safe-by-default posture) MUST
// reject every caller on every route — including would-be admin-
// looking ids.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_allowlist_rejects_every_caller_on_every_route_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "seeded-empty-allowlist");
    let router = build_router_with_admin(&db_path, vec![]);
    for (label, method, uri, body) in route_table(&id) {
        for caller in &["ops:admin", "bob", "alice", "root"] {
            assert_route_rejects(
                &router,
                label,
                method.clone(),
                &uri,
                body.as_ref(),
                Some(caller),
            )
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Admin-admit happy paths — pin that the gate doesn't break the
// operator's intended use cases.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_caller_can_register_949() {
    let (_dir, db_path) = fresh_db();
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let body = json!({"inline_skill": minimal_skill_md("admin-register")});
    let req = build_req(
        Method::POST,
        "/api/v1/skill/register",
        Some("ops:admin"),
        Some(&body),
    );
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#949 admin register MUST succeed; body={v}"
    );
    assert_eq!(v["registered"], json!(true));
    assert_eq!(v["name"], json!("admin-register"));
}

#[tokio::test]
async fn admin_caller_can_list_949() {
    let (_dir, db_path) = fresh_db();
    let _id = seed_skill(&db_path, "admin-list");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let req = build_req(
        Method::GET,
        "/api/v1/skill/list?namespace=testns-949",
        Some("ops:admin"),
        None,
    );
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#949 admin list MUST succeed; body={v}"
    );
    let arr = v["skills"].as_array().expect("skills array");
    assert!(
        arr.iter().any(|s| s["name"].as_str() == Some("admin-list")),
        "#949 admin list MUST return seeded skill; body={v}"
    );
}

#[tokio::test]
async fn admin_caller_can_get_949() {
    let (_dir, db_path) = fresh_db();
    let id = seed_skill(&db_path, "admin-get");
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into()]);
    let uri = format!("/api/v1/skill/{id}");
    let req = build_req(Method::GET, &uri, Some("ops:admin"), None);
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#949 admin get MUST succeed; body={v}"
    );
    assert_eq!(v["id"], json!(id));
    assert_eq!(v["name"], json!("admin-get"));
}

// ---------------------------------------------------------------------------
// Error-body sanitisation — the 403 body MUST NOT leak allowlist
// configuration nor the caller's resolved identity. If a future
// regression added a diagnostic field carrying either, this assertion
// would fail.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_body_is_sanitised_949() {
    let (_dir, db_path) = fresh_db();
    let router = build_router_with_admin(&db_path, vec!["ops:admin".into(), "ops:other".into()]);
    let body = json!({"inline_skill": minimal_skill_md("attacker")});
    let req = build_req(
        Method::POST,
        "/api/v1/skill/register",
        Some("attacker"),
        Some(&body),
    );
    let resp = router.oneshot(req).await.unwrap();
    let (status, v) = read_body_json(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        v,
        json!({"error": "admin role required"}),
        "#949: rejection body MUST be the sanitised constant shape; got body={v}"
    );
}
