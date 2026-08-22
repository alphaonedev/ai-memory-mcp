// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3183 — the skills plane FAILS CLOSED on a postgres-backed daemon.
//!
//! # The defect
//!
//! `src/handlers/skills.rs` reaches the skills substrate through
//! `crate::mcp::handle_skill_*`, which is typed on a
//! `rusqlite::Connection`; every handler therefore took
//! `app.db.lock().await` unconditionally. On a postgres-backed daemon
//! `app.db` is NOT the operator's database — it is the node-local scratch
//! SQLite file `bootstrap_serve` opens against `--db`
//! (`src/store/postgres.rs`, `migrate_v82`: "postgres ships no skills
//! table"). A skill registered against a postgres deployment therefore
//! landed in an empty local file: invisible to every peer, discarded on
//! container restart, while `/api/v1/capabilities` reported
//! `skills.implemented: true`. Split-brain plus a false claim.
//!
//! # What this pins
//!
//! * **Wire contract.** Every one of the 8 `/api/v1/skill/*` paths returns
//!   `501 NOT IMPLEMENTED` with the documented postgres envelope
//!   (`error` / `endpoint` / `storage_backend` / `remediation`) on a
//!   postgres-backed daemon. Fail closed: the worst case is a loud 501,
//!   never a silent write to the wrong database (North Star — degrade,
//!   never corrupt).
//! * **Removal proof for the middleware.** `skill_register_route` is
//!   invoked DIRECTLY, with no router and therefore no
//!   `postgres_route_gate` in the pipeline, and still refuses. Deleting or
//!   reordering the middleware cannot re-open the silent-local-write path.
//! * **Claims-truth.** `/api/v1/capabilities` reports
//!   `skills.implemented: false` plus the additive
//!   `unsupported_on_postgres` / `unsupported_reason` disclosure on
//!   postgres.
//! * **No sqlite regression.** The same assertions inverted on a
//!   sqlite-backed router: registration succeeds and the capability stays
//!   `implemented: true`.
//!
//! The harness is the `build_fake_pg_router` pattern already used by
//! `tests/r40_approval_chokepoint.rs`: `storage_backend = Postgres` with a
//! DISJOINT `SqliteStore` behind the SAL handle. That exercises the real
//! postgres-branch handler code deterministically in CI with no live
//! postgres — and it is the STRICTER fixture here, because the backing
//! store is fully functional, so a handler that failed to refuse would
//! genuinely persist the row rather than error out for an unrelated
//! reason.
//!
//! The 8-path fully-501 partition itself is frozen by
//! `tests/pg_supported_route_inventory_gate_2799.rs`
//! (`expected_fully_501_paths`); this file pins the runtime behaviour that
//! partition promises. Postgres skills storage is tracked by #2804.

// The module docs above ARE the reviewable rationale for this gate; relax
// the doc-style pedantic lints rather than mangle the prose. The two
// `too_many_lines` allows cover the `AppState` fixture (one field per
// line) and the 9-case route table.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
#![cfg(feature = "sal")]

use std::sync::Arc;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Admin id used for every request — the skills surface is admin-only
/// (#949), so a non-admin caller would 403 before reaching the postgres
/// guard and prove nothing.
const ADMIN: &str = "ai:skills-3183";

/// #1751 — this suite's fixtures are unsigned; pin the permissive
/// attestation posture for the test process.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before any gated write is issued.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// Build an `AppState` for `backend`. `app.db` is an in-memory sqlite
/// connection (exactly what `bootstrap_serve` opens on a postgres daemon)
/// and the SAL handle is a real on-disk `SqliteStore`.
fn app_state(backend: StorageBackend) -> AppState {
    permissive_attestation_for_tests();
    // #1570 — model an AUTHENTICATED deployment so the #949 admin
    // header-role claim is honoured; otherwise the sqlite control below
    // would 403 before ever reaching the substrate and would "pass" for
    // the wrong reason.
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
    let store_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
    );
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn router(backend: StorageBackend) -> axum::Router {
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state(backend))
}

async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", ADMIN);
    let payload = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).expect("serialize body"))
        }
        None => Body::empty(),
    };
    let resp = router
        .clone()
        .oneshot(b.body(payload).expect("build request"))
        .await
        .expect("router call");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// A minimal but VALID `SKILL.md` registration body (same shape as
/// `tests/skills_owner_gate_949.rs`) — so a handler that failed to refuse
/// would actually persist a row rather than bounce on a 400 and pass this
/// suite for the wrong reason.
fn valid_register_body() -> Value {
    json!({
        "inline_skill": "---\nnamespace: skills-3183\nname: pg-fail-closed-probe\n\
                         description: A probe skill for the #3183 fail-closed gate.\n---\n\
                         \nBody for the #3183 probe.\n",
    })
}

/// The documented postgres 501 envelope (`postgres_not_implemented` /
/// `postgres_route_gate`): a machine-parseable shape operator scripts key
/// off, so assert every field, not just the status code.
fn assert_documented_501_envelope(status: StatusCode, body: &Value, path: &str) {
    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "{path} must fail closed on a postgres-backed daemon, got {status}: {body}"
    );
    assert_eq!(
        body["error"], "endpoint not yet implemented for postgres-backed daemon",
        "{path}: stable error string: {body}"
    );
    assert_eq!(
        body["storage_backend"], "postgres",
        "{path}: envelope names the backend: {body}"
    );
    assert_eq!(
        body["endpoint"], path,
        "{path}: envelope names the endpoint: {body}"
    );
    assert!(
        body["remediation"].as_str().is_some_and(|r| !r.is_empty()),
        "{path}: envelope carries an actionable remediation: {body}"
    );
}

/// The headline case from the issue: registering a skill against a
/// postgres deployment must NOT land in the node-local scratch sqlite file.
#[tokio::test]
async fn skill_register_returns_the_documented_501_envelope_on_postgres() {
    let router = router(StorageBackend::Postgres);
    let (status, body) = call(
        &router,
        "POST",
        "/api/v1/skill/register",
        Some(valid_register_body()),
    )
    .await;
    assert_documented_501_envelope(status, &body, "/api/v1/skill/register");
}

/// All 8 fully-501 skill paths, every registered method — the partition
/// `expected_fully_501_paths()` promises, proven at runtime.
#[tokio::test]
async fn every_skill_path_fails_closed_on_postgres() {
    let router = router(StorageBackend::Postgres);
    let id = "sk-3183";
    let cases: &[(&str, String, Option<Value>)] = &[
        (
            "POST",
            "/api/v1/skill/register".to_string(),
            Some(valid_register_body()),
        ),
        ("GET", "/api/v1/skill/list".to_string(), None),
        ("GET", format!("/api/v1/skill/{id}"), None),
        (
            "DELETE",
            format!("/api/v1/skill/{id}"),
            Some(json!({ "force": true })),
        ),
        (
            "GET",
            format!("/api/v1/skill/{id}/resource?path=README.md"),
            None,
        ),
        (
            "POST",
            format!("/api/v1/skill/{id}/export"),
            // Deliberately a path that does not exist and is never
            // written: the refusal fires before the handler resolves it.
            // (Project rule: no agent-created files under /tmp.)
            Some(json!({ "target_folder": "./.never-written-3183" })),
        ),
        (
            "POST",
            format!("/api/v1/skill/{id}/promote"),
            Some(json!({ "name": "n", "description": "d" })),
        ),
        (
            "POST",
            format!("/api/v1/skill/{id}/compose"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/api/v1/skill/{id}/retire"),
            Some(json!({ "unretire": false })),
        ),
    ];
    for (method, uri, body) in cases {
        let (status, resp) = call(&router, method, uri, body.clone()).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "{method} {uri} must fail closed on postgres, got {status}: {resp}"
        );
        assert_eq!(
            resp["storage_backend"], "postgres",
            "{method} {uri}: documented envelope: {resp}"
        );
    }
}

/// Removal proof for the router-layer gate: call the handler DIRECTLY, so
/// `postgres_route_gate` is not in the pipeline at all. The handler must
/// still refuse — otherwise a middleware reorder, a custom router, or an
/// in-process caller silently re-opens the local-write path.
#[tokio::test]
async fn skill_register_handler_refuses_without_the_route_gate() {
    use axum::response::IntoResponse as _;

    let app = app_state(StorageBackend::Postgres);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", ADMIN.parse().expect("header value"));
    let resp = ai_memory::handlers::skill_register_route(
        axum::extract::State(app),
        headers,
        axum::Json(valid_register_body()),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_documented_501_envelope(status, &body, "/api/v1/skill/register");
}

/// Claims-truth: `/capabilities` must not advertise a plane that cannot
/// durably hold a row on this backend.
#[tokio::test]
async fn capabilities_discloses_the_skills_plane_as_unsupported_on_postgres() {
    let router = router(StorageBackend::Postgres);
    let (status, body) = call(&router, "GET", "/api/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "capabilities: {body}");
    assert_eq!(
        body["storage_backend"], "postgres",
        "fixture really is postgres-backed: {body}"
    );
    assert_eq!(
        body["skills"]["implemented"], false,
        "postgres must not claim an implemented skills plane: {body}"
    );
    assert_eq!(
        body["skills"]["unsupported_on_postgres"], true,
        "postgres carries the explicit disclosure flag: {body}"
    );
    assert!(
        body["skills"]["unsupported_reason"]
            .as_str()
            .is_some_and(|r| r.contains("501")),
        "the reason states the failure mode is a hard 501: {body}"
    );
    assert!(
        body["skills"]["tools"].is_array(),
        "the canonical tool list stays present (additive disclosure): {body}"
    );
}

/// Control: sqlite is the supported backend and must be untouched by the
/// guard — a refusal that fired everywhere would be a regression, not a fix.
#[tokio::test]
async fn sqlite_daemon_still_serves_the_skills_plane() {
    let router = router(StorageBackend::Sqlite);

    let (status, body) = call(
        &router,
        "POST",
        "/api/v1/skill/register",
        Some(valid_register_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "sqlite skill register must still succeed: {body}"
    );

    let (status, body) = call(&router, "GET", "/api/v1/skill/list", None).await;
    assert_eq!(status, StatusCode::OK, "sqlite skill list: {body}");

    let (status, body) = call(&router, "GET", "/api/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "capabilities: {body}");
    assert_eq!(body["storage_backend"], "sqlite", "control backend: {body}");
    assert_eq!(
        body["skills"]["implemented"], true,
        "sqlite keeps the implemented skills plane: {body}"
    );
    assert!(
        body["skills"].get("unsupported_on_postgres").is_none(),
        "the postgres disclosure must not leak onto sqlite: {body}"
    );
}
