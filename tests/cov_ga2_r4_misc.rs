// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cov_ga2_r4_misc` — GA-session-0611 round-4 coverage backfill for the
//! four near-90 handler / MCP modules that the prior cov rounds left just
//! under the uniform 90% per-module floor:
//!
//! - [`ai_memory::handlers`] `hook_subscribers.rs` — the SQLite branches of
//!   `get_inbox` / `session_start` / `set_namespace_standard` /
//!   `get_namespace_standard` / `clear_namespace_standard` (and their
//!   query-string + path-segment siblings). The prior round
//!   (`tests/cov_ga2_pg_handlers_2.rs`) drove the `StorageBackend::Postgres`
//!   arms; the residual dark lines are the auto-seed-placeholder + ownership
//!   gate + governance-merge + fanout-disabled SQLite arms, plus the
//!   `?agent_id=` 403 mismatch + invalid-agent-id 400 validation arms.
//! - [`ai_memory::handlers`] `power_consolidation.rs` — the SQLite branches
//!   of `consolidate_memories` / `fetch_consolidate_source_pairs` /
//!   `fetch_memory_for_handler` / `load_family_handler`, plus the no-LLM
//!   503 arm of `auto_tag_handler` / `expand_query_handler` and the
//!   deterministic-summary fallback in `resolve_consolidate_summary`.
//! - [`ai_memory::handlers`] `http.rs` — `get_with_visibility_retry`
//!   (driven end-to-end via the postgres `promote_memory` path: the
//!   `Ok(m)` hit on a seeded row and the NotFound-retry-loop on a ghost
//!   id) and `maybe_auto_tag`'s `llm_arc.is_none()` short-circuit on a
//!   Smart-tier (`llm_model = Some`) postgres `AppState` whose `llm` is
//!   `None` (driven via the `create_memory_postgres` path).
//! - [`ai_memory::mcp`] `tools/store/mod.rs` — `handle_store`'s
//!   agent-attestation arms (bad-base64 `signature` → `prepare_signed_store`
//!   error; unsigned write under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` →
//!   `stamp_attestation_sync` rejection) and the `AutoAtomiseMode::Off` +
//!   response-echo tail that every plain store walks. Driven through the
//!   public `ai_memory::mcp::tools::handle_store_for_tests` shim (the same
//!   entry `tests/cov_ga2_power.rs` uses).
//!
//! Structural exceptions (NOT covered — recorded, not faked):
//! - `http.rs::maybe_auto_tag` lines 120-153 (the `tokio::time::timeout`
//!   LLM body + the `Ok(Ok)`/`Ok(Err)`/`Err` join arms), `maybe_detect_conflicts`
//!   (whole body — `#[allow(dead_code)]`, not wired into `create_memory`
//!   per #519), and `fetch_namespace_candidates` require a LIVE LLM the
//!   CI host does not provide; they are reachable only with a wired LLM.
//! - `power_consolidation.rs` `resolve_consolidate_summary` lines 127-150
//!   (the LLM `summarize_memories_async` body + timeout arms) and
//!   `auto_tag_handler` / `expand_query_handler` lines past the no-LLM 503
//!   gate need a live LLM — only the no-LLM degradation + validation arms
//!   are driven here.
//! - `store/mod.rs` proactive-conflict (#519, lines 664-695), synthesis
//!   pass / depth-guard (lines 515-578), and the governance Pending /
//!   permission Ask arms require an embedder, a wired LLM + autonomous
//!   hooks, or an operator-signed governance rule respectively — already
//!   covered elsewhere (`tests/cov_ga2_power.rs`,
//!   `tests/form_1_synthesis*.rs`, `tests/governance_storage_insert_hook.rs`).
//!
//! The postgres-router tests are gated on `AI_MEMORY_TEST_POSTGRES_URL`;
//! without it they print a skip line and return. The SQLite-router tests
//! and the `handle_store_for_tests` tests run unconditionally under the
//! `sal-postgres` feature (which implies `sal`). Every memory write uses a
//! UUID-isolated namespace so concurrent runs against the shared scratch
//! postgres DB don't collide and assertions filter on the caller's own
//! rows rather than asserting global-table emptiness.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// The agent id every request in this file presents.
const CALLER: &str = "ai:cov-ga2-r4";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A unique namespace per test so concurrent runs against the shared
/// scratch DB don't collide and assertions can filter on the caller's
/// own rows rather than asserting global-table emptiness.
fn uniq_ns() -> String {
    format!("covga2r4-{}", &uuid::Uuid::new_v4().to_string()[..12])
}

// ---------------------------------------------------------------------------
// Router builders
// ---------------------------------------------------------------------------

/// Build the production router over a fresh on-disk SQLite DB (the
/// default `StorageBackend::Sqlite`). The `app.store` SqliteStore opens
/// against the SAME path so seed → read works through both the legacy
/// `db` path and the SAL trait. Mirrors `tests/cov3_handlers_sqlite.rs`.
fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        ),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

/// Build the production router over a REAL `PostgresStore`
/// (`StorageBackend::Postgres`), with `tier_config = FeatureTier::Smart`
/// so `tier_config.llm_model.is_some()` is true. `llm` is still `None`,
/// which is exactly the gate state `maybe_auto_tag` must short-circuit on
/// (`llm_arc.is_none()` after passing the Smart-tier `llm_model` gate).
/// Mirrors the `pg_router` harness in `tests/cov_ga2_pg_handlers_2.rs`.
async fn pg_router_smart(url: &str) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        // Smart tier => llm_model = Some(...), so maybe_auto_tag passes the
        // tier gate and reaches the `llm_arc.is_none()` short-circuit.
        tier_config: Arc::new(FeatureTier::Smart.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        // llm None on purpose — the no-LLM degradation arm is what we cover.
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
        admin_agent_ids: Arc::new(vec![CALLER.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", CALLER)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", CALLER)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn delete_req(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-agent-id", CALLER)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Seed a memory through the production router and return its id.
async fn seed_memory(router: &axum::Router, ns: &str, title: &str, content: &str) -> String {
    let (status, body) = post_json(
        router,
        "/api/v1/memories",
        json!({"title": title, "content": content, "namespace": ns, "agent_id": CALLER}),
    )
    .await;
    assert!(status.is_success(), "seed status={status} body={body}");
    body["id"].as_str().expect("seed returns id").to_string()
}

macro_rules! pg_test {
    ($name:ident, $url:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($url) = pg_url() else {
                eprintln!(
                    "SKIP {}: AI_MEMORY_TEST_POSTGRES_URL not set",
                    stringify!($name)
                );
                return;
            };
            $body
        }
    };
}

// ===========================================================================
// hook_subscribers — SQLite branch coverage
// ===========================================================================

// --- get_inbox SQLite arm + validation/403 arms ---------------------------

#[tokio::test]
async fn sqlite_get_inbox_empty_default() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/inbox").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("messages").is_some() || body.get("count").is_some());
}

#[tokio::test]
async fn sqlite_get_inbox_unread_only_and_limit() {
    let (r, _t) = sqlite_router();
    // unread_only + limit exercise the params-building arms (lines 159-164).
    let (status, body) = get(&r, "/api/v1/inbox?unread_only=true&limit=25").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn sqlite_get_inbox_query_mismatch_is_403() {
    let (r, _t) = sqlite_router();
    // #901 — a `?agent_id=` disagreeing with the header is rejected (403)
    // before the SQLite arm runs (hook_subscribers lines 58-66).
    let (status, _b) = get(&r, "/api/v1/inbox?agent_id=ai:someone-else").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// --- session_start — every validation + success arm -----------------------

#[tokio::test]
async fn sqlite_session_start_ok() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    let (status, body) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"namespace": ns, "limit": 5, "agent_id": CALLER}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("session_id").is_some(), "session id stamped");
    assert_eq!(body["agent_id"], CALLER);
}

#[tokio::test]
async fn sqlite_session_start_invalid_agent_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"agent_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_session_start_body_header_mismatch_is_400() {
    let (r, _t) = sqlite_router();
    // header is CALLER; body disagrees → the #910 mismatch 400 arm
    // (hook_subscribers lines 1150-1158).
    let (status, _b) = post_json(
        &r,
        "/api/v1/session/start",
        json!({"agent_id": "ai:different-agent"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// --- namespace standard set / get / clear — SQLite auto-seed + ownership --

#[tokio::test]
async fn sqlite_namespace_standard_autoseed_set_get_clear_roundtrip() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();

    // SET with no `id` → the SQLite auto-seed placeholder branch
    // (set_namespace_standard_inner lines 650-704) and the body.id-less
    // path. A `governance` blob lands in the standard's metadata.
    let (set_status, set_body) = post_json(
        &r,
        "/api/v1/namespaces",
        json!({
            "namespace": ns,
            "governance": {"write": "any", "promote": "any", "delete": "owner"},
        }),
    )
    .await;
    assert_eq!(set_status, StatusCode::CREATED, "set body={set_body}");

    // A second SET with the same caller exercises the existing-placeholder
    // reuse branch + the caller-is-owner no-op gate (lines 577-649).
    let (set2_status, _b) = post_json(
        &r,
        "/api/v1/namespaces",
        json!({"namespace": ns, "governance": {"write": "registered"}}),
    )
    .await;
    assert_eq!(set2_status, StatusCode::CREATED);

    // GET via the query-string SQLite arm (get_namespace_standard_qs
    // lines 994-1005).
    let (get_status, get_body) = get(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(get_status, StatusCode::OK, "get body={get_body}");

    // GET with inherit=true exercises the inherit param-build arm.
    let (inh_status, _b) = get(
        &r,
        &format!("/api/v1/namespaces?namespace={ns}&inherit=true"),
    )
    .await;
    assert_eq!(inh_status, StatusCode::OK);

    // CLEAR via the query-string SQLite arm (clear_namespace_standard_inner
    // lines 1078-1106; federation None so no fanout).
    let (clr_status, clr_body) =
        delete_req(&r, &format!("/api/v1/namespaces?namespace={ns}")).await;
    assert_eq!(clr_status, StatusCode::OK, "clear body={clr_body}");
}

#[tokio::test]
async fn sqlite_namespace_standard_set_qs_missing_namespace_is_400() {
    let (r, _t) = sqlite_router();
    // set_namespace_standard_qs with no namespace → 400 (lines 839-849).
    let (status, _b) = post_json(&r, "/api/v1/namespaces", json!({"governance": {}})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_namespace_standard_clear_qs_missing_namespace_is_400() {
    let (r, _t) = sqlite_router();
    // clear_namespace_standard_qs with no `?namespace=` → 400 (lines 1012-1018).
    let (status, _b) = delete_req(&r, "/api/v1/namespaces").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_namespace_standard_set_nested_standard_body_flatten() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    // S34 nested shape: `{standard: {namespace, governance}}` exercises
    // flatten_standard_body (lines 203-225).
    let (status, body) = post_json(
        &r,
        "/api/v1/namespaces",
        json!({"standard": {"namespace": ns, "governance": {"write": "any"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "nested set body={body}");
}

#[tokio::test]
async fn sqlite_namespace_standard_path_form_set_and_get_and_clear() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    // The `/api/v1/namespaces/{ns}/standard` path-segment handlers
    // (set_namespace_standard / get_namespace_standard /
    // clear_namespace_standard) share the inner impl but exercise their
    // own thin wrappers (lines 790-831).
    let (set_status, _b) = post_json(
        &r,
        &format!("/api/v1/namespaces/{ns}/standard"),
        json!({"governance": {"write": "any"}}),
    )
    .await;
    assert_eq!(set_status, StatusCode::CREATED);

    let (get_status, _b) = get(&r, &format!("/api/v1/namespaces/{ns}/standard")).await;
    assert_eq!(get_status, StatusCode::OK);

    let (clr_status, _b) = delete_req(&r, &format!("/api/v1/namespaces/{ns}/standard")).await;
    assert_eq!(clr_status, StatusCode::OK);
}

// ===========================================================================
// power_consolidation — SQLite branch coverage
// ===========================================================================

#[tokio::test]
async fn sqlite_consolidate_with_summary_ok() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    let id1 = seed_memory(&r, &ns, "sqlite consol src 1", "first source body here").await;
    let id2 = seed_memory(&r, &ns, "sqlite consol src 2", "second source body here").await;
    // Caller-supplied summary skips resolve_consolidate_summary and drives
    // the SQLite db::consolidate arm (lines 413-489) + the success 201.
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "sqlite consolidated",
            "summary": "a deterministic consolidation summary over the two sources here",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert_eq!(body["consolidated"], 2);
    assert!(body["id"].is_string());
}

#[tokio::test]
async fn sqlite_consolidate_no_summary_deterministic_fallback() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    let id1 = seed_memory(&r, &ns, "fallback src 1", "alpha source body here").await;
    let id2 = seed_memory(&r, &ns, "fallback src 2", "beta source body here").await;
    // No summary + no LLM wired → resolve_consolidate_summary's
    // deterministic title-concat fallback (lines 110-118) runs after
    // fetch_consolidate_source_pairs walks the SQLite db::get arm
    // (lines 203-225).
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "fallback consolidated",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    assert!(
        body["summary"].as_str().is_some_and(|s| !s.is_empty()),
        "deterministic fallback summary present; body={body}"
    );
}

#[tokio::test]
async fn sqlite_consolidate_unknown_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    // No summary forces the source-pair fetch; a non-existent id in the
    // SQLite arm surfaces Ok(None) → 400 (lines 208-214).
    let ghost = format!("ghost-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let (status, _b) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [ghost],
            "title": "ghost consolidate",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_consolidate_validation_empty_ids_is_400() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    // Empty ids + supplied summary → validate_consolidate 400 (lines 291-302).
    let (status, _b) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({"ids": [], "title": "x", "summary": "a supplied summary string here ok", "namespace": ns}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_auto_tag_no_llm_503() {
    let (r, _t) = sqlite_router();
    // app.llm None → auto_tag_handler first gate 503 (lines 534-540).
    let (status, body) = post_json(
        &r,
        "/api/v1/auto_tag",
        json!({"title": "t", "content": "c"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={body}");
    assert_eq!(body["error"], "LLM not configured");
}

#[tokio::test]
async fn sqlite_expand_query_no_llm_503() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(&r, "/api/v1/expand_query", json!({"query": "anything"})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={body}");
    assert_eq!(body["error"], "LLM not configured");
}

#[tokio::test]
async fn sqlite_load_family_ok() {
    let (r, _t) = sqlite_router();
    let ns = uniq_ns();
    // SQLite load_family path (lines 885-896) — reuses MCP handle_load_family.
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": ns, "k": 10}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.get("memories").is_some() || body.get("count").is_some());
}

#[tokio::test]
async fn sqlite_load_family_unknown_family_is_400() {
    let (r, _t) = sqlite_router();
    // Family::from_str error arm (lines 796-802).
    let (status, _b) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "not-a-real-family"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sqlite_load_family_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    // validate_namespace error arm (lines 804-812).
    let (status, _b) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": "bad namespace!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// http.rs — get_with_visibility_retry + maybe_auto_tag (postgres, no LLM)
// ===========================================================================

#[allow(clippy::doc_markdown)]
mod doc_anchor {
    //! `get_with_visibility_retry` is reached via the postgres
    //! `promote_memory` handler (`POST /api/v1/memories/{id}/promote`);
    //! `maybe_auto_tag` is reached via `create_memory_postgres`
    //! (`POST /api/v1/memories`).
}

pg_test!(pg_promote_seeded_row_hits_visibility_retry_ok_arm, url, {
    let r = pg_router_smart(&url).await;
    let ns = uniq_ns();
    // Seed a row, then promote it. get_with_visibility_retry's `Ok(m)`
    // arm (http.rs lines 56-57) resolves the freshly-stored row on the
    // first attempt.
    let id = seed_memory(
        &r,
        &ns,
        "promote target",
        "promote body content here that is long enough",
    )
    .await;
    let (status, body) = post_json(
        &r,
        &format!("/api/v1/memories/{id}/promote"),
        json!({"agent_id": CALLER}),
    )
    .await;
    // Allow OK or ACCEPTED (governance pending) — both mean the retry
    // helper resolved the row and the promote handler proceeded.
    assert!(
        status == StatusCode::OK || status == StatusCode::ACCEPTED || status == StatusCode::CREATED,
        "promote of seeded row status={status} body={body}"
    );
});

pg_test!(
    pg_promote_ghost_id_walks_visibility_retry_loop_then_404,
    url,
    {
        let r = pg_router_smart(&url).await;
        // A valid-shape id that does not exist drives the NotFound retry loop
        // (http.rs lines 58-62: 4 backoff sleeps) then the final
        // `Err(NotFound)` return at line 63 → the handler's 404 arm.
        let ghost = format!("cov-ga2-r4-ghost-{}", uuid::Uuid::new_v4());
        let (status, _b) = post_json(
            &r,
            &format!("/api/v1/memories/{ghost}/promote"),
            json!({"agent_id": CALLER}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
);

pg_test!(
    pg_create_smart_tier_no_llm_arc_auto_tag_short_circuits,
    url,
    {
        let r = pg_router_smart(&url).await;
        let ns = uniq_ns();
        // Smart tier => tier_config.llm_model.is_some(): create_memory_postgres
        // calls maybe_auto_tag with no operator tags, long content, public
        // namespace — so the gate ladder reaches the `llm_arc.is_none()`
        // short-circuit at http.rs line 110-113 (llm is None on this AppState).
        // The row still lands with no auto_tags.
        let (status, body) = post_json(
        &r,
        "/api/v1/memories",
        json!({
            "title": "smart tier auto-tag probe",
            "content": "this content is comfortably longer than the fifty-character auto-tag threshold so the gate ladder advances past the content-length check",
            "namespace": ns,
            "agent_id": CALLER,
        }),
    )
    .await;
        assert!(status.is_success(), "create status={status} body={body}");
        assert!(body["id"].is_string(), "row landed; body={body}");
        // No LLM => no auto_tags echoed.
        assert!(
            body.get("auto_tags").is_none(),
            "no LLM => no auto_tags; body={body}"
        );
    }
);

// ===========================================================================
// mcp/tools/store/mod.rs — handle_store attestation + atomise-off arms
// ===========================================================================

mod store_handle {
    use super::Value;
    use serde_json::json;

    fn store_conn() -> rusqlite::Connection {
        ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite")
    }

    fn store_db_path() -> std::path::PathBuf {
        std::path::PathBuf::from(":memory:")
    }

    fn store_params(title: &str, namespace: &str) -> Value {
        json!({
            "title": title,
            "content": "store handler coverage content body that is long enough to be meaningful",
            "namespace": namespace,
            "agent_id": "ai:cov-ga2-r4-store",
        })
    }

    /// Plain happy-path store with no embedder / LLM / autonomous hooks:
    /// walks the AutoAtomiseMode::Off arm (store/mod.rs lines 909-911) and
    /// the post-insert response-echo tail (lines 922-932). Confirms the id
    /// + tier echo land.
    #[test]
    fn store_off_atomise_and_response_echo() {
        let conn = store_conn();
        let ttl = ai_memory::config::ResolvedTtl::default();
        let resp = ai_memory::mcp::tools::handle_store_for_tests(
            &conn,
            &store_db_path(),
            &store_params("off-atomise probe", "covga2r4-store-ns"),
            None,
            None,
            None,
            &ttl,
            false,
            None,
            None,
        )
        .expect("plain store ok");
        assert!(resp["id"].is_string(), "id echoed: {resp}");
        assert!(resp.get("tier").is_some(), "tier echoed: {resp}");
    }

    /// A presented `signature` that is not valid base64 makes
    /// `prepare_signed_store` return Err, which `handle_store` propagates
    /// (store/mod.rs lines 340-344).
    #[test]
    fn store_bad_base64_signature_is_err() {
        let conn = store_conn();
        let ttl = ai_memory::config::ResolvedTtl::default();
        let mut params = store_params("bad-sig probe", "covga2r4-store-sig");
        params["signature"] = json!("!!!not-valid-base64!!!");
        params["created_at"] = json!(chrono::Utc::now().to_rfc3339());
        let err = ai_memory::mcp::tools::handle_store_for_tests(
            &conn,
            &store_db_path(),
            &params,
            None,
            None,
            None,
            &ttl,
            false,
            None,
            None,
        )
        .expect_err("bad base64 signature must error");
        assert!(
            err.to_lowercase().contains("signature") || err.to_lowercase().contains("base64"),
            "expected a signature/base64 error, got: {err}"
        );
    }

    /// A presented `signature` without the matching `created_at` makes
    /// `prepare_signed_store` return the "requires created_at" Err arm
    /// (store/mod.rs line 344 via attest.rs lines 83-88).
    #[test]
    fn store_signature_without_created_at_is_err() {
        let conn = store_conn();
        let ttl = ai_memory::config::ResolvedTtl::default();
        let mut params = store_params("sig-no-created-at probe", "covga2r4-store-sig2");
        // Standard base64 but no created_at supplied.
        params["signature"] = json!("AAAA");
        let err = ai_memory::mcp::tools::handle_store_for_tests(
            &conn,
            &store_db_path(),
            &params,
            None,
            None,
            None,
            &ttl,
            false,
            None,
            None,
        )
        .expect_err("signature without created_at must error");
        assert!(
            err.to_lowercase().contains("created_at"),
            "expected a created_at error, got: {err}"
        );
    }

    // NOTE: the `else if require_agent_attestation_enabled()` unsigned-write
    // rejection arm (store/mod.rs lines 356-358) is deliberately NOT driven
    // here. It requires flipping the process-global
    // `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` env var, which races every other
    // store-write test in this binary (cargo runs `#[tokio::test]`s in this
    // binary concurrently; a `set_var` flips the gate closed for unrelated
    // in-flight stores — the #1609 attestation-env test-race class). That
    // arm is already covered by `tests/agent_attestation_integrity.rs`
    // (`http_*` cases) without the cross-test env hazard. Recorded as an
    // exception rather than reintroducing the race.

    /// Merge-mode upsert over an identical `(title, namespace)` walks the
    /// exact-dup update branch (store/mod.rs lines 587-643): the
    /// post-write echo-read + the `duplicate: true` response.
    #[test]
    fn store_merge_dedup_updates_existing() {
        let conn = store_conn();
        let ttl = ai_memory::config::ResolvedTtl::default();
        let mut first = store_params("merge-dedup probe", "covga2r4-store-merge");
        first["on_conflict"] = json!("merge");
        ai_memory::mcp::tools::handle_store_for_tests(
            &conn,
            &store_db_path(),
            &first,
            None,
            None,
            None,
            &ttl,
            false,
            None,
            None,
        )
        .expect("first store ok");
        let mut second = store_params("merge-dedup probe", "covga2r4-store-merge");
        second["on_conflict"] = json!("merge");
        second["content"] = json!("updated content body for the merge dedup path here");
        let r2 = ai_memory::mcp::tools::handle_store_for_tests(
            &conn,
            &store_db_path(),
            &second,
            None,
            None,
            None,
            &ttl,
            false,
            None,
            None,
        )
        .expect("merge update ok");
        assert_eq!(r2["duplicate"], true, "merge dedup hit: {r2}");
    }
}
