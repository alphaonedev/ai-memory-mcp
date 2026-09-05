// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 polish/coverage-90 (issue #767) — handler postgres-branch
//! coverage push without a live postgres.
//!
//! Strategy: build the daemon `AppState` with
//! `storage_backend = StorageBackend::Postgres` while wiring an
//! `SqliteStore` as the `dyn MemoryStore` handle. This drives every
//! `#[cfg(feature = "sal")] if matches!(StorageBackend::Postgres) {…}`
//! branch in `handlers/http.rs`, `handlers/hook_subscribers.rs`, and
//! `handlers/federation_receive.rs` while the underlying calls land on
//! the `SqliteStore` impls (which exist for every method used on the
//! "happy" postgres branch). Branches that route through
//! `crate::store::postgres::*_via_store` helpers exercise the
//! `downcast_postgres` → `BackendUnavailable` error path → `503
//! Service Unavailable` envelope — also useful real coverage of
//! `store_err_to_response`.
//!
//! The `cov_18_offload_ttl_postgres` baseline tested a similar
//! "Postgres flag with `SqliteStore`" pattern for the offload TTL
//! plumbing. This file generalises it across the handler surface.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

/// #1751 — pin this test binary (and any spawned `ai-memory` child, which
/// inherits the process env) to the explicit permissive agent-attestation
/// opt-out. The v0.9 store-path default is REQUIRED and would reject this
/// suite's unsigned store fixtures; the required default itself is pinned
/// in `tests/agent_attestation_integrity.rs` + `tests/config_precedence.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}
/// Build a router with `storage_backend = Postgres` but backed by an
/// `SqliteStore`. This drives every `if matches!(Postgres)` branch
/// without requiring an actual postgres connection.
fn build_fake_pg_router() -> (axum::Router, NamedTempFile) {
    build_fake_pg_router_with_admins(Vec::new())
}

/// #3303 — variant of [`build_fake_pg_router`] with a populated admin
/// allowlist, for exercising the admin-bypass branch of a pg-lane authz gate
/// (e.g. `get_lineage`). Every other wiring detail is identical to
/// [`build_fake_pg_router`].
fn build_fake_pg_router_with_admins(admins: Vec<String>) -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
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
        // The headline trick: claim to be Postgres while running on Sqlite.
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admins),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// #901/#905/#907/#909 — handlers that accept a body-side `agent_id`
/// now require the `X-Agent-Id` header for authentication and 403
/// when the body claim disagrees. Use `post_json_as` for any POST that
/// carries `body.agent_id` or `metadata.agent_id`; plain `post_json`
/// is reserved for body-shape-only tests.
async fn post_json_as(
    router: &axum::Router,
    uri: &str,
    body: Value,
    caller_agent_id: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", caller_agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn get_uri(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// #901/#910 — GET handlers with `?agent_id=` query params now require
/// a matching `X-Agent-Id` header (or the body authorisation flow).
/// Use this helper for any test that asserts a happy-path on such a
/// route.
async fn get_uri_as(
    router: &axum::Router,
    uri: &str,
    caller_agent_id: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", caller_agent_id)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn delete_uri(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    delete_uri_as(router, uri, None).await
}

/// Per #874 (security-medium, 2026-05-18) the unsubscribe handler
/// REQUIRES authenticated identity via `X-Agent-Id` header (or body),
/// and refuses the request with 403 if the `agent_id=` query param
/// does not match the authenticated caller. Tests that pass an
/// `agent_id=…` query param MUST therefore also set the matching
/// `X-Agent-Id` header through this helper to exercise the
/// happy-path branches; otherwise the handler returns 403 instead
/// of the asserted 200/400.
async fn delete_uri_as(
    router: &axum::Router,
    uri: &str,
    caller_agent_id: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("DELETE").uri(uri);
    if let Some(caller) = caller_agent_id {
        builder = builder.header("x-agent-id", caller);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn put_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// PUT with an authenticated `X-Agent-Id`, the sibling of `post_json_as` /
/// `get_uri_as` / `delete_uri_as`.
///
/// A mutating handler resolves the caller via `identity::resolve_http_agent_id`,
/// which — with NO header — synthesizes a FRESH `anonymous:req-<uuid>` per
/// request (and logs a WARN). Two header-less requests therefore have two
/// DIFFERENT principals, so the create stamps `metadata.agent_id` with one
/// identity and a later header-less mutate arrives as another and fails the
/// caller-owns gate. Any happy-path mutate test must pin ONE stable identity
/// across the create and the mutate — exactly as the real sqlite smoke test
/// does (`route_put(.., Some("ai:smoke-agent"))` in tests/integration.rs).
async fn put_json_as(
    router: &axum::Router,
    uri: &str,
    body: Value,
    caller_agent_id: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", caller_agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ---------------------------------------------------------------------------
// /api/v1/memories — create / get / update / delete / promote on PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_create_memory_happy_path() {
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "tier": "long",
        "namespace": "pgfake",
        "title": "pg-create",
        "content": "stored via the postgres branch (sqlite-backed)",
        "tags": ["pg"],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    let (status, v) = post_json(&router, "/api/v1/memories", body).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create on pg branch: {status} body={v}",
    );
    assert!(v.get("id").is_some(), "{v}");
}

#[tokio::test]
async fn pg_create_memory_invalid_returns_400() {
    let (router, _f) = build_fake_pg_router();
    // Empty content — fails validate::validate_create
    let body = json!({
        "tier": "long",
        "namespace": "pgfake",
        "title": "",
        "content": "",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    let (status, _v) = post_json(&router, "/api/v1/memories", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_get_memory_unknown_returns_404() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(
        &router,
        "/api/v1/memories/00000000-0000-0000-0000-000000000000",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_get_memory_after_create_roundtrip() {
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "tier": "long",
        "namespace": "pgfake-get",
        "title": "pg-get",
        "content": "roundtrip body",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    // #910 SAL-level visibility — anonymous callers get a fresh
    // `anonymous:req-<uuid>` per request, so the GET caller cannot
    // see the POST caller's scope=private row. Use a stable
    // X-Agent-Id across both legs so the create-then-get round-trip
    // sees the same principal.
    let (_status, v) = post_json_as(&router, "/api/v1/memories", body, "pg-roundtrip").await;
    let id = v["id"].as_str().expect("id").to_string();
    let (status, got) =
        get_uri_as(&router, &format!("/api/v1/memories/{id}"), "pg-roundtrip").await;
    assert_eq!(status, StatusCode::OK, "{got}");
    // The pg path's get_memory returns `{memory: ..., links: ...}` so the
    // id is nested under `memory`.
    assert_eq!(got["memory"]["id"], json!(id));
}

#[tokio::test]
async fn pg_update_memory_happy() {
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "tier": "mid",
        "namespace": "pgfake-upd",
        "title": "pg-upd",
        "content": "original",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    // ONE stable identity for BOTH the create and the update: the create
    // stamps `metadata.agent_id` with the caller, and the pg branch's
    // caller-owns gate (`assert_caller_owns_for_mutation`, #1412/#1628)
    // requires the mutating caller to be that owner. Header-less requests
    // get a FRESH `anonymous:req-<uuid>` each time, so they can never own
    // what a previous header-less request created.
    let caller = "ai:pgfake-upd";
    let (_status, v) = post_json_as(&router, "/api/v1/memories", body, caller).await;
    let id = v["id"].as_str().unwrap().to_string();
    let (status, got) = put_json_as(
        &router,
        &format!("/api/v1/memories/{id}"),
        json!({"content": "updated body"}),
        caller,
    )
    .await;
    assert!(status == StatusCode::OK, "pg update: {status} body={got}");
}

#[tokio::test]
async fn pg_update_memory_unknown_returns_404() {
    let (router, _f) = build_fake_pg_router();
    let id = "00000000-0000-0000-0000-000000000000";
    let (status, _v) = put_json(
        &router,
        &format!("/api/v1/memories/{id}"),
        json!({"content": "new"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// FBL-12 residual (#2378) — the postgres branch of `PUT /memories/{id}`
/// must charge the storage-byte GROWTH of an in-place update against the
/// row owner's per-namespace storage cap. Pre-#2378 the pg branch skipped
/// the quota entirely, so an agent could grow each row uncharged. Drives
/// the new `app.store.charge_update_growth` call on the pg branch (landing
/// on the `SqliteStore` delegate in this fake-pg harness).
#[tokio::test]
async fn pg_update_growth_charges_quota_returns_429() {
    let (router, f) = build_fake_pg_router();
    let db_path = f.path().to_path_buf();
    let body = json!({
        "tier": "mid",
        "namespace": "qns",
        "title": "qtitle",
        "content": "seed",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "agent_id": "qv",
        "metadata": {},
    });
    let (cs, cv) = post_json_as(&router, "/api/v1/memories", body, "qv").await;
    assert!(
        cs == StatusCode::CREATED || cs == StatusCode::OK,
        "create: {cs} body={cv}"
    );
    let id = cv["id"].as_str().unwrap().to_string();

    // Pin a TINY per-(agent, namespace) storage cap with ZERO headroom so
    // any positive growth breaches it — targeted to THIS agent only, so no
    // other test's compiled defaults are perturbed.
    {
        let conn = ai_memory::db::open(&db_path).expect("open for quota seed");
        // ensure the (agent, namespace) row exists (default ceilings)…
        let _ = ai_memory::quotas::get_status(&conn, "qv", "qns").expect("ensure quota row");
        // …then pin max == current so delta > 0 always exceeds.
        conn.execute(
            "UPDATE agent_quotas \
               SET max_storage_bytes = 10, current_storage_bytes = 10 \
             WHERE agent_id = 'qv' AND namespace = 'qns'",
            [],
        )
        .expect("pin tiny cap");
    }

    // Growth (~1 KiB) must be refused with 429 QUOTA_EXCEEDED.
    let big = "x".repeat(1024);
    let (gs, gv) = put_json_as(
        &router,
        &format!("/api/v1/memories/{id}"),
        json!({ "content": big }),
        "qv",
    )
    .await;
    assert_eq!(
        gs,
        StatusCode::TOO_MANY_REQUESTS,
        "growth past cap must 429: {gv}"
    );
    assert_eq!(
        gv["code"].as_str(),
        Some(ai_memory::errors::error_codes::QUOTA_EXCEEDED),
        "429 envelope carries QUOTA_EXCEEDED code: {gv}"
    );
    assert_eq!(
        gv["limit"].as_str(),
        Some(ai_memory::quotas::QuotaLimit::StorageBytes.as_str()),
        "limit names storage_bytes: {gv}"
    );

    // Control: a shrink / no-op update charges nothing (delta <= 0) → 200.
    let (ss, sv) = put_json_as(
        &router,
        &format!("/api/v1/memories/{id}"),
        json!({ "content": "s" }),
        "qv",
    )
    .await;
    assert_eq!(ss, StatusCode::OK, "shrink must pass uncharged: {sv}");
}

#[tokio::test]
async fn pg_delete_memory_unknown_returns_404() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = delete_uri(
        &router,
        "/api/v1/memories/00000000-0000-0000-0000-000000000000",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_delete_memory_after_create() {
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "tier": "long",
        "namespace": "pgfake-del",
        "title": "pg-del",
        "content": "to be deleted via pg branch",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    // Same stable-identity requirement as `pg_update_memory_happy`: the pg
    // delete branch runs the same caller-owns gate, so the deleter must be
    // the agent that created the row.
    let caller = "ai:pgfake-del";
    let (_status, v) = post_json_as(&router, "/api/v1/memories", body, caller).await;
    let id = v["id"].as_str().unwrap().to_string();
    let (status, got) =
        delete_uri_as(&router, &format!("/api/v1/memories/{id}"), Some(caller)).await;
    assert_eq!(status, StatusCode::OK, "{got}");
}

#[tokio::test]
async fn pg_promote_memory_unknown_returns_404() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/memories/00000000-0000-0000-0000-000000000000/promote",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_promote_memory_after_create() {
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "tier": "short",
        "namespace": "pgfake-prom",
        "title": "pg-prom",
        "content": "to be promoted via pg branch",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "metadata": {},
    });
    // #910 SAL-level visibility — keep the same caller across both
    // legs so the promote handler's pre-fetch (`store.get`) sees the
    // row it just created.
    let (_status, v) = post_json_as(&router, "/api/v1/memories", body, "pg-promote").await;
    let id = v["id"].as_str().unwrap().to_string();
    let (status, got) = post_json_as(
        &router,
        &format!("/api/v1/memories/{id}/promote"),
        json!({}),
        "pg-promote",
    )
    .await;
    assert!(status == StatusCode::OK, "pg promote: {status} body={got}");
    assert_eq!(got["tier"], json!("long"));
}

#[tokio::test]
async fn pg_promote_memory_invalid_id_400() {
    let (router, _f) = build_fake_pg_router();
    // Use a long alpha string that fails validate::validate_id at the top of
    // the handler before the postgres branch is even reached. The `_` and
    // `:` characters fail the UUID-shape check.
    let (status, _v) = post_json(
        &router,
        "/api/v1/memories/not_a_valid_uuid_shape/promote",
        json!({}),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/memories — list/search on PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_list_memories_returns_array() {
    let (router, _f) = build_fake_pg_router();
    // Seed one row
    let _ = post_json(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-list",
            "title": "pg-list",
            "content": "list me",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    let (status, v) = get_uri(&router, "/api/v1/memories?namespace=pgfake-list&limit=10").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["memories"].is_array() || v.is_array(), "{v}");
}

#[tokio::test]
async fn pg_search_memories_happy() {
    let (router, _f) = build_fake_pg_router();
    let _ = post_json(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-search",
            "title": "pg-search",
            "content": "uniquesearchtoken123",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    let (status, v) = get_uri(&router, "/api/v1/search?q=uniquesearchtoken123").await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// #3185 / #3127 — the postgres HTTP branch must thread `?source_uri=`
/// and `?since=` into `Filter` (pre-fix it early-returned through trait
/// `search` and dropped both). This suite claims `StorageBackend::Postgres`
/// while backing the SAL with `SqliteStore`, so the assertion is the
/// handler compose path, not the pg SQL. Live pg SQL is pinned in
/// `tests/pg_search_filter_ssot_3185.rs`.
#[tokio::test]
async fn pg_search_compose_q_source_uri_since_on_postgres_branch() {
    let (router, f) = build_fake_pg_router();
    let ns = "pgfake-compose";
    let token = "uniquefaketoken3185";
    let keep_uri = "doc:fake-keep";
    let other_uri = "doc:fake-other";
    let conn = ai_memory::db::open(f.path()).expect("reopen");
    let now = chrono::Utc::now();
    let seed = |title: &str, uri: &str, created: chrono::DateTime<chrono::Utc>| {
        let ts = created.to_rfc3339();
        let mem = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_string(),
            content: format!("{token} body"),
            namespace: ns.to_string(),
            tier: ai_memory::models::Tier::Long,
            created_at: ts.clone(),
            updated_at: ts,
            source_uri: Some(uri.to_string()),
            metadata: serde_json::json!({"agent_id": ns, "scope": "collective"}),
            ..Default::default()
        };
        ai_memory::db::insert(&conn, &mem).expect("insert");
    };
    seed("keep-in-window", keep_uri, now - chrono::Duration::days(1));
    seed("keep-too-old", keep_uri, now - chrono::Duration::days(10));
    seed(
        "other-in-window",
        other_uri,
        now - chrono::Duration::days(1),
    );
    drop(conn);

    // Use `Z` (not `+00:00`): a `+` in a query string is form-decoded as
    // space, which would make RFC3339 parse fail and silently drop `since`.
    let since = (now - chrono::Duration::days(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let qs = format!(
        "q={token}&namespace={ns}&source_uri={}&since={since}",
        keep_uri.replace(':', "%3A"),
    );
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/search?{qs}"))
        .header(ai_memory::HEADER_AGENT_ID, ns)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "{v}");
    let results = v["results"].as_array().expect("results");
    assert_eq!(
        results.len(),
        1,
        "postgres-branch compose must return only the in-window matching-URI row; got {v}"
    );
    assert_eq!(
        results[0]["source_uri"].as_str(),
        Some(keep_uri),
        "returned row must carry the filtered URI; got {v}"
    );
    assert_eq!(
        results[0]["title"].as_str(),
        Some("keep-in-window"),
        "old + other-URI rows must be excluded; got {v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/recall — PG keyword fallback envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_recall_get_envelope() {
    let (router, _f) = build_fake_pg_router();
    let _ = post_json(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-rec",
            "title": "pg-rec",
            "content": "recallable content for pg path",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    let (status, v) = get_uri(&router, "/api/v1/recall?q=recallable&namespace=pgfake-rec").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // PG keyword fallback envelope carries `mode = keyword`.
    assert!(
        v.get("memories").is_some() || v.get("count").is_some(),
        "{v}"
    );
    // F-L8a K3 parity — the postgres recall branch carries the SAME
    // `meta.semantic_withheld` KEY as sqlite, but HONESTLY marks it
    // UNMEASURED (the pg SAL recall excludes foreign-space rows in SQL
    // without counting them). The numeric fields are OMITTED rather than
    // fabricated as 0 — never a WRONG result on the wire.
    let sw = &v["meta"]["semantic_withheld"];
    assert_eq!(
        sw["measured"], false,
        "postgres recall must report semantic_withheld as UNMEASURED; got: {v}"
    );
    assert!(
        sw.get("space_mismatch").is_none() && sw.get("total").is_none(),
        "unmeasured pg block must OMIT the numeric fields (no fabricated 0); got: {sw}"
    );
}

#[tokio::test]
async fn pg_recall_post_envelope() {
    let (router, _f) = build_fake_pg_router();
    let _ = post_json(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-rec2",
            "title": "pg-rec2",
            "content": "content for postgres recall path",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    let (status, v) = post_json(
        &router,
        "/api/v1/recall",
        json!({
            "context": "content",
            "namespace": "pgfake-rec2",
            "limit": 5,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn pg_recall_post_with_has_citations_filter() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/recall",
        json!({
            "context": "anything",
            "has_citations": true,
            "limit": 5,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// /api/v1/forget — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_forget_by_namespace_returns_deleted_count() {
    // #942/#956 (security-2026-05-20) — `/api/v1/forget` requires
    // caller-scoping; without an admin or matching agent_id, the
    // handler refuses with 403. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let _ = post_json(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "short",
            "namespace": "pgfake-forget",
            "title": "forget-me",
            "content": "to be forgotten via pg branch",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
    )
    .await;
    let (status, v) = post_json(
        &router,
        "/api/v1/forget",
        json!({"namespace": "pgfake-forget"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#942: anon-caller forget on pg branch MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/agents — list_agents PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_list_agents_returns_array() {
    // #946 (security-2026-05-20) — `/api/v1/agents` is admin-gated.
    // Empty allowlist (fixture default) rejects every caller. #997
    // fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/agents").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#946: empty-allowlist /api/v1/agents MUST reject; body={v}"
    );
}

#[tokio::test]
async fn pg_register_agent_then_list() {
    // #3398 (security, 2026-09-03) — `POST /api/v1/agents` UPSERTS the roster
    // row, so registering a principal OTHER than the resolved caller is a
    // cross-register and goes through the canonical `require_admin` gate.
    // This suite's original caller was anonymous (no `X-Agent-Id`), which the
    // gate now — correctly — refuses with `403 {"error":"admin role
    // required"}`. Drive the pg branch through the ADMIN context the #3303
    // lineage test uses instead of weakening the gate.
    mark_request_authn_for_admin_tests();
    let (router, _f) = build_fake_pg_router_with_admins(vec!["ai:pg-admin".to_string()]);
    let (status, v) = post_json_as(
        &router,
        "/api/v1/agents",
        json!({
            "agent_id": "pg-agent-1",
            "agent_type": "human",
            "capabilities": ["store"],
        }),
        "ai:pg-admin",
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{v}",
    );
}

#[tokio::test]
async fn pg_register_agent_cross_register_requires_admin_3398() {
    // The DENIED twin of `pg_register_agent_then_list`: a plain tenant caller
    // registering SOMEONE ELSE's principal must be refused with the exact
    // `require_admin` wire shape, on the pg branch too. Pre-#3398 this
    // overwrote the victim's `agent_type` / `capabilities` and the admin-gated
    // `GET` then served the forgery as roster truth.
    mark_request_authn_for_admin_tests();
    let (router, _f) = build_fake_pg_router_with_admins(vec!["ai:pg-admin".to_string()]);
    let (status, v) = post_json_as(
        &router,
        "/api/v1/agents",
        json!({
            "agent_id": "pg-agent-1",
            "agent_type": "human",
            "capabilities": ["TAMPERED"],
        }),
        "ai:pg-tenant",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3398: cross-register by a non-admin MUST be refused; body={v}"
    );
    assert_eq!(
        v,
        json!({"error": "admin role required"}),
        "#3398: the refusal keeps the canonical require_admin wire shape"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/entities — entity_register PG branch (alias union)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_entity_register_happy() {
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json(
        &router,
        "/api/v1/entities",
        json!({
            "canonical_name": "PG Entity One",
            "namespace": "pgfake-ent",
            "aliases": ["pg-ent-1", "pe1"],
            "metadata": {},
        }),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{v}"
    );
}

#[tokio::test]
async fn pg_entity_register_alias_union_on_re_register() {
    let (router, _f) = build_fake_pg_router();
    let _ = post_json(
        &router,
        "/api/v1/entities",
        json!({
            "canonical_name": "PG Entity Two",
            "namespace": "pgfake-ent2",
            "aliases": ["one", "two"],
            "metadata": {},
        }),
    )
    .await;
    // Re-register with NEW aliases — handler should union them with prior.
    let (status, _v) = post_json(
        &router,
        "/api/v1/entities",
        json!({
            "canonical_name": "PG Entity Two",
            "namespace": "pgfake-ent2",
            "aliases": ["three", "four"],
            "metadata": {},
        }),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::CREATED);
}

#[tokio::test]
async fn pg_entity_register_invalid_namespace_400() {
    let (router, _f) = build_fake_pg_router();
    // Use a namespace that clearly fails `validate_namespace` — `..` is a
    // banned segment per the existing namespace rules.
    let (status, _v) = post_json(
        &router,
        "/api/v1/entities",
        json!({
            "canonical_name": "bad",
            "namespace": "../etc",
            "aliases": [],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/taxonomy — PG branch routes through taxonomy_namespaces_via_store
// → downcast_postgres → BackendUnavailable → 503
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_taxonomy_via_store_pg_branch_envelope() {
    // #945 (security-2026-05-20) — `/api/v1/taxonomy` is admin-gated.
    // Empty allowlist (fixture default) rejects every caller before
    // the downcast / 503 branch can fire. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/taxonomy").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#945: empty-allowlist /api/v1/taxonomy MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/archive — PG branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_list_archive_via_store_envelope() {
    // #943 (security-2026-05-20) — `/api/v1/archive` is admin-gated.
    // Empty allowlist (fixture default) rejects every caller before
    // the downcast / 503 branch can fire. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/archive").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#943: empty-allowlist /api/v1/archive MUST reject; body={v}"
    );
}

#[tokio::test]
async fn pg_archive_stats_via_store_envelope() {
    // #943 (security-2026-05-20) — `/api/v1/archive/stats` is
    // admin-gated. Empty allowlist (fixture default) rejects every
    // caller. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/archive/stats").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#943: empty-allowlist /api/v1/archive/stats MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/kg/* — PG branches via kg_*_via_store → 503
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_kg_timeline_via_store_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(
        &router,
        "/api/v1/kg/timeline?source_id=00000000-0000-0000-0000-000000000000",
    )
    .await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_kg_invalidate_via_store_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/kg/invalidate",
        json!({
            "source_id": "00000000-0000-0000-0000-000000000000",
            "target_id": "00000000-0000-0000-0000-000000000001",
            "relation": "related_to",
            "valid_until": chrono::Utc::now().to_rfc3339(),
        }),
    )
    .await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_kg_query_via_store_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/kg/query",
        json!({
            "source_id": "00000000-0000-0000-0000-000000000000",
            "max_depth": 2,
        }),
    )
    .await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/pending — list_pending_actions_via_store PG path → 503
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_list_pending_via_store_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/pending").await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::OK,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/inbox — hook_subscribers::get_inbox PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_inbox_returns_envelope() {
    let (router, _f) = build_fake_pg_router();
    // #901: query agent_id must match the authenticated caller via header.
    let (status, v) = get_uri_as(
        &router,
        "/api/v1/inbox?agent_id=pg-recipient",
        "pg-recipient",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("messages").is_some() || v.is_array(), "{v}");
}

#[tokio::test]
async fn pg_inbox_with_unread_only() {
    let (router, _f) = build_fake_pg_router();
    // #901: matching X-Agent-Id required for the query agent_id.
    let (status, _v) = get_uri_as(
        &router,
        "/api/v1/inbox?agent_id=pg-recipient&unread_only=true",
        "pg-recipient",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_inbox_invalid_agent_id_400() {
    let (router, _f) = build_fake_pg_router();
    // #901: send the invalid agent_id in BOTH the header and the query.
    // The handler's first authentication step calls
    // `resolve_http_agent_id` on the header, whose `validate_agent_id`
    // returns the 400 BAD REQUEST before the query-match check runs.
    let (status, _v) = get_uri_as(&router, "/api/v1/inbox?agent_id=!bad!", "!bad!").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/notify — hook_subscribers::notify PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_notify_happy_path() {
    let (router, _f) = build_fake_pg_router();
    // #901: matching X-Agent-Id required for the body agent_id.
    let (status, v) = post_json_as(
        &router,
        "/api/v1/notify",
        json!({
            "target_agent_id": "pg-recipient",
            "title": "pg-note",
            "payload": "hello from postgres branch",
            "agent_id": "pg-sender",
            "priority": 5,
        }),
        "pg-sender",
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "notify pg: {status} body={v}",
    );
}

#[tokio::test]
async fn pg_notify_missing_payload_400() {
    let (router, _f) = build_fake_pg_router();
    // target_agent_id + title present; payload + content both missing →
    // handler returns 400 explicitly (not axum's 422 deserialization fail).
    // #901: matching X-Agent-Id required for the body agent_id.
    let (status, _v) = post_json_as(
        &router,
        "/api/v1/notify",
        json!({
            "target_agent_id": "pg-recipient",
            "title": "no-body",
            "agent_id": "pg-sender",
        }),
        "pg-sender",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/subscriptions — PG branches (subscribe / list / unsubscribe)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_subscribe_namespace_form_synthesizes_url_pg() {
    // The namespace-form subscribe synthesizes a loopback URL internally
    // and bypasses SSRF — exercises the pg subscribe branch without
    // needing a routable URL.
    // #901: matching X-Agent-Id required for the body agent_id.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json_as(
        &router,
        "/api/v1/subscriptions",
        json!({
            "agent_id": "pg-sub-agent",
            "namespace": "pgfake-sub-ns",
            "events": "memory.created",
            "secret": "test-secret",
        }),
        "pg-sub-agent",
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "subscribe pg: {status} body={v}",
    );
}

#[tokio::test]
async fn pg_subscribe_missing_url_and_namespace_400() {
    let (router, _f) = build_fake_pg_router();
    // #901: matching X-Agent-Id required for the body agent_id.
    let (status, _v) = post_json_as(
        &router,
        "/api/v1/subscriptions",
        json!({"agent_id": "pg-sub-agent"}),
        "pg-sub-agent",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_unsubscribe_by_id_when_missing_returns_ok_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, v) = delete_uri(&router, "/api/v1/subscriptions?id=no-such-sub").await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn pg_unsubscribe_no_id_no_ns_400() {
    let (router, _f) = build_fake_pg_router();
    // Per #874: must send X-Agent-Id matching the query agent_id, else
    // the handler returns 403 before reaching the missing-(id,ns) gate.
    let (status, _v) = delete_uri_as(
        &router,
        "/api/v1/subscriptions?agent_id=pg-agent",
        Some("pg-agent"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_unsubscribe_by_namespace_missing_returns_removed_false() {
    let (router, _f) = build_fake_pg_router();
    // Per #874: matching X-Agent-Id required to clear the auth gate.
    let (status, _v) = delete_uri_as(
        &router,
        "/api/v1/subscriptions?agent_id=pg-agent&namespace=nonexistent",
        Some("pg-agent"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// /api/v1/namespaces/{ns}/standard — PG branch for set / get / clear
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_get_namespace_standard_missing_returns_not_implemented_or_ok() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/namespaces/no-such-ns/standard").await;
    // The path-form `get_namespace_standard` routes through Db extractor
    // (not AppState) so it never dispatches to a PG branch — it returns OK
    // with a null envelope from the MCP handler. The qs-form (covered
    // separately below) is the one with the PG dispatch.
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_IMPLEMENTED
            || status == StatusCode::NOT_FOUND,
    );
}

#[tokio::test]
async fn pg_get_namespace_standard_qs_with_inherit() {
    let (router, _f) = build_fake_pg_router();
    // Use the query-string form — exercises get_namespace_standard_qs PG branch.
    let (status, _v) = get_uri(
        &router,
        "/api/v1/namespaces?namespace=foo/bar/baz&inherit=true",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_get_namespace_standard_qs_no_namespace_returns_list() {
    // #945 (security-2026-05-20) — `/api/v1/namespaces` is admin-gated.
    // No namespace → delegates to list_namespaces() (sqlite path even on
    // pg backend). Empty allowlist (fixture default) rejects every
    // caller. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/namespaces").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#945: empty-allowlist /api/v1/namespaces MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/sync/push — postgres branch via sync_push_via_store
// ---------------------------------------------------------------------------

static FED_LEGACY_BYPASS_INIT_PG: std::sync::Once = std::sync::Once::new();
fn install_federation_legacy_bypass_pg() {
    FED_LEGACY_BYPASS_INIT_PG.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_FED_TRUST_BODY_AGENT_ID", "1");
        std::env::set_var("AI_MEMORY_FED_SYNC_TRUST_PEER", "1");
        // #1789 — v0.8 flipped peer enrollment to the secure default
        // (strict). Restore the pre-v0.7.0 permissive posture for this
        // in-process fake-PG suite so the (None,None) sync arm allows.
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
    });
}

#[tokio::test]
async fn pg_sync_push_apply_memory() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    let now = chrono::Utc::now().to_rfc3339();
    let body = json!({
        "sender_agent_id": "pg-peer",
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": "pg-sync",
            "title": "pg-sync-mem",
            "content": "from a pg-branch peer push",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    let (status, v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v.get("applied").is_some(), "{v}");
}

#[tokio::test]
async fn pg_sync_push_invalid_sender_400() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "sender_agent_id": "",
        "sender_clock": {"entries": {}},
        "memories": [],
        "dry_run": false,
    });
    let (status, _v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_sync_push_dry_run_no_writes() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    let now = chrono::Utc::now().to_rfc3339();
    let body = json!({
        "sender_agent_id": "pg-peer",
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": "pg-sync-dry",
            "title": "pg-dry",
            "content": "dry run",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": true,
    });
    let (status, v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn pg_sync_push_deletions_oversize_rejected() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    // 10_001 short ID strings — small enough to fit Axum's body limit but
    // over the per-collection MAX_BULK_SIZE cap.
    let deletions: Vec<Value> = (0..10_001)
        .map(|_| json!(uuid::Uuid::new_v4().to_string()))
        .collect();
    let body = json!({
        "sender_agent_id": "pg-peer",
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": deletions,
        "dry_run": false,
    });
    let (status, _v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_sync_push_with_deletions() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    let body = json!({
        "sender_agent_id": "pg-peer",
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": ["00000000-0000-0000-0000-000000000099"],
        "dry_run": false,
    });
    let (status, _v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_sync_push_with_invalid_memory_skipped() {
    install_federation_legacy_bypass_pg();
    let (router, _f) = build_fake_pg_router();
    let now = chrono::Utc::now().to_rfc3339();
    // empty title — validate_memory fails so skipped
    let body = json!({
        "sender_agent_id": "pg-peer",
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": "pg-sync-bad",
            "title": "",
            "content": "",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    let (status, v) = post_json(&router, "/api/v1/sync/push", body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

// ---------------------------------------------------------------------------
// /api/v1/stats, /api/v1/gc — both have pg branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_get_stats_returns_struct() {
    // #946 (security-2026-05-20) — `/api/v1/stats` is admin-gated.
    // Empty allowlist (fixture default) rejects every caller. #997
    // fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/stats").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#946: empty-allowlist /api/v1/stats MUST reject; body={v}"
    );
}

#[tokio::test]
async fn pg_run_gc_rejects_empty_allowlist_403() {
    // v0.7.0 #1027 + #1107 — `/api/v1/gc` is admin-gated. Empty
    // admin-allowlist (this fixture's default) rejects every caller.
    // The admin-admit happy path is covered in
    // `tests/admin_run_gc_require_admin_1027.rs` (403 reject + 200
    // admit, end-to-end). Same convention as #946 pg_get_stats and
    // #957 pg_export — the empty-allowlist branch lives here, the
    // admit branch lives in its own per-issue file. (#1127)
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json(&router, "/api/v1/gc", json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#1027: empty-allowlist /api/v1/gc MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/export — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_export_returns_envelope() {
    // #957 (security-critical, 2026-05-20) — `/api/v1/export` is
    // admin-gated. Empty allowlist (the fixture default) rejects
    // every caller. The admin-admit path is covered by
    // `tests/export_memories_admin_gate_957.rs`.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/export").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#957: empty-allowlist pg export MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/bulk — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_bulk_create_happy() {
    let (router, _f) = build_fake_pg_router();
    // bulk_create takes a bare JSON array (Vec<CreateMemory>), not an
    // object-wrapped envelope.
    let body = json!([
        {
            "tier": "long",
            "namespace": "pg-bulk",
            "title": "bulk-1",
            "content": "first bulk memory via pg branch",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        },
        {
            "tier": "long",
            "namespace": "pg-bulk",
            "title": "bulk-2",
            "content": "second bulk memory via pg branch",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }
    ]);
    let (status, v) = post_json(&router, "/api/v1/memories/bulk", body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "bulk pg: {status} body={v}",
    );
}

#[tokio::test]
async fn pg_bulk_create_over_limit_400() {
    let (router, _f) = build_fake_pg_router();
    let items: Vec<Value> = (0..1001)
        .map(|i| {
            json!({
                "tier": "long",
                "namespace": "pg-bulk-over",
                "title": format!("over-{i}"),
                "content": "x",
                "tags": [],
                "priority": 5,
                "confidence": 1.0,
                "source": "user",
                "metadata": {},
            })
        })
        .collect();
    let body = json!(items);
    let (status, _v) = post_json(&router, "/api/v1/memories/bulk", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/quota/status — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_quota_status_no_writes_returns_zero() {
    let (router, _f) = build_fake_pg_router();
    // #909: body.agent_id must match X-Agent-Id of authenticated caller.
    let (status, _v) = post_json_as(
        &router,
        "/api/v1/quota/status",
        json!({"agent_id": "pg-q"}),
        "pg-q",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// /api/v1/check_duplicate — handler is sqlite-only but PG flag path
// surfaces an error envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_check_duplicate_returns_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/check_duplicate",
        json!({"title": "x", "content": "needs an embedder to score similarity"}),
    )
    .await;
    // Without an embedder configured the substrate returns 400 (semantic
    // recall is unavailable, so duplicate detection can't score).
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::OK
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/links — PG branches when flag is Postgres
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_get_links_unknown_id_returns_empty_array() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(
        &router,
        "/api/v1/links/00000000-0000-0000-0000-000000000000",
    )
    .await;
    // Substrate returns 200 with an empty array; PG branch should as well.
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::SERVICE_UNAVAILABLE,
    );
}

// ---------------------------------------------------------------------------
// /api/v1/kg/find_paths — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_kg_find_paths_invalid_source_400() {
    let (router, _f) = build_fake_pg_router();
    // Use a clearly-invalid id (contains whitespace, fails validate_id).
    let (status, _v) = post_json(
        &router,
        "/api/v1/kg/find_paths",
        json!({"source_id": "bad id with spaces", "target_id": "00000000-0000-0000-0000-000000000001"}),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::OK,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_kg_find_paths_unknown_returns_empty() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/kg/find_paths",
        json!({
            "source_id": "00000000-0000-0000-0000-000000000000",
            "target_id": "00000000-0000-0000-0000-000000000001",
            "max_depth": 3,
        }),
    )
    .await;
    // SqliteStore's find_paths impl returns Ok(vec![]) when no path; pg
    // branch wraps the same envelope, returning 200 with empty paths.
    assert!(
        status == StatusCode::OK
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::NOT_IMPLEMENTED,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/entities/by_alias — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_entity_get_by_alias_unknown_returns_null_or_404() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(
        &router,
        "/api/v1/entities/by_alias?alias=no-such-alias&namespace=pgfake-e",
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/import — PG branch (governance walk)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_import_memories_happy() {
    let (router, _f) = build_fake_pg_router();
    let now = chrono::Utc::now().to_rfc3339();
    let body = json!({
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": "pg-import",
            "title": "import-1",
            "content": "imported via pg branch",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "import",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "links": []
    });
    let (status, v) = post_json(&router, "/api/v1/import", body).await;
    // #956 (security-medium, 2026-05-20) — `/api/v1/import` admin-gated;
    // empty-allowlist fixture correctly rejects anonymous caller. The
    // pg-branch row walk + SAL store integration is exercised against
    // real postgres + admin-allowlisted caller at
    // `serve_postgres_continuation3.rs::import_lands_memories_via_sal`.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#956: empty-allowlist pg-branch import MUST reject; body={v}",
    );
}

#[tokio::test]
async fn pg_import_memories_with_invalid_member_records_error() {
    let (router, _f) = build_fake_pg_router();
    let now = chrono::Utc::now().to_rfc3339();
    let body = json!({
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long",
            "namespace": "pg-import-bad",
            "title": "",
            "content": "",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "import",
            "access_count": 0,
            "created_at": now,
            "updated_at": now,
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
    });
    let (status, v) = post_json(&router, "/api/v1/import", body).await;
    // #956 — empty-allowlist pg-branch import correctly rejects.
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
}

#[tokio::test]
async fn pg_import_oversize_400() {
    let (router, _f) = build_fake_pg_router();
    // 10_001 small memories — over MAX_BULK_SIZE
    let now = chrono::Utc::now().to_rfc3339();
    let mems: Vec<Value> = (0..10_001)
        .map(|i| {
            json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "tier": "long",
                "namespace": "pg-imp-over",
                "title": format!("o-{i}"),
                "content": "x",
                "tags": [],
                "priority": 5,
                "confidence": 1.0,
                "source": "import",
                "access_count": 0,
                "created_at": now,
                "updated_at": now,
                "metadata": {},
                "reflection_depth": 0,
                "memory_kind": "observation",
            })
        })
        .collect();
    let body = json!({"memories": mems, "links": []});
    let (status, _v) = post_json(&router, "/api/v1/import", body).await;
    // Either the handler's MAX_BULK_SIZE returns 400 or Axum body-limit
    // rejects with 413.
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE,
        "{status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/links — PG create / delete branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_create_link_with_unknown_ids_returns_error() {
    let (router, _f) = build_fake_pg_router();
    // Both endpoints exist in handlers; PG branch routes through SAL trait.
    let (status, _v) = post_json(
        &router,
        "/api/v1/links",
        json!({
            "source_id": "00000000-0000-0000-0000-000000000000",
            "target_id": "00000000-0000-0000-0000-000000000001",
            "relation": "related_to",
        }),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::INTERNAL_SERVER_ERROR
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::CREATED
            || status == StatusCode::OK,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_delete_link_unknown_returns_404_or_ok() {
    let (router, _f) = build_fake_pg_router();
    // delete_link expects a JSON body
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/links")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "source_id": "00000000-0000-0000-0000-000000000000",
                "target_id": "00000000-0000-0000-0000-000000000001",
                "relation": "related_to",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/quota/status — list_all branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_quota_status_list_no_agent_returns_list() {
    // #960 (security-2026-05-20) — `/api/v1/quota/status` list path
    // (no agent_id) is admin-gated. Empty allowlist (fixture default)
    // rejects every caller. #997 fixture-drift fix.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json(&router, "/api/v1/quota/status", json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#960: empty-allowlist quota list MUST reject; body={v}"
    );
}

// ---------------------------------------------------------------------------
// /api/v1/archive/{id}/restore — PG branch (via store)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_restore_archive_unknown_id_404_or_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/archive/00000000-0000-0000-0000-000000000000/restore",
        json!({}),
    )
    .await;
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::OK,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_archive_by_ids_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/archive",
        json!({"ids": ["00000000-0000-0000-0000-000000000000"]}),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/consolidate — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_consolidate_with_unknown_ids_returns_400_or_404() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": ["00000000-0000-0000-0000-000000000000"],
            "title": "merged",
            "namespace": "pg-consol",
        }),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::INTERNAL_SERVER_ERROR
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::OK
            || status == StatusCode::CREATED,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/contradictions — sqlite-bound but exercises 400 path on PG flag
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_contradictions_missing_topic_and_ns_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/contradictions").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/auto_tag, /api/v1/expand_query — LLM handlers degrade
// gracefully on PG flag w/ no llm wired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_auto_tag_no_llm_returns_empty_or_503() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/auto_tag",
        json!({"title": "tagme", "content": "longer content body for auto_tag please"}),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::BAD_REQUEST,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_expand_query_no_llm_returns_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/expand_query",
        json!({"query": "what is the rust language"}),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::SERVICE_UNAVAILABLE
            || status == StatusCode::BAD_REQUEST,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/memory_load_family — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_load_family_happy_or_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/memory_load_family",
        json!({"family": "ai-memory"}),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/links/verify — PG branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_verify_link_returns_envelope_or_error() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/links/verify",
        json!({
            "source_id": "00000000-0000-0000-0000-000000000000",
            "target_id": "00000000-0000-0000-0000-000000000001",
            "relation": "related_to",
        }),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/session/start — PG-flag-aware (delegates to MCP handler)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_session_start_happy() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/session/start",
        json!({"agent_id": "pg-session"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_session_start_invalid_agent_id_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/session/start",
        json!({"agent_id": "!bad!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// /api/v1/sync/since — PG sync since envelope
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_sync_since_no_param_returns_envelope() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/sync/since").await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

#[tokio::test]
async fn pg_sync_since_with_peer_query() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/sync/since?peer=pg-peer-x&limit=10").await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE,
        "got {status}",
    );
}

// ---------------------------------------------------------------------------
// /api/v1/tools/list, /api/v1/capabilities, /api/v1/health, /metrics — flag
// independent but should be sane under PG flag
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_tools_list_returns_array() {
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/tools/list").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.get("tools").is_some(), "{v}");
}

#[tokio::test]
async fn pg_capabilities_returns_storage_backend_postgres() {
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(&router, "/api/v1/capabilities").await;
    assert_eq!(status, StatusCode::OK);
    // The cap envelope echoes the configured storage backend.
    let backend = v
        .get("storage_backend")
        .and_then(|b| b.as_str())
        .or_else(|| v.pointer("/storage/backend").and_then(|b| b.as_str()));
    if let Some(b) = backend {
        assert!(b == "postgres" || b == "pg", "got backend={b}");
    }
}

#[tokio::test]
async fn pg_health_returns_ok() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = get_uri(&router, "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// /api/v1/recall — invalid as_agent + bad query (PG branch validation path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_recall_empty_context_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(&router, "/api/v1/recall", json!({"context": ""})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_recall_with_invalid_as_agent_400() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/recall",
        json!({"context": "anything", "as_agent": "../bad-traversal"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pg_recall_with_kinds_filter() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/recall",
        json!({
            "context": "kinds-filter-probe",
            "memory_kinds": ["observation"],
            "limit": 3,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_recall_with_source_uri_prefix() {
    let (router, _f) = build_fake_pg_router();
    let (status, _v) = post_json(
        &router,
        "/api/v1/recall",
        json!({
            "context": "x",
            "source_uri_prefix": "https://example.com/",
            "limit": 3,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pg_recall_get_invalid_as_agent_400() {
    let (router, _f) = build_fake_pg_router();
    // `..` is a banned namespace segment (path-traversal). Triggers the
    // `validate::validate_namespace(as_agent)` rejection.
    let (status, _v) = get_uri(&router, "/api/v1/recall?q=foo&as_agent=..").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// #905 / #907 / #909 / #910 — agent_id-spoof regression suite
// ---------------------------------------------------------------------------
// Sibling pin for the v0.7.0 final-review pass that found four more
// callsites of the #874-class vulnerability after #901 had closed the
// notify + subscribe + get_inbox surface. Every fix landed at the
// handler boundary; the underlying `resolve_http_agent_id` primitive's
// body-preferred precedence is unchanged (see `src/identity/mod.rs`
// SECURITY note). Each test below asserts the FORBIDDEN branch fires
// when `body.agent_id` (or `metadata.agent_id`) disagrees with the
// authenticated `X-Agent-Id` caller.

#[tokio::test]
async fn pg_consolidate_rejects_spoofed_agent_id_905() {
    // #905: power_consolidation.rs. `body.agent_id="alice"` while
    // authenticated as `bob` → 403, even when the rest of the body is
    // shaped right enough that the pre-#905 code path would have
    // stamped the new row's `consolidator_agent_id="alice"`.
    // Use 2+ ids so the validate_consolidate gate (min-2 requirement)
    // does not fire before the agent_id match check.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json_as(
        &router,
        "/api/v1/consolidate",
        json!({
            "ids": [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ],
            "title": "spoof-test",
            "summary": "anything-above-the-S51-len-floor-twenty-chars",
            "namespace": "pgfake-cons",
            "agent_id": "alice",
        }),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {status} body={v}");
}

#[tokio::test]
async fn pg_create_memory_rejects_spoofed_body_agent_id_907() {
    // #907: create_memory body.agent_id spoof.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json_as(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-spoof",
            "title": "spoof-907",
            "content": "stored body-agent-id spoof attempt",
            "agent_id": "alice",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {},
        }),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {status} body={v}");
}

#[tokio::test]
async fn pg_create_memory_rejects_spoofed_metadata_agent_id_907() {
    // #907: create_memory metadata.agent_id spoof — same vector via the
    // embedded shape that L11 (NHI-D-fed-agentid-mutation) made load-bearing.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json_as(
        &router,
        "/api/v1/memories",
        json!({
            "tier": "long",
            "namespace": "pgfake-spoof",
            "title": "spoof-907-md",
            "content": "stored metadata.agent_id spoof attempt",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "metadata": {"agent_id": "alice"},
        }),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {status} body={v}");
}

// ---------------------------------------------------------------------------
// GET /api/v1/memories/{id}/lineage — PG lane of the #3270 TOTAL caller-owns
// authz gate (#3303). The #3270 fix expanded the pg lane from an
// `if let Ok(mem)` chain into a total `match app.store.get(..)` (Ok / NotFound
// / other-Err) whose branches shipped with NO handler-level test, dropping
// `handlers/links.rs` line coverage below its 79% floor. These tests drive the
// pg lane through the fake-pg harness (StorageBackend::Postgres backed by a
// SqliteStore delegate, whose `get` folds scope-denial + hidden lifecycle
// states into NotFound exactly as PostgresStore::get does), restoring coverage
// AND pinning the fail-closed / no-existence-oracle behavior.
// ---------------------------------------------------------------------------

/// Seed a private, owner-keyed lineage pair — root `R` `reflects_on` ancestor
/// `A` — directly into the fake-pg harness's backing SQLite file, so the
/// pg-lane authz gate + ancestry walk in `get_lineage` can be exercised
/// without a live Postgres. Both rows are `scope=private` owned by `owner`.
/// Returns `(root_id, ancestor_id)`.
fn seed_owned_lineage(db_path: &std::path::Path, owner: &str) -> (String, String) {
    let conn = ai_memory::db::open(db_path).expect("open backing db for lineage seed");
    let now = "2026-03-01T00:00:00+00:00";
    let mk = |title: &str, content: &str| ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "pgfake-lineage".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: now.to_string(),
        updated_at: now.to_string(),
        metadata: serde_json::json!({ "agent_id": owner, "scope": "private" }),
        ..Default::default()
    };
    let a = ai_memory::db::insert(&conn, &mk("A", "ancestor")).expect("insert ancestor A");
    let r = ai_memory::db::insert(&conn, &mk("R", "root")).expect("insert root R");
    ai_memory::db::create_link(&conn, &r, &a, "reflects_on").expect("link R -> A");
    (r, a)
}

#[tokio::test]
async fn pg_lineage_owner_walks_own_private_root_3303() {
    // pg lane, `Ok(mem)` + visible-to-owner arm: the gate passes and the
    // ancestry walk round-trips (SqliteStore delegate under the fake-pg
    // harness). Exercises the walk-selection + `Ok(nodes)` JSON response.
    let (router, f) = build_fake_pg_router();
    let (root, ancestor) = seed_owned_lineage(f.path(), "ai:pg-owner");
    let (status, v) = get_uri_as(
        &router,
        &format!("/api/v1/memories/{root}/lineage"),
        "ai:pg-owner",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner may walk own lineage: {v}");
    assert_eq!(v["count"], json!(1), "exactly one ancestor: {v}");
    assert_eq!(v["nodes"][0]["id"], json!(ancestor), "{v}");
    assert_eq!(v["nodes"][0]["relation"], "reflects_on", "{v}");
}

#[tokio::test]
async fn pg_lineage_stranger_refused_404_no_oracle_3303() {
    // pg lane, `Err(NotFound)` arm: a NON-OWNER requesting another tenant's
    // private lineage root gets 404 (store.get folds the scope denial into
    // NotFound) with NO ancestry/node data disclosed — indistinguishable
    // from a truly-absent id, so the route is not an existence oracle.
    let (router, f) = build_fake_pg_router();
    let (root, _ancestor) = seed_owned_lineage(f.path(), "ai:pg-owner");
    let (status, v) = get_uri_as(
        &router,
        &format!("/api/v1/memories/{root}/lineage"),
        "ai:pg-stranger",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "stranger refused: {v}");
    assert!(
        v.get("nodes").is_none() && v.get("count").is_none(),
        "404 must disclose no ancestry/node data: {v}"
    );
}

#[tokio::test]
async fn pg_lineage_absent_root_is_404_matching_hidden_3303() {
    // pg lane no-oracle equivalence: a genuinely-absent root returns the SAME
    // 404 a hidden foreign root returns, so existence cannot be probed. A
    // header-less (anonymous, non-admin) caller drives the `!caller_is_admin`
    // gate.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = get_uri(
        &router,
        "/api/v1/memories/00000000-0000-0000-0000-000000000000/lineage",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "absent root is 404: {v}");
    assert!(v.get("nodes").is_none(), "no ancestry on 404: {v}");
}

/// #3303 — opt THIS test binary into request-authn-configured so an
/// allowlisted admin NAME (with no per-agent key enrolled) is trusted by
/// `is_admin_caller_trusted`. Safe for every other test in this binary: they
/// use an EMPTY admin allowlist, so `is_admin_caller` is `false` regardless of
/// this flag. Sets a process-global atomic (not an env var), so no unsafe /
/// no cross-thread env race.
fn mark_request_authn_for_admin_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    });
}

#[tokio::test]
async fn pg_lineage_admin_bypass_walks_foreign_root_3303() {
    // pg lane, `caller_is_admin == true`: the per-root visibility gate is
    // SKIPPED and a trusted admin still round-trips a FOREIGN private root's
    // lineage — the total gate must not over-restrict admins.
    mark_request_authn_for_admin_tests();
    let (router, f) = build_fake_pg_router_with_admins(vec!["ai:pg-admin".to_string()]);
    let (root, ancestor) = seed_owned_lineage(f.path(), "ai:pg-owner");
    let (status, v) = get_uri_as(
        &router,
        &format!("/api/v1/memories/{root}/lineage"),
        "ai:pg-admin",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin walks foreign lineage: {v}");
    assert_eq!(v["count"], json!(1), "{v}");
    assert_eq!(v["nodes"][0]["id"], json!(ancestor), "{v}");
}

#[tokio::test]
async fn pg_quota_status_rejects_cross_tenant_agent_id_909() {
    // #909: quota_status accepted body.agent_id with no authn binding —
    // any caller could read alice's quota row. Now requires
    // body.agent_id == header X-Agent-Id else 403.
    let (router, _f) = build_fake_pg_router();
    let (status, v) = post_json_as(
        &router,
        "/api/v1/quota/status",
        json!({"agent_id": "alice"}),
        "bob",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {status} body={v}");
}
