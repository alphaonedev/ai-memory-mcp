// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3423 — `POST /api/v1/memory_reflect` attributed the reflection to the
//! DAEMON HOST principal on sqlite and to the CALLER on postgres.
//!
//! ## The hole
//!
//! The handler resolved the caller header-authoritatively only INSIDE its
//! postgres branch (#2857). The sqlite branch handed the raw body to
//! `crate::mcp::handle_reflect`, whose owner resolution falls through
//! `identity::resolve_agent_id` to `host:<hostname>` when the body carries no
//! `agent_id`. So with `X-Agent-Id: ai:alice` and no body `agent_id`:
//!
//! - sqlite: `200 {id}`, row owned by `host:pop-os` → the caller's very next
//!   `GET /api/v1/memories/{id}` 404s on the owner gate and the row never
//!   lists. A write that reports success and is then unreachable by the only
//!   principal who asked for it.
//! - postgres: row owned by `ai:alice`, GET-able.
//!
//! Same request, same build, different owner depending on the backend.
//!
//! Separately, the `reflects_on` provenance edges landed `self_signed` on
//! sqlite (`db::create_link_signed` via `storage::reflect`) and `unsigned` on
//! postgres, whose `reflect_with_hooks` hardcoded `'unsigned'` and never read
//! `hooks.active_keypair` — despite its own trait-impl docstring claiming the
//! edges "land `self_signed`". A verifier walking a federated hive saw the same
//! logical edge as attested from one peer and unattested from another.
//!
//! ## The control
//!
//! One owner rule, `mcp::tools::reflect::resolve_reflect_owner`, reached by
//! BOTH parsers (`parse_reflect_input` for postgres, `handle_reflect_caller`
//! for sqlite). The HTTP handler resolves the authenticated caller ONCE, above
//! the backend branch, and passes it to whichever parser runs. An authenticated
//! transport principal bypasses the #3171 wire binding by design (see that
//! function's docs); `None` — every MCP/CLI caller, and the header-absent
//! #1317 body-only contract — is byte-identical to pre-#3423. The postgres edge
//! INSERT now signs with `hooks.active_keypair` over the same `SignableLink`
//! CBOR sqlite signs, stamped through #3422's canonical `created_at`.
//!
//! ## What this pins
//!
//! ALLOWED: the header caller owns the reflection and can read it back
//! (the regression proof — pre-fix this GET 404'd). DENIED: another principal
//! still cannot (the owner gate did not become permissive). Plus the
//! header-absent body-only contract, and edge attestation on both backends.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::store::MemoryStore;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

mod common;

const SHARED_KEY: &str = "shared-transport-key";
const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("reflect-owner-parity-3423");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Zero per-agent keys enrolled — the zero-config single-operator posture the
/// sweep ran against, where the #2140/#2156 body-binding block is INERT. That
/// is precisely the posture in which the sqlite branch never learned the
/// caller, so the regression is only reachable here.
fn build_router() -> (axum::Router, NamedTempFile, PathBuf) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let enrolled = Arc::new(HashMap::new());

    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
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
        // Deliberately NOT alice/bob: an admin carve-out would mask the owner
        // gate this test is asserting.
        admin_agent_ids: Arc::new(vec!["ai:operator".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: HttpIdentityMode::Advisory,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

fn req(method: &str, uri: &str, agent_id: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", SHARED_KEY);
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(v).expect("serialise body")))
            .expect("build request"),
        None => b.body(Body::empty()).expect("build request"),
    }
}

async fn call(router: &axum::Router, r: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(r).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Seed a source memory owned by `owner` through the real create route, so the
/// ownership stamp comes from the shipped #907 rule rather than a test fixture.
async fn seed_source(router: &axum::Router, owner: &str) -> String {
    let (status, v) = call(
        router,
        req(
            "POST",
            "/api/v1/memories",
            Some(owner),
            Some(&json!({
                "title": "reflect source",
                "content": "a source memory to reflect over",
                "namespace": "team/3423",
                "tier": "mid",
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "seed create failed: {v}");
    v["id"].as_str().expect("seeded id").to_string()
}

fn reflect_body(source_id: &str) -> Value {
    json!({
        "source_ids": [source_id],
        "title": "a reflection",
        "content": "a synthesised insight over the seeded source",
        "namespace": "team/3423",
    })
}

// ---------------------------------------------------------------------------
// sqlite — the reported repro
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqlite_reflect_is_owned_by_the_header_caller_and_readable_by_them() {
    // THE regression, allowed half. Pre-#3423 the reflect returned 200 with an
    // id and the follow-up GET 404'd, because the row was owned by
    // `host:<hostname>` instead of `ai:alice`.
    let _dir = fresh_dir();
    let (router, _f, _db) = build_router();
    let src = seed_source(&router, ALICE).await;

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/memory_reflect",
            Some(ALICE),
            Some(&reflect_body(&src)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reflect failed: {v}");
    let id = v["id"].as_str().expect("reflection id").to_string();

    let (status, got) = call(
        &router,
        req("GET", &format!("/api/v1/memories/{id}"), Some(ALICE), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the caller must be able to read back their own reflection: {got}"
    );
    assert_eq!(
        got["memory"]["metadata"]["agent_id"].as_str(),
        Some(ALICE),
        "the reflection must be owned by the authenticated caller, not the \
         daemon host principal: {got}"
    );
}

#[tokio::test]
async fn sqlite_reflect_is_not_readable_by_another_principal() {
    // DENIED half — the owner gate did not become permissive; only the OWNER
    // changed. Without this, "the caller can read it" could be satisfied by
    // simply making reflections world-readable.
    let _dir = fresh_dir();
    let (router, _f, _db) = build_router();
    let src = seed_source(&router, ALICE).await;

    let (status, v) = call(
        &router,
        req(
            "POST",
            "/api/v1/memory_reflect",
            Some(ALICE),
            Some(&reflect_body(&src)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reflect failed: {v}");
    let id = v["id"].as_str().expect("reflection id").to_string();

    let (status, got) = call(
        &router,
        req("GET", &format!("/api/v1/memories/{id}"), Some(BOB), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-owner must still be refused (no existence leak): {got}"
    );
}

#[tokio::test]
async fn sqlite_reflect_header_absent_keeps_the_body_only_contract() {
    // #1317 — with NO `X-Agent-Id` header the body-supplied `agent_id` is still
    // honoured verbatim. #3423 must not 403 a legitimate zero-config body-only
    // caller by forcing a synthesised anonymous principal on them.
    let _dir = fresh_dir();
    let (router, _f, _db) = build_router();
    let src = seed_source(&router, ALICE).await;

    let mut body = reflect_body(&src);
    body["agent_id"] = json!(ALICE);
    let (status, v) = call(
        &router,
        req("POST", "/api/v1/memory_reflect", None, Some(&body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body-only reflect must work: {v}");

    let id = v["id"].as_str().expect("reflection id").to_string();
    let (status, got) = call(
        &router,
        req("GET", &format!("/api/v1/memories/{id}"), Some(ALICE), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body-only owner reads back: {got}");
    assert_eq!(got["memory"]["metadata"]["agent_id"].as_str(), Some(ALICE));
}

// ---------------------------------------------------------------------------
// reflects_on edge attestation — sqlite baseline, postgres fix
// ---------------------------------------------------------------------------

/// The attest level of every `reflects_on` edge anchored at `id`.
fn sqlite_edge_attest_levels(db_path: &std::path::Path, id: &str) -> Vec<String> {
    let conn = ai_memory::db::open(db_path).expect("open for edge read");
    let mut stmt = conn
        .prepare(
            "SELECT attest_level FROM memory_links \
             WHERE source_id = ?1 AND relation = 'reflects_on'",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([id], |r| r.get::<_, String>(0))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

#[tokio::test]
async fn sqlite_reflect_edges_are_self_signed_when_a_keypair_is_active() {
    // The sqlite BASELINE the postgres path must now match. Driven through the
    // substrate primitive (the HTTP `AppState` above carries no keypair).
    let dir = fresh_dir();
    let db_path = dir.path().join("edges.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    common::permissive_attestation_for_tests();

    let src = {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: ai_memory::models::Tier::Mid,
            namespace: "team/3423".to_string(),
            title: "edge source".to_string(),
            content: "source for the edge-attestation check".to_string(),
            priority: 5,
            confidence: 1.0,
            source: "nhi".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({ "agent_id": ALICE }),
            memory_kind: ai_memory::models::MemoryKind::Observation,
            version: 1,
            ..ai_memory::models::Memory::default()
        };
        ai_memory::db::insert(&conn, &mem).expect("insert source")
    };

    let kp = ai_memory::identity::keypair::generate(ALICE).expect("generate keypair");
    let out = ai_memory::mcp::handle_reflect(
        &conn,
        &db_path,
        &json!({
            "source_ids": [src],
            "title": "signed-edge reflection",
            "content": "a reflection whose provenance edges must be attested",
            "namespace": "team/3423",
            "agent_id": ALICE,
        }),
        None,
        None,
        None,
        Some(&kp),
    )
    .expect("reflect ok");
    let id = out["id"].as_str().expect("reflection id");

    let levels = sqlite_edge_attest_levels(&db_path, id);
    assert!(
        !levels.is_empty(),
        "the reflect must write a reflects_on edge"
    );
    assert!(
        levels.iter().all(|l| l == "self_signed"),
        "sqlite reflects_on edges must be self_signed with an active keypair, got {levels:?}"
    );
}

// Gated on `sal-postgres`, not `sal`: `common::postgres_env` and
// `store::postgres` are themselves behind that feature, so a `--features sal`
// clippy/build leg must not see this body.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_reflect_edges_are_self_signed_when_a_keypair_is_active() {
    // THE #3423 attestation fix. Pre-fix `PostgresStore::reflect_with_hooks`
    // hardcoded `'unsigned'` in its `memory_links` INSERT and never read
    // `hooks.active_keypair`, so the identical request produced attested
    // provenance on sqlite and unattested provenance on postgres.
    let Some(_lock) = common::postgres_env::PublicSchemaLock::acquire() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (no live postgres tier)");
        return;
    };
    let url = common::postgres_url().expect("postgres url");
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    common::permissive_attestation_for_tests();

    let ns = format!("team/3423-{}", uuid::Uuid::new_v4().simple());
    let ctx = ai_memory::store::CallerContext::for_agent(ALICE);
    let now = chrono::Utc::now().to_rfc3339();
    let src = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: ns.clone(),
        title: "pg edge source".to_string(),
        content: "source for the postgres edge-attestation check".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": ALICE }),
        memory_kind: ai_memory::models::MemoryKind::Observation,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    store.store(&ctx, &src).await.expect("insert pg source");

    let kp = ai_memory::identity::keypair::generate(ALICE).expect("generate keypair");
    let input = ai_memory::db::ReflectInput {
        source_ids: vec![src.id.clone()],
        title: "signed-edge reflection".to_string(),
        content: "a reflection whose provenance edges must be attested".to_string(),
        namespace: Some(ns.clone()),
        tier: ai_memory::models::Tier::Mid,
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "nhi".to_string(),
        agent_id: ALICE.to_string(),
        metadata: json!({}),
    };
    // The TRAIT method is the keypair-carrying one (the inherent
    // `PostgresStore::reflect` takes no signing key), so disambiguate.
    let outcome = <ai_memory::store::postgres::PostgresStore as MemoryStore>::reflect(
        &store,
        &ctx,
        &input,
        Some(&kp),
    )
    .await
    .expect("pg reflect ok");

    let links = store
        .get_links_for_anchor(&outcome.id)
        .await
        .expect("read pg edges");
    let levels: Vec<String> = links
        .iter()
        .filter(|l| {
            l.source_id == outcome.id
                && l.relation == ai_memory::models::MemoryLinkRelation::ReflectsOn
        })
        // `attest_level` is `Option<String>` on the model; a `None` here would
        // itself be a parity defect, so surface it as the literal "absent"
        // rather than silently dropping the edge from the assertion.
        .map(|l| {
            l.attest_level
                .clone()
                .unwrap_or_else(|| "absent".to_string())
        })
        .collect();
    assert!(
        !levels.is_empty(),
        "the pg reflect must write a reflects_on edge"
    );
    assert!(
        levels.iter().all(|l| l == "self_signed"),
        "postgres reflects_on edges must be self_signed with an active keypair \
         (sqlite parity), got {levels:?}"
    );
}
