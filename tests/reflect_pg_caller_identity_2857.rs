// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2857 — `POST /api/v1/memory_reflect` on a POSTGRES-backed daemon must
//! find a source memory that `GET /api/v1/memories/{id}` returns 200 for.
//!
//! ## The bug
//!
//! The postgres SAL branch of `handle_reflect_http`
//! (`src/handlers/route_1111.rs`) resolved the caller identity through
//! `parse_reflect_input`, which reads the caller `agent_id` from the request
//! BODY only and IGNORES the `X-Agent-Id` header. Source existence is then
//! checked through the SAL `MemoryStore::get` scope=private visibility gate,
//! keyed on the `CallerContext` principal. GET-by-id, recall, and store all
//! resolve the caller HEADER-AUTHORITATIVELY (`resolve_http_agent_id`), so a
//! memory written and GET-able under `X-Agent-Id: <owner>` (no body
//! `agent_id`) was INVISIBLE to reflect — its source lookup ran under the
//! host/anonymous default principal instead of `<owner>` — producing a
//! spurious `400 "source memory not found"` for a memory that demonstrably
//! exists. That is the #2792/#2793 owner-scoping-mismatch class for the
//! reflect surface.
//!
//! ## The fix + what this test pins
//!
//! Reflect now resolves the caller header-authoritatively when an
//! `X-Agent-Id` header is present (the `resolve_caller_agent_id` parity
//! helper, matching GET/recall/store), so the source lookup and the
//! reflection authorship use the SAME principal the memory was written
//! under. The body `agent_id` stays a refinement that MUST match the header
//! (#2140 forge protection preserved). The regression asserts:
//!
//!   1. GET-by-id returns 200 for a private source owned by `alice`
//!      (X-Agent-Id: alice).
//!   2. reflect over that source, header-only (no body `agent_id`),
//!      SUCCEEDS (200) — the fix. Pre-fix this was a false 400.
//!   3. reflect STILL correctly refuses a caller who cannot see the source
//!      (X-Agent-Id: bob) with the honest `source memory not found`.
//!
//! ## Gating
//!
//! `#[ignore]` + `sal-postgres`; run locally with:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://... \
//!   cargo test --features sal-postgres --test reflect_pg_caller_identity_2857 \
//!   -- --include-ignored --test-threads=1
//! ```

#![cfg(feature = "sal-postgres")]

mod common;

use std::sync::Arc;

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::postgres_env::PostgresTestEnv;
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// A private (default-scope) memory owned by `owner` in `ns`.
fn owned_private(owner: &str, ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("source body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2857".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        // No `scope` key → defaults to private → visible ONLY to `owner`.
        metadata: json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn build_pg_router(url_store: Arc<dyn MemoryStore>) -> axum::Router {
    // A throwaway sqlite handle satisfies the `Db` field; the postgres
    // branch of every touched handler dispatches through `app.store`.
    let sqlite_dir = tempfile::tempdir().expect("tempdir");
    let sqlite_path = sqlite_dir.path().join("reflect-2857-http.db");
    // Keep the dir alive for the process lifetime (leak is fine in a test).
    std::mem::forget(sqlite_dir);
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        ai_memory::db::open(&sqlite_path).expect("sqlite open"),
        sqlite_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let app_state = ai_memory::handlers::AppState {
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
        storage_backend: ai_memory::handlers::StorageBackend::Postgres,
        store: url_store,
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
        admin_agent_ids: Arc::new(Vec::new()),
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
    ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app_state,
    )
}

/// GET `/api/v1/memories/{id}` as `agent_id`; returns (status, body).
async fn get_as(router: &axum::Router, id: &str, agent_id: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/memories/{id}"))
                .header("x-agent-id", agent_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// POST `/api/v1/memory_reflect` as `agent_id` (header only) with `body`.
async fn reflect_as(router: &axum::Router, agent_id: &str, body: Value) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/memory_reflect")
                .header("content-type", "application/json")
                .header("x-agent-id", agent_id)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn reflect_finds_get_visible_pg_source_2857() {
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("reflect_2857").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");

    // Seed a PRIVATE source memory owned by `alice`, mirroring an
    // `X-Agent-Id: alice` HTTP write (the store-side identity `alice`).
    let ns = "reflect-2857-ns";
    let source = owned_private("alice", ns, "reflect 2857 source");
    let ctx_alice = CallerContext::for_agent("alice");
    let source_id = store.store(&ctx_alice, &source).await.expect("seed source");

    let store_arc: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(env.url())
            .await
            .expect("connect http store"),
    );
    let router = build_pg_router(store_arc);

    // (1) The source demonstrably EXISTS + is visible to alice via GET.
    let (get_status, get_body) = get_as(&router, &source_id, "alice").await;
    assert_eq!(
        get_status,
        StatusCode::OK,
        "GET-by-id must 200 for alice's own private source; body={get_body}"
    );

    // (2) THE FIX: reflect over that source, HEADER-ONLY (no body agent_id),
    //     as alice must SUCCEED. Pre-#2857 this was a false 400
    //     "source memory not found" because the source lookup ran under the
    //     host/anonymous principal instead of alice.
    let (r_status, r_body) = reflect_as(
        &router,
        "alice",
        json!({
            "source_ids": [source_id],
            "title": "reflection 2857",
            "content": "a reflection over alice's source",
            "namespace": ns,
        }),
    )
    .await;
    assert_eq!(
        r_status,
        StatusCode::OK,
        "#2857: reflect (header-only) must find alice's GET-visible source; body={r_body}"
    );
    let reflection_id = r_body["id"].as_str().expect("reflection id");
    // The reflect envelope keys the source edges under the `reflects_on`
    // relation (the `MemoryLinkRelation::ReflectsOn` wire value).
    let reflects_on = r_body["reflects_on"].as_array().expect("reflects_on array");
    assert!(
        reflects_on
            .iter()
            .any(|v| v.as_str() == Some(source_id.as_str())),
        "reflection must reflect_on the source; body={r_body}"
    );

    // The reflection is AUTHORED as the header-resolved caller (alice),
    // consistent with how store/GET resolve identity.
    let (rget_status, rget_body) = get_as(&router, reflection_id, "alice").await;
    assert_eq!(
        rget_status,
        StatusCode::OK,
        "reflection must be readable by alice"
    );
    assert_eq!(
        rget_body["memory"]["metadata"]["agent_id"], "alice",
        "reflection authorship must be the header-resolved caller (alice); body={rget_body}"
    );

    // (3) DEGRADE-not-corrupt: reflect STILL correctly refuses a caller who
    //     cannot see the source. Bob is not the owner of alice's private row,
    //     so the source is genuinely invisible to him → honest 400.
    let (bob_status, bob_body) = reflect_as(
        &router,
        "bob",
        json!({
            "source_ids": [source_id],
            "title": "bob reflection 2857",
            "content": "bob cannot see alice's private source",
            "namespace": ns,
        }),
    )
    .await;
    assert_eq!(
        bob_status,
        StatusCode::BAD_REQUEST,
        "#2857: reflect must still refuse a caller who cannot see the source; body={bob_body}"
    );
    assert!(
        bob_body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("source memory not found"),
        "refusal must be the honest source-not-found; body={bob_body}"
    );
}
