// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov3 — postgres-router coverage for the federation/kg/recall/misc HTTP
//! handlers' `StorageBackend::Postgres` branches. Drives the production
//! router (`ai_memory::build_router`) backed by a live `PostgresStore`
//! via `tower::oneshot`, so the postgres SAL-dispatch arms in
//! `handlers/{kg,links,recall,route_1111}` and the postgres
//! `sync_push_via_store` path in `handlers/federation_signing_check`
//! execute end-to-end.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.
//! Without the env var every test prints a skip line and returns.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

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

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn pg_router(url: &str) -> axum::Router {
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
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
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
        admin_agent_ids: Arc::new(vec!["ai:cov3-pg".to_string()]),
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

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:cov3-pg")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", "ai:cov3-pg")
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

/// A unique namespace per test run so concurrent runs against the
/// shared scratch DB don't collide.
fn uniq_ns() -> String {
    format!("cov3pg-{}", &uuid::Uuid::new_v4().to_string()[..8])
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

/// Serializes the federation tests that mutate the process-global
/// `REQUIRE_SIG_ENV` / `TRUST_BODY_AGENT_ID_ENV` env vars. cargo runs
/// `#[tokio::test]`s in this binary concurrently, so without this guard
/// one test's `remove_var` clobbers another's `set_var` mid-request,
/// flipping the signature gate back on and yielding a spurious 403.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// recall — postgres hybrid/keyword branch
// ---------------------------------------------------------------------------

pg_test!(pg_recall_get_keyword_branch, url, {
    let r = pg_router(&url).await;
    let (status, body) = get(&r, "/api/v1/recall?context=anything&limit=5").await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["storage_backend"], "postgres");
    assert_eq!(body["mode"], "keyword");
});

pg_test!(pg_recall_post_with_filters, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let (status, _b) = post_json(
        &r,
        "/api/v1/recall",
        json!({
            "context": "pipeline status",
            "namespace": ns,
            "limit": 8,
            "budget_tokens": 400,
            "tags": "alpha,beta",
            "since": "2020-01-01T00:00:00Z",
            "until": "2030-01-01T00:00:00Z",
            "session_id": "s-pg",
            "kinds": ["observation"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
});

// ---------------------------------------------------------------------------
// kg — postgres branches (entity register/by_alias, query, timeline,
// invalidate, find_paths)
// ---------------------------------------------------------------------------

pg_test!(pg_entity_register_and_by_alias, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "Acme PG", "namespace": ns, "aliases": ["AcmePG"], "agent_id": "ai:cov3-pg"}),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED || status == StatusCode::ACCEPTED,
        "register status={status}"
    );
    // by_alias on the postgres trait path.
    let (s2, _b2) = get(
        &r,
        &format!("/api/v1/entities/by_alias?alias=AcmePG&namespace={ns}"),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
});

pg_test!(pg_entity_register_invalid_name_is_400, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "", "namespace": "alpha"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

pg_test!(pg_kg_query_valid_source, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(&r, "/api/v1/kg/query", json!({"source_id": "anchor-pg-1"})).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
        "status={status}"
    );
});

pg_test!(pg_kg_timeline_nonexistent_source, url, {
    let r = pg_router(&url).await;
    let (status, _b) = get(&r, "/api/v1/kg/timeline?source_id=anchor-pg-2&limit=5").await;
    // Source not found → 404 (the postgres get→NotFound arm).
    assert_eq!(status, StatusCode::NOT_FOUND);
});

pg_test!(pg_kg_invalidate_arm, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/kg/invalidate",
        json!({"source_id": "src-pg-1", "target_id": "tgt-pg-1", "relation": "related_to"}),
    )
    .await;
    assert!(
        status == StatusCode::OK
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::BAD_REQUEST,
        "status={status}"
    );
});

pg_test!(pg_kg_find_paths_arm, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(
        &r,
        "/api/v1/find_paths",
        json!({"source_id": "src-pg-1", "target_id": "tgt-pg-1", "max_depth": 3}),
    )
    .await;
    // find_paths over AGE may be 501 when the graph extension is not
    // active on the scratch DB — all three are covered handler arms.
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_IMPLEMENTED,
        "status={status}"
    );
});

// ---------------------------------------------------------------------------
// links — postgres branches (create signed, get_links, verify)
// ---------------------------------------------------------------------------

pg_test!(pg_link_create_and_get_links, url, {
    let r = pg_router(&url).await;
    let ns = uniq_ns();
    // Seed two memories so the link endpoints have real anchors.
    let mk = |title: &str| json!({"title": title, "content": "cov3 pg link anchor", "namespace": ns, "agent_id": "ai:cov3-pg"});
    let (cs1, b1) = post_json(&r, "/api/v1/memories", mk("cov3-pg-src")).await;
    let (cs2, b2) = post_json(&r, "/api/v1/memories", mk("cov3-pg-tgt")).await;
    assert!(
        cs1.is_success() && cs2.is_success(),
        "seed memories: {cs1} {cs2}"
    );
    let src = b1["id"].as_str().unwrap_or("cov3-pg-src").to_string();
    let tgt = b2["id"].as_str().unwrap_or("cov3-pg-tgt").to_string();

    let (ls, _lb) = post_json(
        &r,
        "/api/v1/links",
        json!({"source_id": src, "target_id": tgt, "relation": "related_to"}),
    )
    .await;
    assert!(
        ls.is_success() || ls == StatusCode::CONFLICT,
        "create_link status={ls}"
    );

    // get_links postgres trait branch (admin caller bypasses filter).
    let (gs, gbody) = get(&r, &format!("/api/v1/links/{src}")).await;
    assert_eq!(gs, StatusCode::OK);
    assert!(gbody.get("links").is_some());
});

pg_test!(pg_link_verify_missing_args_is_400, url, {
    let r = pg_router(&url).await;
    let (status, _b) = post_json(&r, "/api/v1/links/verify", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
});

pg_test!(pg_link_verify_nonexistent_arm, url, {
    let r = pg_router(&url).await;
    // Valid args but no such link → the postgres verify_link trait arm
    // (NotFound → store_err_to_response).
    let (status, _b) = post_json(
        &r,
        "/api/v1/links/verify",
        json!({"source_id": "ghost-src", "target_id": "ghost-tgt"}),
    )
    .await;
    assert!(
        status == StatusCode::NOT_FOUND
            || status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST,
        "status={status}"
    );
});

// ---------------------------------------------------------------------------
// federation_signing_check — postgres sync_push_via_store path
// ---------------------------------------------------------------------------

pg_test!(pg_sync_push_via_store_invalid_sender_rejected, url, {
    let _env_guard = FED_ENV_LOCK.lock().await;
    // REQUIRE_SIG=0 so we skip the sig gate; TRUST_BODY so the
    // attestation gate trusts the body sender and we reach the postgres
    // sync_push_via_store entry where validate_agent_id fires.
    // SAFETY: the test owns this process's env for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "sender_agent_id": "bad id with spaces",
                "sender_clock": {"entries": {}},
                "memories": []
            }))
            .unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    // An invalid sender_agent_id is rejected — 400 from
    // sync_push_via_store's validate_agent_id, or 403 if the
    // attestation gate refuses first. Both are covered refusal arms.
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "invalid sender_agent_id must be rejected on pg path; status={status}"
    );
});

pg_test!(pg_sync_push_via_store_empty_batch_ok, url, {
    let _env_guard = FED_ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "sender_agent_id": "ai:cov3-pg-peer",
                "sender_clock": {"entries": {}},
                "memories": []
            }))
            .unwrap(),
        ))
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    // Empty batch through the postgres store path acks cleanly.
    assert!(status.is_success(), "empty pg sync_push status={status}");
});
