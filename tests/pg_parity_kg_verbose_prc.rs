// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PR-C pg-parity remediation (5-agent vote `4d3ea1c5`, Option B+) —
//! cross-backend regression harness for the two integrity-cheap parity
//! fixes:
//!
//! 1. **`kg_backend` capabilities wiring.** `/api/v1/capabilities` now
//!    surfaces the live knowledge-graph traversal backend resolved from
//!    the SAL store (`cte` on sqlite / a non-AGE postgres, `age` on an
//!    AGE-enabled postgres) instead of the config-construction default
//!    `kg_backend: None` (field omitted). The `MemoryStore::kg_backend`
//!    default is `Cte`; `PostgresStore` overrides it with its
//!    connect-time detection.
//!
//! 2. **verbose-recall `latest_link_attest_level` parity.** The postgres
//!    `Accept-Provenance: verbose` recall envelope now carries the
//!    `latest_link_attest_level` decoration (the strongest incident-edge
//!    attestation per row), matching the sqlite `decorate_memory_many`
//!    path. Powered by the new SAL `MemoryStore::latest_link_attest_levels`
//!    method (sqlite delegates to the recall decorator free-fn; postgres
//!    runs one batched `memory_links` scan + the shared best-of ranking).
//!
//! The sqlite half is always-on (default sqlite adapter under `sal`); the
//! postgres half is `#[ignore]`d + gated on `AI_MEMORY_TEST_POSTGRES_URL`
//! (Track C blocker per issue #79), but COMPILES under `sal-postgres` so a
//! future runner picks up zero-friction coverage. Run the pg half with:
//! `AI_MEMORY_TEST_POSTGRES_URL=… cargo test --test pg_parity_kg_verbose_prc \
//!  --features sal-postgres -- --ignored --test-threads=1`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation};
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

fn sample_memory(id: &str, ns: &str, content: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ns.to_string(),
        title: format!("title-{id}"),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        // Own the row by the HTTP recall caller AND mark it `collective` so
        // the read-path visibility filter (`is_visible_to_caller`) never
        // drops it — otherwise the verbose-recall cell recalls as the caller
        // `ai:prc-parity` and a no-owner / default-private row would be
        // hidden, yielding an empty result unrelated to the decoration under
        // test.
        metadata: serde_json::json!({ "agent_id": "ai:prc-parity", "scope": "collective" }),
        memory_kind: ai_memory::models::MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn unsigned_link(source: &str, target: &str) -> MemoryLink {
    MemoryLink {
        source_id: source.to_string(),
        target_id: target.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        // `link()` ALWAYS persists `attest_level = "unsigned"` regardless of
        // this field (see the `MemoryStore::link` contract), which is exactly
        // the non-null incident-edge attestation the decoration surfaces.
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Build the production router over an arbitrary [`MemoryStore`] so the
/// live `/api/v1/capabilities` + `/api/v1/recall` handler branches execute
/// end-to-end. Mirrors `tests/cov3_handlers_postgres.rs::pg_router`.
fn build_test_router(
    store: Arc<dyn MemoryStore>,
    backend: ai_memory::handlers::StorageBackend,
) -> axum::Router {
    // `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` — the v1.0.0 HTTP-direct default
    // is REQUIRED and would reject this suite's unsigned fixtures; but this
    // harness never issues an HTTP store (it seeds via the SAL store), so no
    // env write is needed here.
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: ai_memory::handlers::Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
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
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["ai:prc-parity".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn get_json(router: &axum::Router, uri: &str) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt as _;
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", "ai:prc-parity")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[cfg(feature = "sal-postgres")]
async fn recall_verbose(
    router: &axum::Router,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt as _;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/recall")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:prc-parity")
        // The v0.7.x (#1155) HTTP negotiation surface — opt in to the Gap-7
        // verbose provenance envelope that carries `latest_link_attest_level`.
        .header("accept-provenance", "verbose")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

// ===========================================================================
// SQLite half — always runs under `sal` (the reference adapter).
// ===========================================================================

#[tokio::test]
async fn sqlite_kg_backend_default_is_cte() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path().join("m.db"))
        .expect("open SqliteStore");
    // The SqliteStore inherits the `MemoryStore::kg_backend` default: every
    // sqlite deployment traverses `memory_links` via recursive CTE.
    assert_eq!(MemoryStore::kg_backend(&store), KgBackend::Cte);
    assert_eq!(MemoryStore::kg_backend(&store).as_str(), "cte");
}

#[tokio::test]
async fn sqlite_latest_link_attest_levels_returns_unsigned_for_linked_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path().join("m.db"))
        .expect("open SqliteStore");
    let ctx = CallerContext::for_agent("ai:prc-parity");

    let a = sample_memory("sq-a", "prc/sqlite", "zebra pipeline widget parity alpha");
    let b = sample_memory("sq-b", "prc/sqlite", "zebra pipeline widget parity beta");
    store.store(&ctx, &a).await.expect("store a");
    store.store(&ctx, &b).await.expect("store b");
    store
        .link(&ctx, &unsigned_link("sq-a", "sq-b"))
        .await
        .expect("link");

    let map = store
        .latest_link_attest_levels(&["sq-a", "sq-b"])
        .await
        .expect("latest_link_attest_levels");
    // `link()` persists `attest_level = "unsigned"`; both endpoints of the
    // incident edge resolve to that level.
    assert_eq!(map.get("sq-a").map(String::as_str), Some("unsigned"));
    assert_eq!(map.get("sq-b").map(String::as_str), Some("unsigned"));

    // An unlinked id is ABSENT from the map (the free-fn contract).
    let empty = store
        .latest_link_attest_levels(&["sq-nonexistent"])
        .await
        .expect("latest_link_attest_levels empty");
    assert!(!empty.contains_key("sq-nonexistent"));
}

#[tokio::test]
async fn sqlite_capabilities_http_reports_kg_backend_cte() {
    let tmp = tempfile::tempdir().unwrap();
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(tmp.path().join("m.db"))
            .expect("open SqliteStore"),
    );
    let router = build_test_router(store, ai_memory::handlers::StorageBackend::Sqlite);
    let (status, body) = get_json(&router, "/api/v1/capabilities").await;
    assert_eq!(status, axum::http::StatusCode::OK, "body={body}");
    // Pre-PR-C this field was OMITTED (config-construction default None +
    // skip_serializing_if). Now always emitted, and on sqlite it is `cte`.
    assert_eq!(
        body["kg_backend"], "cte",
        "sqlite capabilities must report the recursive-CTE KG backend; body={body}"
    );
}

// ===========================================================================
// Postgres half — gated on `sal-postgres` + AI_MEMORY_TEST_POSTGRES_URL.
// ===========================================================================

#[cfg(feature = "sal-postgres")]
async fn live_pg() -> Option<ai_memory::store::postgres::PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "SKIP pg parity: PostgresStore::connect failed: {e} \
                 (Track C blocker per issue #79)"
            );
            None
        }
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn pg_capabilities_http_reports_kg_backend() {
    let Some(pg) = live_pg().await else { return };
    let expected = MemoryStore::kg_backend(&pg).as_str().to_string();
    assert!(
        expected == "age" || expected == "cte",
        "pg kg_backend must be age|cte, got {expected}"
    );
    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    let router = build_test_router(store, ai_memory::handlers::StorageBackend::Postgres);
    let (status, body) = get_json(&router, "/api/v1/capabilities").await;
    assert_eq!(status, axum::http::StatusCode::OK, "body={body}");
    // The live daemon reports the SAL store's connect-time posture — `age`
    // when the `age` extension is installed, else `cte`. Never omitted.
    assert_eq!(
        body["kg_backend"], expected,
        "pg capabilities kg_backend must match the store's connect-time backend; body={body}"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn pg_latest_link_attest_levels_sal() {
    let Some(pg) = live_pg().await else { return };
    let ctx = CallerContext::for_agent("ai:prc-parity");
    let ns = format!("prc/pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let a = format!("pg-a-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let b = format!("pg-b-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    pg.store(
        &ctx,
        &sample_memory(&a, &ns, "orange satellite compass parity alpha"),
    )
    .await
    .expect("store a");
    pg.store(
        &ctx,
        &sample_memory(&b, &ns, "orange satellite compass parity beta"),
    )
    .await
    .expect("store b");
    pg.link(&ctx, &unsigned_link(&a, &b)).await.expect("link");

    let map = pg
        .latest_link_attest_levels(&[a.as_str(), b.as_str()])
        .await
        .expect("pg latest_link_attest_levels");
    assert_eq!(map.get(&a).map(String::as_str), Some("unsigned"));
    assert_eq!(map.get(&b).map(String::as_str), Some("unsigned"));
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
async fn pg_verbose_recall_carries_latest_link_attest_level() {
    let Some(pg) = live_pg().await else { return };
    let ctx = CallerContext::for_agent("ai:prc-parity");
    let ns = format!("prc/pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let a = format!("pg-r-a-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let b = format!("pg-r-b-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    // Real-word FTS tokens (postgres `to_tsvector('english', …)` indexes
    // these as stable lexemes — unlike a made-up alnum token that
    // `plainto_tsquery` can normalise away). The UNIQUE namespace filter
    // isolates the recall to exactly this pair on the shared test DB, so a
    // common query word is safe.
    pg.store(
        &ctx,
        &sample_memory(&a, &ns, "zephyr narwhal ledger parity alpha"),
    )
    .await
    .expect("store a");
    pg.store(
        &ctx,
        &sample_memory(&b, &ns, "zephyr narwhal ledger parity beta"),
    )
    .await
    .expect("store b");
    pg.link(&ctx, &unsigned_link(&a, &b)).await.expect("link");

    let store: Arc<dyn MemoryStore> = Arc::new(pg);
    let router = build_test_router(store, ai_memory::handlers::StorageBackend::Postgres);
    let (status, body) = recall_verbose(
        &router,
        serde_json::json!({ "context": "zephyr narwhal", "namespace": ns, "limit": 10 }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "body={body}");
    let mems = body["memories"].as_array().expect("memories array");
    assert!(
        !mems.is_empty(),
        "verbose recall returned no rows; body={body}"
    );
    // At least one recalled row (the linked pair) must carry the
    // `latest_link_attest_level` decoration — the exact field the sqlite
    // path emits via `decorate_memory_many`. Pre-PR-C the pg branch DROPPED
    // it (shipping a bare envelope + a not-yet-implemented log line).
    let decorated = mems
        .iter()
        .any(|m| (m["id"] == a || m["id"] == b) && m["latest_link_attest_level"] == "unsigned");
    assert!(
        decorated,
        "pg verbose recall must carry latest_link_attest_level=unsigned on the linked pair; body={body}"
    );
}
