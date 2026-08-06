// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_lazy_continuation, clippy::too_many_lines)]
//! #2613 — `find_paths` on a postgres-AGE daemon is served by the
//! relational recursive-CTE, NOT an AGE Cypher traversal.
//!
//! ## History (why this file used to assert something false)
//!
//! This file was `g5_find_paths_cypher_no_syntax_error.rs`, a v0.7.0.1
//! reproducer that a live-AGE `find_paths` must not surface the Cypher
//! `syntax error at or near "|"` / `"("` that AGE's parser raised on the
//! list-comprehension / `ALL(...)` shapes. Those shapes were never
//! parseable on the SSOT-pinned AGE 1.7 at all, so #2582 routed
//! `find_paths` to the relational recursive-CTE UNCONDITIONALLY on both
//! `KgBackend` values, and #2613 DELETED the unreachable AGE
//! `find_paths_cypher` reader + its builder. The old filename now asserts
//! a falsehood (there is no Cypher `find_paths` to keep syntactically
//! clean), so it is renamed and repurposed into the regression that
//! belongs here: proving `find_paths` on an AGE deployment resolves via
//! the CTE and returns correct paths, with no AGE traversal invoked.
//!
//! ## What this test asserts
//!
//! 1. Boot an in-process HTTP daemon backed by [`PostgresStore`] against
//!    a database with Apache AGE enabled (so the SAL dispatcher's
//!    `kg_backend = Age` branch resolves — even though `find_paths` no
//!    longer dispatches to it).
//! 2. Seed a chain A→B→C→D→E through `POST /api/v1/memories`
//!    + `POST /api/v1/links` — same wire shape S65 uses; the relational
//!    `memory_links` rows the CTE walks are in place by the time
//!    `find_paths` runs.
//! 3. POST `{source_id, target_id, max_depth}` to
//!    `/api/v1/kg/find_paths` and assert a 200 with a non-empty `paths`
//!    array whose shortest path spans the chain. On an AGE deployment
//!    this proves the CTE serves `find_paths` correctly (pre-#2582 the
//!    AGE branch surfaced a 503 with the `"|"` syntax-error wire shape).
//!
//! ## Gating
//!
//! Same as `g4_postgres_link_projects_into_age_graph.rs` —
//! `feature = "sal-postgres"` plus `AI_MEMORY_TEST_AGE_URL`
//! (or `AI_MEMORY_TEST_POSTGRES_URL` — fallback) must point at a
//! database with the `age` extension. Without either, the test prints
//! a skip line and returns cleanly.

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, wait_for_http_ready};

/// AGE-or-Postgres URL fallback — sibling of g2/g4; differs from
/// `common::age_url` because `find_paths` is tested against whatever
/// Postgres (AGE-enabled) is available.
fn age_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

async fn build_postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let path = std::path::PathBuf::from(":memory:");
    let db: Db = Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    );
    AppState {
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
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),

        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

async fn spawn_daemon(
    url: &str,
) -> (
    String,
    Arc<Notify>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let app_state = build_postgres_app_state(url).await;
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_daemon = shutdown.clone();
    let addr_for_daemon = addr.clone();
    let handle = tokio::spawn(async move {
        ai_memory::daemon_runtime::serve_http_with_shutdown(
            &addr_for_daemon,
            api_key_state,
            app_state,
            shutdown_for_daemon,
        )
        .await
    });
    // #1194: progress-detecting health-check loop with 5 min generous
    // overall timeout. See `tests/common::wait_for_http_ready`.
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("postgres-backed serve never became ready");
    (format!("http://{addr}"), shutdown, handle)
}

/// Stable agent id — see g4 fix for full rationale. Required so the
/// #910 SAL-level visibility filter on `find_paths` doesn't drop the
/// seeded chain because per-request anonymous ids leave each memory
/// orphaned relative to the `find_paths` caller.
const G5_TEST_AGENT_ID: &str = "ai:g5-test";

async fn store_memory(
    client: &reqwest::Client,
    base: &str,
    namespace: &str,
    title: &str,
) -> String {
    let body = json!({
        "tier": "long",
        "namespace": namespace,
        "title": title,
        "content": format!("g5 reproducer node {title}"),
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "system",
    });
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .header("X-Agent-Id", G5_TEST_AGENT_ID)
        .json(&body)
        .send()
        .await
        .expect("store POST");
    assert!(
        resp.status().is_success(),
        "store should succeed: status={} body={:?}",
        resp.status(),
        resp.text().await.ok()
    );
    let v: Value = resp.json().await.expect("body");
    v["id"].as_str().expect("id").to_string()
}

/// #2613 — `POST /api/v1/kg/find_paths` over a 5-node chain must return a
/// 200 with a non-empty `paths` array on a postgres-AGE daemon, proving
/// `find_paths` is served by the relational recursive-CTE (no AGE Cypher
/// traversal is invoked). This deliberately runs against an AGE-installed
/// fixture (`kg_backend = Age`) so the assertion covers the AGE deployment
/// specifically — the honesty guarantee that a `KgBackend::Age` node still
/// gets correct, CTE-served path-finding.
#[tokio::test(flavor = "multi_thread")]
async fn g5_find_paths_cte_served_on_age() {
    let Some(url) = age_url() else {
        eprintln!(
            "skipping g5_find_paths_cte_served_on_age: \
             AI_MEMORY_TEST_AGE_URL / AI_MEMORY_TEST_POSTGRES_URL not set"
        );
        return;
    };

    // Probe the connection's `kg_backend`; this test only asserts the
    // AGE-installed shape (a CTE-only fixture has no `KgBackend::Age`
    // branch to prove find_paths is nonetheless CTE-served).
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    if !matches!(store.kg_backend(), ai_memory::store::KgBackend::Age) {
        eprintln!(
            "skipping g5_find_paths_cte_served_on_age: \
             kg_backend != Age (no AGE extension on this fixture)"
        );
        return;
    }
    drop(store);

    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();

    // Per-test namespace so concurrent runs against a shared scratch DB
    // don't reuse memory ids.
    let suffix = uuid::Uuid::new_v4();
    let ns = format!("g5-find-paths-cypher-{suffix}");

    // Build chain A→B→C→D→E in `memories` + `memory_links`. The G4 fix
    // mirrors each link write into the AGE `memory_graph` projection so
    // the corpus is in place by the time `find_paths` runs.
    let mut ids = Vec::new();
    for label in ["A", "B", "C", "D", "E"] {
        ids.push(store_memory(&client, &base, &ns, &format!("g5-{suffix}-{label}")).await);
    }
    for w in ids.windows(2) {
        let resp = client
            .post(format!("{base}/api/v1/links"))
            .header("X-Agent-Id", G5_TEST_AGENT_ID)
            .json(&json!({
                "source_id": w[0],
                "target_id": w[1],
                "relation": "related_to",
            }))
            .send()
            .await
            .expect("link POST");
        assert!(
            resp.status().is_success(),
            "link should succeed: status={} body={:?}",
            resp.status(),
            resp.text().await.ok()
        );
    }

    // Wire shape lifted from the live R1b reproducer:
    // `{source_id, target_id, max_depth: 3}` against the 4-hop chain.
    // depth=3 only covers an A→B→C→D path which is intentional — the
    // assertion is "no 503", not "every path is enumerated"; the longer
    // 4-hop A→…→E path stays out so we can prove the depth knob round-
    // trips the handler boundary as well as the CTE traversal.
    let resp = client
        .post(format!("{base}/api/v1/kg/find_paths"))
        .header("X-Agent-Id", G5_TEST_AGENT_ID)
        .json(&json!({
            "source_id": ids[0],
            "target_id": ids[3],
            "max_depth": 3,
            "max_results": 16,
        }))
        .send()
        .await
        .expect("find_paths POST");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({}));

    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "#2613: find_paths must return 200 from a postgres-AGE daemon \
         (served by the relational CTE, no AGE Cypher traversal) — \
         pre-#2582 the AGE branch surfaced 503 with `cypher find_paths: \
         syntax error at or near \"|\"`; got status={status} body={body}."
    );

    let paths = body["paths"].as_array().expect("paths must be an array");
    assert!(
        !paths.is_empty(),
        "#2613: find_paths must surface at least one path through the \
         A→B→C→D chain at max_depth=3 via the CTE; got empty: {body}"
    );

    // First (shortest) path should be the 4-node A→B→C→D chain.
    let first: Vec<&str> = paths[0]
        .as_array()
        .expect("path[0] is an array")
        .iter()
        .map(|v| v.as_str().expect("path[0] entries are strings"))
        .collect();
    assert_eq!(
        first.len(),
        4,
        "shortest path through A→B→C→D must be 4 nodes long: {first:?}"
    );
    assert_eq!(first[0], ids[0]);
    assert_eq!(first[3], ids[3]);

    // Second 200-pass over the full 4-hop chain (A→…→E at max_depth=7)
    // — same wire shape the R1b reproducer captured and the smoke a
    // 4-hop traversal at the published ceiling depth.
    let resp = client
        .post(format!("{base}/api/v1/kg/find_paths"))
        .header("X-Agent-Id", G5_TEST_AGENT_ID)
        .json(&json!({
            "source_id": ids[0],
            "target_id": ids[ids.len() - 1],
            "max_depth": 7,
            "max_results": 16,
        }))
        .send()
        .await
        .expect("find_paths POST (4-hop)");

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({}));
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "G5: find_paths must return 200 for the 4-hop chain at depth=7; \
         got status={status} body={body}"
    );
    let paths = body["paths"].as_array().expect("paths must be an array");
    assert!(
        !paths.is_empty(),
        "G5: find_paths must surface at least one 5-node path through \
         A→B→C→D→E at max_depth=7; got empty: {body}"
    );
    let first: Vec<&str> = paths[0]
        .as_array()
        .expect("path[0] is an array")
        .iter()
        .map(|v| v.as_str().expect("path[0] entries are strings"))
        .collect();
    assert_eq!(
        first.len(),
        5,
        "shortest path through A→B→C→D→E must be 5 nodes long: {first:?}"
    );
    assert_eq!(first[0], ids[0]);
    assert_eq!(first[4], ids[4]);

    shutdown.notify_one();
    let _ = handle.await;
}
