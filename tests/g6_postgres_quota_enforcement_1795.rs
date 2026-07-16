// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::items_after_statements)]
//! #1795 (5-agent vote 4d3ea1c5) — PostgresStore now ENFORCES the per-agent
//! daily memory-count quota at the tenant-handler seam (single create + bulk +
//! consolidate). Pre-#1795 the postgres path only RECORDED usage, so a
//! postgres-backed daemon never capped the daily count. The enforcement is the
//! new SAL `check_memory_quota` called by the 3 postgres tenant handlers BEFORE
//! their store write; exempt paths (federation/migrate/CLI/curator) never call it.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`; skips
//! cleanly otherwise (CI's Postgres-gate + Per-Module Coverage jobs set it).

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, postgres_url, wait_for_http_ready};

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
        llm: Arc::new(None),
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
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
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
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("postgres-backed serve never became ready");
    (format!("http://{addr}"), shutdown, handle)
}

/// Upsert the (agent, namespace) `agent_quotas` row with a tight daily memory
/// cap. On INSERT the counters seed at 0; on CONFLICT only the cap is set so a
/// prior store's count is preserved.
async fn pg_set_cap(url: &str, agent: &str, ns: &str, cap: i64) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("pg pool");
    sqlx::query(
        "INSERT INTO agent_quotas (
             agent_id, namespace, max_memories_per_day, max_storage_bytes, max_links_per_day,
             current_memories_today, current_storage_bytes, current_links_today,
             day_started_at, created_at, updated_at
         ) VALUES ($1, $2, $3, 104857600, 5000, 0, 0, 0, now(), now(), now())
         ON CONFLICT (agent_id, namespace) DO UPDATE SET max_memories_per_day = $3",
    )
    .bind(agent)
    .bind(ns)
    .bind(cap)
    .execute(&pool)
    .await
    .expect("seed cap");
}

async fn http_store(
    client: &reqwest::Client,
    base: &str,
    agent: &str,
    ns: &str,
    title: &str,
) -> reqwest::StatusCode {
    let body = json!({
        "tier": "long", "namespace": ns, "title": title,
        "content": "1795 quota body", "tags": [], "priority": 5,
        "confidence": 1.0, "source": "api", "metadata": {}, "agent_id": agent,
    });
    client
        .post(format!("{base}/api/v1/memories"))
        .header("X-Agent-Id", agent)
        .json(&body)
        .send()
        .await
        .expect("store POST")
        .status()
}

/// Single create on postgres must 429 once the daily cap is reached.
#[tokio::test(flavor = "multi_thread")]
async fn pg_single_create_enforces_daily_quota_1795() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skipping pg_single_create_enforces_daily_quota_1795: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("g6-single-{suffix}");
    let ns = format!("g6-single-ns-{suffix}");

    // First store creates the row (count=1); tighten the cap to 1 → at cap.
    assert!(
        http_store(&client, &base, &agent, &ns, "first")
            .await
            .is_success()
    );
    pg_set_cap(&url, &agent, &ns, 1).await;

    // The next store would be count 2 > cap 1 → 429 QUOTA_EXCEEDED.
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .header("X-Agent-Id", &agent)
        .json(&json!({
            "tier": "long", "namespace": ns, "title": "over-cap",
            "content": "x", "tags": [], "priority": 5, "confidence": 1.0,
            "source": "api", "metadata": {}, "agent_id": agent,
        }))
        .send()
        .await
        .expect("over-cap POST");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "#1795: postgres single create over the daily cap must 429"
    );
    let v: Value = resp.json().await.unwrap_or(json!({}));
    assert_eq!(
        v["code"], "QUOTA_EXCEEDED",
        "429 envelope carries the code: {v}"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

/// Bulk create on postgres must partial-fill: only the rows that fit the cap
/// persist; the rest land in errors[] (parity with the sqlite #1788 path).
#[tokio::test(flavor = "multi_thread")]
async fn pg_bulk_create_partial_fills_at_quota_1795() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skipping pg_bulk_create_partial_fills_at_quota_1795: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("g6-bulk-{suffix}");
    let ns = format!("g6-bulk-ns-{suffix}");

    // Seed a fresh row with cap=3, count=0 (no prior store).
    pg_set_cap(&url, &agent, &ns, 3).await;

    let bodies: Vec<Value> = (0..8)
        .map(|i| {
            json!({
                "tier": "long", "namespace": ns, "title": format!("g6-bulk #{i}"),
                "content": "x", "tags": [], "priority": 5, "confidence": 1.0,
                "source": "api", "metadata": {},
            })
        })
        .collect();
    let resp = client
        .post(format!("{base}/api/v1/memories/bulk"))
        .header("X-Agent-Id", &agent)
        .json(&Value::Array(bodies))
        .send()
        .await
        .expect("bulk POST");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.expect("bulk body");
    assert_eq!(
        v["created"], 3,
        "#1795: postgres bulk fills to the cap of 3: {v}"
    );
    assert_eq!(
        v["errors"].as_array().map(Vec::len),
        Some(5),
        "#1795: the 5 over-cap rows are rejected into errors[]: {v}"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

/// Consolidate on postgres charges 1 and 429s at the cap.
#[tokio::test(flavor = "multi_thread")]
async fn pg_consolidate_enforces_daily_quota_1795() {
    let Some(url) = postgres_url() else {
        eprintln!(
            "skipping pg_consolidate_enforces_daily_quota_1795: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("g6-cons-{suffix}");
    let ns = format!("g6-cons-ns-{suffix}");

    // Store two sources (count=2 under the default cap), then tighten to 2 → at cap.
    let store_id = |title: &'static str| {
        let client = client.clone();
        let base = base.clone();
        let agent = agent.clone();
        let ns = ns.clone();
        async move {
            let resp = client
                .post(format!("{base}/api/v1/memories"))
                .header("X-Agent-Id", &agent)
                .json(&json!({
                    "tier": "long", "namespace": ns, "title": title,
                    "content": "src", "tags": [], "priority": 5, "confidence": 1.0,
                    "source": "api", "metadata": {}, "agent_id": agent,
                }))
                .send()
                .await
                .expect("store source");
            let v: Value = resp.json().await.expect("store body");
            v["id"].as_str().expect("id").to_string()
        }
    };
    let id1 = store_id("cons source one").await;
    let id2 = store_id("cons source two").await;
    pg_set_cap(&url, &agent, &ns, 2).await;

    let resp = client
        .post(format!("{base}/api/v1/consolidate"))
        .header("X-Agent-Id", &agent)
        .json(&json!({
            "ids": [id1, id2],
            "title": "g6 consolidated",
            "summary": "merged summary that is comfortably longer than twenty chars",
            "namespace": ns,
            "agent_id": agent,
        }))
        .send()
        .await
        .expect("consolidate POST");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "#1795: postgres consolidate at the daily cap must 429"
    );

    shutdown.notify_one();
    let _ = handle.await;
}
