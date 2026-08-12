// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! #1788 (5-agent vote 4d3ea1c5) — the bulk-create + consolidate HTTP/MCP
//! surfaces must charge the per-agent daily write quota, closing the
//! bypass where a caller loops 1000-item bulk POSTs to author unlimited
//! memories. Mirrors the single-write enforcement (`round2_f7_http_quota`).
//!
//! sqlite-backed (the backend whose `check_and_record` enforcement model
//! #1788 describes). The postgres-wide non-enforcement is the distinct,
//! broader #1795.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

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
fn build_test_router() -> (axum::Router, std::path::PathBuf, NamedTempFile) {
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
    #[cfg(feature = "sal")]
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
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
        auto_tag_queue: None,
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db_path, f)
}

/// Seed the (agent, namespace) quota row then tighten the daily memory cap.
fn seed_cap(db_path: &Path, agent_id: &str, namespace: &str, cap: i64) {
    let conn = Connection::open(db_path).expect("open for cap seed");
    // ensure_row via get_status creates the default row for this (agent, ns).
    ai_memory::quotas::get_status(&conn, agent_id, namespace).expect("seed row");
    conn.execute(
        "UPDATE agent_quotas SET max_memories_per_day = ?1 WHERE agent_id = ?2 AND namespace = ?3",
        params![cap, agent_id, namespace],
    )
    .expect("tighten cap");
}

fn quota_count(db_path: &Path, agent_id: &str) -> i64 {
    let conn = Connection::open(db_path).expect("open for quota read");
    ai_memory::quotas::get_aggregate_status(&conn, agent_id)
        .expect("quota row")
        .current_memories_today
}

async fn http_store(
    router: &axum::Router,
    agent_id: &str,
    namespace: &str,
    title: &str,
) -> (StatusCode, Option<String>) {
    let body = json!({
        "tier": "long", "namespace": namespace, "title": title,
        "content": "1788 quota body", "tags": [], "priority": 5,
        "confidence": 1.0, "source": "api", "metadata": {}, "agent_id": agent_id,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let id = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v["id"].as_str().map(str::to_string));
    (status, id)
}

/// bulk_create must charge per row and partial-fill: a batch that exceeds
/// the daily cap persists only the rows that fit; the rest land in errors[].
#[tokio::test]
async fn bulk_create_enforces_daily_quota_partial_fill_1788() {
    let (router, db_path, _keep) = build_test_router();
    let agent_id = "bulk-1788-agent";
    let namespace = "bulk-1788";
    seed_cap(&db_path, agent_id, namespace, 3);

    let bodies: Vec<Value> = (0..8)
        .map(|i| {
            json!({
                "tier": "long", "namespace": namespace, "title": format!("bulk-1788 #{i}"),
                "content": "x", "tags": [], "priority": 5, "confidence": 1.0,
                "source": "api", "metadata": {},
            })
        })
        .collect();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(
            serde_json::to_vec(&Value::Array(bodies)).unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    // #2588 — a PARTIAL fill is not an unqualified success. Pre-#2588 this
    // asserted 200, which is the #2444/#2490 false-success shape: 3 of 8 rows
    // landed and a client checking only the status saw "OK".
    assert_eq!(
        resp.status(),
        StatusCode::MULTI_STATUS,
        "bulk partial fill returns 207, not 200"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        v["created"], 3,
        "#1788: only 3 rows fit the daily cap of 3: {v}"
    );
    assert_eq!(
        v["errors"].as_array().map(Vec::len),
        Some(5),
        "#1788: the 5 over-cap rows are rejected into errors[]: {v}"
    );
    // #2588 — the quota rejection is now TYPED, not the opaque "internal
    // error" that hid 31,000 dropped rows behind an HTTP 200.
    assert_eq!(
        v["errors"][0]["code"], "QUOTA_EXCEEDED",
        "#2588: quota rejections classify as QUOTA_EXCEEDED: {v}"
    );
    // #2551 — the reconciliation identity a fleet loader asserts on.
    assert_eq!(v["sent"], 8, "{v}");
    assert_eq!(
        v["created"].as_u64().unwrap()
            + v["updated"].as_u64().unwrap()
            + v["deduped"].as_u64().unwrap()
            + v["rejected"].as_u64().unwrap()
            + v["pending"].as_array().unwrap().len() as u64,
        8,
        "#2551: created+updated+deduped+rejected+pending == sent: {v}"
    );
    assert_eq!(
        quota_count(&db_path, agent_id),
        3,
        "#1788: the quota counter equals exactly the persisted rows (no over-count, refund-correct)"
    );
}

/// bulk_create with no X-Agent-Id (anonymous) is not quota-charged — parity
/// with the single-write skip-on-empty-principal behaviour.
#[tokio::test]
async fn bulk_create_anonymous_not_charged_1788() {
    let (router, _db_path, _keep) = build_test_router();
    let namespace = "bulk-1788-anon";
    let bodies: Vec<Value> = (0..4)
        .map(|i| {
            json!({
                "tier": "long", "namespace": namespace, "title": format!("anon #{i}"),
                "content": "x", "tags": [], "priority": 5, "confidence": 1.0,
                "source": "api", "metadata": {},
            })
        })
        .collect();
    // No x-agent-id header → anonymous principal → all 4 persist.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&Value::Array(bodies)).unwrap(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["created"], 4,
        "anonymous bulk is uncharged — all rows persist: {v}"
    );
}

/// consolidate is a tenant authoring write — it charges 1 against the daily
/// quota and 429s when the cap is reached.
#[tokio::test]
async fn consolidate_charges_daily_quota_1788() {
    let (router, db_path, _keep) = build_test_router();
    let agent_id = "consolidate-1788-agent";
    let namespace = "consolidate-1788";
    // Cap = 2: the two source stores fit; the consolidate (the 3rd authoring
    // write) tips the cap and must 429.
    seed_cap(&db_path, agent_id, namespace, 2);

    let (s1, id1) = http_store(&router, agent_id, namespace, "source one").await;
    let (s2, id2) = http_store(&router, agent_id, namespace, "source two").await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::CREATED);
    assert_eq!(
        quota_count(&db_path, agent_id),
        2,
        "two source stores consumed the cap"
    );

    let body = json!({
        "ids": [id1.unwrap(), id2.unwrap()],
        "title": "consolidated 1788",
        "summary": "merged",
        "namespace": namespace,
        "agent_id": agent_id,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/consolidate")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "#1788: consolidate at the daily cap must 429 (it authors a net-new memory)"
    );
    assert_eq!(
        quota_count(&db_path, agent_id),
        2,
        "#1788: a rejected consolidate must not advance the counter past the cap"
    );
}

/// A consolidate whose write fails AFTER the quota charge must refund the
/// charge (mirrors the single-write refund path). A provided `summary` skips
/// the pre-charge source fetch, and a bogus source id makes `db::consolidate`
/// fail after the charge — exercising the #1788 refund branch.
#[tokio::test]
async fn consolidate_refunds_quota_on_failure_1788() {
    let (router, db_path, _keep) = build_test_router();
    let agent_id = "consolidate-refund-1788";
    let namespace = "consolidate-refund-1788";
    seed_cap(&db_path, agent_id, namespace, 1000);

    // One real source so the (agent, ns) row has a known count; consolidate
    // references it plus a bogus id so the write fails post-charge.
    let (s1, id1) = http_store(&router, agent_id, namespace, "refund source").await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(
        quota_count(&db_path, agent_id),
        1,
        "one source store charged"
    );

    let body = json!({
        "ids": [id1.unwrap(), "bogus-nonexistent-1788"],
        "title": "refund consolidate",
        "summary": "merged summary that is comfortably longer than twenty chars",
        "namespace": namespace,
        "agent_id": agent_id,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/consolidate")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::CREATED,
        "a consolidate referencing a bogus source id must not succeed"
    );
    assert_eq!(
        quota_count(&db_path, agent_id),
        1,
        "#1788: a failed consolidate refunds its quota charge (counter stays at the 1 source store)"
    );
}

/// A quota SUBSTRATE failure (not a cap breach) during consolidate surfaces
/// as a sanitized 500, not a 429 — exercising the #1788 `QuotaCheckError::Sql`
/// arm. Dropping `agent_quotas` makes `check_and_record`'s row read fail.
#[tokio::test]
async fn consolidate_quota_substrate_error_500_1788() {
    let (router, db_path, _keep) = build_test_router();
    let agent_id = "consolidate-sqlerr-1788";
    let namespace = "consolidate-sqlerr-1788";

    // Two real sources stored while the quota table is intact.
    let (s1, id1) = http_store(&router, agent_id, namespace, "sqlerr source one").await;
    let (s2, id2) = http_store(&router, agent_id, namespace, "sqlerr source two").await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::CREATED);

    // Corrupt the quota substrate so the consolidate quota charge errors.
    {
        let conn = Connection::open(&db_path).expect("open to drop quota table");
        conn.execute("DROP TABLE agent_quotas", [])
            .expect("drop agent_quotas");
    }

    let body = json!({
        "ids": [id1.unwrap(), id2.unwrap()],
        "title": "sqlerr consolidate",
        "summary": "merged summary that is comfortably longer than twenty chars",
        "namespace": namespace,
        "agent_id": agent_id,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/consolidate")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "#1788: a quota substrate read failure surfaces as 500, not a 429 cap breach"
    );
}
