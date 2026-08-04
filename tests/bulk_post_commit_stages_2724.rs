// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #2724 (CB-22) — `POST /api/v1/memories/bulk` must run the post-commit
//! stages single-create runs.
//!
//! `bulk_create` re-implemented the single-create funnel and omitted three
//! post-commit stages (the same re-implementation-omits-a-stage root cause as
//! #2550/#2551/#2552/#2588/#2594):
//!
//! - **F1 audit** — the funnel emitted ZERO `AuditAction::Store` rows, so a
//!   fleet corpus load left an invisible gap in the tamper-evident chain.
//! - **F2 dispatch** — the funnel fired ZERO `subscriptions::dispatch_event`,
//!   so a registered `memory_store` subscriber received nothing.
//! - **F3 postgres federation fanout** — covered by the `sal-postgres` twin in
//!   `tests/federation_postgres_fanout.rs::bulk_create_postgres_fans_out_to_peers_2724`.
//!
//! These sqlite cells pin the F1 + F2 OUTCOMES and, critically, that the
//! stages fire ONCE per DISTINCT persisted row and NEVER for a rejected /
//! collapsed input row — the partial-failure honesty the North Star requires.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl, set_allow_loopback_webhooks};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::subscriptions::{self, NewSubscription};

/// #1751 — the v0.9 HTTP-direct default is REQUIRED; opt out so the unsigned
/// store fixtures below exercise the post-commit stages, not a 403.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

const AGENT: &str = "bulk-postcommit-agent";

fn build_router(db_path: &Path) -> axum::Router {
    permissive_attestation_for_tests();
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
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
        llm_call_timeout: Duration::from_secs(30),
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn fresh_db() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("bulk-2724.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    (dir, db_path)
}

async fn post(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

fn row(namespace: &str, title: &str, content: &str) -> Value {
    json!({
        "tier": "long", "namespace": namespace, "title": title, "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "api", "metadata": {},
    })
}

fn db_row_count(db_path: &Path, namespace: &str) -> i64 {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            params![namespace],
            |r| r.get(0),
        )
        .expect("count")
}

/// Count `AuditAction::Store` NDJSON rows in the audit log whose target
/// namespace matches `namespace`. Filtering by namespace makes the count
/// robust against any other rows that share the process-global audit sink.
fn store_audit_rows_for_ns(audit_file: &Path, namespace: &str) -> usize {
    let raw = std::fs::read_to_string(audit_file).unwrap_or_default();
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|ev| {
            ev["action"] == json!("store") && ev["target"]["namespace"] == json!(namespace)
        })
        .count()
}

// ---------------------------------------------------------------------------
// F1 — audit emit.
// ---------------------------------------------------------------------------

/// PARENT: `grep -n "crate::audit::emit" src/handlers/bulk.rs` returned ZERO
/// hits — a bulk load left NO `Store` rows in the tamper-evident chain while
/// single-create wrote one per memory. Post-#2724 the funnel emits one `Store`
/// row per DISTINCT persisted row: a clean batch of N draws N; an in-batch
/// collapse draws one per surviving row (never one per input index); a
/// rejected row draws none.
#[tokio::test]
async fn bulk_emits_one_store_audit_row_per_persisted_row_2724() {
    let (_dir, db_path) = fresh_db();
    let audit_dir = TempDir::new().expect("audit dir");
    let audit_file = audit_dir.path().join("audit.ndjson");
    // Enable the (process-global) audit sink; the namespace filter below keeps
    // the counts correct even if a concurrent test shares this sink.
    ai_memory::audit::init(&audit_file, false, false).expect("audit init");
    assert!(ai_memory::audit::is_enabled(), "audit sink must be enabled");

    let router = build_router(&db_path);

    // (1) A clean batch of 3 distinct rows draws exactly 3 Store rows.
    let ns_clean = "audit-clean-2724";
    let clean = json!([
        row(ns_clean, "c1", "x"),
        row(ns_clean, "c2", "y"),
        row(ns_clean, "c3", "z"),
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &clean).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(db_row_count(&db_path, ns_clean), 3, "3 rows persisted: {v}");
    assert_eq!(
        store_audit_rows_for_ns(&audit_file, ns_clean),
        3,
        "#2724 F1: one Store audit row per persisted memory (found for ns {ns_clean})"
    );

    // (2) A batch with an in-batch collapse (two rows share a title, last-wins)
    // plus a validation-rejected empty-title row persists 2 distinct rows, so
    // it draws 2 Store rows — NOT 3 (per input index) and NOT for the reject.
    let ns_mixed = "audit-mixed-2724";
    let mixed = json!([
        row(ns_mixed, "dup", "first"),
        row(ns_mixed, "uniq", "u"),
        row(ns_mixed, "dup", "second wins"),
        row(ns_mixed, "", "rejected-empty-title"),
    ]);
    let (status2, v2) = post(&router, "/api/v1/memories/bulk", &mixed).await;
    assert_eq!(status2, StatusCode::MULTI_STATUS, "{v2}");
    assert_eq!(db_row_count(&db_path, ns_mixed), 2, "2 distinct rows: {v2}");
    assert_eq!(v2["created"], 2, "{v2}");
    assert_eq!(v2["deduped"], 1, "{v2}");
    assert_eq!(v2["rejected"], 1, "{v2}");
    assert_eq!(
        store_audit_rows_for_ns(&audit_file, ns_mixed),
        2,
        "#2724 F1: the audit fires per DISTINCT persisted row, never for a \
         collapsed or rejected input index"
    );
}

// ---------------------------------------------------------------------------
// F2 — subscription dispatch.
// ---------------------------------------------------------------------------

/// PARENT: `grep -n "dispatch_event" src/handlers/bulk.rs` returned ZERO hits
/// — a `memory_store` subscriber received NOTHING from a bulk write while
/// single-create fired the event on every store. Post-#2724 a bulk write fires
/// one `memory_store` dispatch per persisted row, so a registered subscriber's
/// webhook is invoked once per committed row and never for a rejected one.
#[tokio::test]
async fn bulk_dispatches_memory_store_event_per_persisted_row_2724() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The dispatcher counts a delivery successful ONLY on a 2xx whose body
    /// echoes `{"status":"ack","correlation_id":<the sent id>}`; anything else
    /// is retried on the [200ms, 1s, 5s] ladder (which would double the
    /// observed request count). Echo the id so each delivery lands once.
    struct AckEcho;
    impl wiremock::Respond for AckEcho {
        fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
            let corr = serde_json::from_slice::<Value>(&req.body)
                .ok()
                .and_then(|v| {
                    v.get("correlation_id")
                        .and_then(|c| c.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| "missing".to_string());
            ResponseTemplate::new(200)
                .set_body_json(json!({"status": "ack", "correlation_id": corr}))
        }
    }

    // Wiremock binds loopback; the SSRF guard rejects loopback by default.
    set_allow_loopback_webhooks(true);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(AckEcho)
        .mount(&server)
        .await;

    let (_dir, db_path) = fresh_db();
    let hook_url = format!("{}/hook", server.uri());
    // ONE wildcard subscriber registered in the SAME db the router reads.
    {
        let conn = Connection::open(&db_path).expect("open");
        subscriptions::insert(
            &conn,
            &NewSubscription {
                url: &hook_url,
                events: "*",
                // HMAC-signed dispatch is mandatory at v0.7.0 (unsigned
                // delivery DISABLED), so a secret-less subscription would be
                // skipped and never deliver.
                secret: Some("bulk-2724-secret"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .expect("insert subscription");
    }

    let router = build_router(&db_path);
    let ns = "dispatch-2724";
    // 3 distinct rows commit; the empty-title row is rejected and must NOT
    // fire a dispatch.
    let batch = json!([
        row(ns, "d1", "x"),
        row(ns, "d2", "y"),
        row(ns, "d3", "z"),
        row(ns, "", "rejected"),
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;
    assert_eq!(status, StatusCode::MULTI_STATUS, "{v}");
    assert_eq!(db_row_count(&db_path, ns), 3, "3 committed rows: {v}");

    // Poll until the fire-and-forget deliveries land. Exactly 3 — one per
    // committed row, zero for the rejected row.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut delivered = 0usize;
    while std::time::Instant::now() < deadline {
        delivered = server.received_requests().await.map_or(0, |r| r.len());
        if delivered >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Small settle so a spurious 4th (e.g. from the rejected row) would surface.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let final_count = server.received_requests().await.map_or(0, |r| r.len());
    assert_eq!(
        final_count, 3,
        "#2724 F2: the subscriber must receive exactly one memory_store \
         dispatch per committed row (3), never for the rejected row \
         (observed {delivered} during poll, {final_count} final): {v}"
    );
}
