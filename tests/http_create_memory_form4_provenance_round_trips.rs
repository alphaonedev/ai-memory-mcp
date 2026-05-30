// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 issue #1411 — HTTP POST /api/v1/memories Form 4 wire-truthfulness.
//!
//! Pre-#1411 the `create_memory` (sqlite) and `create_memory_postgres`
//! handlers both hardcoded `citations: Vec::new()`, `source_uri:
//! None`, and `source_span: None` on insert, dropping the validated
//! caller-supplied Form 4 fields. This binary pins the round-trip:
//! a POST with all three fields populated stores them, and a GET
//! by id returns them verbatim. Sister bug to #1385 (kind drop).
//!
//! The test exercises the sqlite branch (`StorageBackend::Sqlite`,
//! the default the in-tests `build_test_router` configures). The
//! postgres branch carries an identical fix; postgres-route-gate
//! coverage of the same shape is tracked separately under #1182's
//! integrated regression run.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

fn build_test_router() -> (axum::Router, NamedTempFile) {
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
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post_json(router: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json")
        .header("X-Agent-Id", "ai:http-1411-test")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("X-Agent-Id", "ai:http-1411-test")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_post_memories_round_trips_citations_source_uri_and_source_span() {
    let (router, _f) = build_test_router();

    let body = json!({
        "title": "form4-roundtrip-1411",
        "content": "Form 4 wire-truthfulness regression body.",
        "tier": "mid",
        "namespace": "ns-1411",
        "tags": ["form4", "regression"],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "citations": [
            {
                "uri": "uri:https://example.test/spec.html",
                "accessed_at": "2026-01-01T00:00:00Z",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "span": { "start": 0, "end": 64 }
            }
        ],
        "source_uri": "doc:parent-1411",
        "source_span": { "start": 12, "end": 24 }
    });

    let (status, resp) = post_json(&router, "/api/v1/memories", &body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "POST /api/v1/memories returned {status}: {resp}"
    );

    let id = resp["id"]
        .as_str()
        .expect("response carries `id` for the newly-created row")
        .to_string();

    let (get_status, got) = get_json(&router, &format!("/api/v1/memories/{id}")).await;
    assert_eq!(
        get_status,
        StatusCode::OK,
        "GET /api/v1/memories/{{id}} returned {get_status}: {got}"
    );

    // GET wraps the row in `{memory, links}`.
    let mem = &got["memory"];

    let citations = mem["citations"]
        .as_array()
        .unwrap_or_else(|| panic!("citations array present on GET response; got: {got}"))
        .clone();
    assert_eq!(
        citations.len(),
        1,
        "pre-#1411 this was 0 (citations dropped on insert); post-#1411 the single supplied citation round-trips"
    );
    assert_eq!(
        citations[0]["uri"].as_str(),
        Some("uri:https://example.test/spec.html"),
        "citation.uri round-trips"
    );

    assert_eq!(
        mem["source_uri"].as_str(),
        Some("doc:parent-1411"),
        "pre-#1411 this was absent (source_uri dropped on insert); post-#1411 it round-trips. got: {got}"
    );

    let span = &mem["source_span"];
    assert!(
        !span.is_null(),
        "pre-#1411 this was absent (source_span dropped on insert); post-#1411 it round-trips. got: {got}"
    );
    assert_eq!(
        span["start"].as_u64(),
        Some(12),
        "source_span.start round-trips"
    );
    assert_eq!(
        span["end"].as_u64(),
        Some(24),
        "source_span.end round-trips"
    );
}

#[tokio::test]
async fn http_post_memories_with_no_form4_fields_still_succeeds_and_returns_empty_defaults() {
    // Negative control — pre-#1411 the same shape worked accidentally
    // because empty defaults matched what the handler hardcoded.
    // Post-#1411 the body fields are honored, and an absent field
    // still resolves to the typed default (empty Vec / None / None).
    let (router, _f) = build_test_router();

    let body = json!({
        "title": "form4-control-1411",
        "content": "No Form 4 fields supplied.",
        "tier": "mid",
        "namespace": "ns-1411-control",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api"
    });

    let (status, resp) = post_json(&router, "/api/v1/memories", &body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "POST without Form 4 fields succeeds: {status} {resp}"
    );

    let id = resp["id"]
        .as_str()
        .expect("response carries id")
        .to_string();
    let (_s, got) = get_json(&router, &format!("/api/v1/memories/{id}")).await;
    let mem = &got["memory"];
    assert_eq!(
        mem["citations"].as_array().map(Vec::len),
        Some(0),
        "absent citations → empty Vec on GET; got: {got}"
    );
    // `source_uri` + `source_span` use `skip_serializing_if = Option::is_none`,
    // so an absent value is a missing key (Value::Null) on the wire.
    assert!(
        mem["source_uri"].is_null(),
        "absent source_uri → null/missing on GET; got: {got}"
    );
    assert!(
        mem["source_span"].is_null(),
        "absent source_span → null/missing on GET; got: {got}"
    );
}
