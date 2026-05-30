// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 issue #1422 — HTTP POST /api/v1/memories/bulk Form-4 +
//! Form-6 wire-truthfulness sister-fix to #1385 (single-create kind)
//! plus #1411 (single-create citations/source_uri/source_span) plus
//! #1421 (MCP store).
//!
//! Pre-fix `src/handlers/memories_query.rs::bulk_create` validated each
//! row via `RequestValidator::validate_create(&body)` (which validates
//! `citations` / `source_uri` / `source_span` / `kind`) and then BOTH
//! branches (postgres line 562-589, sqlite 705-734) hardcoded defaults
//! on insert: `memory_kind: MemoryKind::Observation`, `citations:
//! Vec::new()`, `source_uri: None`, `source_span: None`. A caller
//! posting a batch with full Form-4+Form-6 fields silently lost
//! everything.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

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
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn post_json(router: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json")
        .header("X-Agent-Id", "ai:http-1422-test")
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

async fn list_namespace(router: &axum::Router, namespace: &str) -> Vec<Value> {
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/api/v1/memories?namespace={namespace}&limit=50&as_agent=ai:http-1422-test"
        ))
        .header("X-Agent-Id", "ai:http-1422-test")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    parsed["memories"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn http_bulk_create_round_trips_kind_citations_source_uri_source_span() {
    let (router, _f) = build_test_router();

    // bulk_create accepts a bare JSON array (Vec<CreateMemory>), not
    // wrapped in {"items": ...}.
    let body = json!([
        {
            "title": "bulk-1422-claim",
            "content": "first body - claim with citation",
            "tier": "mid",
            "namespace": "ns-1422",
            "tags": ["bulk", "1422"],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "kind": "claim",
            "citations": [
                { "uri": "doc:bulk-source-1", "accessed_at": "2026-01-01T00:00:00Z" }
            ],
            "source_uri": "doc:parent-1",
            "source_span": { "start": 0, "end": 10 }
        },
        {
            "title": "bulk-1422-decision",
            "content": "second body - decision",
            "tier": "mid",
            "namespace": "ns-1422",
            "tags": ["bulk", "1422"],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "kind": "decision",
            "source_uri": "doc:parent-2"
        },
        {
            "title": "bulk-1422-default",
            "content": "third body - defaults preserved",
            "tier": "mid",
            "namespace": "ns-1422",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api"
        }
    ]);

    let (status, resp) = post_json(&router, "/api/v1/memories/bulk", &body).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "bulk POST got {status}: {resp}"
    );
    assert_eq!(
        resp["created"].as_u64(),
        Some(3),
        "all 3 rows landed; got: {resp}"
    );

    // bulk response shape is {created, errors} with no per-row id —
    // cross-reference each row via list-by-namespace.
    let mems = list_namespace(&router, "ns-1422").await;
    assert_eq!(mems.len(), 3, "all 3 rows visible to caller; got: {mems:?}");

    let by_title: std::collections::HashMap<String, Value> = mems
        .into_iter()
        .filter_map(|m| {
            let t = m.get("title")?.as_str()?.to_string();
            Some((t, m))
        })
        .collect();

    // Row 1: kind=claim + citation + source_uri + source_span all round-trip.
    let mem_1 = by_title.get("bulk-1422-claim").expect("row 1 present");
    assert_eq!(
        mem_1["memory_kind"].as_str(),
        Some("claim"),
        "pre-#1422 this was 'observation' (kind dropped); now round-trips"
    );
    let citations = mem_1["citations"].as_array().expect("citations array");
    assert_eq!(
        citations.len(),
        1,
        "pre-#1422 this was 0 (citations dropped); now round-trips"
    );
    assert_eq!(
        mem_1["source_uri"].as_str(),
        Some("doc:parent-1"),
        "source_uri round-trips"
    );
    let span = &mem_1["source_span"];
    assert!(
        !span.is_null(),
        "pre-#1422 this was absent (source_span dropped); now round-trips. got: {mem_1}"
    );
    assert_eq!(span["start"].as_u64(), Some(0));
    assert_eq!(span["end"].as_u64(), Some(10));

    // Row 2: kind=decision + source_uri; no citations/span supplied.
    let mem_2 = by_title.get("bulk-1422-decision").expect("row 2 present");
    assert_eq!(mem_2["memory_kind"].as_str(), Some("decision"));
    assert_eq!(mem_2["source_uri"].as_str(), Some("doc:parent-2"));
    assert_eq!(
        mem_2["citations"].as_array().map(Vec::len),
        Some(0),
        "absent citations - empty Vec"
    );
    assert!(mem_2["source_span"].is_null(), "absent source_span - null");

    // Row 3: all defaults - legacy posture preserved.
    let mem_3 = by_title.get("bulk-1422-default").expect("row 3 present");
    assert_eq!(
        mem_3["memory_kind"].as_str(),
        Some("observation"),
        "absent kind - default Observation"
    );
    assert_eq!(mem_3["citations"].as_array().map(Vec::len), Some(0));
    assert!(mem_3["source_uri"].is_null());
    assert!(mem_3["source_span"].is_null());
}
