// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 Provenance Gap 6 (issue #889) — HTTP `?source_uri=X` query
//! param end-to-end coverage.
//!
//! Pins the wire shape documented in the gap-6 release notes: a
//! `GET /api/v1/search?source_uri=X` (or `GET /api/v1/search?q=…&
//! source_uri=X`) returns memories filtered by the first-class
//! `source_uri` column. The response envelope mirrors the existing
//! search wire shape (`{results, count}`) with a `source_uri` field
//! echoed when the filter narrowed the result set.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{Memory, Tier};

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

fn seed_many(path: &std::path::Path, namespace: &str, count: usize, uri: Option<&str>) {
    let conn = ai_memory::db::open(path).expect("reopen for seed");
    // #891 followup: include source_uri tag in title so seeds with
    // different uris don't collide on the (title, namespace) upsert key.
    let uri_tag = uri.unwrap_or("none").replace([':', '/'], "_");
    for i in 0..count {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("{namespace}-{uri_tag}-{i}"),
            content: format!("body searchable content for {namespace}-{uri_tag}-{i}"),
            namespace: namespace.to_string(),
            tier: Tier::Mid,
            created_at: now.clone(),
            updated_at: now,
            source_uri: uri.map(str::to_string),
            ..Default::default()
        };
        ai_memory::db::insert(&conn, &mem).expect("insert");
    }
}

async fn get_search(router: &axum::Router, query: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/search?{query}"))
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
async fn http_search_composes_q_with_source_uri_filter() {
    // Composition case: when `q` is non-empty, the source_uri filter
    // narrows the FTS result set. Note: this exercises only ONE row
    // per source URI (the FTS query is title-based and the seed_many
    // helper writes per-iteration distinct titles).
    //
    // #975 (2026-05-20): pass `as_agent=ns-compose` so the post-#942
    // visibility filter (which synthesises `anonymous:req-<uuid>` for
    // HTTP requests without `X-Agent-Id`) sees the seeded rows.
    // `as_agent` aligns the caller's visibility-principal namespace
    // with the seeded rows' namespace so the `scope=private` rows
    // are visible. Pre-#975 the test ran against a synthetic anon
    // principal and the visibility WHERE-clause rejected every row,
    // returning count=0.
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-compose", 3, Some("doc:abc"));
    seed_many(file.path(), "ns-compose", 2, Some("doc:xyz"));

    // FTS sanitization breaks tokens apart — pick a specific title
    // token so the result set is deterministic and the URI filter
    // can be observed shrinking it.
    let (status, body) = get_search(
        &router,
        "q=ns-compose&source_uri=doc%3Aabc&as_agent=ns-compose",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let count = body["count"].as_u64().unwrap_or_default();
    assert!(
        (1..=3).contains(&count),
        "URI filter narrows to 1-3 abc rows (got {count}), never xyz rows"
    );
    let results = body["results"].as_array().expect("results");
    for r in results {
        assert_eq!(
            r["source_uri"].as_str(),
            Some("doc:abc"),
            "every returned row carries the filtered URI"
        );
    }
}

#[tokio::test]
async fn http_search_with_invalid_source_uri_returns_400() {
    let (router, _file) = build_test_router();
    // A URI without one of the accepted schemes (`uri:`, `doc:`,
    // `file:`) is invalid per src/validate.rs::validate_source_uri.
    // We must pass a non-empty `q` to bypass the unrelated empty-q
    // early-return; the URI validator still rejects with 400.
    let (status, body) = get_search(&router, "source_uri=not-a-valid-scheme&q=anything").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid scheme ⇒ 400, got {status}: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("source_uri") || err.contains("source URI"),
        "error message names the source_uri filter: {err}"
    );
}

#[tokio::test]
async fn http_search_with_unknown_source_uri_intersected_returns_empty() {
    // URI filter intersected with an FTS query returns empty when no
    // row carries the URI. Uses a non-empty `q` to exercise the
    // search-with-source-uri branch (not the URI-only branch, which
    // requires the issue-#891 fix landing first).
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-unk", 3, Some("doc:abc"));
    let (status, body) = get_search(&router, "q=body&source_uri=doc%3Anope").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "unknown URI intersected with q=body returns empty"
    );
}

#[tokio::test]
async fn http_search_with_source_uri_only_returns_all_rows_from_that_doc_issue_891() {
    // AC pin (blocked): \"HTTP `GET /api/v1/memories?source_uri=X`
    // query param\" per issue #889.
    //
    // #975 (2026-05-20): the source_uri-only reciprocal endpoint now
    // applies the same scope=private visibility gate as
    // `search_with_source_uri` (closing the post-#942 visibility
    // inconsistency). The test passes `as_agent=ns-doc` so the
    // caller's visibility-principal namespace matches the seeded
    // rows. Pre-#975 the source_uri-only path bypassed visibility
    // entirely — any HTTP caller (no `X-Agent-Id`, no `as_agent`)
    // could read every row in every document.
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-doc", 5, Some("doc:contract-2026"));
    seed_many(file.path(), "ns-doc", 3, Some("doc:other-thing"));
    seed_many(file.path(), "ns-doc", 2, None);

    let (status, body) =
        get_search(&router, "source_uri=doc%3Acontract-2026&as_agent=ns-doc").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"].as_u64(), Some(5));
    let results = body["results"].as_array().expect("results");
    for r in results {
        assert_eq!(r["source_uri"].as_str(), Some("doc:contract-2026"));
    }
}

// #975 regression pin (2026-05-20): the source_uri-only reciprocal
// endpoint MUST apply the same scope=private visibility gate as
// `search_with_source_uri`. Pre-#975 every HTTP caller (including a
// synthetic `anonymous:req-<uuid>` principal) could see scope=private
// rows in any document by hitting `?source_uri=X` alone. After #975
// the `as_agent` principal is honoured; a mismatched principal sees
// no rows even when the requested doc has matches.
#[tokio::test]
async fn http_search_source_uri_only_applies_visibility_gate_975() {
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-private-doc", 4, Some("doc:secret"));
    // Caller asks under a DIFFERENT principal namespace than the
    // seeded rows. With scope=private (the default) the visibility
    // WHERE-clause must reject every row.
    let (status, body) = get_search(&router, "source_uri=doc%3Asecret&as_agent=ns-other").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "source_uri-only path must honour the scope=private visibility gate (was leaking pre-#975)",
    );
}

// #975 regression pin (2026-05-20): q+source_uri composition with the
// matching `as_agent` principal returns the abc rows only. Co-pinned
// with the source_uri-only sibling above so future drift in either
// path is caught by the same test file.
#[tokio::test]
async fn http_search_q_plus_source_uri_applies_visibility_gate_975() {
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-vg", 3, Some("doc:abc"));
    seed_many(file.path(), "ns-vg", 2, Some("doc:xyz"));
    // Mismatched principal — visibility gate rejects every row.
    let (status, body) =
        get_search(&router, "q=ns-vg&source_uri=doc%3Aabc&as_agent=ns-other").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "q+source_uri must reject when caller principal mismatches seeded namespace",
    );
    // Matched principal — abc rows surface.
    let (status, body) = get_search(&router, "q=ns-vg&source_uri=doc%3Aabc&as_agent=ns-vg").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let count = body["count"].as_u64().unwrap_or_default();
    assert!(
        (1..=3).contains(&count),
        "matched principal sees abc rows only (got {count})",
    );
}
