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
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
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
            // v0.8.0 #1720 A3/A4 — scope=private visibility is now
            // OWNER-keyed (metadata.agent_id == caller), not
            // namespace-keyed. Stamp a concrete owner equal to the
            // namespace string (a valid agent_id) so a request that
            // authenticates as that owner via `X-Agent-Id` can see the
            // rows, while any other principal (a different concrete
            // owner, or an anonymous header-less caller) is fail-closed.
            // The default-metadata seed left agent_id absent, which under
            // the owner-keyed model is un-ownable → hidden from every
            // caller (the pre-#1720 `as_agent`-namespace grant was the
            // cross-tenant leak that #1720 closed).
            metadata: serde_json::json!({ "agent_id": namespace }),
            ..Default::default()
        };
        ai_memory::db::insert(&conn, &mem).expect("insert");
    }
}

async fn get_search(router: &axum::Router, query: &str) -> (StatusCode, Value) {
    get_search_inner(router, query, None).await
}

// v0.8.0 #1720 A3/A4 — authenticate as a concrete owner via the
// `X-Agent-Id` header. The HTTP search handler resolves the owner-keyed
// `scope=private` visibility caller exclusively from this header
// (`memories_query.rs` → `resolve_http_agent_id`), DISTINCT from the
// `as_agent` query-param that only drives the team/unit/org subtree
// arms. Sending `X-Agent-Id == <row owner>` lets the caller see its own
// private rows; a different value is fail-closed.
async fn get_search_as(router: &axum::Router, query: &str, agent_id: &str) -> (StatusCode, Value) {
    get_search_inner(router, query, Some(agent_id)).await
}

async fn get_search_inner(
    router: &axum::Router,
    query: &str,
    agent_id: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/search?{query}"));
    if let Some(a) = agent_id {
        builder = builder.header(ai_memory::HEADER_AGENT_ID, a);
    }
    let req = builder.body(Body::empty()).unwrap();
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
    // v0.8.0 #1720 A3/A4: scope=private visibility is OWNER-keyed.
    // `seed_many` stamps `metadata.agent_id = "ns-compose"` on every
    // row, so the caller must authenticate as that owner via the
    // `X-Agent-Id` header to see them. (Pre-#1720 a same-namespace
    // `as_agent` grant sufficed — that was the cross-tenant leak #1720
    // closed; #975 originally relied on it.)
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-compose", 3, Some("doc:abc"));
    seed_many(file.path(), "ns-compose", 2, Some("doc:xyz"));

    // FTS sanitization breaks tokens apart — pick a specific title
    // token so the result set is deterministic and the URI filter
    // can be observed shrinking it.
    let (status, body) =
        get_search_as(&router, "q=ns-compose&source_uri=doc%3Aabc", "ns-compose").await;
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
    // Authenticate as the rows' owner ("ns-unk") so the empty result is
    // unambiguously the URI filter (doc:nope matches nothing), not the
    // #1720 owner-keyed visibility gate.
    let (status, body) = get_search_as(&router, "q=body&source_uri=doc%3Anope", "ns-unk").await;
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
    // #975 (2026-05-20): the source_uri-only reciprocal endpoint
    // applies the same scope=private visibility gate as
    // `search_with_source_uri`. v0.8.0 #1720 A3/A4 made that gate
    // OWNER-keyed: `seed_many` stamps `metadata.agent_id = "ns-doc"`,
    // so the caller authenticates as that owner via `X-Agent-Id` to
    // read the document's rows. Pre-#1720 the source_uri-only path
    // bypassed visibility / granted same-namespace `as_agent` access —
    // any caller could read every row in every document.
    let (router, file) = build_test_router();
    seed_many(file.path(), "ns-doc", 5, Some("doc:contract-2026"));
    seed_many(file.path(), "ns-doc", 3, Some("doc:other-thing"));
    seed_many(file.path(), "ns-doc", 2, None);

    let (status, body) = get_search_as(&router, "source_uri=doc%3Acontract-2026", "ns-doc").await;
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
    // v0.8.0 #1720 A3/A4: the rows are OWNED by "ns-private-doc". A
    // caller authenticating as a DIFFERENT concrete owner
    // ("ns-other") must be rejected by the owner-keyed scope=private
    // gate — a non-tautological negative (proves the gate discriminates
    // between two real owners, not merely that an absent identity
    // fails).
    let (status, body) = get_search_as(&router, "source_uri=doc%3Asecret", "ns-other").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "source_uri-only path must honour the owner-keyed scope=private gate (#1720)",
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
    // v0.8.0 #1720 A3/A4 — rows are OWNED by "ns-vg". A DIFFERENT
    // concrete owner ("ns-other") is rejected by the owner-keyed
    // scope=private gate (non-tautological negative).
    let (status, body) = get_search_as(&router, "q=ns-vg&source_uri=doc%3Aabc", "ns-other").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["count"].as_u64(),
        Some(0),
        "q+source_uri must reject when caller is not the rows' owner (#1720 owner-keyed)",
    );
    // The owner ("ns-vg") authenticating via X-Agent-Id sees abc rows.
    let (status, body) = get_search_as(&router, "q=ns-vg&source_uri=doc%3Aabc", "ns-vg").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let count = body["count"].as_u64().unwrap_or_default();
    assert!(
        (1..=3).contains(&count),
        "owner sees abc rows only (got {count})",
    );
}
