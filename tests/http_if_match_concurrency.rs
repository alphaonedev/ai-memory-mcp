// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 Provenance Gap 1 (issue #884) — HTTP `If-Match: <version>`
//! header → 409 CONFLICT envelope end-to-end coverage.
//!
//! Pins the wire shape the substrate documents in CLAUDE.md and the
//! gap-1 release notes: a `PUT /api/v1/memories/:id` carrying
//! `If-Match: <version>` MUST refuse the mutation with a 409 status +
//! a structured JSON envelope naming both the expected + current
//! versions so the caller can re-read and retry. When the header is
//! absent (legacy v0.6.x callers) the mutation lands without any
//! gate, preserving back-compat.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{Memory, Tier};

/// Mirror of the build helper used by every other HTTP integration
/// test (e.g. `tests/round2_f9_http_400.rs`). Stands up a router with
/// the keyword tier (no embedder, no federation) so the only moving
/// parts are the JSON extractor + storage layer.
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
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// Seed a single memory directly through the substrate so the test
/// has a stable id + version=1 starting point.
fn seed(path: &std::path::Path, title: &str) -> String {
    let conn = ai_memory::db::open(path).expect("reopen for seed");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        content: "v1 body".to_string(),
        namespace: "ifmatch-test".to_string(),
        tier: Tier::Mid,
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("insert")
}

async fn put_with_if_match(
    router: &axum::Router,
    id: &str,
    if_match: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/memories/{id}"))
        .header("content-type", "application/json");
    if let Some(v) = if_match {
        req = req.header("if-match", v);
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_put_with_matching_if_match_succeeds() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "match-success");
    // Baseline version is 1 (newly inserted row).
    let (status, body) = put_with_if_match(
        &router,
        &id,
        Some("1"),
        json!({"content": "v2 body via match"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "matching If-Match must produce 200, got {status}: {body}"
    );
    assert_eq!(body["content"].as_str(), Some("v2 body via match"));
    assert_eq!(body["version"].as_i64(), Some(2), "version bumped");
}

#[tokio::test]
async fn http_put_with_stale_if_match_returns_409_with_envelope() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "stale-conflict");
    // First write lands at version=2.
    let _ = put_with_if_match(
        &router,
        &id,
        Some("1"),
        json!({"content": "winner from caller A"}),
    )
    .await;
    // Second caller still believes the row is at version=1.
    let (status, body) = put_with_if_match(
        &router,
        &id,
        Some("1"),
        json!({"content": "loser from caller B"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale If-Match must produce 409, got {status}: {body}"
    );
    assert_eq!(body["status"].as_str(), Some("conflict"));
    assert_eq!(body["id"].as_str(), Some(id.as_str()));
    assert_eq!(body["expected_version"].as_i64(), Some(1));
    assert_eq!(
        body["current_version"].as_i64(),
        Some(2),
        "envelope must name the current stored version so caller can re-read + retry"
    );
}

#[tokio::test]
async fn http_put_without_if_match_preserves_legacy_last_write_wins() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "no-header");
    // Two updates without `If-Match` both succeed — the gate is
    // strictly opt-in. The version column still advances internally so
    // a later If-Match caller will see the latest value.
    let (a, _) = put_with_if_match(&router, &id, None, json!({"content": "a"})).await;
    let (b, _) = put_with_if_match(&router, &id, None, json!({"content": "b"})).await;
    assert_eq!(a, StatusCode::OK, "first update: {a}");
    assert_eq!(b, StatusCode::OK, "second update: {b}");
}

#[tokio::test]
async fn http_put_with_quoted_if_match_etag_style_value_parses() {
    // The header value may arrive ETag-style with surrounding quotes
    // (`If-Match: "1"`). The handler trims them before parsing the
    // int — pin that behaviour so a future strict-parser refactor is
    // loud.
    let (router, file) = build_test_router();
    let id = seed(file.path(), "etag-quoted");
    let (status, body) = put_with_if_match(
        &router,
        &id,
        Some("\"1\""),
        json!({"content": "etag-quoted body"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "quoted If-Match value should parse: {status}: {body}"
    );
}

/// #4061 — a PRESENT `If-Match` that names no version used to be read as
/// "no precondition": the compare-and-swap fence vanished and the stale
/// write landed. It is now refused with 400 and the row is left untouched
/// (fail closed; data integrity over convenience). The RFC 9110 wildcard
/// `*` ("any current representation") still means last-write-wins.
#[tokio::test]
async fn http_put_with_unparseable_if_match_is_refused_4061() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "bogus-header");
    for bogus in ["not-an-integer", "W/\"1\"", "1.5", "99999999999999999999"] {
        let (status, body) = put_with_if_match(
            &router,
            &id,
            Some(bogus),
            json!({"content": "stale overwrite"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "If-Match {bogus:?} must be refused, not silently dropped: {body}"
        );
    }
    let conn = ai_memory::db::open(file.path()).expect("reopen");
    let row = ai_memory::db::get(&conn, &id)
        .expect("get")
        .expect("row still present");
    assert_eq!(row.content, "v1 body", "a refused If-Match must not write");
    assert_eq!(
        row.version, 1,
        "a refused If-Match must not bump the version"
    );
}

#[tokio::test]
async fn http_put_with_wildcard_if_match_is_last_write_wins_4061() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "wildcard-header");
    let (status, body) =
        put_with_if_match(&router, &id, Some("*"), json!({"content": "any"})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "If-Match: * is no precondition: {body}"
    );
}

/// PUT with an arbitrary list of raw `If-Match` field lines (0..n).
async fn put_with_if_match_lines(
    router: &axum::Router,
    id: &str,
    lines: &[&[u8]],
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/memories/{id}"))
        .header("content-type", "application/json");
    for line in lines {
        req = req.header(
            "if-match",
            axum::http::HeaderValue::from_bytes(line).expect("header value"),
        );
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// #4061 (R10 retest gap) — the WHOLE received `If-Match` field is parsed
/// strictly. A repeated field line (RFC 9110 §5.2 combines them; `*` mixed
/// with a tag is invalid), a comma list, unbalanced / stray / doubled
/// quotes, a weak `W/` tag, signs, inner whitespace and an empty value are
/// all refused with 400 and write nothing. Pre-fix the first field line
/// alone was read (`*` then `"0"` wrote unconditionally) and edge quotes
/// were trimmed arbitrarily (`"1` read as version 1 and wrote).
#[tokio::test]
async fn http_put_with_multiple_or_malformed_if_match_is_refused_4061() {
    let (router, file) = build_test_router();
    let id = seed(file.path(), "strict-if-match");
    let cases: &[&[&[u8]]] = &[
        // multiple field lines
        &[b"*", b"\"0\""],
        &[b"\"1\"", b"\"1\""],
        &[b"1", b"1"],
        &[b"*", b"*"],
        // comma lists
        &[b"\"1\", \"2\""],
        &[b"*, \"1\""],
        &[b"1,1"],
        &[b"1,"],
        // unbalanced / stray / doubled quotes
        &[b"\"1"],
        &[b"1\""],
        &[b"\"\"1\"\""],
        &[b"\""],
        &[b"\"\""],
        &[b"\"1\"\""],
        // weak tags (If-Match uses strong comparison)
        &[b"W/\"1\""],
        &[b"w/\"1\""],
        &[b"W/1"],
        // signs, whitespace inside the tag, empty, non-ASCII
        &[b"+1"],
        &[b"-1"],
        &[b"\" 1\""],
        &[b"1 2"],
        &[b""],
        &[b"\xc2\xb9"],
    ];
    for lines in cases {
        let (status, body) =
            put_with_if_match_lines(&router, &id, lines, json!({"content": "clobber"})).await;
        let shown: Vec<String> = lines
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "If-Match {shown:?} must be refused before any write: {body}"
        );
    }
    let conn = ai_memory::db::open(file.path()).expect("reopen");
    let row = ai_memory::db::get(&conn, &id)
        .expect("get")
        .expect("row present");
    assert_eq!(row.content, "v1 body", "no malformed If-Match may write");
    assert_eq!(row.version, 1, "no malformed If-Match may bump the version");

    // Controls on the same row: a single bare / quoted current version and
    // surrounding whitespace are accepted; a single stale tag is a 409.
    let (status, body) =
        put_with_if_match_lines(&router, &id, &[b" \"1\" "], json!({"content": "v2"})).await;
    assert_eq!(status, StatusCode::OK, "quoted current version: {body}");
    let (status, body) =
        put_with_if_match_lines(&router, &id, &[b"2"], json!({"content": "v3"})).await;
    assert_eq!(status, StatusCode::OK, "bare current version: {body}");
    let (status, body) =
        put_with_if_match_lines(&router, &id, &[b"\"1\""], json!({"content": "stale"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "single stale tag: {body}");
}
