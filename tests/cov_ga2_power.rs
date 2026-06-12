// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov_ga2_power — CodeGraph-directed coverage backfill for the three
//! "power" surfaces below 90% line coverage at the GA-2 measurement
//! (`.local-runs/ga-session-0611/gaps/`):
//!
//! * [`ai_memory::handlers`] `power.rs` — the LLM-adjacent /
//!   computation-heavy HTTP handlers `check_duplicate`,
//!   `detect_contradictions`, `get_taxonomy` (+ `list_namespaces`).
//! * [`ai_memory::handlers`] `power_consolidation.rs` —
//!   `consolidate_memories`, `auto_tag_handler`, `expand_query_handler`,
//!   `load_family_handler`, plus the `fetch_memory_for_handler` /
//!   `resolve_consolidate_summary` / `default_ns` helpers.
//! * [`ai_memory::mcp`] `tools/store/mod.rs` — the `handle_store`
//!   dispatch arms (driven through the `handle_store_for_tests`
//!   shim), including the federation-forward bridge error path.
//!
//! Method (per the GA coverage standard): codegraph-directed
//! reachability + oracle-STRONG assertions. The HTTP surfaces ride the
//! real production router (`ai_memory::build_router`) over an in-memory
//! / on-disk sqlite store via `tower::oneshot`, mirroring
//! `tests/cov3_handlers_sqlite.rs`. The MCP `handle_store` surface
//! rides the public `ai_memory::mcp::tools::handle_store_for_tests`
//! entry, mirroring `tests/store_legacy_classifier_paths.rs`.
//!
//! CI runs postgres+AGE but NO LLM service, so the LLM-backed arms of
//! `auto_tag_handler` / `expand_query_handler` / the consolidate
//! auto-summary are covered at their NO-LLM-configured reachable arm
//! (the `app.llm.is_none()` 503 early-return and the deterministic
//! concat fallback). The lines reachable ONLY with a live LLM client
//! are documented as structural exceptions in the module header of the
//! deliverable report — they are not faked here.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_update)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

// ---------------------------------------------------------------------------
// Harness — production router over a fresh sqlite DB. Mirrors
// `tests/cov3_handlers_sqlite.rs::sqlite_router`. The `admin_ids`
// parameter lets the admin-gated `get_taxonomy` / `list_namespaces`
// happy paths be exercised (empty = the secure-default 403 arm).
// ---------------------------------------------------------------------------

const TESTER_AGENT: &str = "ai:cov-ga2-tester";

fn build_state(db_path: &std::path::Path, admin_ids: Vec<String>) -> AppState {
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
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
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore")),
        llm: Arc::new(None),
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
        admin_agent_ids: Arc::new(admin_ids),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    }
}

/// Default (non-admin) router — empty admin allowlist, no api_key.
fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let _ = ai_memory::db::open(db_tmp.path()).expect("db::open");
    let app_state = build_state(db_tmp.path(), Vec::new());
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

/// Admin router — the tester agent is allowlisted AND the process-wide
/// `request_authn_configured` flag is set, so the `require_admin`
/// gate (`is_admin_caller_trusted`) admits the tester. This lets the
/// admin-gated `get_taxonomy` / `list_namespaces` success arms run.
fn admin_router() -> (axum::Router, tempfile::NamedTempFile) {
    // #1570 — the admin-role gate honors the self-asserted X-Agent-Id
    // header only when the daemon has request authentication configured.
    // The flag is a process-wide atomic set once at boot; tests model an
    // authenticated deployment by flipping it on.
    ai_memory::handlers::mark_request_authn_configured(true);
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let _ = ai_memory::db::open(db_tmp.path()).expect("db::open");
    let app_state = build_state(db_tmp.path(), vec![TESTER_AGENT.to_string()]);
    let api_key_state = ApiKeyState {
        key: Some("cov-ga2-key".to_string()),
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", TESTER_AGENT)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", TESTER_AGENT)
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn get_keyed(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", TESTER_AGENT)
        .header("x-api-key", "cov-ga2-key")
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Store a memory via the production `POST /api/v1/memories` route so
/// downstream power handlers (consolidate / contradictions / taxonomy)
/// have a real row to operate on. Returns the new id.
async fn create_memory(
    router: &axum::Router,
    title: &str,
    content: &str,
    namespace: &str,
) -> String {
    // Always present the api-key header so this helper works on both the
    // keyless default router (header ignored) and the keyed admin router
    // (middleware demands it before the handler runs).
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", TESTER_AGENT)
        .header("x-api-key", "cov-ga2-key")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "title": title,
                "content": content,
                "namespace": namespace,
                "tier": "long",
            }))
            .unwrap(),
        ))
        .unwrap();
    let (status, body) = decode(router, req).await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create_memory {title} returned {status}: {body}"
    );
    body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create_memory {title} response missing id: {body}"))
        .to_string()
}

// ===========================================================================
// power.rs — check_duplicate
// ===========================================================================

#[tokio::test]
async fn check_duplicate_invalid_title_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": "", "content": "some body"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("title"),
        "error should name title: {body}"
    );
}

#[tokio::test]
async fn check_duplicate_invalid_content_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": "valid title", "content": ""}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("content")
    );
}

#[tokio::test]
async fn check_duplicate_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({"title": "valid title", "content": "valid body content", "namespace": "bad ns!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn check_duplicate_no_embedder_is_503() {
    // The cov harness wires `embedder: None`, so the sqlite branch hits
    // the "requires the embedder" 503 arm (the reachable terminal state
    // for a keyword-tier daemon).
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/check_duplicate",
        json!({
            "title": "Quarterly OKR review",
            "content": "We shipped the recall pipeline and closed the coverage lane.",
            "namespace": "alpha",
            "threshold": 0.8
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("embedder"),
        "503 body should name the embedder requirement: {body}"
    );
}

// ===========================================================================
// power.rs — detect_contradictions
// ===========================================================================

#[tokio::test]
async fn contradictions_missing_topic_and_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/contradictions").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("topic"),
        "error should mention the topic/namespace requirement: {body}"
    );
}

#[tokio::test]
async fn contradictions_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/contradictions?namespace=bad%20ns").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn contradictions_empty_namespace_is_200_empty() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/contradictions?namespace=emptyns").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("memories").is_some(),
        "envelope has memories: {body}"
    );
    assert!(body.get("links").is_some());
    assert_eq!(
        body["memories"].as_array().map(Vec::len),
        Some(0),
        "no rows seeded in this ns yet"
    );
}

#[tokio::test]
async fn contradictions_synthesizes_pairwise_links_on_topic() {
    let (r, _t) = sqlite_router();
    // Two memories sharing a topic but with materially different
    // content → the pairwise heuristic synthesizes a `contradicts` link.
    let ns = "contra-ns";
    let _a = post_json(
        &r,
        "/api/v1/memories",
        json!({
            "title": "deadline-A",
            "content": "Launch ships on the 1st of next month, no slip.",
            "namespace": ns,
            "tier": "long",
            "metadata": {"topic": "launch-date"}
        }),
    )
    .await;
    let _b = post_json(
        &r,
        "/api/v1/memories",
        json!({
            "title": "deadline-B",
            "content": "Launch is delayed to the following quarter per the steering review.",
            "namespace": ns,
            "tier": "long",
            "metadata": {"topic": "launch-date"}
        }),
    )
    .await;
    let (status, body) = get(
        &r,
        "/api/v1/contradictions?topic=launch-date&namespace=contra-ns",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mems = body["memories"].as_array().expect("memories array");
    assert_eq!(
        mems.len(),
        2,
        "both topic-matched candidates returned: {body}"
    );
    let links = body["links"].as_array().expect("links array");
    assert_eq!(links.len(), 1, "one synthesized pairwise contradicts link");
    assert_eq!(links[0]["relation"], "contradicts");
    assert_eq!(links[0]["synthesized"], true);
}

#[tokio::test]
async fn contradictions_no_topic_groups_by_title() {
    let (r, _t) = sqlite_router();
    // No topic → the None arm; candidates filtered only by visibility,
    // pairwise synth keyed on identical title (none collide here).
    let ns = "contra-title-ns";
    create_memory(&r, "alpha-row", "first distinct body of text", ns).await;
    create_memory(&r, "beta-row", "second distinct body of text", ns).await;
    let (status, body) = get(&r, "/api/v1/contradictions?namespace=contra-title-ns").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["memories"].as_array().map(Vec::len), Some(2));
    // Distinct titles → no synthesized links.
    assert_eq!(body["links"].as_array().map(Vec::len), Some(0));
}

// ===========================================================================
// power.rs — get_taxonomy + list_namespaces (admin-gated)
// ===========================================================================

#[tokio::test]
async fn taxonomy_without_admin_is_403() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/taxonomy").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("admin"),
        "non-admin caller refused: {body}"
    );
}

#[tokio::test]
async fn list_namespaces_without_admin_is_403() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/namespaces").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn taxonomy_admin_happy_path_is_200() {
    let (r, _t) = admin_router();
    // Seed a small hierarchy so the tree-fold produces nodes + counts.
    create_memory(&r, "root-mem", "root level memory body", "proj").await;
    create_memory(&r, "child-mem", "child level memory body", "proj/sub").await;
    create_memory(&r, "leaf-mem", "leaf level memory body", "proj/sub/leaf").await;

    let (status, body) = get_keyed(&r, "/api/v1/taxonomy?prefix=proj&depth=8&limit=100").await;
    assert_eq!(status, StatusCode::OK, "admin taxonomy: {body}");
    assert!(body.get("tree").is_some(), "tree present: {body}");
    assert!(body.get("total_count").is_some());
    assert!(body.get("truncated").is_some());
    // The prefix-rooted tree's root node is `proj`.
    assert_eq!(body["tree"]["namespace"], "proj");
    assert!(
        body["total_count"].as_u64().unwrap_or(0) >= 3,
        "all three seeded rows counted: {body}"
    );
}

#[tokio::test]
async fn taxonomy_admin_invalid_prefix_is_400() {
    let (r, _t) = admin_router();
    let (status, body) = get_keyed(&r, "/api/v1/taxonomy?prefix=bad%20ns").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("namespace"),
        "invalid prefix surfaced: {body}"
    );
}

#[tokio::test]
async fn taxonomy_admin_root_alias_and_no_prefix() {
    let (r, _t) = admin_router();
    create_memory(&r, "aliased", "memory under the aliased namespace", "fleet").await;
    // `?root=` alias resolves to the same path as `?prefix=`.
    let (status, body) = get_keyed(&r, "/api/v1/taxonomy?root=fleet").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tree"]["namespace"], "fleet");

    // No prefix at all → whole-tree walk rooted at "".
    let (status2, body2) = get_keyed(&r, "/api/v1/taxonomy").await;
    assert_eq!(status2, StatusCode::OK);
    assert!(body2.get("tree").is_some());
}

#[tokio::test]
async fn list_namespaces_admin_happy_path_is_200() {
    let (r, _t) = admin_router();
    create_memory(&r, "ns-seed", "a memory so a namespace exists", "fleet-a").await;
    let (status, body) = get_keyed(&r, "/api/v1/namespaces").await;
    assert_eq!(status, StatusCode::OK, "admin namespaces: {body}");
    let arr = body["namespaces"].as_array().expect("namespaces array");
    // The sqlite branch returns `{namespace, count}` objects.
    assert!(
        arr.iter().any(|v| v
            .get("namespace")
            .and_then(Value::as_str)
            .or_else(|| v.as_str())
            == Some("fleet-a")),
        "seeded namespace present: {body}"
    );
}

// ===========================================================================
// power_consolidation.rs — consolidate_memories (+ resolve_consolidate_summary
// no-LLM fallback, fetch_consolidate_source_pairs, default_ns)
// ===========================================================================

#[tokio::test]
async fn consolidate_invalid_ids_is_400() {
    let (r, _t) = sqlite_router();
    // No ids + summary supplied → validate_consolidate rejects the empty
    // ids list at the validator arm (summary present skips the LLM path).
    let (status, _b) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({"ids": [], "title": "merged", "summary": "a supplied summary string here"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consolidate_missing_source_id_is_400() {
    let (r, _t) = sqlite_router();
    // No summary → resolve_consolidate_summary fetches source pairs;
    // a missing id short-circuits to 400 naming the offending id.
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({"ids": ["ghost-id-1", "ghost-id-2"], "title": "merge"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("ghost-id-1")
            || body["error"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .contains("not found"),
        "missing-source error: {body}"
    );
}

#[tokio::test]
async fn consolidate_no_llm_deterministic_summary_is_201() {
    let (r, _t) = sqlite_router();
    // Two real rows, NO summary supplied, NO LLM wired → the
    // deterministic concat-of-titles fallback in
    // resolve_consolidate_summary materializes the summary and the row
    // lands. Also exercises default_ns (namespace omitted).
    let id1 = create_memory(
        &r,
        "fact one about the project",
        "body one with enough length",
        "consol",
    )
    .await;
    let id2 = create_memory(
        &r,
        "fact two about the project",
        "body two with enough length",
        "consol",
    )
    .await;
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({"ids": [id1, id2], "title": "Consolidated project facts"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "consolidate 201: {body}");
    assert!(body["id"].is_string());
    assert_eq!(body["consolidated"], 2);
    let summary = body["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("Consolidated summary of 2 memories"),
        "deterministic fallback summary: {body}"
    );
    // L7-followup mirror fields.
    assert_eq!(body["content"], body["summary"]);
    assert_eq!(body["memory"]["title"], "Consolidated project facts");
}

#[tokio::test]
async fn consolidate_supplied_summary_is_201() {
    let (r, _t) = sqlite_router();
    let id1 = create_memory(&r, "alpha source", "alpha body long enough", "consol2").await;
    let id2 = create_memory(&r, "beta source", "beta body long enough", "consol2").await;
    let (status, body) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "Merged with explicit summary",
            "summary": "This is the operator-supplied consolidation summary text.",
            "namespace": "consol2",
            "tier": "long"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "consolidate 201: {body}");
    assert_eq!(
        body["summary"],
        "This is the operator-supplied consolidation summary text."
    );
}

#[tokio::test]
async fn consolidate_agent_id_body_mismatch_is_403() {
    let (r, _t) = sqlite_router();
    let id1 = create_memory(&r, "src-a", "body a long enough text", "consol3").await;
    let id2 = create_memory(&r, "src-b", "body b long enough text", "consol3").await;
    // body.agent_id != authenticated X-Agent-Id → 403 provenance guard.
    let (status, _b) = post_json(
        &r,
        "/api/v1/consolidate",
        json!({
            "ids": [id1, id2],
            "title": "merge attempt",
            "summary": "a supplied summary string of sufficient length",
            "namespace": "consol3",
            "agent_id": "ai:someone-else"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ===========================================================================
// power_consolidation.rs — auto_tag_handler (NO-LLM reachable arm)
// ===========================================================================

#[tokio::test]
async fn auto_tag_no_llm_is_503() {
    // CI has no LLM service; the cov harness wires `llm: None` → the
    // `app.llm.is_none()` early-return 503 is the reachable terminal
    // arm. The LLM-success / LLM-error / timeout arms are live-LLM-only
    // (documented structural exceptions).
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/auto_tag",
        json!({"title": "some title", "content": "some content to tag"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "LLM not configured");
}

// ===========================================================================
// power_consolidation.rs — expand_query_handler (NO-LLM + validation arms)
// ===========================================================================

#[tokio::test]
async fn expand_query_no_llm_is_503() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/expand_query",
        json!({"query": "kubernetes rollout strategy"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "LLM not configured");
}

// ===========================================================================
// power_consolidation.rs — load_family_handler (sqlite branch + validation)
// ===========================================================================

#[tokio::test]
async fn load_family_unknown_family_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "not-a-real-family"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.get("error").is_some());
}

#[tokio::test]
async fn load_family_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": "bad ns!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn load_family_valid_is_200() {
    let (r, _t) = sqlite_router();
    // Seed a memory tagged with a `family` metadata field so the
    // sqlite handle_load_family path returns it.
    let _ = post_json(
        &r,
        "/api/v1/memories",
        json!({
            "title": "core-tagged",
            "content": "a memory that belongs to the core family",
            "namespace": "famns",
            "tier": "long",
            "metadata": {"family": "core"}
        }),
    )
    .await;
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_load_family",
        json!({"family": "core", "namespace": "famns", "k": 10}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "load_family 200: {body}");
    assert_eq!(body["family"], "core");
    assert!(body.get("memories").is_some());
    assert!(body.get("count").is_some());
}

#[tokio::test]
async fn load_family_default_k_no_namespace_is_200() {
    let (r, _t) = sqlite_router();
    // Omit namespace + k → exercises the k-default (20) clamp and the
    // namespace-None scan-all branch.
    let (status, body) =
        post_json(&r, "/api/v1/memory_load_family", json!({"family": "graph"})).await;
    assert_eq!(status, StatusCode::OK, "load_family 200: {body}");
    assert_eq!(body["family"], "graph");
}

// ===========================================================================
// mcp/tools/store/mod.rs — handle_store dispatch arms via the
// public `handle_store_for_tests` shim (mirrors
// tests/store_legacy_classifier_paths.rs).
// ===========================================================================

use ai_memory::embeddings::Embed;
use ai_memory::hnsw::VectorIndex;

/// Local test embedder — the `#[cfg(test)]`-gated `MockEmbedder` in
/// `src/embeddings.rs` is not visible to an integration-test crate, so
/// we implement the public `Embed` trait directly here. Returns a
/// FIXED 8-dim vector regardless of input text, so any two writes are
/// cosine 1.0 — exactly what the store proactive-conflict guard needs
/// to fire (near-duplicate + differing content).
struct ConstEmbed;

impl Embed for ConstEmbed {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Ok(vec![0.5_f32; 8])
    }
    fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|_| vec![0.5_f32; 8]).collect())
    }
}

/// Always-`Err` embedder — exercises the `emb.embed(...)` failure
/// branch in `handle_store` (the conflict-check embed call that errors
/// then falls through without refusing the write).
struct FailEmbed;

impl Embed for FailEmbed {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Err(anyhow::anyhow!("cov-ga2: synthetic embed failure"))
    }
    fn embed_batch(&self, _texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        Err(anyhow::anyhow!("cov-ga2: synthetic embed_batch failure"))
    }
}

fn store_conn() -> rusqlite::Connection {
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("in-memory db")
}

fn store_db_path() -> std::path::PathBuf {
    std::path::PathBuf::from(":memory:")
}

fn store_params(title: &str, namespace: &str) -> Value {
    json!({
        "title": title,
        "content": format!(
            "Body of {title}: a sufficiently long prose body so the synthesis \
             and autonomy content-length gates can be evaluated end to end."
        ),
        "namespace": namespace,
        "tier": "mid",
        "tags": ["cov"],
        "priority": 5,
        "confidence": 0.9,
        "source": "api",
        "agent_id": "ai:store-cov",
    })
}

#[test]
fn store_happy_path_no_embedder() {
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("alpha-fact", "store-ns"),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("store ok");
    assert!(resp["id"].is_string());
    assert_eq!(resp["title"], "alpha-fact");
    assert_eq!(resp["agent_id"], "ai:store-cov");
    assert_eq!(resp["namespace"], "store-ns");
}

#[test]
fn store_with_embedder_warms_index() {
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let mock = ConstEmbed;
    let idx = VectorIndex::empty();
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("embedded-fact", "store-emb-ns"),
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("store ok");
    assert!(resp["id"].is_string());
}

#[test]
fn store_proactive_conflict_refuses_near_duplicate() {
    // With an embedder wired and force unset, a second write whose
    // embedding is a near-duplicate (MockEmbedder vectors are
    // near-parallel) of an existing row with DIFFERING content is
    // refused with a CONFLICT: prefix (store/mod.rs proactive-conflict
    // arm). Exercises db::proactive_conflict_check_with_index Some().
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let mock = ConstEmbed;
    let idx = VectorIndex::empty();
    // First write lands.
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("conflict-anchor", "conflict-ns"),
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("anchor store ok");
    // Second write — distinct title (no dedup) but a near-parallel
    // embedding + differing content → the proactive conflict guard fires.
    let err = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("conflict-rival", "conflict-ns"),
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect_err("near-duplicate must be refused");
    assert!(
        err.starts_with("CONFLICT:"),
        "proactive conflict refusal prefix: {err}"
    );
}

#[test]
fn store_force_bypasses_proactive_conflict() {
    // force=true skips the proactive conflict check (the `!force_write`
    // guard false-branch), so the near-duplicate write lands.
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let mock = ConstEmbed;
    let idx = VectorIndex::empty();
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("forced-anchor", "forced-ns"),
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("anchor ok");
    let mut p = store_params("forced-rival", "forced-ns");
    p["force"] = json!(true);
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &p,
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("forced write must land despite near-duplicate");
    assert!(resp["id"].is_string());
}

#[test]
fn store_merge_on_conflict_updates_existing() {
    // on_conflict=merge + identical (title, namespace) → the exact-dup
    // update branch (store/mod.rs merge-dedup arm), echoing
    // duplicate:true and the preserved original agent_id.
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let mut first = store_params("merge-target", "merge-ns");
    first["on_conflict"] = json!("merge");
    let r1 = ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &dbp, &first, None, None, None, &ttl, false, None, None,
    )
    .expect("first ok");
    let original_id = r1["id"].as_str().unwrap().to_string();

    let mut second = store_params("merge-target", "merge-ns");
    second["on_conflict"] = json!("merge");
    second["content"] = json!("Updated body content that differs from the first write entirely.");
    second["agent_id"] = json!("ai:different-writer");
    let r2 = ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &dbp, &second, None, None, None, &ttl, false, None, None,
    )
    .expect("merge update ok");
    assert_eq!(r2["duplicate"], true, "merge dedup hit: {r2}");
    assert_eq!(r2["id"].as_str(), Some(original_id.as_str()));
    // Provenance is immutable — original agent_id preserved over the
    // second writer's claim.
    assert_eq!(r2["agent_id"], "ai:store-cov");
    assert_eq!(r2["action"], "updated existing memory");
}

#[test]
fn store_merge_with_embedder_regenerates_embedding() {
    // Merge-dedup with an embedder wired + content changed → the
    // content_changed embedding-regeneration branch fires.
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let mock = ConstEmbed;
    let idx = VectorIndex::empty();
    let mut first = store_params("merge-emb", "merge-emb-ns");
    first["on_conflict"] = json!("merge");
    first["force"] = json!(true);
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &first,
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("first ok");
    let mut second = store_params("merge-emb", "merge-emb-ns");
    second["on_conflict"] = json!("merge");
    second["force"] = json!(true);
    second["content"] = json!("A wholly different body so content_changed is true on update.");
    let r2 = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &second,
        Some(&mock as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("merge update ok");
    assert_eq!(r2["duplicate"], true);
}

#[test]
fn store_failing_embedder_skips_conflict_check() {
    // A FailingEmbedder makes emb.embed(...) error → the inner
    // `if let Ok(query_embedding)` false-branch; the store still lands
    // (no conflict check could run). Exercises the embed-error arm.
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    let failing = FailEmbed;
    let idx = VectorIndex::empty();
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("failing-emb", "fail-ns"),
        Some(&failing as &dyn Embed),
        None,
        Some(&idx),
        &ttl,
        false,
        None,
        None,
    )
    .expect("store lands despite embed failure");
    assert!(resp["id"].is_string());
}

#[test]
fn store_federation_forward_unreachable_is_err() {
    // A forward_url pointing at a closed loopback port drives the
    // `forward_store_to_http` → `forward_to_http` send() error arm
    // (store/mod.rs transport bridge). The structured error names the
    // forward URL so operators can distinguish "fanout down".
    let conn = store_conn();
    let dbp = store_db_path();
    let ttl = ResolvedTtl::default();
    // 127.0.0.1:1 — reserved/closed; connect refuses immediately.
    let err = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &dbp,
        &store_params("forwarded", "fwd-ns"),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        Some("http://127.0.0.1:1"),
    )
    .expect_err("forward to a closed port must error");
    assert!(
        err.contains("federation_forward"),
        "forward error names the bridge: {err}"
    );
}
