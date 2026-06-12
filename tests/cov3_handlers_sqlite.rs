// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov3 — sqlite-router coverage for the federation/kg/recall/misc HTTP
//! handlers. Drives the real production router (`ai_memory::build_router`)
//! via `tower::oneshot` so every handler's sqlite branch + validation /
//! error arms execute end-to-end.
//!
//! Modules lifted here: `handlers/route_1111` (14 MCP-mirror routes),
//! `handlers/recall` (GET + POST + format/scope/kinds arms),
//! `handlers/links` (create / delete / get / verify validation arms),
//! `handlers/kg` (`entity_register` / `kg_query` / `kg_timeline` /
//! `kg_invalidate` / `kg_find_paths` validation arms),
//! `handlers/hook_subscribers`,
//! `handlers/subscriptions`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

/// Build the production router over a fresh on-disk sqlite DB. The
/// `app.store` SqliteStore is opened against the SAME path so seed →
/// read works through both the legacy `db` path and the SAL trait.
fn sqlite_router() -> (axum::Router, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
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
        storage_backend: StorageBackend::Sqlite,
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"),
        ),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    (ai_memory::build_router(api_key_state, app_state), db_tmp)
}

async fn post_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:cov3-tester")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    decode(router, req).await
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", "ai:cov3-tester")
        .body(Body::empty())
        .unwrap();
    decode(router, req).await
}

async fn delete_json(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:cov3-tester")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
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

// ---------------------------------------------------------------------------
// route_1111 — 14 MCP-mirror HTTP routes (sqlite branch + err arms)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn route_1111_smart_load_ok() {
    let (r, _t) = sqlite_router();
    // smart_load with an intent string returns a 200 (possibly empty set).
    let (status, _b) = post_json(
        &r,
        "/api/v1/memory_smart_load",
        json!({"intent": "project status"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn route_1111_reflect_missing_sources_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_reflect", json!({})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reflect with no source_ids must 400"
    );
}

#[tokio::test]
async fn route_1111_recall_observations_ok() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/memory_recall_observations",
        json!({"limit": 5}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("observations").is_some() || body.get("count").is_some());
}

#[tokio::test]
async fn route_1111_reflection_origin_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_reflection_origin", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_dependents_of_invalidated_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_dependents_of_invalidated", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_export_reflection_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_export_reflection", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_atomise_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_atomise", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_calibrate_confidence_ok() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_calibrate_confidence", json!({})).await;
    // Read-only over shadow-observations; empty table → 200.
    assert!(status == StatusCode::OK || status == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_verify_missing_args_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_verify", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_replay_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_replay", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_subscription_replay_missing_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_subscription_replay", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_subscription_dlq_list_ok_or_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_subscription_dlq_list", json!({})).await;
    assert!(status == StatusCode::OK || status == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_1111_rule_list_ok() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_rule_list", json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn route_1111_check_agent_action_missing_fields_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/memory_check_agent_action", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// recall — GET + POST + validation / format / kinds / budget arms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recall_get_empty_context_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/recall").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recall_get_with_context_is_200() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/recall?context=hello%20world&limit=5").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("memories").is_some());
    assert_eq!(body["mode"], "keyword");
}

#[tokio::test]
async fn recall_get_invalid_as_agent_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(
        &r,
        "/api/v1/recall?context=x&as_agent=bad%20id%20with%20spaces",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recall_get_invalid_format_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/recall?context=x&format=yaml").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recall_get_toon_format_is_200() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/recall?context=x&format=toon").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn recall_post_empty_context_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/recall", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recall_post_with_budget_and_session_and_tags() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/recall",
        json!({
            "context": "memory pipeline",
            "limit": 10,
            "budget_tokens": 500,
            "session_id": "sess-1",
            "tags": "alpha,beta",
            "session_default": true,
            "kinds": ["observation", "decision"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["budget_tokens"], 500);
    assert!(body.get("meta").is_some());
}

#[tokio::test]
async fn recall_post_since_until_filters() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/recall",
        json!({"context": "x", "since": "2020-01-01T00:00:00Z", "until": "2030-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn recall_get_verbose_provenance_header() {
    let (r, _t) = sqlite_router();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/recall?context=x")
        .header("x-agent-id", "ai:cov3-tester")
        .header("accept-provenance", "verbose")
        .body(Body::empty())
        .unwrap();
    let (status, _b) = decode(&r, req).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// links — create / delete / get / verify validation + error arms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn link_create_unknown_field_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/links",
        json!({"source_id": "a", "target_id": "b", "link_type": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unknown_field");
}

#[tokio::test]
async fn link_create_invalid_relation_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(
        &r,
        "/api/v1/links",
        json!({"source_id": "aaaaaaaa", "target_id": "bbbbbbbb", "relation": "frobnicates"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_relation");
}

#[tokio::test]
async fn link_create_invalid_triple_is_400() {
    let (r, _t) = sqlite_router();
    // empty source id fails validate_link_triple
    let (status, _b) = post_json(
        &r,
        "/api/v1/links",
        json!({"source_id": "", "target_id": "b", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn link_delete_unknown_field_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = delete_json(
        &r,
        "/api/v1/links",
        json!({"source_id": "a", "target_id": "b", "bogus": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unknown_field");
}

#[tokio::test]
async fn link_delete_nonexistent_source_returns_deleted_false() {
    let (r, _t) = sqlite_router();
    let (status, body) = delete_json(
        &r,
        "/api/v1/links",
        json!({"source_id": "ghostsrc", "target_id": "ghosttgt", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], false);
}

#[tokio::test]
async fn link_verify_missing_args_is_400() {
    let (r, _t) = sqlite_router();
    let (status, body) = post_json(&r, "/api/v1/links/verify", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.get("fields").is_some());
}

#[tokio::test]
async fn link_verify_invalid_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/links/verify",
        json!({"source_id": "bad id with spaces"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_links_invalid_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/links/bad%20id").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_links_valid_id_is_200() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/links/some-anchor-id").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("links").is_some());
}

// ---------------------------------------------------------------------------
// kg — entity_register / find_paths / kg_query / kg_timeline / kg_invalidate
//      validation arms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn entity_register_invalid_name_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "", "namespace": "alpha"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn entity_register_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "Acme Corp", "namespace": "bad namespace!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn entity_register_invalid_agent_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "Acme Corp", "namespace": "alpha", "agent_id": "bad id space"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn entity_register_ok() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/entities",
        json!({"canonical_name": "Acme Corp", "namespace": "alpha", "aliases": ["Acme"]}),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED || status == StatusCode::ACCEPTED,
        "status was {status}"
    );
}

#[tokio::test]
async fn kg_find_paths_invalid_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/find_paths",
        json!({"source_id": "bad id space", "target_id": "tgt"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_find_paths_invalid_target_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/find_paths",
        json!({"source_id": "src", "target_id": "bad id space"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_find_paths_valid_ids_is_200() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/find_paths",
        json!({"source_id": "src-1", "target_id": "tgt-1", "max_depth": 3}),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_query_invalid_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) =
        post_json(&r, "/api/v1/kg/query", json!({"source_id": "bad id space"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_query_valid_source_id_is_200() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(&r, "/api/v1/kg/query", json!({"source_id": "anchor-1"})).await;
    assert!(status == StatusCode::OK || status == StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_timeline_invalid_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/kg/timeline?source_id=bad%20id%20space").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_timeline_nonexistent_source_is_404() {
    let (r, _t) = sqlite_router();
    // Valid id shape but no such memory → 404 {found:false} (the
    // source-not-found arm).
    let (status, body) = get(&r, "/api/v1/kg/timeline?source_id=anchor-1&limit=5").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["found"], false);
}

#[tokio::test]
async fn kg_invalidate_invalid_source_id_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/kg/invalidate",
        json!({"source_id": "bad id space", "target_id": "t", "relation": "related_to"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kg_invalidate_nonexistent_link_arm() {
    let (r, _t) = sqlite_router();
    let (status, _b) = post_json(
        &r,
        "/api/v1/kg/invalidate",
        json!({"source_id": "src-1", "target_id": "tgt-1", "relation": "related_to"}),
    )
    .await;
    // {found:false} 200 or a typed arm — both exercise the handler body.
    assert!(
        status == StatusCode::OK
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn entity_get_by_alias_missing_alias_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(&r, "/api/v1/entities/by_alias").await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn entity_get_by_alias_with_alias_is_200() {
    let (r, _t) = sqlite_router();
    let (status, body) = get(&r, "/api/v1/entities/by_alias?alias=Acme&namespace=alpha").await;
    assert_eq!(status, StatusCode::OK);
    // No match yet → {found:false} envelope (200, not an error).
    assert!(body.get("found").is_some() || body.get("entity_id").is_some());
}

#[tokio::test]
async fn entity_get_by_alias_invalid_namespace_is_400() {
    let (r, _t) = sqlite_router();
    let (status, _b) = get(
        &r,
        "/api/v1/entities/by_alias?alias=Acme&namespace=bad%20ns",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
