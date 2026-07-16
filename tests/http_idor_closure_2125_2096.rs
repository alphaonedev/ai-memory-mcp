// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2125 (HIGH — destructive-write IDOR) + #2096 (HIGH — identity-sensitive
//! read IDOR) — the COMPLETE H1 IDOR closure across every remaining
//! identity-sensitive route, driven end-to-end through `build_router` (the
//! `api_key_auth` middleware + handler wiring), not just the gate primitive
//! (`tests/http_per_agent_key_binding_2044.rs`).
//!
//! The invariant, for EVERY route below: under `HttpIdentityMode::Enforce`
//! with per-agent keys enrolled, a shared-transport-key caller forging
//! `X-Agent-Id: <victim>` is refused `403 attested_identity_required` BEFORE
//! the ownership / visibility / write check. The legitimately key-bound
//! principal (`alice`) is admitted (never the identity 403). Under
//! `Advisory`, the forged caller is corrected+warned but ADMITTED (no 403),
//! preserving the single-operator zero-config posture.
//!
//! Applies the #2088 gate pattern (`identity_binding::enforce_idor_identity`,
//! reused from get/update/delete/promote in `memories.rs`). See
//! rust-skills `err-result-over-panic` / `type-result-fallible` (the gate
//! returns `Option<Response>` rather than panicking) and M-STRONG-TYPES-GUARD
//! (the `AuthLevel` newtype guards the key-bound invariant).

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "shared-transport-key";
const ALICE_KEY: &str = "alice-per-agent-key";
const VICTIM: &str = "victim";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("issue-2125-2096-idor-closure");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build a router in `mode` with `alice` enrolled as the owner of the
/// `ALICE_KEY` per-agent api-key. The shared transport key (`SHARED_KEY`)
/// authenticates transport but resolves to NO per-agent principal.
fn build_router(mode: HttpIdentityMode) -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));

    let mut enrolled = HashMap::new();
    enrolled.insert(api_key_sha256_hex(ALICE_KEY), "alice".to_string());
    let enrolled = Arc::new(enrolled);

    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
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
        admin_agent_ids: Arc::new(vec!["alice".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: mode,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

/// The complete identity-sensitive route set closed by #2125 (writes) and
/// #2096 (reads), plus the audit-found extras. Each entry drives one real
/// Axum route. Bodies are minimal-but-valid so control reaches the gate
/// (which sits AFTER input validation, BEFORE the owner/visibility check).
fn routes() -> Vec<(&'static str, &'static str, Option<serde_json::Value>)> {
    use serde_json::json;
    let link_body = json!({
        "source_id": "mem-victim-0001",
        "target_id": "mem-victim-0002",
        "relation": "related_to"
    });
    vec![
        // ---- #2125 destructive-write routes ----
        ("POST", "/api/v1/links", Some(link_body.clone())), // create_link
        ("DELETE", "/api/v1/links", Some(link_body.clone())), // delete_link
        ("POST", "/api/v1/kg/invalidate", Some(link_body)), // kg_invalidate
        (
            "POST",
            "/api/v1/archive",
            Some(json!({"ids": ["mem-victim-0001"], "reason": "x"})),
        ), // archive_by_ids
        ("POST", "/api/v1/archive/mem-victim-0001/restore", None), // restore_archive
        // ---- #2096 identity-sensitive read routes ----
        ("GET", "/api/v1/links/mem-victim-0001", None), // get_links
        ("GET", "/api/v1/memories/mem-victim-0001/lineage", None), // get_lineage
        ("GET", "/api/v1/entities/by_alias?alias=secret", None), // entity_get_by_alias
        ("GET", "/api/v1/contradictions?namespace=victimns", None), // detect_contradictions
        (
            "POST",
            "/api/v1/check_duplicate",
            Some(json!({"title": "t", "content": "some content"})),
        ), // check_duplicate
        ("GET", "/api/v1/pending", None),               // list_pending
        // ---- audit-found extras (same H1 IDOR shape) ----
        (
            "POST",
            "/api/v1/consolidate",
            Some(
                json!({"ids": ["mem-victim-0001", "mem-victim-0002"], "title": "t", "summary": "s"}),
            ),
        ), // consolidate_memories
        ("GET", "/api/v1/inbox", None), // get_inbox
        ("GET", "/api/v1/kg/timeline?source_id=mem-victim-0001", None), // kg_timeline
        ("DELETE", "/api/v1/subscriptions?id=sub-1", None), // unsubscribe
        ("GET", "/api/v1/subscriptions", None), // list_subscriptions
        (
            "POST",
            "/api/v1/namespaces/victimns/standard",
            Some(json!({})),
        ), // set_namespace_standard
        ("POST", "/api/v1/memory_replay", Some(json!({}))), // handle_replay
        (
            "POST",
            "/api/v1/memory_subscription_replay",
            Some(json!({})),
        ), // handle_subscription_replay
        (
            "POST",
            "/api/v1/memory_subscription_dlq_list",
            Some(json!({})),
        ), // handle_subscription_dlq_list
    ]
}

fn req(
    method: &str,
    uri: &str,
    api_key: &str,
    agent_id: Option<&str>,
    body: Option<&serde_json::Value>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", api_key);
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(v).unwrap()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// #2125 + #2096 — under `enforce`, a shared-key caller forging
/// `X-Agent-Id: <victim>` is refused `403 attested_identity_required` on
/// EVERY identity-sensitive route, BEFORE the ownership/visibility/write check.
#[tokio::test]
async fn enforce_shared_key_victim_spoof_is_403_on_every_route() {
    let _dir = fresh_dir();
    for (method, uri, body) in routes() {
        let (router, _f) = build_router(HttpIdentityMode::Enforce);
        let resp = router
            .oneshot(req(method, uri, SHARED_KEY, Some(VICTIM), body.as_ref()))
            .await
            .unwrap();
        let status = resp.status();
        let text = body_text(resp).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "#2125/#2096: {method} {uri} must 403 for a shared-key caller \
             forging X-Agent-Id:{VICTIM} under enforce (got {status}, body={text})"
        );
        assert!(
            text.contains("attested_identity_required"),
            "#2125/#2096: {method} {uri} 403 must be the identity gate, not an \
             incidental owner/validation 403 (body={text})"
        );
    }
}

/// The legitimately key-bound principal (`alice`, whose `ALICE_KEY` the
/// middleware binds to `X-Agent-Id=alice`) is NEVER refused by the identity
/// gate — control passes THROUGH to the handler (downstream 200/404/400/503
/// are route-specific, but never the identity 403).
#[tokio::test]
async fn enforce_key_bound_principal_passes_the_identity_gate_on_every_route() {
    let _dir = fresh_dir();
    for (method, uri, body) in routes() {
        let (router, _f) = build_router(HttpIdentityMode::Enforce);
        let resp = router
            .oneshot(req(method, uri, ALICE_KEY, None, body.as_ref()))
            .await
            .unwrap();
        let status = resp.status();
        let text = body_text(resp).await;
        assert!(
            !(status == StatusCode::FORBIDDEN && text.contains("attested_identity_required")),
            "#2125/#2096: {method} {uri} must NOT trip the identity gate for the \
             enrolled per-agent key (got {status}, body={text})"
        );
    }
}

/// Under `advisory` (the v1.0.0 default), the forged shared-key caller is
/// corrected+warned but ADMITTED — the identity gate never 403s. This is the
/// zero-config single-operator posture: the fix is inert until an operator
/// opts into `enforce`.
#[tokio::test]
async fn advisory_shared_key_victim_spoof_is_not_403_on_every_route() {
    let _dir = fresh_dir();
    for (method, uri, body) in routes() {
        let (router, _f) = build_router(HttpIdentityMode::Advisory);
        let resp = router
            .oneshot(req(method, uri, SHARED_KEY, Some(VICTIM), body.as_ref()))
            .await
            .unwrap();
        let status = resp.status();
        let text = body_text(resp).await;
        assert!(
            !(status == StatusCode::FORBIDDEN && text.contains("attested_identity_required")),
            "#2125/#2096: {method} {uri} must NOT identity-403 under advisory \
             (corrects+warns, admits) (got {status}, body={text})"
        );
    }
}
