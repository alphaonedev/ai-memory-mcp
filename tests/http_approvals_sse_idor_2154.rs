// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2154 (v1.0.0, #2032-A / H1 IDOR — SSE lane) — ROUTE-LEVEL regression pins
//! for the per-agent-key identity gate on the SSE approval stream
//! (`GET /api/v1/approvals/stream`, `handlers::approvals_sse`).
//!
//! `approvals_sse` filters a live broadcast of `ApprovalEvent` metadata by the
//! self-asserted `X-Agent-Id` (`subscriber_agent`) via `sse_event_visible_to`.
//! With only `api_key_auth` in front, a shared-global-key caller (`is_global`
//! → skips the #2044 middleware identity-binding block) forging
//! `X-Agent-Id: <victim>` under `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce`
//! would stream the victim's governance-workflow events. This is the SSE cousin
//! of the already-gated request/response reads (`get_memory`, `get_inbox`,
//! `list_pending`); the gate is applied at STREAM OPEN (before the broadcast
//! subscription is filtered by `subscriber_agent`).
//!
//! The SSE handshake response is assertable via the router `oneshot`: the
//! immediate status is the 403 (refused at open, before any stream body) or the
//! 200 `text/event-stream` handshake head (stream opened). We never drain the
//! long-lived body.
//!
//!   * **H1 (SSE metadata IDOR)** — a shared-transport-key caller forging a
//!     victim `X-Agent-Id` on `GET /api/v1/approvals/stream` is refused
//!     `403 attested_identity_required` at open under `enforce`, BEFORE any
//!     broadcast subscription — so no victim `ApprovalEvent` can leak.
//!   * **Key-bound principal** — the enrolled per-agent key for a principal
//!     opens the stream (200) and rides its OWN events (the middleware rebinds
//!     `X-Agent-Id` to the key-derived id; the gate admits `KeyAuthenticated`).
//!   * **Zero-enrollment** — with NO per-agent keys enrolled the gate is fully
//!     inert even under `enforce`; the stream opens exactly as before (no
//!     regression for legitimate single-operator deployments).

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::api_key_sha256_hex;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const SHARED_KEY: &str = "shared-transport-key";
const ALICE_KEY: &str = "alice-per-agent-key";
const APPROVALS_STREAM: &str = "/api/v1/approvals/stream";

fn fresh_dir() -> TempDir {
    let root = PathBuf::from(".local-runs").join("issue-2154-approvals-sse-idor");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

/// Build a router in the given identity `mode`, optionally enrolling `alice`'s
/// per-agent api-key (`ALICE_KEY`). The shared transport key (`SHARED_KEY`)
/// authenticates transport but resolves to NO per-agent principal — the H1
/// shared-transport-key actor.
fn build_router(
    mode: HttpIdentityMode,
    enroll_alice: bool,
) -> (axum::Router, AppState, NamedTempFile) {
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
    if enroll_alice {
        enrolled.insert(api_key_sha256_hex(ALICE_KEY), "alice".to_string());
    }
    let enrolled = Arc::new(enrolled);

    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["alice".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
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
    let router = ai_memory::build_router(api_key_state, app_state.clone());
    (router, app_state, f)
}

// ---------------------------------------------------------------------------
// (1) H1 — shared-key victim spoof on the SSE stream, refused at open.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h1_approvals_sse_shared_key_victim_spoof_is_403_under_enforce() {
    let _dir = fresh_dir();
    // enforce + alice enrolled (so the gate is active), attacker holds only the
    // shared transport key and forges the victim's X-Agent-Id.
    let (router, _app, _f) = build_router(HttpIdentityMode::Enforce, true);
    let req = Request::builder()
        .method("GET")
        .uri(APPROVALS_STREAM)
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "ai:victim@host")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "#2154 H1: a shared-key caller forging a victim X-Agent-Id must be \
         refused at SSE stream-open under enforce (Claimed, not key-attested)"
    );
    // Refused BEFORE any broadcast subscription — the response is the typed
    // JSON refusal, NOT a text/event-stream handshake. A victim ApprovalEvent
    // can therefore never leak onto this connection.
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !ct.contains("text/event-stream"),
        "#2154 H1: a refused open must NOT establish an event-stream (got {ct:?})"
    );
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("collect body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json refusal body");
    assert_eq!(
        json.get("error").and_then(serde_json::Value::as_str),
        Some("attested_identity_required"),
        "#2154 H1: refusal must carry the sibling-matching error code"
    );
}

// ---------------------------------------------------------------------------
// (2) Key-bound principal — enrolled per-agent key opens its OWN stream.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approvals_sse_per_agent_key_principal_opens_stream() {
    let _dir = fresh_dir();
    let (router, _app, _f) = build_router(HttpIdentityMode::Enforce, true);
    // alice's enrolled per-agent key → api_key_auth rebinds X-Agent-Id=alice,
    // the gate sees KeyAuthenticated → admits → the SSE handshake opens (200).
    // The subscriber_agent that reaches sse_event_visible_to is the BOUND
    // principal, so alice rides only her own events.
    let req = Request::builder()
        .method("GET")
        .uri(APPROVALS_STREAM)
        .header("x-api-key", ALICE_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#2154: alice's enrolled per-agent key must open the SSE stream under enforce"
    );
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "#2154: a key-bound principal must get the SSE handshake (got {ct:?})"
    );
}

// ---------------------------------------------------------------------------
// (3) Zero-enrollment — gate fully inert; stream opens (no regression).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approvals_sse_zero_enrollment_gate_inert_opens_under_enforce() {
    let _dir = fresh_dir();
    // enforce mode but NO per-agent keys enrolled → the whole #2044 gate is
    // inert (empty enrolled map short-circuits to None). A legitimate
    // single-operator subscriber presenting the shared key + its own
    // self-asserted X-Agent-Id opens the stream exactly as before the fix.
    let (router, _app, _f) = build_router(HttpIdentityMode::Enforce, false);
    let req = Request::builder()
        .method("GET")
        .uri(APPROVALS_STREAM)
        .header("x-api-key", SHARED_KEY)
        .header("x-agent-id", "ai:operator@host")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "#2154: with zero per-agent keys enrolled the gate is inert even under \
         enforce — the SSE stream must open (no regression)"
    );
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "#2154: zero-enrollment open must establish the SSE handshake (got {ct:?})"
    );
}
