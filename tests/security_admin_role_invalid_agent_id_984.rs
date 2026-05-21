// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on the regression we pin.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! v0.7.0 #984 — admin handler surfaces invalid `X-Agent-Id` as 400.
//!
//! Pre-#984 `require_admin` in `src/handlers/admin_role.rs:143` ran
//! `.unwrap_or_else(|_| "anonymous:invalid".to_string())` on the
//! result of `resolve_http_agent_id`. A wire caller who supplied an
//! `X-Agent-Id` that failed `validate_agent_id` (invalid char class,
//! oversize, or — post-#977 — one of the `RESERVED_AGENT_IDS`)
//! reached the admin allowlist check with the literal
//! `"anonymous:invalid"` principal. The sentinel failed the allowlist
//! check (it's not in any operator's `AdminConfig`) so the wire
//! caller still saw 403 — but:
//!
//! - The audit chain captured `"anonymous:invalid"` instead of the
//!   actionable validation diagnostic (operator forensics rotted).
//! - A wire spoof of `X-Agent-Id: daemon` (the bypass attempt
//!   closed by #977) landed in the audit chain as
//!   `"anonymous:invalid"` rather than as a recorded probe of a
//!   reserved name (lost the L1-6 audit-trail honesty contract).
//!
//! Post-#984 `require_admin` returns 400 BAD_REQUEST with the
//! validator's error message when the header fails to resolve. The
//! audit chain captures a `"deny"` decision with
//! `agent_id="anonymous:resolve-failed"` + the validator's reason in
//! the action body BEFORE the wire 400.
//!
//! This file pins the new wire shape for two failure modes:
//!
//! 1. Invalid char class — `X-Agent-Id: bad;rm` (semicolon rejected
//!    by `validate_agent_id_shape`).
//! 2. Reserved name — `X-Agent-Id: daemon` (rejected by #977's
//!    reserved-name set, sibling to TB1).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

mod common_admin {
    use std::sync::Arc;

    pub fn build_router_with_admin_allowlist() -> axum::Router {
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
        let path = std::path::PathBuf::from(":memory:");
        let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
            conn,
            path,
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        #[cfg(feature = "sal")]
        let store: Arc<dyn ai_memory::store::MemoryStore> = {
            let tmp = tempfile::NamedTempFile::new().expect("tempfile");
            let p = tmp.path().to_path_buf();
            std::mem::forget(tmp);
            Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"))
        };
        let app_state = ai_memory::handlers::AppState {
            db: db.clone(),
            embedder: Arc::new(None),
            vector_index: Arc::new(tokio::sync::Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
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
            replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(
                ai_memory::identity::replay::FederationNonceCache::default(),
            ),
            autonomous_hooks: false,
            recall_scope: Arc::new(None),
            deferred_audit_queue: Arc::new(None),
            // Operator allowlist with one explicit admin so a legitimate
            // caller would be admitted — proves the failure paths below
            // are due to the agent_id resolution, not a missing admin.
            admin_agent_ids: Arc::new(vec!["ai:operator".to_string()]),
        };
        let api_key_state = ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
        };
        ai_memory::build_router(api_key_state, app_state)
    }
}

#[tokio::test]
async fn admin_endpoint_returns_400_on_invalid_char_class_agent_id_984() {
    let router = common_admin::build_router_with_admin_allowlist();
    // `bad;rm` fails validate_agent_id_shape — `;` is not in the
    // allowed char class.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/stats")
        .header("X-Agent-Id", "bad;rm")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid char-class agent_id MUST 400, not 403 with audit pollution (issue #984)",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|s| s.contains("invalid agent_id")),
        "body should cite the validator error; got {body}",
    );
}

#[tokio::test]
async fn admin_endpoint_returns_400_on_reserved_name_spoof_984() {
    // Post-#977, X-Agent-Id: daemon is rejected by validate_agent_id
    // as a reserved name. Pre-#984 the admin handler silently
    // resolved it to "anonymous:invalid" and returned 403; post-#984
    // it returns 400 with the reserved-name reason, so the audit
    // chain captures the spoof attempt + the operator sees the
    // actionable validator diagnostic.
    let router = common_admin::build_router_with_admin_allowlist();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/stats")
        .header("X-Agent-Id", "daemon")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "reserved-name spoof MUST 400 with the validator's reason — pre-#984 this was a silent 403 with audit pollution (issues #977 + #984)",
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("reserved for internal use"),
        "body must cite the reserved-name reason from #977; got {body}",
    );
}

#[tokio::test]
async fn admin_endpoint_returns_403_on_non_admin_caller_984() {
    // Pin the non-regression: a LEGITIMATE non-admin caller still
    // gets 403 (not 400). Only invalid-shape inputs go to 400.
    let router = common_admin::build_router_with_admin_allowlist();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/stats")
        .header("X-Agent-Id", "ai:not-an-admin")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "legitimate non-admin caller MUST still get 403 — #984 only changes the invalid-input path",
    );
}
