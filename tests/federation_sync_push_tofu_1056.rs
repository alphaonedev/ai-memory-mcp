// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1056 (Agent-2 #6) — TOFU spoofing guard regression test.
//!
//! Pre-#1056 the `(no sig, no enrolled key)` arm of
//! `verify_signature_or_reject` allowed the `/sync/push` request
//! through with a WARN ("strict enforcement skipped") so an
//! unenrolled federation pair stayed operational. That permissive
//! posture let an attacker who knew a legitimate peer's id but had
//! NOT yet been enrolled (heterogeneous rollout window — operator
//! enrolled half the mesh) impersonate the unenrolled half.
//!
//! The #1056 fix adds a TOFU gate BEFORE the signature verifier:
//! when the operator has configured `AI_MEMORY_FED_PEER_ATTESTATION`
//! at all, any `x-peer-id` NOT in the allowlist is refused with a
//! `401 x_peer_id_not_in_allowlist`. With NO allowlist configured
//! (zero-config), the gate is a no-op and the legacy permissive
//! posture stands — so the security uplift only fires when the
//! operator has explicitly enrolled peers.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn setup_router() -> axum::Router {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    std::mem::forget(db_tmp);
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
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
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
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn post_sync_push(
    router: &axum::Router,
    body: Value,
    peer_id: Option<&str>,
) -> (StatusCode, Value) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json");
    if let Some(p) = peer_id {
        builder = builder.header(ai_memory::federation::peer_attestation::PEER_ID_HEADER, p);
    }
    let req = builder.body(Body::from(body_bytes)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn sample_body(sender: &str) -> Value {
    json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "memories": [],
        "dry_run": false,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_unknown_peer_id_refused_when_allowlist_configured_1056() {
    let _g = env_lock();
    // Operator has enrolled "enrolled-peer" — anything else is refused.
    unsafe {
        std::env::set_var(
            PEER_ATTESTATION_ENV,
            r#"{"enrolled-peer": {"allowed_namespaces": ["ns/*"]}}"#,
        );
        // Disable sig requirement so we're isolating the TOFU gate.
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
    }
    let router = setup_router();
    let (status, body) = post_sync_push(
        &router,
        sample_body("attacker-claim"),
        Some("attacker-claim"),
    )
    .await;
    unsafe {
        std::env::remove_var(PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
    }
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "#1056: unknown x-peer-id MUST be refused when allowlist configured; body={body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "x_peer_id_not_in_allowlist",
        "#1056: refusal MUST carry the canonical TOFU-guard tag; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_enrolled_peer_id_passes_tofu_gate_1056() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(
            PEER_ATTESTATION_ENV,
            r#"{"enrolled-peer": {"allowed_namespaces": ["ns/*"]}}"#,
        );
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        // Also set TRUST_BODY_AGENT_ID so the #238 attestation
        // doesn't reject when sender_agent_id != peer-id (we're
        // isolating the TOFU gate, not testing attestation here).
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let router = setup_router();
    let (status, _body) = post_sync_push(
        &router,
        sample_body("ai:enrolled-sender"),
        Some("enrolled-peer"),
    )
    .await;
    unsafe {
        std::env::remove_var(PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    // The enrolled peer's request passes the TOFU gate; downstream
    // pipeline (sig check, attestation, body parsing, store fanout)
    // may produce any non-401 outcome — what we pin is that the
    // TOFU gate did NOT refuse on x_peer_id_not_in_allowlist.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "#1056: enrolled peer MUST pass the TOFU gate"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_push_zero_config_skips_tofu_gate_1056() {
    let _g = env_lock();
    unsafe {
        std::env::remove_var(PEER_ATTESTATION_ENV);
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let router = setup_router();
    // No allowlist configured → TOFU gate is a no-op → request
    // flows through to downstream processing.
    let (status, _body) =
        post_sync_push(&router, sample_body("ai:anyone"), Some("any-peer-id")).await;
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    }
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "#1056: zero-config (no allowlist) MUST skip the TOFU gate (legacy posture)"
    );
}
