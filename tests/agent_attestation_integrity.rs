// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! #626 Layer-3 (C6) — end-to-end agent-attestation integrity over the
//! HTTP `POST /api/v1/memories` create path.
//!
//! Exercises the C7 signature/created_at wire fields threaded through the
//! sqlite-backed daemon: a remote caller signs the `SignableWrite`
//! envelope (agent_id+namespace+title+kind+created_at+sha256(content)),
//! presents the standard-base64 detached Ed25519 signature plus the
//! `created_at` it signed, and the daemon:
//!
//!   * stamps `metadata.attest_level = "agent_attested"` when the
//!     signature verifies against the agent's bound public key (and adopts
//!     the signed `created_at` verbatim), and
//!   * rejects a forged signature with `403 ATTESTATION_FAILED`, and
//!   * rejects an unsigned write with `403` when the operator set
//!     `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`.
//!
//! Env-mutating cases serialise on [`ENV_LOCK`]; edition-2024 requires the
//! `unsafe` env mutators.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

/// Serialises the env-mutating require-attestation case against any other
/// test in this binary that reads `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn build_test_router() -> (axum::Router, NamedTempFile, std::path::PathBuf) {
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
    (router, f, db_path)
}

/// Register `agent_id` and bind `kp`'s public key through a fresh
/// connection on the daemon's db file so the gate's `db::agent_pubkey`
/// lookup resolves it.
fn provision_agent(db_path: &std::path::Path, agent_id: &str, pubkey_b64: &str) {
    let conn = ai_memory::db::open(db_path).expect("reopen for provision");
    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &[]).expect("register");
    ai_memory::storage::bind_agent_pubkey(&conn, agent_id, pubkey_b64).expect("bind");
}

/// Standard-base64 Ed25519 signature over the canonical store envelope.
fn sign_envelope(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    agent_id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    created_at: &str,
) -> String {
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id,
        namespace,
        title,
        kind: ai_memory::models::MemoryKind::Observation.as_str(),
        created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

async fn post_memory(router: &axum::Router, agent_id: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_signed_store_stamps_agent_attested_and_adopts_created_at() {
    let (router, _f, db_path) = build_test_router();
    let kp = ai_memory::identity::keypair::generate("ai:alice").expect("keypair");
    provision_agent(&db_path, "ai:alice", &kp.public_base64());

    let title = "http-signed";
    let content = "This is the body of http-signed, long enough to be meaningful prose.";
    let created_at = chrono::Utc::now().to_rfc3339();
    let sig_b64 = sign_envelope(&kp, "ai:alice", "attest-it", title, content, &created_at);

    let (status, resp) = post_memory(
        &router,
        "ai:alice",
        json!({
            "title": title,
            "content": content,
            "namespace": "attest-it",
            "tier": "mid",
            "signature": sig_b64,
            "created_at": created_at,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "signed store must 201; got {resp}"
    );
    let id = resp["id"].as_str().expect("id in response");

    let conn = ai_memory::db::open(&db_path).expect("reopen for read");
    let stored = ai_memory::db::get(&conn, id).expect("get").expect("row");
    assert_eq!(
        stored.metadata["attest_level"].as_str(),
        Some("agent_attested"),
        "a valid signature against the bound key must stamp agent_attested"
    );
    assert_eq!(
        stored.created_at, created_at,
        "the daemon must adopt the caller-signed created_at verbatim"
    );
}

#[tokio::test]
async fn http_forged_signature_is_rejected_403() {
    let (router, _f, db_path) = build_test_router();
    let bound = ai_memory::identity::keypair::generate("ai:alice").expect("kp1");
    let attacker = ai_memory::identity::keypair::generate("ai:alice").expect("kp2");
    provision_agent(&db_path, "ai:alice", &bound.public_base64());

    let title = "http-forged";
    let content = "This is the body of http-forged, long enough to be meaningful prose.";
    let created_at = chrono::Utc::now().to_rfc3339();
    // Sign with the attacker key — does NOT match the bound key.
    let sig_b64 = sign_envelope(
        &attacker,
        "ai:alice",
        "attest-it",
        title,
        content,
        &created_at,
    );

    let (status, resp) = post_memory(
        &router,
        "ai:alice",
        json!({
            "title": title,
            "content": content,
            "namespace": "attest-it",
            "tier": "mid",
            "signature": sig_b64,
            "created_at": created_at,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "forged signature must 403; got {resp}"
    );
    assert_eq!(
        resp["code"].as_str(),
        Some("ATTESTATION_FAILED"),
        "403 envelope must carry the ATTESTATION_FAILED code; got {resp}"
    );
}

#[tokio::test]
async fn http_signature_without_created_at_is_400() {
    let (router, _f, _db_path) = build_test_router();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let (status, resp) = post_memory(
        &router,
        "ai:alice",
        json!({
            "title": "http-no-ts",
            "content": "This is the body of http-no-ts, long enough to be meaningful prose.",
            "namespace": "attest-it",
            "tier": "mid",
            "signature": sig_b64,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing created_at must 400; got {resp}"
    );
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or_default()
            .contains("created_at"),
        "400 must name created_at; got {resp}"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // intentional: serialise the env mutation across the request
async fn http_require_attestation_rejects_unsigned_403() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: edition-2024 env mutation; serialised by ENV_LOCK above.
    unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "1") };

    let (router, _f, _db_path) = build_test_router();
    let (status, resp) = post_memory(
        &router,
        "ai:alice",
        json!({
            "title": "http-unsigned",
            "content": "This is the body of http-unsigned, long enough to be meaningful prose.",
            "namespace": "attest-it",
            "tier": "mid",
        }),
    )
    .await;

    // Restore BEFORE asserting so a panic can't leak the var into siblings.
    unsafe { std::env::remove_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION") };

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "required attestation must reject an unsigned write; got {resp}"
    );
    assert_eq!(
        resp["code"].as_str(),
        Some("ATTESTATION_FAILED"),
        "403 envelope must carry the ATTESTATION_FAILED code; got {resp}"
    );
}
