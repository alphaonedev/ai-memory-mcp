// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! FUPB coverage — `src/handlers/federation_signing_check.rs` router-level
//! enrolled-key enforcement arms.
//!
//! The in-file `verify_arm_tests` mod covers the require-sig-off bypass,
//! the `(Some, None)` no-enrolled-key refusal, and the `(None, None)`
//! permissive/strict arms. What it does NOT cover (because those arms
//! need an enrolled peer key on disk) are the `(Some, Some)` arms:
//!   - valid signature against an enrolled key → push proceeds (no 401),
//!   - tampered/bad signature against an enrolled key → 401,
//!   - enrolled peer omits the signature header (`(None, Some)`) → 401.
//!
//! Strategy: enrol a peer's PUBLIC key into a temp `AI_MEMORY_KEY_DIR`
//! (so `load_daemon_verifying_key(<peer_id>)` resolves it), set
//! `AI_MEMORY_FED_REQUIRE_SIG=1` + `AI_MEMORY_FED_REQUIRE_NONCE=0`, build
//! a sqlite router, and POST a real Ed25519-signed `/sync/push` body
//! through `ai_memory::build_router`. Env mutation is process-global so
//! the cases serialise behind a single lock.

#![cfg(feature = "sal")]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use ai_memory::federation::signing as fed_signing;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair::AgentKeypair;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use serde_json::json;
use tower::ServiceExt as _;

static FED_SIGNING_ENV_LOCK: Mutex<()> = Mutex::new(());

const PEER_ID: &str = "peer-fupb-signing";

fn build_sqlite_router() -> axum::Router {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
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
    ai_memory::build_router(api_key_state, app_state)
}

/// Enrol `signer`'s public key under `PEER_ID` in a fresh temp key dir
/// and point `AI_MEMORY_KEY_DIR` at it. Returns the dir guard (dropping
/// it removes the files). Caller holds `FED_SIGNING_ENV_LOCK`.
fn enrol_peer_key(signer: &SigningKey) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = AgentKeypair {
        agent_id: PEER_ID.to_string(),
        public: signer.verifying_key(),
        private: None,
    };
    ai_memory::identity::keypair::save_public_only(&kp, dir.path()).expect("save pubkey");
    // SAFETY: env mutation under FED_SIGNING_ENV_LOCK.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", dir.path());
        std::env::set_var("AI_MEMORY_FED_REQUIRE_SIG", "1");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_NONCE", "0");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
    }
    dir
}

fn clear_env() {
    // SAFETY: env mutation under FED_SIGNING_ENV_LOCK.
    unsafe {
        std::env::remove_var("AI_MEMORY_KEY_DIR");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_SIG");
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_NONCE");
    }
}

fn push_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "sender_agent_id": PEER_ID,
        "memories": [],
    }))
    .unwrap()
}

fn build_push_request(body: &[u8], sig_header: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header("x-peer-id", PEER_ID);
    if let Some(sig) = sig_header {
        b = b.header(fed_signing::SIGNATURE_HEADER, sig);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

/// `(Some sig, Some key)` — a valid signature over the exact wire bytes
/// against the enrolled key passes the verifier; the push proceeds (the
/// 200 envelope, NOT a 401). Pins the success arm of the enforcement
/// matrix the in-file tests can't reach without an on-disk key.
#[tokio::test]
async fn signed_push_with_enrolled_key_is_accepted() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[7u8; 32]);
    let _dir = enrol_peer_key(&signer);
    let router = build_sqlite_router();

    let body = push_body();
    let sig = fed_signing::sign_body_header(&signer, &body);
    let resp = router
        .oneshot(build_push_request(&body, Some(&sig)))
        .await
        .unwrap();
    let status = resp.status();
    clear_env();
    assert_eq!(
        status,
        StatusCode::OK,
        "a valid signature against the enrolled peer key must be accepted, not 401; got {status}"
    );
}

/// `(Some sig, Some key)` but the signature is bogus → 401. The verify
/// failure arm with an enrolled key.
#[tokio::test]
async fn signed_push_with_bad_signature_is_rejected_401() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[9u8; 32]);
    let _dir = enrol_peer_key(&signer);
    let router = build_sqlite_router();

    let body = push_body();
    // A correctly-shaped but wrong signature: sign a DIFFERENT body.
    let wrong_sig = fed_signing::sign_body_header(&signer, b"some other body");
    let resp = router
        .oneshot(build_push_request(&body, Some(&wrong_sig)))
        .await
        .unwrap();
    let status = resp.status();
    clear_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a signature that does not verify against the enrolled key must 401"
    );
}

/// `(None sig, Some key)` — an enrolled peer that omits the signature
/// header must be refused (enrolled peer must sign) → 401.
#[tokio::test]
async fn enrolled_peer_omitting_signature_is_rejected_401() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[11u8; 32]);
    let _dir = enrol_peer_key(&signer);
    let router = build_sqlite_router();

    let body = push_body();
    let resp = router
        .oneshot(build_push_request(&body, None))
        .await
        .unwrap();
    let status = resp.status();
    clear_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an enrolled peer that omits X-Memory-Sig must be refused"
    );
}
