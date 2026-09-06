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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
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
    ai_memory::build_router(api_key_state, app_state)
}

/// Enrol `signer`'s public key under `PEER_ID` in a fresh temp key dir
/// and point `AI_MEMORY_KEY_DIR` at it. Returns the dir guard (dropping
/// it removes the files). Caller holds `FED_SIGNING_ENV_LOCK`.
fn enrol_peer_key(signer: &SigningKey) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    // #3198 — the key store must not be group- or world-writable, and
    // `keypair::save*` refuses one that is. On a host whose TMPDIR carries a
    // permissive default ACL the fresh temp dir comes back `0775`, so pin
    // `0700` explicitly rather than depending on the host's umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("tighten the temp key dir to 0700");
    }
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

// ---------------------------------------------------------------------------
// #3521 — the NONCE half of the `(Some sig, Some key)` enforcement matrix.
//
// A valid Ed25519 signature over the body proves authorship; it does NOT
// prove freshness. Without the nonce gate a captured `/sync/push` (or
// catch-up `/sync/since`) is infinitely REPLAYABLE by anyone who can see the
// wire, so a peer could be made to re-apply an old federated batch — or to
// re-serve an old snapshot — long after the sender moved on. These pins cover
// the two strict arms that had no test: a signed request that omits the nonce
// under `AI_MEMORY_FED_REQUIRE_NONCE=1`, and a nonce presented twice.
// ---------------------------------------------------------------------------

/// Turn the nonce gate on for the current (lock-held) test.
///
/// SAFETY: every caller holds `FED_SIGNING_ENV_LOCK` for the duration.
unsafe fn require_nonce_on() {
    unsafe {
        std::env::set_var(fed_signing::REQUIRE_NONCE_ENV, "1");
    }
}

async fn status_of(router: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// A correctly SIGNED push from an enrolled peer that carries NO nonce is
/// refused when the nonce gate is on. A signature alone is replayable.
#[tokio::test]
async fn signed_push_without_a_nonce_is_refused_when_the_nonce_gate_is_on() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[21u8; 32]);
    let _dir = enrol_peer_key(&signer);
    // SAFETY: FED_SIGNING_ENV_LOCK is held for the whole test.
    unsafe { require_nonce_on() };
    let router = build_sqlite_router();

    let body = push_body();
    let sig = fed_signing::sign_body_header(&signer, &body);
    let (status, payload) = status_of(&router, build_push_request(&body, Some(&sig))).await;
    clear_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a signed but nonce-less push must be refused under REQUIRE_NONCE=1; body={payload}"
    );
    assert_eq!(
        payload["error"],
        ai_memory::federation::signing::VerifyError::NonceMissing.tag(),
        "the refusal must name the missing nonce; body={payload}"
    );
}

/// A nonce is single-use. The FIRST signed push carrying it is accepted; an
/// identical replay of the SAME bytes and the SAME nonce is refused, so a
/// captured batch cannot be re-applied.
#[tokio::test]
async fn a_replayed_nonce_on_a_signed_push_is_refused() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[22u8; 32]);
    let _dir = enrol_peer_key(&signer);
    // SAFETY: FED_SIGNING_ENV_LOCK is held for the whole test.
    unsafe { require_nonce_on() };
    let router = build_sqlite_router();

    let body = push_body();
    let nonce = "cov-3521-nonce-a";
    let sig = fed_signing::sign_body_with_nonce_header(&signer, &body, nonce);
    let build = || {
        let mut b = Request::builder()
            .method("POST")
            .uri("/api/v1/sync/push")
            .header("content-type", "application/json")
            .header("x-peer-id", PEER_ID)
            .header(fed_signing::SIGNATURE_HEADER, sig.clone());
        b = b.header(fed_signing::NONCE_HEADER, nonce);
        b.body(Body::from(body.clone())).expect("request")
    };

    let (first, first_body) = status_of(&router, build()).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "the first use of a fresh nonce must be accepted; body={first_body}"
    );
    let (second, second_body) = status_of(&router, build()).await;
    clear_env();
    assert_eq!(
        second,
        StatusCode::UNAUTHORIZED,
        "an identical replay must be refused; body={second_body}"
    );
    assert_eq!(
        second_body["error"],
        ai_memory::federation::signing::VerifyError::ReplayedNonce.tag(),
        "the refusal must name the replay; body={second_body}"
    );
}

/// The catch-up GET carries the same contract: a signed `/sync/since`
/// without a nonce is refused under the nonce gate. A replayable catch-up
/// GET lets an observer re-drive a peer's snapshot pull.
#[tokio::test]
async fn signed_sync_since_without_a_nonce_is_refused_when_the_nonce_gate_is_on() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[23u8; 32]);
    let _dir = enrol_peer_key(&signer);
    // SAFETY: FED_SIGNING_ENV_LOCK is held for the whole test.
    unsafe { require_nonce_on() };
    let router = build_sqlite_router();

    let path = "/api/v1/sync/since";
    let query = format!("peer={PEER_ID}");
    let canonical = fed_signing::canonical_get_bytes("GET", path, &query);
    let sig = fed_signing::sign_body_header(&signer, &canonical);
    let req = Request::builder()
        .method("GET")
        .uri(format!("{path}?{query}"))
        .header("x-peer-id", PEER_ID)
        .header(fed_signing::SIGNATURE_HEADER, sig)
        .body(Body::empty())
        .expect("request");
    let (status, payload) = status_of(&router, req).await;
    clear_env();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a signed but nonce-less catch-up GET must be refused; body={payload}"
    );
    assert_eq!(
        payload["error"],
        ai_memory::federation::signing::VerifyError::NonceMissing.tag(),
        "the refusal must name the missing nonce; body={payload}"
    );
}

/// A catch-up GET nonce is single-use too.
#[tokio::test]
async fn a_replayed_nonce_on_a_signed_sync_since_is_refused() {
    let _g = FED_SIGNING_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let signer = SigningKey::from_bytes(&[24u8; 32]);
    let _dir = enrol_peer_key(&signer);
    // SAFETY: FED_SIGNING_ENV_LOCK is held for the whole test.
    unsafe { require_nonce_on() };
    let router = build_sqlite_router();

    let path = "/api/v1/sync/since";
    let query = format!("peer={PEER_ID}");
    let canonical = fed_signing::canonical_get_bytes("GET", path, &query);
    let nonce = "cov-3521-nonce-b";
    let sig = fed_signing::sign_body_with_nonce_header(&signer, &canonical, nonce);
    let build = || {
        Request::builder()
            .method("GET")
            .uri(format!("{path}?{query}"))
            .header("x-peer-id", PEER_ID)
            .header(fed_signing::SIGNATURE_HEADER, sig.clone())
            .header(fed_signing::NONCE_HEADER, nonce)
            .body(Body::empty())
            .expect("request")
    };

    let (first, first_body) = status_of(&router, build()).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "the first use of a fresh catch-up nonce must be accepted; body={first_body}"
    );
    let (second, second_body) = status_of(&router, build()).await;
    clear_env();
    assert_eq!(
        second,
        StatusCode::UNAUTHORIZED,
        "an identical catch-up replay must be refused; body={second_body}"
    );
    assert_eq!(
        second_body["error"],
        ai_memory::federation::signing::VerifyError::ReplayedNonce.tag(),
        "the refusal must name the replay; body={second_body}"
    );
}
