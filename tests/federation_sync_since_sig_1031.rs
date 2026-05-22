// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1031 (Agent-5 #2) — `/sync/since` X-Peer-Id signature
//! verification regression test.
//!
//! Pre-#1031 the GET `/api/v1/sync/since` handler accepted `X-Peer-Id`
//! verbatim without ANY signature check; an attacker who cleared the
//! api-key middleware or rode the mTLS bypass at `transport.rs:644`
//! could spoof the header and project every `federation_share=true`
//! row plus every `scope=private` row "owned" by the spoofed peer
//! (the visibility-gate's `is_visible_to_caller` treated the
//! spoofed header as the caller identity).
//!
//! The fix mirrors `/sync/push`: require an `X-Memory-Sig` over
//! canonical GET-request bytes binding `method + path + canonical-query`,
//! plus the same `X-Memory-Nonce` replay protection. Same env-var
//! gate (`AI_MEMORY_FED_REQUIRE_SIG=1` — v0.7.0 secure default).
//!
//! This test stands up the real production router via
//! `ai_memory::build_router` so the wire shape is verified end-to-end,
//! mirroring `tests/federation_nonce_replay_922.rs`.

#![allow(clippy::too_many_lines)]
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::federation::signing::{
    NONCE_HEADER, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER, sign_body_with_nonce_header,
};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::keypair as kp_mod;

struct Fixture {
    router: axum::Router,
    alice: kp_mod::AgentKeypair,
    _db_tmp: tempfile::NamedTempFile,
    _key_tmp: TempDir,
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn setup() -> Fixture {
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

    let key_tmp = TempDir::new().expect("key tempdir");
    // SAFETY: env mutation; the test holds the env_lock for the
    // duration so no other test sees the intermediate state.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_tmp.path());
    }

    let alice = kp_mod::generate("ai:peer-alice").expect("generate alice keypair");
    let alice_pub_only = kp_mod::AgentKeypair {
        agent_id: alice.agent_id.clone(),
        public: alice.public,
        private: None,
    };
    kp_mod::save_public_only(&alice_pub_only, key_tmp.path()).expect("enrol alice pubkey on bob");

    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
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
    };
    let router = ai_memory::build_router(api_key_state, app_state);

    Fixture {
        router,
        alice,
        _db_tmp: db_tmp,
        _key_tmp: key_tmp,
    }
}

/// Drive a single `sync_since` GET and return the parsed (status, body).
async fn sync_since_get(
    router: &axum::Router,
    query: &str,
    sig_header: Option<&str>,
    nonce_header: Option<&str>,
    peer_id_header: Option<&str>,
) -> (StatusCode, Value) {
    let uri = if query.is_empty() {
        "/api/v1/sync/since".to_string()
    } else {
        format!("/api/v1/sync/since?{query}")
    };
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(p) = peer_id_header {
        builder = builder.header(ai_memory::federation::peer_attestation::PEER_ID_HEADER, p);
    }
    if let Some(sig) = sig_header {
        builder = builder.header(SIGNATURE_HEADER, sig);
    }
    if let Some(nonce) = nonce_header {
        builder = builder.header(NONCE_HEADER, nonce);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Canonical bytes the receiver hashes — must match the helper at
/// `src/handlers/federation_signing_check.rs::canonical_get_bytes`.
fn canonical_get(method: &str, path: &str, query: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(method.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(path.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(query.as_bytes());
    v
}

#[tokio::test(flavor = "current_thread")]
async fn sync_since_enrolled_peer_without_signature_is_refused_1031() {
    let _g = env_lock();
    // SAFETY: env mutation; lock held for test duration.
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "0");
    }
    let host = setup();
    // Alice (enrolled peer) sends X-Peer-Id but NO X-Memory-Sig.
    // Pre-#1031: 200 with rows projected (exfil vector).
    // Post-#1031: 401 because the peer is enrolled but omitted the sig.
    let (status, body) = sync_since_get(
        &host.router,
        "limit=10",
        None, /* no signature */
        None,
        Some(&host.alice.agent_id),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "#1031: enrolled peer without sig MUST be refused; body={body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "x_memory_sig_missing",
        "#1031: refusal MUST carry the canonical missing-sig tag; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_since_enrolled_peer_with_bad_signature_is_refused_1031() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "0");
    }
    let host = setup();
    // Alice sends a sig that's malformed (correct prefix, wrong bytes).
    let bogus_sig = format!(
        "{}{}",
        ai_memory::federation::signing::ED25519_PREFIX,
        // 64 zero bytes = valid length, but won't verify under Alice's
        // verifying key over the canonical bytes.
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64],),
    );
    let (status, body) = sync_since_get(
        &host.router,
        "limit=10",
        Some(&bogus_sig),
        None,
        Some(&host.alice.agent_id),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "#1031: bad signature MUST be refused; body={body}"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "x_memory_sig_bad_signature",
        "#1031: refusal MUST carry the canonical bad-sig tag; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_since_enrolled_peer_with_valid_signature_is_accepted_1031() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "1");
    }
    let host = setup();
    let priv_key = host.alice.private.as_ref().expect("alice has private key");
    let query = "limit=10";
    let canonical = canonical_get("GET", "/api/v1/sync/since", query);
    let nonce = uuid::Uuid::new_v4().to_string();
    let sig = sign_body_with_nonce_header(priv_key, &canonical, &nonce);
    let (status, body) = sync_since_get(
        &host.router,
        query,
        Some(&sig),
        Some(&nonce),
        Some(&host.alice.agent_id),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1031: valid sig + nonce MUST be accepted; body={body}"
    );
    // Body still has the standard sync_since envelope (count + memories).
    assert!(
        body.get("memories").is_some(),
        "#1031: accepted response MUST carry the standard sync_since envelope; body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_since_unenrolled_peer_without_signature_is_permitted_1031() {
    let _g = env_lock();
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "1");
        std::env::set_var(REQUIRE_NONCE_ENV, "0");
    }
    let host = setup();
    // No X-Peer-Id at all — the "neither side enrolled" allow-with-WARN
    // arm fires. This preserves the v0.6.x permissive default for the
    // peer-rollout window (operators flip AI_MEMORY_FED_REQUIRE_SIG=1
    // only after every peer has a keypair on disk).
    let (status, body) = sync_since_get(&host.router, "limit=10", None, None, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1031: unenrolled peer without sig MUST still 200 (degraded permissive); body={body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sync_since_require_sig_off_skips_all_checks_1031() {
    let _g = env_lock();
    // Operator opts out via REQUIRE_SIG=0 (legacy compat).
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
    }
    let host = setup();
    let (status, _) = sync_since_get(
        &host.router,
        "limit=10",
        None,
        None,
        Some(&host.alice.agent_id),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "#1031: REQUIRE_SIG=0 MUST bypass every signature check"
    );
}
