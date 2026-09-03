// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1843 (v0.8.1, security-high) — federated SIGNAL authorship binding.
//!
//! A federated signal received via `POST /sync/push` has `from_agent` set by
//! the wire. Before #1843 the receive loop only called `signals::verify`, which
//! validates the signature against the signal's OWN wire-supplied
//! `sender_pubkey` — it never bound `from_agent` to the enrolled peer's
//! authorship allowlist nor to `from_agent`'s locally-enrolled key. So an
//! enrolled peer could forge signals as ANY agent (CWE-346). The memory lane
//! (`resolve_inbound_attribution`) and the transition lane
//! (`authorize_remote_transition`) already closed this for their subcollections.
//!
//! Signals cannot be cleanly re-attributed (`from_agent` is inside the signed
//! canonical bytes), so the disposition is a PER-SIGNAL skip — never a
//! re-attribution and never a drop of the rest of the batch.
//!
//! The fix is two layers (5-agent vote `4d3ea1c5`):
//! - **Layer 1 (always-on base)** — gated on `PeerAttestationConfig::has_allowlist()`:
//!   under an enrolled posture, a relayed signal is trusted only when it
//!   self-relays (`from_agent == sender_agent_id`) OR `from_agent` is in the
//!   peer's `allowed_sender_agent_ids`. Zero-config does nothing new.
//! - **Layer 2 (opt-in `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`)** — additionally
//!   require the signature to verify against `from_agent`'s locally-enrolled key.
//!
//! These tests exercise the `SQLite` `/sync/push` receive handler end-to-end:
//! (a) forged signature → skipped; (b) enrolled peer + allowlist, `from_agent`
//! OUTSIDE the allowlist → skipped while a co-resident memory in the SAME push
//! still applies (batch survival); (c) self-relay + allowlisted third-party →
//! accepted; (d) zero-config (no allowlist) → accepted (faith-based); (e) strict
//! mode → enrolled+valid accepted, unenrolled skipped.

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
use ai_memory::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV;
use ai_memory::federation::signing::REQUIRE_SIG_ENV;
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Signal, SignalType};

/// Process-wide env serialization: every test in this file mutates the same
/// federation env vars (allowlist, sig-require, peer-enrollment, key dir).
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn setup_router() -> (axum::Router, Db) {
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
        db: db.clone(),
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
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
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
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// Disable the orthogonal federation gates so each test isolates the #1843
/// signal-authorship behavior: body-signature requirement (#791) and
/// peer-enrollment requirement (#1789).
fn relax_orthogonal_gates() {
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
    }
}

fn clear_all_env() {
    unsafe {
        std::env::remove_var(PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var(REQUIRE_SIGNAL_SIG_ENV);
        std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        std::env::remove_var("AI_MEMORY_KEY_DIR");
    }
}

/// Build an unsigned [`Signal`] with the given `from_agent`.
fn make_signal(from_agent: &str, namespace: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        from_agent: from_agent.to_string(),
        to_agent: None,
        subject: "sig-1843".to_string(),
        body: json!({"hello": "world"}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

/// A signal self-signed with a freshly-generated keypair for `from_agent` (the
/// `sender_pubkey` is that key, so `signals::verify` accepts it as non-forged).
fn signed_signal(from_agent: &str, namespace: &str) -> Signal {
    let kp = ai_memory::identity::keypair::generate(from_agent).expect("gen keypair");
    let mut sig = make_signal(from_agent, namespace);
    ai_memory::signals::sign_into(&mut sig, &kp).expect("sign signal");
    sig
}

fn sig_to_value(sig: &Signal) -> Value {
    serde_json::to_value(sig).expect("serialize signal")
}

/// A self-authored memory body fragment (author == `sender`), used to prove
/// batch survival: it must still apply even when a co-resident signal is skipped.
fn self_memory(sender: &str, namespace: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "tier": "long",
        "namespace": namespace,
        "title": "co-resident memory",
        "content": "must survive a skipped signal in the same push",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "user",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": sender},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn post_sync_push(router: &axum::Router, body: Value, peer_id: &str) -> (StatusCode, Value) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer_id,
        )
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn i(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(-1)
}

// ---- (a) forged signature → skipped ------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn forged_signature_signal_is_skipped_1843() {
    let _g = env_lock();
    clear_all_env();
    relax_orthogonal_gates(); // zero-config (no allowlist) → Layer 1 is a no-op
    let (router, _db) = setup_router();

    let mut sig = signed_signal("ai:relay", "sig-test/forged");
    sig.signature[0] ^= 0xff; // tamper → signals::verify fails (forged)
    let body = json!({
        "sender_agent_id": "ai:relay",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [sig_to_value(&sig)],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:relay").await;
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        0,
        "forged signal MUST NOT apply"
    );
    assert!(i(&resp, "skipped") >= 1, "forged signal MUST be skipped");
}

// ---- (b) enrolled peer, from_agent outside allowlist → skip; memory survives -

#[tokio::test(flavor = "current_thread")]
async fn enrolled_peer_forged_authorship_skipped_batch_survives_1843() {
    let _g = env_lock();
    clear_all_env();
    relax_orthogonal_gates();
    unsafe {
        // relay-peer may author signals only as "alice"; "mallory" is NOT allowed.
        std::env::set_var(
            PEER_ATTESTATION_ENV,
            r#"{"relay-peer": {"allowed_sender_agent_ids": ["alice"], "allowed_namespaces": ["sig-test/**"]}}"#,
        );
    }
    let (router, _db) = setup_router();

    let forged = signed_signal("mallory", "sig-test/b"); // validly self-signed, but unauthorized author
    let body = json!({
        "sender_agent_id": "relay-peer",
        "sender_clock": {"entries": {}},
        "memories": [self_memory("relay-peer", "sig-test/mem")],
        "signals": [sig_to_value(&forged)],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "relay-peer").await;
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        0,
        "signal authored as a non-allowlisted agent MUST be skipped: {resp}"
    );
    assert_eq!(
        i(&resp, "applied"),
        1,
        "co-resident memory in the SAME push MUST still apply (batch survival): {resp}"
    );
    assert!(i(&resp, "skipped") >= 1, "the skipped signal is counted");
}

// ---- (c) self-relay + allowlisted third-party → accepted ---------------------

#[tokio::test(flavor = "current_thread")]
async fn self_relay_and_allowlisted_author_accepted_1843() {
    let _g = env_lock();
    clear_all_env();
    relax_orthogonal_gates();
    unsafe {
        std::env::set_var(
            PEER_ATTESTATION_ENV,
            r#"{"relay-peer": {"allowed_sender_agent_ids": ["alice"], "allowed_namespaces": ["sig-test/**"]}}"#,
        );
        // #1801→#1954 item 5 — this test isolates Layer-1 (authorship
        // allowlist) acceptance. Post-v1.0.0-flip, Layer-2 (`require_signal_sig`)
        // defaults ON and additionally demands each `from_agent`'s ENROLLED key
        // (which this fixture does not provision), so opt Layer-2 out explicitly
        // to pin the Layer-1 behavior unchanged (the `=0` staged-rollout bridge).
        std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0");
    }
    let (router, _db) = setup_router();

    let self_sig = signed_signal("relay-peer", "sig-test/c"); // from_agent == sender → self-relay
    let allowed = signed_signal("alice", "sig-test/c"); // in allowed_sender_agent_ids
    let body = json!({
        "sender_agent_id": "relay-peer",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [sig_to_value(&self_sig), sig_to_value(&allowed)],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "relay-peer").await;
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        2,
        "self-relay + allowlisted-author signals MUST both apply: {resp}"
    );
}

// ---- (d) zero-config (no allowlist) → accepted (faith-based, byte-unchanged) --

#[tokio::test(flavor = "current_thread")]
async fn zero_config_accepts_any_author_1843() {
    let _g = env_lock();
    clear_all_env();
    relax_orthogonal_gates(); // no PEER_ATTESTATION_ENV → has_allowlist()==false
    // #1801→#1954 item 5 — the signal-sig default flipped `false → true` at
    // v1.0.0, so an UNSET knob now resolves STRICT (an unenrolled `from_agent`
    // would be skipped). The permissive "zero-config faith-based" posture this
    // test documents is now the EXPLICIT `=0` opt-out (the staged-rollout
    // bridge); pin the byte-identical pre-flip behavior under that opt-out.
    unsafe { std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "0") };
    let (router, _db) = setup_router();

    let sig = signed_signal("ai:anyone", "sig-test/d");
    let body = json!({
        "sender_agent_id": "ai:relay",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [sig_to_value(&sig)],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:relay").await;
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        1,
        "zero-config MUST keep the faith-based posture (accept signed signal): {resp}"
    );
}

// ---- (e) strict mode: enrolled+valid accepted, unenrolled skipped ------------

#[tokio::test(flavor = "current_thread")]
async fn strict_mode_requires_enrolled_author_key_1843() {
    let _g = env_lock();
    clear_all_env();
    relax_orthogonal_gates();

    // Enroll "alice"'s public key in an isolated key dir; "bob" stays unenrolled.
    let key_dir = tempfile::tempdir().expect("key dir");
    let alice = ai_memory::identity::keypair::generate("alice").expect("gen alice");
    ai_memory::identity::keypair::save(&alice, key_dir.path()).expect("save alice");
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_dir.path());
        std::env::set_var(REQUIRE_SIGNAL_SIG_ENV, "1");
    }
    let (router, _db) = setup_router();

    // alice: sign with the SAME enrolled key → Layer 2 verifies against it.
    let mut alice_sig = make_signal("alice", "sig-test/e");
    ai_memory::signals::sign_into(&mut alice_sig, &alice).expect("sign alice");
    // bob: validly self-signed (passes the forged check) but NOT enrolled locally.
    let bob_sig = signed_signal("bob", "sig-test/e");

    let body = json!({
        "sender_agent_id": "ai:relay",
        "sender_clock": {"entries": {}},
        "memories": [],
        "signals": [sig_to_value(&alice_sig), sig_to_value(&bob_sig)],
        "dry_run": false,
    });
    let (status, resp) = post_sync_push(&router, body, "ai:relay").await;
    clear_all_env();

    assert_eq!(status, StatusCode::OK, "resp={resp}");
    assert_eq!(
        i(&resp, "signals_applied"),
        1,
        "strict mode: only the enrolled+valid author (alice) applies; bob is skipped: {resp}"
    );
    assert!(
        i(&resp, "skipped") >= 1,
        "strict mode: the unenrolled author (bob) is skipped: {resp}"
    );
}
