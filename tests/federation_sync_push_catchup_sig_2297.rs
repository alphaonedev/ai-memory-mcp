// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2297 regression test — the federation catch-up `/sync/push`
//! PUSH lane of `daemon_runtime::sync_cycle_once` MUST sign its outbound
//! POST body so an ENROLLED peer accepts the push under the default
//! `AI_MEMORY_FED_REQUIRE_SIG=1` posture.
//!
//! ## Root cause (#2297 — the PUSH sibling of #2290)
//! The inbound `/sync/push` receiver (`verify_signature_or_reject`)
//! enforces the #791/#922 body-signature contract: an enrolled peer that
//! omits `X-Memory-Sig` is refused `401`. #2290 (PR #2296) fixed the PULL
//! direction (`/sync/since` GET) inside `sync_cycle_once`, but the PUSH
//! direction still attached only `X-Agent-Id`/`X-Peer-Id`/`x-api-key` —
//! no `X-Memory-Sig`. So the CLI `sync-daemon` push lane was structurally
//! 401'd on every tick for a fully-enrolled strict mesh (degrade, not
//! corrupt: the push never converged, but no wrong data was written).
//!
//! ## What this test pins
//! The REAL `daemon_runtime::sync_cycle_once` client drives against a mock
//! receiver whose `/sync/push` enforces the SAME body-signature contract the
//! production receiver does (`verify_header_with_nonce` over the raw POST
//! body bytes || 0x00 || nonce, against the enrolled peer key). The daemon
//! signing key is enrolled ON DISK under `AI_MEMORY_KEY_DIR` exactly as
//! `load_daemon_signing_key` reads it.
//!
//! - `push_signed_is_accepted_2297` — with a daemon signing key on disk,
//!   the push carries a *verifiable* `X-Memory-Sig`/`X-Memory-Nonce` over
//!   the body and the enrolled receiver returns `200` (push converges).
//!   This is the fix.
//!
//! - `push_unsigned_is_refused_2297` — the PRE-FIX behaviour (mutation
//!   check): with NO signing key on disk the push carries no signature and
//!   the enrolled, strict receiver refuses it `401`, so `sync_cycle_once`
//!   returns `Err`. This is the exact #2297 break; if a future refactor
//!   drops the push signing, this test re-reddens.

#![allow(clippy::await_holding_lock)]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use tempfile::TempDir;
use tokio::net::TcpListener;

use ai_memory::db;
use ai_memory::federation::signing::{NONCE_HEADER, SIGNATURE_HEADER, verify_header_with_nonce};
use ai_memory::identity::keypair as kp_mod;
use ai_memory::models::{Memory, Tier};
use ed25519_dalek::VerifyingKey;

/// `AI_MEMORY_KEY_DIR` is a PROCESS-GLOBAL env var and `sync_cycle_once`
/// reads it (via `load_daemon_signing_key`) at run time; the two tests
/// below must not race on it. This file-scoped mutex serialises the
/// set-key-dir → run → assert window per test.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone)]
struct EnrolledReceiver {
    /// The enrolled peer's verifying key — the receiver verifies the
    /// inbound `X-Memory-Sig` against this (mirrors the production
    /// `resolve_peer_verifying_key` path).
    peer_pubkey: VerifyingKey,
    push_hits: Arc<AtomicUsize>,
    saw_push_signature: Arc<AtomicBool>,
    push_accepted: Arc<AtomicBool>,
}

/// Mock `/sync/since` GET — the PULL lane runs first inside
/// `sync_cycle_once`; return the standard empty envelope so the flow
/// proceeds to the PUSH lane under test. (The pull-side signing is the
/// already-landed #2290 concern; this mock accepts it unconditionally so
/// the push is isolated.)
async fn since_handler() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"count": 0, "limit": 10, "memories": []})),
    )
}

/// Mock `/sync/push` POST enforcing the production `/sync/push`
/// body-signature contract (`verify_signature_or_reject` under
/// `AI_MEMORY_FED_REQUIRE_SIG=1`): a missing/invalid `X-Memory-Sig` over
/// the raw body bytes is `401`, a valid nonce-bound one is `200`.
async fn push_handler(
    State(state): State<EnrolledReceiver>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.push_hits.fetch_add(1, Ordering::Relaxed);

    let sig = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
    let nonce = headers.get(NONCE_HEADER).and_then(|v| v.to_str().ok());
    state
        .saw_push_signature
        .store(sig.is_some(), Ordering::Relaxed);

    // Verify over the RAW body bytes exactly as the production receiver
    // does (`verify_header_with_nonce(sig, body_bytes, nonce, pk)`).
    let verified = match (sig, nonce) {
        (Some(sig), Some(nonce)) => {
            verify_header_with_nonce(Some(sig), &body, nonce, &state.peer_pubkey).is_ok()
        }
        _ => false,
    };

    if verified {
        state.push_accepted.store(true, Ordering::Relaxed);
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"applied": 0})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "x_memory_sig_missing"})),
        )
    }
}

async fn spawn_enrolled_receiver(peer_pubkey: VerifyingKey) -> (String, EnrolledReceiver) {
    let state = EnrolledReceiver {
        peer_pubkey,
        push_hits: Arc::new(AtomicUsize::new(0)),
        saw_push_signature: Arc::new(AtomicBool::new(false)),
        push_accepted: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route("/api/v1/sync/since", get(since_handler))
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), state)
}

/// Seed one memory into a fresh sqlite DB so `sync_cycle_once`'s
/// `memories_updated_since` returns a non-empty `outgoing` batch and the
/// push actually fires.
fn seed_db_with_one_memory() -> tempfile::NamedTempFile {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let conn = db::open(db_tmp.path()).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: "00000000-0000-0000-0000-00000000229a".to_string(),
        title: "push-sig-target".to_string(),
        content: "outgoing row that must be pushed to the enrolled peer".to_string(),
        namespace: "ns-2297".to_string(),
        tier: Tier::Mid,
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    };
    db::insert(&conn, &mem).expect("insert outgoing memory");
    drop(conn); // release before sync_cycle_once opens its own connections
    db_tmp
}

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client")
}

/// The fix: an enrolled peer (daemon signing key on disk) signs its
/// catch-up PUSH body, and the strict receiver ACCEPTS it (200).
#[tokio::test(flavor = "current_thread")]
async fn push_signed_is_accepted_2297() {
    let _g = env_lock();
    let key_tmp = TempDir::new().expect("key tempdir");
    // SAFETY: env mutation; the file-scoped env_lock is held for the whole
    // set → run → assert window so no sibling test sees intermediate state.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_tmp.path());
    }

    let agent_id = "ai:node-2297a";
    let kp = kp_mod::generate(agent_id).expect("generate daemon keypair");
    // Save the FULL keypair (incl. private) so `load_daemon_signing_key`
    // finds it on disk and `sync_cycle_once` signs the push.
    kp_mod::save(&kp, key_tmp.path()).expect("enrol daemon signing key on disk");
    let peer_pub = kp.public;

    let db_tmp = seed_db_with_one_memory();
    let (peer_url, recv) = spawn_enrolled_receiver(peer_pub).await;
    let client = build_client();

    let res = ai_memory::daemon_runtime::sync_cycle_once(
        &client,
        db_tmp.path(),
        agent_id,
        &peer_url,
        None,
        100,
    )
    .await;

    unsafe {
        std::env::remove_var("AI_MEMORY_KEY_DIR");
    }

    assert!(
        res.is_ok(),
        "#2297 fix: the signed push MUST be accepted (200) by the enrolled \
         receiver, so sync_cycle_once returns Ok; got {res:?}"
    );
    assert_eq!(
        recv.push_hits.load(Ordering::Relaxed),
        1,
        "the push must hit the peer exactly once"
    );
    assert!(
        recv.saw_push_signature.load(Ordering::Relaxed),
        "#2297 fix: the outbound /sync/push POST MUST carry an X-Memory-Sig \
         header when a daemon signing key is enrolled on disk"
    );
    assert!(
        recv.push_accepted.load(Ordering::Relaxed),
        "#2297 fix: the signature MUST verify against the enrolled peer key \
         over the raw POST body bytes + nonce — the enrolled receiver accepts \
         the push (200) instead of 401'ing it"
    );
}

/// Mutation check (the pre-#2297 break): with NO signing key on disk the
/// push body is unsigned, and the enrolled, strict receiver REFUSES it
/// (401), so `sync_cycle_once` returns `Err` — exactly the #2297 symptom.
#[tokio::test(flavor = "current_thread")]
async fn push_unsigned_is_refused_2297() {
    let _g = env_lock();
    // Empty key dir → `load_daemon_signing_key` returns None → the pre-#2297
    // unsigned push client.
    let key_tmp = TempDir::new().expect("key tempdir");
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_tmp.path());
    }

    let agent_id = "ai:node-2297b";
    // Generate a throwaway keypair only to give the mock receiver a pubkey to
    // enrol; it is NOT saved to the key dir, so the client stays unsigned.
    let kp = kp_mod::generate(agent_id).expect("generate throwaway keypair");
    let peer_pub = kp.public;

    let db_tmp = seed_db_with_one_memory();
    let (peer_url, recv) = spawn_enrolled_receiver(peer_pub).await;
    let client = build_client();

    let res = ai_memory::daemon_runtime::sync_cycle_once(
        &client,
        db_tmp.path(),
        agent_id,
        &peer_url,
        None,
        100,
    )
    .await;

    unsafe {
        std::env::remove_var("AI_MEMORY_KEY_DIR");
    }

    assert!(
        res.is_err(),
        "pre-#2297 baseline: the enrolled strict receiver refuses the unsigned \
         push (401), so sync_cycle_once MUST return Err; got {res:?}"
    );
    assert_eq!(
        recv.push_hits.load(Ordering::Relaxed),
        1,
        "the push must still be attempted exactly once"
    );
    assert!(
        !recv.saw_push_signature.load(Ordering::Relaxed),
        "pre-#2297 baseline: an unsigned client sends no X-Memory-Sig"
    );
    assert!(
        !recv.push_accepted.load(Ordering::Relaxed),
        "pre-#2297 baseline: the enrolled strict receiver refuses the unsigned \
         push (401) — this is the functional break #2297 fixes"
    );
}
