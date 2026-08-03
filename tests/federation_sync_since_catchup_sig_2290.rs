// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2290 regression test — the federation catch-up `/sync/since`
//! puller MUST sign its outbound GET so an ENROLLED peer accepts the pull
//! under the default `AI_MEMORY_FED_REQUIRE_SIG=1` posture.
//!
//! ## Root cause (#2290)
//! The inbound `/sync/since` receiver
//! (`verify_get_signature_or_reject`) enforces the #1031 signed-GET
//! contract: an enrolled peer that omits `X-Memory-Sig` is refused
//! `401 x_memory_sig_missing`. But pre-#2290 NO outbound catch-up client
//! signed the GET, so the MOST-secure (fully enrolled, default-strict)
//! mesh got the WORST catch-up — the pull lane was structurally 401'd on
//! every tick (degrade, not corrupt: fewer results, never wrong ones).
//!
//! ## What this test pins
//! A mock `/sync/since` receiver enforces the SAME signature contract the
//! production receiver does (verify `X-Memory-Sig` over the shared
//! `canonical_get_bytes` + `X-Memory-Nonce` against the enrolled peer key):
//!
//! - `catchup_signed_get_is_accepted_2290` — with a daemon signing key on
//!   the `FederationConfig`, the catch-up GET carries a *verifiable*
//!   `X-Memory-Sig`/`X-Memory-Nonce` and the enrolled receiver returns
//!   `200` (the pull lane converges). This is the fix.
//!
//! - `catchup_unsigned_get_is_refused_2290` — the PRE-FIX behaviour
//!   (mutation check): with NO signing key the GET carries no signature
//!   and the enrolled, strict receiver refuses it `401`. This is the exact
//!   #2290 break; if a future refactor drops the signing, this test
//!   re-reddens.

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;

use ai_memory::federation::signing::{
    NONCE_HEADER, SIGNATURE_HEADER, canonical_get_bytes, verify_header_with_nonce,
};
use ai_memory::federation::{FederationConfig, PeerEndpoint, catchup_once_for_tests};
use ai_memory::replication::QuorumPolicy;
use ed25519_dalek::{SigningKey, VerifyingKey};

#[derive(Clone)]
struct EnrolledReceiver {
    /// The enrolled peer's verifying key — the receiver verifies the
    /// inbound `X-Memory-Sig` against this (mirrors the production
    /// `resolve_peer_verifying_key` → `load_daemon_verifying_key` path).
    peer_pubkey: VerifyingKey,
    hits: Arc<AtomicUsize>,
    saw_signature: Arc<AtomicBool>,
    accepted: Arc<AtomicBool>,
}

/// Mock `/sync/since` receiver enforcing the #1031 signed-GET contract the
/// production `verify_get_signature_or_reject` gate enforces under
/// `AI_MEMORY_FED_REQUIRE_SIG=1`: a missing/invalid `X-Memory-Sig` is `401`,
/// a valid one is `200`.
async fn strict_since_handler(
    State(state): State<EnrolledReceiver>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.hits.fetch_add(1, Ordering::Relaxed);

    let sig = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
    let nonce = headers.get(NONCE_HEADER).and_then(|v| v.to_str().ok());
    state.saw_signature.store(sig.is_some(), Ordering::Relaxed);

    // Rebuild the canonical GET bytes from the request-target EXACTLY as
    // the production receiver does (method + path + query via OriginalUri).
    let canonical = canonical_get_bytes("GET", uri.path(), uri.query().unwrap_or(""));

    let verified = match (sig, nonce) {
        (Some(sig), Some(nonce)) => {
            verify_header_with_nonce(Some(sig), &canonical, nonce, &state.peer_pubkey).is_ok()
        }
        _ => false,
    };

    if verified {
        state.accepted.store(true, Ordering::Relaxed);
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"memories": []})),
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
        hits: Arc::new(AtomicUsize::new(0)),
        saw_signature: Arc::new(AtomicBool::new(false)),
        accepted: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route("/api/v1/sync/since", get(strict_since_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), state)
}

fn build_cfg(peer_url: &str, signing_key: Option<SigningKey>) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-0".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:nodeSQ".to_string(),
        api_key: None,
        signing_key: signing_key.map(Arc::new),
        dlq_sink: None,
    }
}

/// The fix: an enrolled peer (daemon signing key present) signs its
/// catch-up GET, and the strict receiver ACCEPTS it (200).
#[tokio::test]
async fn catchup_signed_get_is_accepted_2290() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let (peer_url, recv) = spawn_enrolled_receiver(sk.verifying_key()).await;
    let cfg = build_cfg(&peer_url, Some(sk));

    catchup_once_for_tests(&cfg).await;

    assert_eq!(
        recv.hits.load(Ordering::Relaxed),
        1,
        "catch-up must hit the peer exactly once"
    );
    assert!(
        recv.saw_signature.load(Ordering::Relaxed),
        "#2290 fix: the outbound /sync/since catch-up GET MUST carry an \
         X-Memory-Sig header when a daemon signing key is configured"
    );
    assert!(
        recv.accepted.load(Ordering::Relaxed),
        "#2290 fix: the signature MUST verify against the enrolled peer key \
         over the shared canonical GET bytes — the enrolled receiver accepts \
         the catch-up pull (200) instead of 401'ing it"
    );
}

/// Mutation check (the pre-#2290 break): with NO signing key the catch-up
/// GET is unsigned, and the enrolled, strict receiver REFUSES it (401) —
/// exactly the #2290 symptom (`x_memory_sig_missing` on every tick).
#[tokio::test]
async fn catchup_unsigned_get_is_refused_2290() {
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let (peer_url, recv) = spawn_enrolled_receiver(sk.verifying_key()).await;
    // No signing key on the config → the pre-#2290 unsigned client.
    let cfg = build_cfg(&peer_url, None);

    catchup_once_for_tests(&cfg).await;

    assert_eq!(recv.hits.load(Ordering::Relaxed), 1);
    assert!(
        !recv.saw_signature.load(Ordering::Relaxed),
        "pre-#2290 baseline: an unsigned client sends no X-Memory-Sig"
    );
    assert!(
        !recv.accepted.load(Ordering::Relaxed),
        "pre-#2290 baseline: the enrolled strict receiver refuses the unsigned \
         catch-up GET (401) — this is the functional break #2290 fixes"
    );
}
