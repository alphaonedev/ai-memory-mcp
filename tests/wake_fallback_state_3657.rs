// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #3657 — the daemon's wake fallback gauge must be a MEASURED posture.
//!
//! The handoff's trap 1: `install_uds` stamped BACKSTOP on success, so a
//! healthy hub one handshake away reported itself as fallen back to the poll.
//! This binary is its own process (the sink install and the metrics registry
//! are both process-wide — trap 2), and pins the ladder end to end against a
//! real hub over a real socket:
//!
//! `unobserved (0)` → install → `connecting (3)` → handshake → `hub live (1)`
//! → the hub stops → `backstop (2)`.
//!
//! Deliberately written against the handoff's symbols only, so it compiles on
//! `9a3054e7a` and FAILS there at the "never backstop at install" assertion —
//! the behavioural negative for trap 1. The delivered-counter proof lives in
//! `tests/wake_delivered_3657.rs`.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::sentinels::WAKE_HUB_PRODUCER;
use ai_memory::metrics::{
    self, WAKE_FALLBACK_BACKSTOP, WAKE_FALLBACK_HUB_LIVE, WAKE_FALLBACK_UNOBSERVED,
};
use ai_memory::wake_hub::frame::Kind;
use ai_memory::wake_sink::uds::{
    CredentialError, HelloCredential, JoinCredential, UdsSinkConfig, install_uds,
};
use ed25519_dalek::{Signer as _, SigningKey};
use wake_hub_harness::{Harness, TestVerifier};

struct TestCredential(SigningKey);

impl JoinCredential for TestCredential {
    fn agent_id(&self) -> &str {
        WAKE_HUB_PRODUCER
    }

    fn sign_hello(&self, transcript: &[u8]) -> Result<HelloCredential, CredentialError> {
        Ok(HelloCredential {
            pubkey: self.0.verifying_key().to_bytes(),
            signature: self.0.sign(transcript).to_bytes(),
            delegation: bytes::Bytes::new(),
        })
    }
}

/// Poll the gauge until it reads `want` or the deadline passes.
async fn wait_for_state(want: i64) -> i64 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let now = metrics::wake_fallback_state();
        if now == want || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn installed_forwarder_reports_connecting_then_hub_live_then_backstop_3657() {
    assert_eq!(
        metrics::wake_fallback_state(),
        WAKE_FALLBACK_UNOBSERVED,
        "a fresh process has observed nothing"
    );
    let recipient = format!("erin-{}", uuid::Uuid::new_v4());
    let producer_key = SigningKey::from_bytes(&[41u8; 32]);
    let recipient_key = SigningKey::from_bytes(&[42u8; 32]);
    let mut verifier = TestVerifier::new();
    verifier.allow(WAKE_HUB_PRODUCER, &producer_key);
    verifier.allow(&recipient, &recipient_key);
    let harness = Harness::with_verifier(verifier);
    let mut client = harness.connect().await;
    client.hello(&recipient, &recipient_key, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    let mut cfg = UdsSinkConfig::with_socket_path(harness.socket.clone());
    cfg.hub_id = harness.hub_id.clone();
    let sink_metrics = install_uds(cfg, Arc::new(TestCredential(producer_key)))
        .expect("the forwarder installs for an enrolled producer credential");
    // Trap 1: a successful install is NOT "fallen back" (the handoff's
    // inversion), and it is not "unobserved" either — something was observed.
    // Written against the handoff's own constants so this test compiles on
    // 9a3054e7a and fails there.
    let at_install = metrics::wake_fallback_state();
    assert_ne!(
        at_install, WAKE_FALLBACK_BACKSTOP,
        "the handoff's inversion"
    );
    assert_ne!(
        at_install, WAKE_FALLBACK_UNOBSERVED,
        "the install was observed"
    );
    assert_eq!(
        wait_for_state(WAKE_FALLBACK_HUB_LIVE).await,
        WAKE_FALLBACK_HUB_LIVE
    );

    // The install's counters are the ones boot can reach afterwards.
    let installed = ai_memory::wake_sink::installed_sink_metrics()
        .expect("boot no longer discards the installed sink's counters");
    assert!(Arc::ptr_eq(&installed, &sink_metrics));
    // A real notify: the substrate publishes onto the bus, the installed
    // forwarder carries it over the socket, the hub writes it to the client.
    // (A tempdir-scoped database, never a `NamedTempFile` path — #3669.)
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wake-3657.db");
    let conn = ai_memory::db::open(&db_path).expect("open");
    ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &serde_json::json!({
            "target_agent_id": recipient,
            "title": "SUBJECT-3657",
            "payload": "BODY-3657",
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");
    let frame = client.expect_frame().await;
    assert_eq!(frame.kind, Kind::Wake, "the live session carries wakes");

    // The hub goes away: the session breaks and the gauge must say BACKSTOP,
    // not keep advertising a session that no longer exists.
    harness.stop().await;
    assert_eq!(
        wait_for_state(WAKE_FALLBACK_BACKSTOP).await,
        WAKE_FALLBACK_BACKSTOP
    );
}
