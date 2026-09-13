// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #3657 — "delivered" is MEASURED at the hub writer.
//!
//! A socket probe proves the hub answers; it does not prove a wake reached a
//! recipient. This binary (its own process: one sink install, one registry)
//! forwards a real substrate `notify` through an installed UDS forwarder to a
//! real hub and asserts the hub writer counted the wake frame it wrote —
//! `HubMetrics::wakes_written` and the scrape series
//! `ai_memory_wake_delivered_total` — and that a control frame did not.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::sentinels::WAKE_HUB_PRODUCER;
use ai_memory::metrics;
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

#[tokio::test]
async fn a_wake_written_to_the_recipient_socket_counts_as_delivered_3657() {
    let recipient = format!("erin-{}", uuid::Uuid::new_v4());
    let producer_key = SigningKey::from_bytes(&[41u8; 32]);
    let recipient_key = SigningKey::from_bytes(&[42u8; 32]);
    let mut verifier = TestVerifier::new();
    verifier.allow(WAKE_HUB_PRODUCER, &producer_key);
    verifier.allow(&recipient, &recipient_key);
    let harness = Harness::with_verifier(verifier);
    let mut client = harness.connect().await;
    client.hello(&recipient, &recipient_key, &[]).await;
    // The welcome is a CONTROL frame the writer wrote: it must not count.
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    assert_eq!(harness.metrics.snapshot(0).wakes_written, 0);
    let delivered_before = metrics::wake_delivered_count();

    let mut cfg = UdsSinkConfig::with_socket_path(harness.socket.clone());
    cfg.hub_id = harness.hub_id.clone();
    install_uds(cfg, Arc::new(TestCredential(producer_key))).expect("forwarder installs");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metrics::wake_fallback_state() != metrics::WAKE_FALLBACK_HUB_LIVE
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A tempdir-scoped database, never a `NamedTempFile` path (#3669).
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wake-delivered-3657.db");
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
    assert_eq!(client.expect_frame().await.kind, Kind::Wake);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metrics::wake_delivered_count() == delivered_before
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        metrics::wake_delivered_count() > delivered_before,
        "delivery was not counted"
    );
    assert_eq!(harness.metrics.snapshot(0).wakes_written, 1);
    assert!(
        metrics::render().contains(metrics::METRIC_WAKE_DELIVERED_TOTAL),
        "delivered series missing from the scrape"
    );
    harness.stop().await;
}
