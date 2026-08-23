// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3148 — the federation S40 catch-up batch lane
//! (`federation::sync::bulk_catchup_push`) MUST present the same wire
//! IDENTITY as the per-row fanout: the FED-P3a credential header
//! (`x-memory-cred`) and the FED-P4d anchor-first intermediate-chain header
//! (`x-memory-cred-chain`).
//!
//! Pre-fix only `post_once` attached them (the catch-up lane open-coded its
//! own request builder), so a receiver that resolves a sender's verifying key
//! from the trust bundle could verify a per-row push but had to fall back to a
//! manually enrolled `.pub` for the catch-up batch carrying the SAME memory
//! rows — a per-lane trust asymmetry on identical content.
//!
//! Own test binary because `identity::outbound`'s holder is a process-global
//! `OnceLock`-seeded singleton: this file owns the credential it stores.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use ed25519_dalek::SigningKey;

use ai_memory::federation::identity::chain::CHAIN_HEADER;
use ai_memory::federation::identity::credential::CREDENTIAL_HEADER;
use ai_memory::federation::identity::issuer::{FederationIssuer, IssuerConfig};
use ai_memory::federation::identity::outbound;
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;

const SENDER: &str = "ai:catchup-headers-3148";

type Captured = Arc<std::sync::Mutex<Vec<HeaderMap>>>;

async fn spawn_capturing_peer() -> (String, Captured) {
    let captured: Captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/api/v1/sync/push",
            post(
                |State(state): State<Captured>, headers: HeaderMap| async move {
                    state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(headers);
                    (StatusCode::OK, "{}")
                },
            ),
        )
        .with_state(Arc::clone(&captured));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/api/v1/sync/push"), captured)
}

fn fixture_memory(id: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "catchup-headers-3148".to_string(),
        title: format!("catch-up fixture {id}"),
        content: "durable memory text carried by the catch-up batch".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: "2026-08-20T00:00:00+00:00".to_string(),
        updated_at: "2026-08-20T00:00:00+00:00".to_string(),
        metadata: serde_json::json!({}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// The catch-up batch carries the FED-P3a credential AND the FED-P4d
/// intermediate-chain header, alongside the signature / nonce / api-key /
/// peer-id / `X-Catchup` set the lane already had.
#[tokio::test]
async fn bulk_catchup_attaches_credential_and_chain_headers() {
    let now_unix = chrono::Utc::now().timestamp();
    let root = FederationIssuer::new(
        SigningKey::from_bytes(&[1u8; 32]),
        IssuerConfig::new("trust-domain-root-3148", "fleet.example"),
    );
    let intermediate_key = SigningKey::from_bytes(&[2u8; 32]);
    let intermediate = root
        .issue_intermediate(
            "region/test/ca-3148",
            &intermediate_key.verifying_key(),
            now_unix,
        )
        .expect("mint intermediate");
    let intermediate_issuer = FederationIssuer::new(
        intermediate_key,
        IssuerConfig::new("region/test/ca-3148", "fleet.example"),
    );
    let leaf_key = SigningKey::from_bytes(&[3u8; 32]);
    let leaf = intermediate_issuer
        .issue(SENDER, &leaf_key.verifying_key(), now_unix)
        .expect("mint leaf");
    outbound::store(Some(leaf));
    outbound::store_intermediates(vec![intermediate]);

    let (url, captured) = spawn_capturing_peer().await;
    let _ = ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION
        .set(Box::new(|_action| Ok(())));
    let cfg = FederationConfig {
        policy: QuorumPolicy::new(1, 2, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: "peer-headers-3148".to_string(),
            sync_push_url: url,
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client"),
        sender_agent_id: SENDER.to_string(),
        api_key: Some("catchup-api-key-3148".to_string()),
        signing_key: Some(Arc::new(SigningKey::from_bytes(&[4u8; 32]))),
        dlq_sink: None,
    };

    let memories = vec![fixture_memory("mem-headers-3148")];
    let errors = ai_memory::federation::sync::bulk_catchup_push(&cfg, &memories).await;
    assert!(errors.is_empty(), "catch-up must succeed: {errors:?}");

    let seen = captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = seen.first().expect("peer received the catch-up POST");
    assert!(
        h.get(CREDENTIAL_HEADER).is_some(),
        "the catch-up batch must present the FED-P3a credential header"
    );
    assert!(
        h.get(CHAIN_HEADER).is_some(),
        "the catch-up batch must present the FED-P4d intermediate-chain header"
    );
    // The pre-existing header set is unchanged (no regression from the
    // shared-builder refactor).
    assert_eq!(
        h.get("X-Catchup").and_then(|v| v.to_str().ok()),
        Some("bulk")
    );
    assert!(
        h.get(ai_memory::federation::signing::SIGNATURE_HEADER)
            .is_some()
    );
    assert!(
        h.get(ai_memory::federation::signing::NONCE_HEADER)
            .is_some()
    );
    assert_eq!(
        h.get(ai_memory::HEADER_API_KEY)
            .and_then(|v| v.to_str().ok()),
        Some("catchup-api-key-3148")
    );
    assert_eq!(
        h.get(ai_memory::federation::peer_attestation::PEER_ID_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(SENDER)
    );
}
