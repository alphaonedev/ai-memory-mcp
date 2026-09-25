// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::field_reassign_with_default, clippy::doc_markdown)]
//! #3806 vote R9 — the decision seams carry a CIRCUIT BREAKER.
//!
//! `classify_kind` runs inside the curator's transcript-classify batch
//! loop (`max_per_cycle` rows per cycle). With the decision endpoint
//! down, every row paid a full network attempt — up to
//! `[decision].timeout_secs` each — so one dead endpoint turned a batch
//! into minutes of blocked work and a stream of identical requests at a
//! host that is not answering.
//!
//! The breaker trips on consecutive UNAVAILABILITY (timeout, transport
//! failure, non-2xx) and short-circuits to the same `unavailable`
//! abstain the call would have produced — so it can only shorten an
//! outage's cost, never change what a seam does with it (`fallback`
//! still governs, case 2). A DECLINE is an answer and never trips it,
//! and a decided answer closes it.
//!
//! This binary is its own process, so the breaker and the metrics
//! registry it touches are not shared with any other test.

use std::sync::Arc;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::{BREAKER_THRESHOLD, attach_decider};
use ai_memory::llm::OllamaClient;
use ai_memory::models::MemoryKind;

const DECISION_PATH: &str = "/chat/completions";
/// Enough rows that an untripped breaker is unmistakable.
const BATCH: usize = 10;

fn cfg_with_decision(decision_url: &str, generative_url: &str) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some(generative_url.to_string()),
        ..LlmSection::default()
    });
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decider-1".to_string()),
        base_url: Some(decision_url.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(DecisionFallback::Abstain),
    });
    cfg
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// A fresh surface: its own decision endpoint answering with `response`,
/// its own boot-chokepoint attachment (so its own breaker).
async fn surface(response: ResponseTemplate) -> (MockServer, MockServer, Arc<OllamaClient>) {
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(response)
        .mount(&decision)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri());
    let client = OllamaClient::new_with_url_no_health_check(&generative.uri(), "vendor/chat-1")
        .expect("client builds");
    let client = attach_decider(Some(client), &cfg, db.path()).expect("client returned");
    (decision, generative, Arc::new(client))
}

/// Run the seam `BATCH` times, as the curator's loop does.
async fn classify_batch(client: &Arc<OllamaClient>) -> Vec<Option<MemoryKind>> {
    let client = Arc::clone(client);
    tokio::task::spawn_blocking(move || {
        (0..BATCH)
            .map(|_| {
                client
                    .classify_kind("t", "c")
                    .expect("`fallback = abstain` never errors")
            })
            .collect()
    })
    .await
    .expect("join")
}

fn body(content: &str) -> serde_json::Value {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_decider_stops_being_dialled_after_the_threshold() {
    // ABSENCE — an endpoint answering 503 is asked exactly THRESHOLD
    // times, then the breaker answers for it. Every row still takes the
    // SAME conservative branch it would have taken (`Ok(None)`), so the
    // breaker changed the cost of the outage, not its outcome.
    let (dead, generative, client) = surface(ResponseTemplate::new(503)).await;
    let seen = classify_batch(&client).await;
    assert_eq!(seen, vec![None; BATCH], "an outage never becomes a kind");
    assert_eq!(
        hits(&dead).await,
        usize::try_from(BREAKER_THRESHOLD).expect("small"),
        "after {BREAKER_THRESHOLD} consecutive outages the decision lane must stop dialling \
         a dead endpoint for every row of the batch (#3806 R9)"
    );
    assert_eq!(hits(&generative).await, 0, "`abstain` never reaches [llm]");

    // PRESENCE controls on the same sink shape — the breaker is about
    // UNAVAILABILITY only:
    // (a) a DECLINE is an answer: every row is asked.
    let (declining, _g, client) =
        surface(ResponseTemplate::new(200).set_body_json(body("I would rather not say."))).await;
    let seen = classify_batch(&client).await;
    assert_eq!(seen, vec![None; BATCH]);
    assert_eq!(
        hits(&declining).await,
        BATCH,
        "a decline never trips the breaker"
    );

    // (b) a healthy decider: every row is asked and decided.
    let (healthy, _g, client) = surface(
        ResponseTemplate::new(200).set_body_json(body(&json!({"choice": "decision"}).to_string())),
    )
    .await;
    let seen = classify_batch(&client).await;
    assert_eq!(seen, vec![Some(MemoryKind::Decision); BATCH]);
    assert_eq!(hits(&healthy).await, BATCH);
}
