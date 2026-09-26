// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #3806 — f1's DELTA security review of god/3806-w125 @ 9361f0699
//! (REVIEW-3806-W125-SECURITY-f1.md), findings N1 and N2, pinned through
//! the REAL seam: a client built by `attach_decider` (the boot
//! chokepoint) and `OllamaClient::detect_contradiction_async`.
//!
//! * N1 — an explicit `message.refusal` is a terminal decline even when
//!   `content` ALSO parses to a verdict. f1's exact mock body.
//! * N2 — the R9 breaker is a TRUE half-open: after the cooldown, a
//!   concurrent wave sends exactly ONE probe to the dead endpoint; the rest
//!   fail closed. Recovery control on a second surface: a successful probe
//!   closes the breaker and the following wave is admitted in full.
//!
//! N2 waits out the real 30 s cooldown once (both surfaces share it). This
//! binary is its own process, so the breakers and metrics are not shared.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::{BREAKER_COOLDOWN, BREAKER_THRESHOLD, attach_decider};
use ai_memory::llm::OllamaClient;

const DECISION_PATH: &str = "/chat/completions";
const GENERATIVE_PATH: &str = "/api/chat";
const A: &str = "The primary database listens on port 5432.";
const B: &str = "The primary database listens on port 6543.";
/// Callers released together after the cooldown.
const WAVE: usize = 6;

fn cfg(decision_url: &str, generative_url: &str, fallback: DecisionFallback) -> AppConfig {
    AppConfig {
        llm: Some(LlmSection {
            backend: Some("ollama".to_string()),
            model: Some("fixture-chat".to_string()),
            base_url: Some(generative_url.to_string()),
            ..LlmSection::default()
        }),
        decision: Some(DecisionSection {
            provider: Some("openai-compatible".to_string()),
            model: Some("fixture-decider".to_string()),
            base_url: Some(decision_url.to_string()),
            api_key_env: None,
            api_key_file: None,
            api_key: None,
            timeout_secs: Some(2),
            fallback: Some(fallback),
        }),
        ..AppConfig::default()
    }
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// A surface: its own decision + generative mocks and its own attachment.
async fn surface(
    decision: &MockServer,
    fallback: DecisionFallback,
) -> (MockServer, Arc<OllamaClient>, tempfile::TempDir) {
    let generative = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GENERATIVE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"role": "assistant", "content": "yes"}})),
        )
        .mount(&generative)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let conf = cfg(&decision.uri(), &generative.uri(), fallback);
    let client = OllamaClient::new_with_url_no_health_check(&generative.uri(), "fixture-chat")
        .expect("client builds");
    let client = attach_decider(Some(client), &conf, db.path()).expect("client returned");
    (generative, Arc::new(client), db)
}

fn chat(content: &str) -> serde_json::Value {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
}

// ---------------------------------------------------------------- N1

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_refusal_is_terminal_even_when_content_parses_n1() {
    // Controls on the same client shape first: a plain yes decides; an
    // explicit refusal with null content is a decline.
    for (body, want_contradiction) in [
        (chat("{\"verdict\":\"yes\"}"), true),
        (
            json!({"choices":[{"message":{"content":null,"refusal":"I decline"}}]}),
            false,
        ),
    ] {
        let decision = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DECISION_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&decision)
            .await;
        let (generative, client, _db) = surface(&decision, DecisionFallback::Refuse).await;
        let got = client
            .detect_contradiction_async(A, B)
            .await
            .expect("a decision or a decline is never an error under refuse");
        assert_eq!(got, want_contradiction);
        assert_eq!(hits(&generative).await, 0);
    }

    // f1's exact contradictory envelope: content says yes, refusal says no.
    let decision = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {"choices":[{"message":{"content":"{\"verdict\":\"yes\"}","refusal":"I decline"}}]}
        )))
        .mount(&decision)
        .await;
    let (generative, client, _db) = surface(&decision, DecisionFallback::Refuse).await;
    let got = client.detect_contradiction_async(A, B).await;
    assert!(
        matches!(got, Ok(false)),
        "an explicit refusal must be the terminal DECLINE (non-action, never an error, \
         never a verdict), whatever the content says: got {got:?}"
    );
    assert_eq!(hits(&decision).await, 1);
    assert_eq!(hits(&generative).await, 0, "a decline is never re-asked");
}

// ---------------------------------------------------------------- N2

/// Release `WAVE` concurrent seam calls at once.
async fn wave(client: &Arc<OllamaClient>) -> Vec<bool> {
    let barrier = Arc::new(tokio::sync::Barrier::new(WAVE));
    let tasks: Vec<_> = (0..WAVE)
        .map(|_| {
            let client = Arc::clone(client);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                client
                    .detect_contradiction_async(A, B)
                    .await
                    .expect("`fallback = abstain` never errors")
            })
        })
        .collect();
    let mut out = Vec::with_capacity(WAVE);
    for t in tasks {
        out.push(t.await.expect("join"));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_cooldown_a_concurrent_wave_sends_exactly_one_probe_n2() {
    let threshold = usize::try_from(BREAKER_THRESHOLD).expect("small");

    // DEAD surface: every call 503s, with a delay so the whole wave is in
    // admission before any probe completes.
    let dead = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(300)))
        .mount(&dead)
        .await;
    let (_g1, dead_client, _db1) = surface(&dead, DecisionFallback::Abstain).await;

    // RECOVERING surface: 503 for the tripping calls, then healthy.
    let recovering = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(u64::from(BREAKER_THRESHOLD))
        .with_priority(1)
        .mount(&recovering)
        .await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_json(chat("{\"verdict\":\"no\"}")),
        )
        .with_priority(2)
        .mount(&recovering)
        .await;
    let (_g2, rec_client, _db2) = surface(&recovering, DecisionFallback::Abstain).await;

    // Trip both, serially.
    for client in [&dead_client, &rec_client] {
        for _ in 0..threshold {
            assert!(
                !client
                    .detect_contradiction_async(A, B)
                    .await
                    .expect("abstain")
            );
        }
        // Open: an immediate call is short-circuited.
        assert!(
            !client
                .detect_contradiction_async(A, B)
                .await
                .expect("abstain")
        );
    }
    assert_eq!(hits(&dead).await, threshold);
    assert_eq!(hits(&recovering).await, threshold);

    tokio::time::sleep(BREAKER_COOLDOWN + Duration::from_millis(500)).await;

    // ABSENCE — the dead endpoint sees exactly ONE half-open probe.
    let seen = wave(&dead_client).await;
    assert_eq!(seen, vec![false; WAVE], "an outage never becomes a verdict");
    assert_eq!(
        hits(&dead).await,
        threshold + 1,
        "after the cooldown a concurrent wave must send exactly ONE probe (f1 delta N2)"
    );

    // RECOVERY control — one probe decides and closes the breaker...
    let seen = wave(&rec_client).await;
    assert_eq!(seen, vec![false; WAVE]);
    assert_eq!(hits(&recovering).await, threshold + 1, "one probe");
    // ...and the next wave is admitted in full.
    let seen = wave(&rec_client).await;
    assert_eq!(seen, vec![false; WAVE]);
    assert_eq!(
        hits(&recovering).await,
        threshold + 1 + WAVE,
        "a closed breaker admits every caller"
    );
}
