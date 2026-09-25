// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::all, clippy::pedantic, unused_imports, dead_code)]
//! #3806 — f1's adversarial pre-rebase security probe (REVIEW-3806-PREREBASE-
//! SECURITY-f1.md), PORTED VERBATIM as red-first pins onto god/3806-w125 at
//! GOD's ruling. Each named test is one finding: F2 — a BOOT egress refusal must honour `fallback =
//! "refuse"`. Its own binary: it sets the process-global posture
//! (`AI_MEMORY_INFERENCE_EGRESS=loopback-only`) and holds the ONE test here. Test NAMES and ASSERTIONS are f1's verbatim
//! (rustfmt re-laid the source); lints are allowed for the port.
use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision::{AbstainReason, DecisionProvider, DecisionSource};
use ai_memory::decision_clients::{
    OutboundCheck, chat::OpenAiCompatibleDecider, fallback::GenerativeFallbackDecider,
    systemone::SystemOneDecider,
};
use ai_memory::decision_config::{DecisionFallback, DecisionSection, resolve_decision};
use ai_memory::decision_seams::attach_decider;
use ai_memory::llm::OllamaClient;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
const A: &str = "The primary database listens on port 5432.";
const B: &str = "The primary database listens on port 6543.";
fn cfg(url: &str, fallback: DecisionFallback) -> AppConfig {
    let mut c = AppConfig::default();
    c.decision = Some(DecisionSection {
        provider: Some("openai-compatible".into()),
        model: Some("fixture-model".into()),
        base_url: Some(url.into()),
        timeout_secs: Some(1),
        fallback: Some(fallback),
        ..Default::default()
    });
    c
}
fn permit() -> OutboundCheck {
    Arc::new(|_| Ok(()))
}
fn body(s: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":s}}]})
}
async fn mount(s: &MockServer, r: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(r)
        .mount(s)
        .await;
}
async fn count(s: &MockServer) -> usize {
    s.received_requests().await.unwrap().len()
}
fn client(c: &AppConfig, url: &str, p: &std::path::Path) -> OllamaClient {
    attach_decider(
        Some(OllamaClient::new_with_url_no_health_check(url, "fixture-chat").unwrap()),
        c,
        p,
    )
    .unwrap()
}
#[tokio::test]
async fn boot_egress_refusal_must_honor_refuse() {
    // SAFETY: this binary holds exactly one test, so no other thread reads or
    // writes the process environment concurrently (f1 set it on the command line).
    unsafe { std::env::set_var("AI_MEMORY_INFERENCE_EGRESS", "loopback-only") };
    assert_eq!(
        std::env::var("AI_MEMORY_INFERENCE_EGRESS").unwrap(),
        "loopback-only"
    );
    let genserver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message":{"role":"assistant","content":"yes"}})),
        )
        .mount(&genserver)
        .await;
    let mut c = cfg("https://decision.invalid", DecisionFallback::Refuse);
    c.llm = Some(LlmSection {
        backend: Some("ollama".into()),
        model: Some("fixture-chat".into()),
        base_url: Some(genserver.uri()),
        ..Default::default()
    });
    let d = tempfile::tempdir().unwrap();
    let c = client(&c, &genserver.uri(), &d.path().join("audit.db"));
    let got = c.detect_contradiction_async(A, B).await;
    println!(
        "PROBE_BOOT_REFUSE result={got:?} legacy_hits={}",
        count(&genserver).await
    );
    assert!(
        got.is_err(),
        "refused decision boot bypassed fallback=refuse"
    );
}
