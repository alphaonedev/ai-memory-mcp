// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(
    clippy::field_reassign_with_default,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::similar_names,
    clippy::cast_precision_loss
)]
//! #3806 W1c — the `[decision]` client pins, over a LOCAL mock HTTP
//! server (`wiremock`, the idiom `src/llm.rs`'s own tests use). No test
//! in this file touches a real network: every endpoint is a mock bound
//! to loopback on an ephemeral port, and the one "unreachable endpoint"
//! case uses a port that was bound and immediately released.
//!
//! Each pin below pairs an ABSENCE assertion with a PRESENCE control on
//! the same sink, because "no confidence" and "no request" are both
//! trivially satisfiable by a broken harness.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::AppConfig;
use ai_memory::decision::{AbstainReason, DecisionProvider, DecisionSource};
use ai_memory::decision_clients::chat::OpenAiCompatibleDecider;
use ai_memory::decision_clients::fallback::GenerativeFallbackDecider;
use ai_memory::decision_clients::systemone::SystemOneDecider;
use ai_memory::decision_clients::{OutboundCheck, construct};
use ai_memory::decision_config::{
    DecisionFallback, DecisionSection, ResolvedDecision, resolve_decision,
};
use ai_memory::llm::OllamaClient;

/// The chat-completions route the structured client posts to.
const CHAT_PATH: &str = "/chat/completions";
/// The direct decision route.
const SYSTEMONE_PATH: &str = "/v1/systemone";

/// A hook that permits every destination.
fn permit() -> OutboundCheck {
    Arc::new(|_| Ok(()))
}

/// A hook that refuses every destination, as a `deny` egress posture
/// would.
fn refuse() -> OutboundCheck {
    Arc::new(|_| Err(anyhow::anyhow!("egress posture refused this destination")))
}

/// Build a `ResolvedDecision` through the real resolver, so these pins
/// exercise the same construction path the boot chokepoint will.
fn resolve_for(
    provider: &str,
    base_url: &str,
    timeout_secs: u64,
    fallback: DecisionFallback,
) -> ResolvedDecision {
    let mut cfg = AppConfig::default();
    cfg.decision = Some(DecisionSection {
        provider: Some(provider.to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(base_url.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(timeout_secs),
        fallback: Some(fallback),
    });
    resolve_decision(&cfg).expect("a complete [decision] section must resolve")
}

/// A chat-completions body carrying `content`, with optional token
/// logprobs.
fn chat_body(content: &str, logprobs: Option<Value>) -> Value {
    let mut choice = json!({"message": {"role": "assistant", "content": content}});
    if let Some(tokens) = logprobs {
        choice["logprobs"] = json!({"content": tokens});
    }
    json!({"choices": [choice]})
}

async fn mount_chat(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path(CHAT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn hits(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .len()
}

// ---------------------------------------------------------------------
// 1. A schema-conformant answer decides, and logprobs are the ONLY thing
//    that licenses a confidence.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_conformant_answer_decides_and_only_logprobs_license_a_confidence() {
    // PRESENCE: logprobs present => a confidence in (0, 1].
    let with_logprobs = MockServer::start().await;
    mount_chat(
        &with_logprobs,
        chat_body(
            "{\"verdict\":\"yes\"}",
            Some(json!([
                {"token": "{\"verdict\":\"", "logprob": -0.001},
                {"token": "yes", "logprob": -0.105_360_515_657_826_3},
                {"token": "\"}", "logprob": -0.001},
            ])),
        ),
    )
    .await;
    let resolved = resolve_for(
        "openai-compatible",
        &with_logprobs.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("client constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.verdict(),
        Some(true),
        "a schema-conformant answer must DECIDE"
    );
    assert_eq!(judgement.source(), DecisionSource::DecisionModel);
    let confidence = judgement
        .confidence()
        .expect("logprobs present => a confidence");
    assert!(
        confidence > 0.0 && confidence <= 1.0,
        "confidence must be a probability, got {confidence}"
    );
    assert!(
        (confidence - 0.9).abs() < 1e-3,
        "the confidence must be exp(logprob of the decided token), got {confidence}"
    );

    // ABSENCE, same sink: identical body with NO logprobs block still
    // decides, but carries NO confidence — never a fabricated 1.0.
    let without = MockServer::start().await;
    mount_chat(&without, chat_body("{\"verdict\":\"yes\"}", None)).await;
    let resolved = resolve_for(
        "openai-compatible",
        &without.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("client constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(true), "still decides");
    assert_eq!(
        judgement.confidence(),
        None,
        "no logprobs => NO confidence, not 1.0"
    );

    // And a closed-set choice reports the VOCABULARY's spelling.
    let choose = MockServer::start().await;
    mount_chat(&choose, chat_body("{\"choice\":\"fact\"}", None)).await;
    let resolved = resolve_for(
        "openai-compatible",
        &choose.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("client constructs");
    let choice = decider.choose("classify", &["Fact", "Decision"]).await;
    assert_eq!(choice.chosen(), Some("Fact"));
}

// ---------------------------------------------------------------------
// 2. Malformed, off-vocabulary and non-2xx answers abstain as Unusable —
//    and NEVER become a `false`.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_or_off_vocabulary_answer_abstains_as_unusable() {
    for content in [
        "I think they conflict, because the ports differ.",
        "{\"verdict\":\"maybe\"}",
        "{\"other\":\"yes\"}",
        "",
    ] {
        let server = MockServer::start().await;
        mount_chat(&server, chat_body(content, None)).await;
        let resolved = resolve_for(
            "openai-compatible",
            &server.uri(),
            2,
            DecisionFallback::Abstain,
        );
        let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
        let judgement = decider.judge("do these two records conflict?").await;
        assert_eq!(
            judgement.abstain_reason(),
            Some(AbstainReason::Unusable),
            "unusable body {content:?} must abstain"
        );
        assert_eq!(judgement.verdict(), None, "an abstain carries no verdict");
        assert_ne!(
            judgement.verdict(),
            Some(false),
            "an unusable answer must NEVER become a `false` ({content:?})"
        );
        assert_eq!(judgement.confidence(), None);
    }

    // A non-2xx status is likewise an abstain, not an error a seam could
    // coerce.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CHAT_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream on fire"))
        .mount(&server)
        .await;
    let resolved = resolve_for(
        "openai-compatible",
        &server.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.abstain_reason(), Some(AbstainReason::Unusable));
    assert_eq!(judgement.verdict(), None);
}

// ---------------------------------------------------------------------
// 3. A silent endpoint abstains as a TIMEOUT, inside the budget.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_endpoint_abstains_as_a_timeout_inside_the_budget() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(CHAT_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(chat_body("{\"verdict\":\"yes\"}", None))
                .set_delay(Duration::from_secs(20)),
        )
        .mount(&server)
        .await;
    let resolved = resolve_for(
        "openai-compatible",
        &server.uri(),
        1,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");

    let started = Instant::now();
    let judgement = decider.judge("do these two records conflict?").await;
    let elapsed = started.elapsed();

    assert_eq!(
        judgement.abstain_reason(),
        Some(AbstainReason::Timeout),
        "a timeout is an ABSTAIN with its own reason"
    );
    assert_eq!(judgement.verdict(), None, "a timeout is never a verdict");
    assert!(
        elapsed < Duration::from_secs(5),
        "the abstain must land near timeout_secs = 1, took {elapsed:?}"
    );

    // PRESENCE control: the same server without the delay decides well
    // inside the same budget, so the assertion above is about the delay
    // and not about the client being broken.
    let quick = MockServer::start().await;
    mount_chat(&quick, chat_body("{\"verdict\":\"yes\"}", None)).await;
    let resolved = resolve_for(
        "openai-compatible",
        &quick.uri(),
        1,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    assert_eq!(
        decider
            .judge("do these two records conflict?")
            .await
            .verdict(),
        Some(true)
    );
}

// ---------------------------------------------------------------------
// 4. The outbound hook runs BEFORE the socket: a refusal leaves no trace
//    on the mock.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_outbound_refusal_stops_the_request_before_the_socket() {
    let server = MockServer::start().await;
    mount_chat(&server, chat_body("{\"verdict\":\"yes\"}", None)).await;
    let resolved = resolve_for(
        "openai-compatible",
        &server.uri(),
        2,
        DecisionFallback::Abstain,
    );

    // ABSENCE: the hook refuses; the endpoint never hears from us.
    let refused = OpenAiCompatibleDecider::new(&resolved, refuse()).expect("constructs");
    let judgement = refused.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.abstain_reason(),
        Some(AbstainReason::EgressRefused),
        "a refused destination abstains with its own reason"
    );
    assert_eq!(judgement.verdict(), None);
    assert_eq!(
        hits(&server).await,
        0,
        "a refused call must NOT reach the endpoint"
    );

    // Every method, not just `judge`.
    assert_eq!(
        refused.choose("x", &["a", "b"]).await.abstain_reason(),
        Some(AbstainReason::EgressRefused)
    );
    assert_eq!(
        refused
            .score("x", ai_memory::decision::ScoreRange::unit())
            .await
            .abstain_reason(),
        Some(AbstainReason::EgressRefused)
    );
    assert_eq!(hits(&server).await, 0, "still zero after three refusals");

    // PRESENCE control on the same sink: the hook allows, and EXACTLY
    // one request arrives. Without this the assertion above would pass
    // against a mock nothing could ever reach.
    let allowed = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    assert_eq!(
        allowed
            .judge("do these two records conflict?")
            .await
            .verdict(),
        Some(true)
    );
    assert_eq!(hits(&server).await, 1, "exactly one request, no retry");

    // The hook is consulted with the REAL request URL.
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let observing: OutboundCheck = Arc::new(move |url: &reqwest::Url| {
        recorder.lock().expect("lock").push(url.to_string());
        Ok(())
    });
    let watched = OpenAiCompatibleDecider::new(&resolved, observing).expect("constructs");
    let _ = watched.judge("do these two records conflict?").await;
    let urls = seen.lock().expect("lock").clone();
    assert_eq!(urls.len(), 1, "one call, one check");
    assert!(
        urls[0].ends_with(CHAT_PATH),
        "the hook must see the resolved request URL, got {}",
        urls[0]
    );
}

// ---------------------------------------------------------------------
// 5. The credential never reaches a `Debug` render or a log line — that
//    pin lives in `tests/decision_client_secret_redaction_3806.rs`,
//    because `tracing` caches callsite interest per PROCESS and a
//    sibling test driving the same `warn!` without a subscriber would
//    make the log capture vacuous.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// 6. The direct decision route: the assumed body shape, over the wire.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_direct_route_sends_the_documented_body_and_honours_an_absent_probability() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SYSTEMONE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"decision": "yes", "probability": 0.7})),
        )
        .mount(&server)
        .await;
    let resolved = resolve_for("systemone", &server.uri(), 2, DecisionFallback::Abstain);
    let decider = SystemOneDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(true));
    assert_eq!(judgement.confidence(), Some(0.7));
    assert_eq!(judgement.source(), DecisionSource::DecisionModel);

    // GOLDEN: the body this repository assumes, sent verbatim.
    let requests = server
        .received_requests()
        .await
        .expect("wiremock records requests");
    assert_eq!(requests.len(), 1);
    let sent: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        sent,
        json!({
            "model": "vendor/decision-1",
            "input": "do these two records conflict?",
            "temperature": 0.0,
            "seed": 3806,
            "task": "judge",
            "options": ["yes", "no"],
        }),
        "the assumed direct-route body is a REVIEWABLE artefact, not an accident"
    );
    assert_eq!(requests[0].url.path(), SYSTEMONE_PATH);

    // An answer with no probability still DECIDES, with NO confidence.
    let quiet = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SYSTEMONE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision": "no"})))
        .mount(&quiet)
        .await;
    let resolved = resolve_for("systemone", &quiet.uri(), 2, DecisionFallback::Abstain);
    let decider = SystemOneDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(false));
    assert_eq!(
        judgement.confidence(),
        None,
        "an absent probability is an absent confidence, never a 1.0"
    );

    // An off-vocabulary decision abstains rather than guessing.
    let noisy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SYSTEMONE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision": "perhaps"})))
        .mount(&noisy)
        .await;
    let resolved = resolve_for("systemone", &noisy.uri(), 2, DecisionFallback::Abstain);
    let decider = SystemOneDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.abstain_reason(), Some(AbstainReason::Unusable));
    assert_eq!(judgement.verdict(), None);
}

// ---------------------------------------------------------------------
// 7. The generative fallback parses the closed vocabulary — and abstains
//    on the prose today's `starts_with("yes")` would have accepted.
// ---------------------------------------------------------------------

fn generative_for(server: &MockServer, timeout_secs: u64) -> GenerativeFallbackDecider {
    // `OllamaClient` appends `/chat/completions` to the base URL, which is
    // where `mount_chat` listens.
    let base = server.uri();
    let client = OllamaClient::new_openai_compatible(&base, "chat-model", "unused-in-mock")
        .expect("generative client constructs");
    GenerativeFallbackDecider::new(
        Arc::new(client),
        &base,
        permit(),
        Duration::from_secs(timeout_secs),
    )
    .expect("fallback constructs")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_generative_fallback_parses_the_vocabulary_and_abstains_on_prose() {
    // PRESENCE: a bare vocabulary token decides — with NO confidence and
    // the generative provenance.
    let clean = MockServer::start().await;
    mount_chat(&clean, chat_body("yes", None)).await;
    let decider = generative_for(&clean, 5);
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(true));
    assert_eq!(
        judgement.confidence(),
        None,
        "a generative answer carries no logprobs, so no confidence"
    );
    assert_eq!(judgement.source(), DecisionSource::GenerativeFallback);

    // ABSENCE, same sink: the sentence `starts_with(\"yes\")` accepts
    // today is an ABSTAIN here.
    for prose in [
        "Yes, because the two records disagree about the port.",
        "I'm sorry, I can't determine that.",
        "The answer is: yes",
        "",
    ] {
        let noisy = MockServer::start().await;
        mount_chat(&noisy, chat_body(prose, None)).await;
        let decider = generative_for(&noisy, 5);
        let judgement = decider.judge("do these two records conflict?").await;
        assert_eq!(
            judgement.abstain_reason(),
            Some(AbstainReason::Unusable),
            "prose must abstain, not parse: {prose:?}"
        );
        assert_ne!(judgement.verdict(), Some(false), "and never become a false");
    }

    // A closed-set choice reports the vocabulary's own spelling.
    let choose = MockServer::start().await;
    mount_chat(&choose, chat_body("  \"fact\" ", None)).await;
    let decider = generative_for(&choose, 5);
    let choice = decider.choose("classify", &["Fact", "Decision"]).await;
    assert_eq!(choice.chosen(), Some("Fact"));
    assert_eq!(choice.confidence(), None);
}

// ---------------------------------------------------------------------
// 8. The factory: routing, refusals, and the one abstain that never
//    falls back.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_factory_routes_refuses_and_never_routes_around_an_egress_refusal() {
    let decision_endpoint = MockServer::start().await;
    mount_chat(
        &decision_endpoint,
        chat_body("I am prose, not a decision.", None),
    )
    .await;
    let generative_endpoint = MockServer::start().await;
    mount_chat(&generative_endpoint, chat_body("yes", None)).await;

    // Routing: `systemone` and an alias reach different clients.
    let systemone = resolve_for(
        "systemone",
        &decision_endpoint.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let provider = construct(&systemone, permit(), None).expect("systemone constructs");
    assert_eq!(provider.provider_id(), "systemone");

    let openrouter = resolve_for(
        "openai-compatible",
        &decision_endpoint.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let provider = construct(&openrouter, permit(), None).expect("openai-compatible constructs");
    assert_eq!(provider.provider_id(), "openai-compatible");

    // `local-nli` is REFUSED here rather than silently turned into a
    // network client: W1d owns it.
    let mut cfg = AppConfig::default();
    cfg.decision = Some(DecisionSection {
        provider: Some("local-nli".to_string()),
        model: Some("cross-encoder".to_string()),
        base_url: None,
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(DecisionFallback::Abstain),
    });
    let local = resolve_decision(&cfg).expect("local-nli resolves");
    let refusal = construct(&local, permit(), None).expect_err("local-nli must be refused");
    assert!(
        refusal.to_string().contains("local-nli"),
        "the refusal must NAME the provider: {refusal}"
    );

    // `fallback = generative` with nothing to fall back to is a refusal,
    // not a half-configured provider.
    let wants_fallback = resolve_for(
        "openai-compatible",
        &decision_endpoint.uri(),
        2,
        DecisionFallback::Generative,
    );
    assert!(
        construct(&wants_fallback, permit(), None).is_err(),
        "a generative fallback with no generative backend must refuse"
    );

    // PRESENCE: an UNUSABLE primary does fall back, and the generative
    // endpoint is reached.
    let chained = construct(
        &wants_fallback,
        permit(),
        Some(generative_for(&generative_endpoint, 5)),
    )
    .expect("chain constructs");
    let judgement = chained.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.verdict(),
        Some(true),
        "an unusable primary must hand off to the fallback"
    );
    assert_eq!(judgement.source(), DecisionSource::GenerativeFallback);
    assert_eq!(hits(&generative_endpoint).await, 1);

    // ABSENCE, the invariant that matters: an EGRESS REFUSAL is never
    // routed around. The generative endpoint must not be touched.
    let generative_only = MockServer::start().await;
    mount_chat(&generative_only, chat_body("yes", None)).await;
    let chained = construct(
        &wants_fallback,
        refuse(),
        Some(generative_for(&generative_only, 5)),
    )
    .expect("chain constructs");
    let judgement = chained.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.abstain_reason(),
        Some(AbstainReason::EgressRefused),
        "a refused destination stays refused"
    );
    assert_eq!(judgement.verdict(), None);
    assert_eq!(
        hits(&generative_only).await,
        0,
        "an egress refusal must NOT be answered by a second endpoint"
    );
}

// ---------------------------------------------------------------------
// 9. The `logprobs` capability latch: one retry, then permanently no
//    confidence — a degradation, never a fabrication.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_endpoint_that_refuses_logprobs_degrades_to_no_confidence() {
    let server = MockServer::start().await;
    // Requests carrying `logprobs` are rejected; requests without it are
    // answered. Two mounts, distinguished by a body matcher.
    let strict = server;
    Mock::given(method("POST"))
        .and(path(CHAT_PATH))
        .and(LogprobsPresent(true))
        .respond_with(ResponseTemplate::new(400).set_body_string("logprobs is not supported"))
        .mount(&strict)
        .await;
    Mock::given(method("POST"))
        .and(path(CHAT_PATH))
        .and(LogprobsPresent(false))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body(
            "{\"verdict\":\"yes\"}",
            Some(json!([{"token": "yes", "logprob": -0.1}])),
        )))
        .mount(&strict)
        .await;

    let resolved = resolve_for(
        "openai-compatible",
        &strict.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    assert!(
        decider.logprobs_enabled(),
        "presence control: the client asks for logprobs first"
    );
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.verdict(),
        Some(true),
        "the retry without logprobs must still produce a decision"
    );
    assert_eq!(
        judgement.confidence(),
        None,
        "a decision obtained WITHOUT logprobs must carry no confidence, even though \
         the mock echoed a logprobs block"
    );
    assert!(
        !decider.logprobs_enabled(),
        "the latch is one-way: no further request asks for logprobs"
    );
    assert_eq!(hits(&strict).await, 2, "exactly one retry, not a loop");

    // The second call does not retry: one request, still no confidence.
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(true));
    assert_eq!(judgement.confidence(), None);
    assert_eq!(hits(&strict).await, 3, "one request, no second retry");
}

/// Matches a chat-completions request by whether it carries `logprobs`.
struct LogprobsPresent(bool);

impl wiremock::Match for LogprobsPresent {
    fn matches(&self, request: &wiremock::Request) -> bool {
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return false;
        };
        body.get("logprobs").is_some() == self.0
    }
}

// ---------------------------------------------------------------------
// 10. An unreachable endpoint abstains; it never decides.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_endpoint_abstains_rather_than_deciding() {
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    };
    let resolved = resolve_for(
        "openai-compatible",
        &format!("http://127.0.0.1:{closed_port}"),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert!(
        judgement.is_abstain(),
        "an unreachable endpoint cannot decide"
    );
    assert_eq!(judgement.verdict(), None);
    assert_ne!(judgement.verdict(), Some(false));
}

// ---------------------------------------------------------------------
// 11. A calibration row round-trips from a real decision.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_decision_renders_into_the_preregistered_calibration_shape() {
    use ai_memory::decision_clients::calibration::{CalibrationRow, CalibrationSeam};

    let server = MockServer::start().await;
    mount_chat(
        &server,
        chat_body(
            "{\"verdict\":\"no\"}",
            Some(json!([{"token": "{\"verdict\":\"", "logprob": -0.001},
                        {"token": "no", "logprob": -0.105_360_515_657_826_3},
                        {"token": "\"}", "logprob": -0.001}])),
        ),
    )
    .await;
    let resolved = resolve_for(
        "openai-compatible",
        &server.uri(),
        2,
        DecisionFallback::Abstain,
    );
    let decider = OpenAiCompatibleDecider::new(&resolved, permit()).expect("constructs");
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(judgement.verdict(), Some(false));

    let row = CalibrationRow::from_judgement(
        "dc-live-001",
        CalibrationSeam::DetectContradiction,
        &judgement,
        false,
    );
    let value: Value = serde_json::from_str(&row.to_json_line()).expect("row is JSON");
    let object = value.as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["item_id", "label", "predicted", "seam", "source"]);
    assert_eq!(object["seam"], json!("detect_contradiction"));
    assert_eq!(object["source"], json!("decision_model"));
    assert_eq!(object["label"], json!(false));
    let predicted = object["predicted"].as_f64().expect("a scored row");
    assert!(
        (predicted - 0.1).abs() < 1e-3,
        "a confident `no` assigns a LOW probability to the label being true, got {predicted}"
    );

    // An abstain renders `predicted` as an explicit null.
    let no_options: [&str; 0] = [];
    let abstained = decider.choose("classify", &no_options).await;
    assert!(abstained.is_abstain());
    let row = CalibrationRow::from_choice(
        "ck-live-001",
        CalibrationSeam::ClassifyKind,
        &abstained,
        "Fact",
    );
    let value: Value = serde_json::from_str(&row.to_json_line()).expect("row is JSON");
    assert_eq!(value["predicted"], Value::Null);
    assert!(
        value.as_object().expect("object").contains_key("predicted"),
        "the key must be PRESENT and null, never omitted"
    );
}
