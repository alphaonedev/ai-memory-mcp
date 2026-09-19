// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::field_reassign_with_default)]
//! #3806 Crossroads R1 + R2 — **`fallback = "refuse"` must be able to
//! refuse.**
//!
//! The posture exists for one purpose: fail the operation rather than
//! proceed without a decision. Two routes defeated it, and both failed
//! OPEN — the strongest posture producing the most permissive outcome:
//!
//! * **R1** — the generative fallback classed a TRANSPORT failure as
//!   `Unusable`, i.e. as a DECLINE. A decline is terminal under the
//!   2026-09-19 ruling, so `refuse` returned the conservative branch
//!   during an outage: exactly the failure it exists to refuse.
//! * **R2** — when the boot chokepoint refused to build a provider at
//!   all (egress gate, or an unresolvable section), nothing was
//!   attached, every seam answered `RunLegacy`, and the v1.0.0
//!   generative path ran. `fallback` was bypassed entirely. A permanent
//!   refusal was quieter AND more permissive than a two-second blip.
//!
//! Each pin below is paired with its allowed-path control (rule p3): a
//! refusal pin with no control pins nothing, because a posture that
//! refuses everything is not a posture.

use std::sync::LazyLock;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision::{AbstainReason, DecisionSource};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::attach_decider;
use ai_memory::llm::OllamaClient;

const MEM_A: &str = "The primary database listens on port 5432.";
const MEM_B: &str = "The primary database listens on port 6543.";

/// A port nothing binds. Deterministic, and NOT a released mock port —
/// see #3855.
const DEAD: &str = "http://127.0.0.1:1";

/// Every test here takes this. It is an ASYNC mutex because the guard
/// is held across `.await` points, and because the egress posture some
/// of these tests set is PROCESS-GLOBAL: a concurrent test observing it
/// would be reading another test's configuration.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn serialize() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

fn cfg(decision_url: &str, generative_url: &str, fallback: DecisionFallback) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some(generative_url.to_string()),
        ..LlmSection::default()
    });
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(decision_url.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(fallback),
    });
    cfg
}

fn client(cfg: &AppConfig, generative_url: &str, db: &std::path::Path) -> Option<OllamaClient> {
    attach_decider(
        Some(
            OllamaClient::new_with_url_no_health_check(generative_url, "vendor/chat-1")
                .expect("client builds"),
        ),
        cfg,
        db,
    )
}

async fn mount_generative(server: &MockServer, content: &str) {
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"role": "assistant", "content": content}})),
        )
        .mount(server)
        .await;
}

fn abstain_child(seam: &str, reason: &str) -> u64 {
    let needle =
        format!("ai_memory_decision_abstain_total{{reason=\"{reason}\",seam=\"{seam}\"}} ");
    ai_memory::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(needle.as_str()))
        .and_then(|r| r.trim().parse().ok())
        .unwrap_or(0)
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

// ------------------------------------------------------------------ R1

/// **R1.** The generative fallback's TRANSPORT failure must be an
/// OUTAGE (`Unavailable`), not a DECLINE (`Unusable`).
///
/// Only `fallback = "generative"` builds a `FallbackChain`, so that is
/// the posture which reaches `decision_clients::fallback`. The primary
/// decision endpoint is unreachable, so the chain asks the secondary;
/// the `[llm]` endpoint answers 500, so the secondary's own call fails
/// at the transport layer. That is the `Ok(Err(_transport_or_parse))`
/// arm.
///
/// With the defect it returned `Unusable` — a DECLINE, which is
/// terminal under the 2026-09-19 ruling — so the seam took the
/// conservative branch and the caller got `Ok(false)` during a TOTAL
/// outage: both endpoints down, and a definite answer returned. Fixed,
/// the reason is `Unavailable`, CASE 2 applies, `generative` runs the
/// old path, and the outage surfaces as an error instead of a verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_generative_fallback_transport_failure_is_an_outage_not_a_decline() {
    let _serialized = serialize().await;
    let llm = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&llm)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let conf = cfg(DEAD, &llm.uri(), DecisionFallback::Generative);
    let client = client(&conf, &llm.uri(), db.path()).expect("client back");

    let before_unavailable = abstain_child("detect_contradiction", "unavailable");
    let before_unusable = abstain_child("detect_contradiction", "unusable");
    let outcome = client.detect_contradiction_async(MEM_A, MEM_B).await;

    assert!(
        outcome.is_err(),
        "both endpoints are down: a TOTAL outage must not return a definite verdict, \
         and it returned {outcome:?}"
    );
    assert_eq!(
        abstain_child("detect_contradiction", "unavailable"),
        before_unavailable + 1,
        "a transport failure of the generative fallback is an OUTAGE"
    );
    assert_eq!(
        abstain_child("detect_contradiction", "unusable"),
        before_unusable,
        "and it must NOT be recorded as the model ANSWERING and declining — that \
         classification is terminal, and it is what let `refuse` fail open"
    );
}

/// ALLOWED-PATH CONTROL for R1 (rule p3): the same `refuse` posture
/// still DECIDES when the endpoint answers in its vocabulary. `refuse`
/// refuses unavailability and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_still_decides_a_healthy_answer() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"role": "assistant",
                                     "content": "{\"verdict\":\"yes\"}"}}]
        })))
        .mount(&decision)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let conf = cfg(&decision.uri(), DEAD, DecisionFallback::Refuse);
    let client = client(&conf, DEAD, db.path()).expect("client back");

    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("a healthy answer decides under every posture");
    assert!(verdict, "`yes` is a verdict, not a refusal");
}

// ------------------------------------------------------------------ R2

/// **R2.** `[decision]` CONFIGURED, provider NEVER BUILT (the egress
/// gate refuses a remote endpoint under `deny`): under `refuse` the
/// operation must FAIL, and the generative endpoint must NOT be
/// consulted.
///
/// Before the fix nothing was attached, the seam answered `RunLegacy`,
/// and the v1.0.0 generative classifier ran — so the most permanent
/// failure produced the most permissive outcome, and `refuse` was
/// bypassed entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_fails_when_the_provider_was_never_built() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    mount_generative(&generative, "yes").await;
    let db = tempfile::tempdir().expect("tempdir");
    // A REMOTE decision endpoint under `deny`: the boot chokepoint
    // refuses to construct it, so no handle is ever produced.
    let conf = cfg(
        "https://decide.example.net/v1",
        &generative.uri(),
        DecisionFallback::Refuse,
    );

    let restore = EgressVar::set("deny");
    let client = client(&conf, &generative.uri(), db.path()).expect("client back");
    let outcome = client.detect_contradiction_async(MEM_A, MEM_B).await;
    drop(restore);

    let err = outcome.expect_err(
        "a PERMANENT boot refusal must not be quieter than a transient outage: \
         `refuse` must refuse",
    );
    assert!(
        format!("{err:#}").contains("refuse"),
        "the refusal must name the posture: {err:#}"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "and the v1.0.0 generative path must NOT have run"
    );
}

/// ALLOWED-PATH CONTROL for R2, on the same sink: with the SAME
/// never-built provider but `fallback = "generative"`, the old path
/// DOES run and answers. So the refusal above is a property of the
/// posture, not of a seam that fails whenever no provider exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generative_still_runs_the_old_path_when_the_provider_was_never_built() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    mount_generative(&generative, "yes").await;
    let db = tempfile::tempdir().expect("tempdir");
    let conf = cfg(
        "https://decide.example.net/v1",
        &generative.uri(),
        DecisionFallback::Generative,
    );

    let restore = EgressVar::set("deny");
    let client = client(&conf, &generative.uri(), db.path()).expect("client back");
    let verdict = client.detect_contradiction_async(MEM_A, MEM_B).await;
    drop(restore);

    assert!(
        verdict.expect("`generative` runs the old path"),
        "the v1.0.0 body answered"
    );
    assert_eq!(hits(&generative).await, 1, "exactly one old-path call");
}

// ------------------------------------------------------------------ R3

/// **R3.** The two public decision enums are `#[non_exhaustive]`, so a
/// later variant is a non-breaking change for an external `match`.
///
/// Asserted structurally: this file is an EXTERNAL crate, so a
/// `match` here without a wildcard would not compile if the attribute
/// is present — and would compile if it were removed. The wildcard arm
/// below is the pin.
#[test]
fn the_public_decision_enums_are_non_exhaustive() {
    // Every CURRENT variant is named, so the wildcard covers nothing
    // that exists today. It compiles ONLY because the enum is
    // `#[non_exhaustive]` and this is an external crate. Drop the
    // attribute and the wildcard becomes unreachable, which
    // `unreachable_patterns` turns into a compile FAILURE under the
    // `-D warnings` the CI clippy legs pass. That is the pin: it is
    // enforced by the build, not by an assertion.
    let described = match AbstainReason::Unavailable {
        AbstainReason::NoProvider => "no_provider",
        AbstainReason::Timeout => "timeout",
        AbstainReason::EgressRefused => "egress_refused",
        AbstainReason::Unavailable => "outage",
        AbstainReason::Unusable => "decline",
        AbstainReason::Unsupported => "unsupported",
        _ => "a variant added after this pin was written",
    };
    assert_eq!(described, "outage");

    let source = match DecisionSource::DecisionModel {
        DecisionSource::DecisionModel => "decision_model",
        DecisionSource::GenerativeFallback => "generative_fallback",
        DecisionSource::Deterministic => "deterministic",
        _ => "a variant added after this pin was written",
    };
    assert_eq!(source, "decision_model");
}

/// Set `AI_MEMORY_INFERENCE_EGRESS` for the duration of a scope and put
/// it back, so no other test in this binary inherits it.
struct EgressVar(Option<String>);

impl EgressVar {
    fn set(value: &str) -> Self {
        let prior = std::env::var("AI_MEMORY_INFERENCE_EGRESS").ok();
        // SAFETY: the process-global egress posture is serialised by
        // `EGRESS_LOCK`, which every caller of this helper holds.
        unsafe { std::env::set_var("AI_MEMORY_INFERENCE_EGRESS", value) };
        Self(prior)
    }
}

impl Drop for EgressVar {
    fn drop(&mut self) {
        // SAFETY: as above.
        match self.0.take() {
            Some(prior) => unsafe {
                std::env::set_var("AI_MEMORY_INFERENCE_EGRESS", prior);
            },
            None => unsafe { std::env::remove_var("AI_MEMORY_INFERENCE_EGRESS") },
        }
    }
}
