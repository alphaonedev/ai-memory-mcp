// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(
    clippy::field_reassign_with_default,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names
)]
//! #3806 W2 — the two DECISION SEAM pins, over local mock HTTP servers
//! (`wiremock`, the idiom `src/llm.rs`'s own tests and W1c's client pins
//! use). No test here touches a real network.
//!
//! The defect this unit exists to remove is
//! `OllamaClient::detect_contradiction_async`'s
//! `answer.starts_with("yes")`: a refusal, a preamble and a hedge all
//! became a VERDICT, and `memory_detect_contradiction` returned it as
//! `true`/`false` with no way to tell "no opinion" from "decided no".
//! Every pin below therefore pairs an ABSENCE with a PRESENCE control on
//! the SAME sink, and the sink that matters most is
//! `ai_memory_decision_outcome_total`: it is what makes an abstain
//! distinguishable from a decision on the wire.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::attach_decider;
use ai_memory::llm::OllamaClient;
use ai_memory::models::MemoryKind;

/// The route the OpenAI-compatible DECISION client posts to.
const DECISION_PATH: &str = "/chat/completions";
/// The route the Ollama-native GENERATIVE client posts to — the v1.0.0
/// path, and the one that must stay untouched once a decider answers.
const GENERATIVE_PATH: &str = "/api/chat";

/// Two statements that SHARE a subject token, so the F-L1 deterministic
/// pre-check does not short-circuit before the seam is reached.
const MEM_A: &str = "The primary database listens on port 5432.";
const MEM_B: &str = "The primary database listens on port 6543.";

/// A `[decision]` section pointed at `base_url`.
fn cfg_with_decision(
    decision_url: &str,
    generative_url: &str,
    fallback: DecisionFallback,
) -> AppConfig {
    let mut cfg = cfg_generative_only(generative_url);
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

/// The same config with NO `[decision]` section — the v1.0.0 shape.
fn cfg_generative_only(generative_url: &str) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some(generative_url.to_string()),
        ..LlmSection::default()
    });
    cfg
}

/// An OpenAI-compatible chat body whose `content` is `content`
/// VERBATIM. The structured client expects a JSON document there, so a
/// non-JSON string is exactly the "the model answered in prose" case.
fn decision_body(content: &str) -> Value {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
}

/// Mount the DECISION endpoint answering a well-formed structured
/// document whose one field carries `value`. `value` is NOT validated
/// here — the point of several pins below is to hand the strict parser
/// something outside its closed vocabulary.
async fn mount_decision_field(server: &MockServer, field: &str, value: &str) {
    let document = json!({ field: value }).to_string();
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(decision_body(&document)))
        .mount(server)
        .await;
}

/// Mount the DECISION endpoint answering PROSE — no structured document
/// at all, which is what a refusal actually looks like on the wire.
async fn mount_decision_prose(server: &MockServer, prose: &str) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(decision_body(prose)))
        .mount(server)
        .await;
}

/// The schema field the yes/no JUDGE task reads back.
const FIELD_VERDICT: &str = "verdict";
/// The schema field the closed-set CHOOSE task reads back.
const FIELD_CHOICE: &str = "choice";

/// Every test in this binary takes this lock.
///
/// `crate::metrics` renders a PROCESS-GLOBAL registry, so the delta
/// assertions below are only exact while no other test in this binary is
/// recording concurrently. Serializing the file is cheaper than making
/// every pin settle for "the counter moved by at least one", which is
/// what a race would force.
/// An ASYNC mutex on purpose: every pin here holds the lock across
/// `.await` points, and a `std::sync::MutexGuard` held across an await
/// is both a clippy error and a real hazard.
static SEAM_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn serialize() -> tokio::sync::MutexGuard<'static, ()> {
    SEAM_LOCK.lock().await
}

/// Mount the DECISION endpoint so it never answers inside the budget:
/// the provider is UNAVAILABLE, which is case 2 and NOT a decline.
async fn mount_decision_silent(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(decision_body("{}")),
        )
        .mount(server)
        .await;
}

/// Mount the GENERATIVE endpoint with one answer.
async fn mount_generative(server: &MockServer, content: &str) {
    Mock::given(method("POST"))
        .and(path(GENERATIVE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"role": "assistant", "content": content}})),
        )
        .mount(server)
        .await;
}

/// Requests the mock actually received.
async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// The current value of `ai_memory_decision_outcome_total` for one
/// `seam`/`outcome` pair. The registry is process-global and shared with
/// every other test in this binary, so every pin below measures a DELTA
/// rather than an absolute.
fn outcome_count(seam: &str, outcome: &str) -> u64 {
    let needle =
        format!("ai_memory_decision_outcome_total{{outcome=\"{outcome}\",seam=\"{seam}\"}} ");
    ai_memory::metrics::render()
        .lines()
        .find_map(|line| line.strip_prefix(needle.as_str()))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or(0)
}

/// Build a generative client against `server` and attach whatever `cfg`
/// implies through the BOOT CHOKEPOINT — the only way a decider is
/// obtainable.
fn client_for(cfg: &AppConfig, generative_url: &str, db: &std::path::Path) -> OllamaClient {
    let client = OllamaClient::new_with_url_no_health_check(generative_url, "vendor/chat-1")
        .expect("the mock client builds");
    attach_decider(Some(client), cfg, db)
        .expect("attach_decider must return the client it was given")
}

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ---------------------------------------------------------------- 1

/// `[decision]` UNSET is byte-identical v1.0.0: the generative endpoint
/// answers and its LOOSE parse is still in force.
///
/// This is the control the other pins are measured against — without it
/// "the decision endpoint was not consulted" would be satisfiable by a
/// harness that consults nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unset_runs_the_v100_body_including_its_loose_parse() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    // A PREAMBLE. v1.0.0 reads this as `true` via `starts_with("yes")`.
    mount_generative(&generative, "Yes, because the two disagree about the port.").await;
    let db = tmpdir();
    let cfg = cfg_generative_only(&generative.uri());
    let client = client_for(&cfg, &generative.uri(), db.path());

    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("the v1.0.0 path answers");

    assert!(
        verdict,
        "with no [decision] section the v1.0.0 body must run UNCHANGED, preamble and all"
    );
    assert_eq!(
        hits(&generative).await,
        1,
        "PRESENCE: the generative endpoint is the one that answered"
    );
}

// ---------------------------------------------------------------- 2

/// A REFUSAL from the decision endpoint is an ABSTAIN, never a verdict —
/// and the generative endpoint is NOT consulted in its place, so the
/// loose parse is out of the picture entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_abstains_and_never_reaches_a_text_parse() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_prose(&decision, "I'm sorry, I can't help with that.").await;
    // Armed and deliberately never called: if the seam fell through to
    // the v1.0.0 body, this would answer `true` and the pin would fail
    // on BOTH the verdict and the hit count.
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count("detect_contradiction", "abstained");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("an abstain under `fallback = abstain` is not an error");

    assert!(
        !verdict,
        "a refusal must take the conservative NON-ACTION branch: no contradiction edge"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "ABSENCE: with a decider configured the generative endpoint — and therefore \
         `starts_with(\"yes\")` — is never consulted"
    );
    assert_eq!(
        outcome_count("detect_contradiction", "abstained"),
        before + 1,
        "the abstain must be DISTINGUISHABLE from a decided `no` on the wire; that is \
         what stops `false` from meaning two different things"
    );
}

/// PRESENCE control for the pin above, on the same sinks: the same
/// wiring with a PARSEABLE answer decides, counts as `decided`, and
/// still never touches the generative endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vocabulary_answer_decides_and_is_counted_as_decided() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_field(&decision, FIELD_VERDICT, "yes").await;
    mount_generative(&generative, "no").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count("detect_contradiction", "decided");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("a decided verdict is not an error");

    assert!(
        verdict,
        "`yes` from the decision model is a verdict of true"
    );
    assert_eq!(hits(&decision).await, 1, "PRESENCE: the decider answered");
    assert_eq!(hits(&generative).await, 0);
    assert_eq!(outcome_count("detect_contradiction", "decided"), before + 1);
}

/// A PREAMBLE — the exact shape `starts_with("yes")` turns into `true` —
/// is an abstain once a decider is configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preamble_abstains_where_v100_read_it_as_yes() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_field(
        &decision,
        FIELD_VERDICT,
        "yes, because the two records disagree about the port",
    )
    .await;
    mount_generative(&generative, "no").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count("detect_contradiction", "abstained");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("an abstain under `fallback = abstain` is not an error");

    assert!(
        !verdict,
        "the sentence v1.0.0 read as `true` must now be no opinion at all"
    );
    assert_eq!(
        outcome_count("detect_contradiction", "abstained"),
        before + 1
    );
    assert_eq!(hits(&generative).await, 0);
}

// ---------------------------------------------------------------- 3

/// `fallback = "refuse"` turns UNAVAILABILITY into a loud error.
///
/// Case 2: the decision endpoint never answers inside the budget, so the
/// instrument is unavailable and the operator asked for the operation to
/// fail rather than proceed without a decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_posture_turns_unavailability_into_an_error() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_silent(&decision).await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri(), DecisionFallback::Refuse);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let err = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect_err("`fallback = refuse` must refuse when the instrument is unavailable");
    let text = format!("{err:#}");
    assert!(
        text.contains("refuse"),
        "the refusal must name the posture that caused it: {text}"
    );
    assert_eq!(hits(&generative).await, 0);
}

/// ABSENCE control for the pin above, and the Conductor's case 3:
/// `fallback = "refuse"` does NOT error on a DECLINE, because `fallback`
/// governs unavailability and not abstention. The provider answered; the
/// instrument worked; there is nothing to fall back from and nothing to
/// refuse. The seam takes its conservative non-action branch under this
/// posture exactly as under the other two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_posture_does_not_error_on_a_decline() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_prose(&decision, "I'm sorry, I can't help with that.").await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri(), DecisionFallback::Refuse);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("a DECLINE is terminal, not an error: `fallback` governs unavailability");
    assert!(
        !verdict,
        "the conservative non-action branch, under every posture"
    );
    assert_eq!(hits(&generative).await, 0);
}

/// PRESENCE control: under the SAME `refuse` posture a parseable answer
/// still decides, so `refuse` refuses abstains and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuse_posture_still_decides_a_parseable_answer() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_field(&decision, FIELD_VERDICT, "no").await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri(), DecisionFallback::Refuse);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("a parseable answer decides under every posture");
    assert!(!verdict);
    assert_eq!(hits(&generative).await, 0);
}

// ---------------------------------------------------------------- 4

/// `classify_kind` chooses over ALL SIXTEEN kinds.
///
/// The v1.0.0 prompt named 8 of the 16, so half the vocabulary was
/// unreachable no matter what the model knew. The option set is derived
/// from `MemoryKind::all()`, so a variant added later cannot fall out of
/// it silently — which is the defect, not the symptom.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classify_kind_chooses_over_all_sixteen_kinds() {
    let _serialized = serialize().await;
    assert_eq!(
        MemoryKind::all().len(),
        16,
        "the vocabulary this seam chooses over is the WHOLE kind enum"
    );

    for kind in MemoryKind::all() {
        let decision = MockServer::start().await;
        let generative = MockServer::start().await;
        mount_decision_field(&decision, FIELD_CHOICE, kind.as_str()).await;
        mount_generative(&generative, "observation").await;
        let db = tmpdir();
        let cfg = cfg_with_decision(
            &decision.uri(),
            &generative.uri(),
            DecisionFallback::Abstain,
        );
        let client = Arc::new(client_for(&cfg, &generative.uri(), db.path()));

        let seen = {
            let client = Arc::clone(&client);
            tokio::task::spawn_blocking(move || client.classify_kind("t", "c"))
                .await
                .expect("join")
                .expect("classify_kind answers")
        };
        assert_eq!(
            seen,
            Some(*kind),
            "the decision model naming `{}` must resolve to that kind",
            kind.as_str()
        );
        assert_eq!(
            hits(&generative).await,
            0,
            "ABSENCE: the generative classifier is not consulted once a decider answers"
        );
    }
}

/// ABSENCE control for the pin above: an answer OUTSIDE the closed
/// vocabulary is an abstain, and an abstain leaves the caller's kind
/// untouched rather than inventing one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kind_outside_the_vocabulary_abstains() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_field(&decision, FIELD_CHOICE, "speculation").await;
    mount_generative(&generative, "decision").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = Arc::new(client_for(&cfg, &generative.uri(), db.path()));

    let before = outcome_count("classify_kind", "abstained");
    let seen = {
        let client = Arc::clone(&client);
        tokio::task::spawn_blocking(move || client.classify_kind("t", "c"))
            .await
            .expect("join")
            .expect("an abstain under `fallback = abstain` is not an error")
    };
    assert_eq!(
        seen, None,
        "an out-of-vocabulary label must not become a kind"
    );
    assert_eq!(outcome_count("classify_kind", "abstained"), before + 1);
    assert_eq!(hits(&generative).await, 0);
}

// ---------------------------------------------------------------- 4b
//  The Conductor's ruling of 2026-09-19, as three pins: `fallback`
//  governs UNAVAILABILITY (case 2), not ABSTENTION (case 3).

/// **CASE 3, the pin the ruling asks for.** A provider that ANSWERED AND
/// DECLINED produces NO second model call — under `fallback =
/// "generative"`, the posture where a second call is most tempting.
///
/// An abstain is information, not an absence of information. Re-asking
/// the same question of a weaker reader manufactures a definite answer
/// out of a deliberate refusal, which is worse than the `starts_with`
/// defect this unit removes, not a milder version of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decline_produces_no_second_model_call() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    // The provider ANSWERS — with prose. That is the decline.
    mount_decision_prose(&decision, "I'm sorry, I can't help with that.").await;
    // Armed and deliberately never called.
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Generative,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count("detect_contradiction", "abstained");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("a decline is terminal, not an error");

    assert_eq!(
        hits(&decision).await,
        1,
        "the decision provider was asked exactly once"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "ABSENCE (ruling case 3): a DECLINE is terminal — not the provider chain, not \
         the seam, and not the v1.0.0 text parse may re-ask the question"
    );
    assert!(!verdict, "the conservative NON-ACTION branch");
    assert_eq!(
        outcome_count("detect_contradiction", "abstained"),
        before + 1
    );
}

/// **CASE 2, the presence control.** An UNAVAILABLE provider under
/// `fallback = "generative"` DOES produce exactly ONE old-path call.
///
/// The decision endpoint never answers inside the budget, so nothing
/// declined and falling back to the instrument used before is
/// legitimate. Exactly one call, and it is labelled `fallback` rather
/// than `decided`, so a generative guess is never reportable as a
/// decision-model verdict.
///
/// This control is what makes the absence above a property of the
/// DECLINE rather than of a seam that never falls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unavailable_provider_under_generative_makes_exactly_one_old_path_call() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_silent(&decision).await;
    mount_generative(&generative, "no").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Generative,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count("detect_contradiction", "fallback");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("the old path answers");

    assert!(!verdict, "`no` from the old path is a verdict of false");
    assert_eq!(
        hits(&generative).await,
        1,
        "PRESENCE (ruling case 2): EXACTLY one old-path call — the [llm] endpoint is a \
         DIFFERENT origin from the gated decision endpoint, so this also proves the \
         per-call outbound check approves it"
    );
    assert_eq!(
        outcome_count("detect_contradiction", "fallback"),
        before + 1,
        "labelled `fallback`, never `decided`"
    );
}

/// The old path is read STRICTLY too. Case 2 admits the previous
/// instrument; it does not admit the previous instrument's text parse.
///
/// The decision endpoint is unavailable and the generative model answers
/// the exact sentence `starts_with("yes")` reads as `true`. One call,
/// and the answer is an abstain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_old_path_is_read_strictly_too() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_decision_silent(&decision).await;
    mount_generative(&generative, "Yes, they appear to conflict.").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Generative,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before_abstain = outcome_count("detect_contradiction", "abstained");
    let before_fallback = outcome_count("detect_contradiction", "fallback");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("an abstain is not an error under `generative`");

    assert!(
        !verdict,
        "prose from the old path is no opinion, not the `true` v1.0.0 would have read"
    );
    assert_eq!(hits(&generative).await, 1, "asked once, not twice");
    assert_eq!(
        outcome_count("detect_contradiction", "abstained"),
        before_abstain + 1
    );
    assert_eq!(
        outcome_count("detect_contradiction", "fallback"),
        before_fallback,
        "nothing decided, so nothing is labelled `fallback`"
    );
}

// ---------------------------------------------------------------- 5

/// An UNREACHABLE decision endpoint is an abstain, not an error and not
/// a verdict — the failure mode an operator is most likely to meet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_decider_abstains() {
    let _serialized = serialize().await;
    // Port 1 on loopback: privileged, never bound by a test, and a
    // connection there is refused immediately. A "bound then released"
    // port is NOT safe here — the OS can hand the same port to the
    // generative mock started two lines later, and the pin would then be
    // measuring the wrong server.
    let dead = "http://127.0.0.1:1".to_string();
    let generative = MockServer::start().await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&dead, &generative.uri(), DecisionFallback::Abstain);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("an unreachable decider abstains rather than erroring");
    assert!(
        !verdict,
        "no endpoint answered, so no contradiction is asserted"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "ABSENCE: a dead decider does not silently reopen the v1.0.0 text parse"
    );
}
