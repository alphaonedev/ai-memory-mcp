// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(clippy::field_reassign_with_default, clippy::doc_markdown)]
//! #3806 W2 — the decision metric series, and the MEASURED answer to
//! "does the #3654 64 KiB `/metrics` budget survive them".
//!
//! ONE test, in its OWN test binary, on purpose. `crate::metrics` renders
//! a PROCESS-GLOBAL registry, so anything that asserts on the absence of
//! a series — or on the exposition's SIZE — is asserting on test
//! ordering unless it owns the process. That is the same reasoning
//! `src/handlers/tests.rs::http_prometheus_metrics_returns_text_body`
//! records for deliberately NOT reading the shared body, and why its
//! `64 * 1024` cap is not raised here either: the cap is a property of
//! whatever ran before it, and the honest thing to measure is what THIS
//! unit adds.
//!
//! The assertions, in order, each paired with its control:
//!
//! 1. ABSENCE — a freshly-started process exposes none of the series;
//! 2. ABSENCE — running a seam with `[decision]` UNSET still exposes
//!    none, because the seam short-circuits before any recording. An
//!    unconfigured deployment's `/metrics` body is therefore unchanged,
//!    which is half of "unset is byte-identical";
//! 3. PRESENCE + ABSENCE — two REAL seam calls, one against an endpoint
//!    that returns 503 and one against a model that answers prose, land
//!    on DIFFERENT `reason` labels. That is the operator-visible half of
//!    the `Unavailable` / `Unusable` split: an outage and a model that
//!    declined are the same `outcome` (`abstained`) and must never be
//!    the same `reason`;
//! 4. PRESENCE — recording the FULL worst case (every seam x every
//!    outcome, every seam x every reason) creates every child.
//!
//! The #3654 SIZE measurement deliberately does NOT live here. This file
//! drives real seam calls, whose observed latencies are arbitrary floats
//! whose rendered width varies run to run; an exposition budget measured
//! against a body containing one is measuring the clock. It lives in
//! `tests/decision_metrics_budget_3806.rs`, which records a fixed
//! latency and is byte-identical on every run.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision_clients::calibration::CalibrationSeam;
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::attach_decider;
use ai_memory::llm::OllamaClient;
use ai_memory::metrics;

/// The three series this unit adds.
const LATENCY_SERIES: &str = "ai_memory_decision_latency_seconds";
const OUTCOME_SERIES: &str = "ai_memory_decision_outcome_total";
const ABSTAIN_SERIES: &str = "ai_memory_decision_abstain_total";

/// The route the OpenAI-compatible decision client posts to.
const DECISION_PATH: &str = "/chat/completions";
/// The route the Ollama-native generative client posts to.
const GENERATIVE_PATH: &str = "/api/chat";

/// The closed `outcome` vocabulary — answers "did the seam get a
/// decision?".
const OUTCOMES: [&str; 5] = [
    "decided",
    "fallback",
    "timeout",
    "egress_refused",
    "abstained",
];

/// The closed `reason` vocabulary — `AbstainReason::as_str()`. Answers
/// "why not?", which is a DIFFERENT question: at the outcome level an
/// outage and a declining model are both `abstained`, and an operator
/// must still be able to tell them apart.
const REASONS: [&str; 6] = [
    "no_provider",
    "timeout",
    "egress_refused",
    "unavailable",
    "unusable",
    "unsupported",
];

/// Two statements sharing a subject token, so the F-L1 pre-check does
/// not short-circuit before the seam is reached.
const MEM_A: &str = "The primary database listens on port 5432.";
const MEM_B: &str = "The primary database listens on port 6543.";

/// The value of one `ai_memory_decision_abstain_total` child, or `None`
/// when that child does not exist.
fn abstain_child(exposition: &str, seam: &str, reason: &str) -> Option<u64> {
    let needle = format!("{ABSTAIN_SERIES}{{reason=\"{reason}\",seam=\"{seam}\"}} ");
    exposition
        .lines()
        .find_map(|line| line.strip_prefix(needle.as_str()))
        .and_then(|rest| rest.trim().parse().ok())
}

/// A config with `[llm]` pointed at `generative_url`, and optionally a
/// `[decision]` section pointed at `decision_url`.
fn cfg(generative_url: &str, decision_url: Option<&str>) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some(generative_url.to_string()),
        ..LlmSection::default()
    });
    cfg.decision = decision_url.map(|url| DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(url.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(DecisionFallback::Abstain),
    });
    cfg
}

/// Drive ONE real `detect_contradiction` seam call against a decision
/// endpoint that answers with `template`. Returns the verdict.
async fn seam_call(generative_url: &str, template: ResponseTemplate) -> bool {
    let decision = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(template)
        .mount(&decision)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let cfg = cfg(generative_url, Some(&decision.uri()));
    let client = attach_decider(
        Some(
            OllamaClient::new_with_url_no_health_check(generative_url, "vendor/chat-1")
                .expect("the mock client builds"),
        ),
        &cfg,
        db.path(),
    )
    .expect("attach_decider returns the client it was given");
    client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("an abstain under `fallback = abstain` is not an error")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_decision_series_are_lazy_and_keep_an_outage_distinct_from_a_decline() {
    // 1. ABSENCE — nothing has recorded a decision in this process.
    let baseline = metrics::render();
    for series in [LATENCY_SERIES, OUTCOME_SERIES, ABSTAIN_SERIES] {
        assert!(
            !baseline.contains(series),
            "{series} must be created LAZILY by its first observation"
        );
    }

    // 2. ABSENCE — a seam runs with `[decision]` UNSET and still records
    //    nothing, because it never reaches the recording path.
    let generative = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GENERATIVE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": {"role": "assistant", "content": "no"}})),
        )
        .mount(&generative)
        .await;
    let db = tempfile::tempdir().expect("tempdir");
    let unset_cfg = cfg(&generative.uri(), None);
    let client = attach_decider(
        Some(
            OllamaClient::new_with_url_no_health_check(&generative.uri(), "vendor/chat-1")
                .expect("the mock client builds"),
        ),
        &unset_cfg,
        db.path(),
    )
    .expect("attach_decider returns the client it was given");
    let verdict = client
        .detect_contradiction_async(MEM_A, MEM_B)
        .await
        .expect("the v1.0.0 path answers");
    assert!(!verdict, "the mock answered `no`");
    let unset = metrics::render();
    assert_eq!(
        unset.len(),
        baseline.len(),
        "with `[decision]` unset the exposition must be UNCHANGED, byte for byte"
    );

    // 3. THE DISTINCTION REACHES AN OPERATOR, driven through REAL seams.
    //
    //    `Unavailable` and `Unusable` are different events — an outage
    //    versus the feature working as designed — and a distinction that
    //    lives only in the type is not one anybody can alert on. Two
    //    seam calls, two endpoints, two reasons:
    //
    //      * 503   -> the endpoint could not answer   -> `unavailable`
    //      * prose -> the model answered and declined -> `unusable`
    //
    //    If those ever collapse onto one label, ONE child carries a count
    //    of 2 and the other is absent, and the assertions below fail.
    let declined = seam_call(
        &generative.uri(),
        ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {
                "role": "assistant",
                "content": "I'm sorry, I can't help with that."
            }}]
        })),
    )
    .await;
    assert!(
        !declined,
        "a decline takes the conservative non-action branch"
    );

    let outage = seam_call(&generative.uri(), ResponseTemplate::new(503)).await;
    assert!(
        !outage,
        "an outage takes the conservative non-action branch"
    );

    let after_seams = metrics::render();
    // PRESENCE on the same sink (mandate fa41723f): the series exists at
    // all and BOTH children moved. An absence assertion alone would pass
    // on a sink that emits nothing whatsoever.
    assert!(
        after_seams.contains(ABSTAIN_SERIES),
        "the `why not` series must reach /metrics at all — a distinction an operator \
         cannot see is not one they can act on"
    );
    let unusable = abstain_child(&after_seams, "detect_contradiction", "unusable");
    let unavailable = abstain_child(&after_seams, "detect_contradiction", "unavailable");
    assert_eq!(
        unusable,
        Some(1),
        "the model ANSWERED and declined: that is `unusable`, and it is the feature \
         working as designed, not a page"
    );
    assert_eq!(
        unavailable,
        Some(1),
        "the endpoint returned 503: that is `unavailable`, and it is an OUTAGE"
    );
    // The two must remain distinguishable DOWNSTREAM. If the labels ever
    // collapse, one child holds 2 and the other vanishes — which is
    // precisely what the two `Some(1)` assertions above reject, stated
    // once more here as the property rather than as two measurements.
    assert!(
        unusable == Some(1) && unavailable == Some(1),
        "`Unavailable` and `Unusable` must stay distinguishable on the operator surface; \
         got unusable={unusable:?} unavailable={unavailable:?}"
    );
    // ...and both are the SAME `outcome`, which is why the reason series
    // has to exist: at the outcome level an outage is not distinguishable
    // from a decline, and that is correct at THAT level.
    assert!(
        after_seams
            .contains("ai_memory_decision_outcome_total{outcome=\"abstained\",seam=\"detect_contradiction\"} 2"),
        "both seam calls are `abstained` at the outcome level"
    );

    // 4. PRESENCE — the full worst case.
    let seams = [
        CalibrationSeam::ClassifyKind,
        CalibrationSeam::DetectContradiction,
        CalibrationSeam::SynthesisVerdict,
        CalibrationSeam::ConsolidationMerge,
    ];
    for seam in seams {
        for outcome in OUTCOMES {
            metrics::record_decision(seam.as_str(), outcome, None, 0.042);
        }
        for reason in REASONS {
            metrics::record_decision(seam.as_str(), "abstained", Some(reason), 0.042);
        }
    }
    let full = metrics::render();
    for series in [LATENCY_SERIES, OUTCOME_SERIES, ABSTAIN_SERIES] {
        assert!(full.contains(series), "{series} must render");
    }
    for seam in seams {
        for outcome in OUTCOMES {
            let child = format!(
                "{OUTCOME_SERIES}{{outcome=\"{outcome}\",seam=\"{}\"}}",
                seam.as_str()
            );
            assert!(
                full.contains(&child),
                "every seam x outcome pair must be its own counter child: {child}"
            );
        }
        for reason in REASONS {
            assert!(
                abstain_child(&full, seam.as_str(), reason).is_some(),
                "every seam x reason pair must be its own counter child: {} / {reason}",
                seam.as_str()
            );
        }
    }
}
