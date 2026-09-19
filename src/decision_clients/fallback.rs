// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1c — the generative fallback decider.
//!
//! `[decision].fallback = "generative"` means: when the decision model
//! has no opinion, ask the `[llm]` backend the same question. This is
//! the adapter that makes a generative chat model answer in the
//! decision types — and, just as importantly, the one that makes it
//! ABSTAIN when it answers in prose instead.
//!
//! It reuses the existing client (`crate::llm::OllamaClient`) rather
//! than opening a second one: the circuit breaker, the redaction
//! discipline, the transport error classification and the `[llm]`
//! governance gate all apply unchanged, and no second credential is
//! resolved for the same endpoint.
//!
//! ## What "parses strictly" means here
//!
//! The prompt asks for exactly one token from the closed vocabulary, and
//! the parser accepts exactly that (modulo surrounding whitespace, one
//! layer of quoting, and a trailing period —
//! `super::normalize_answer`). `"yes, because the two records disagree
//! about the port"` does NOT parse. That sentence is the whole reason
//! this programme exists: `detect_contradiction` reads it today with
//! `starts_with("yes")`, so a refusal, a preamble and a hedge all become
//! a verdict. Here it becomes an ABSTAIN.
//!
//! ## Confidence
//!
//! ALWAYS absent. A generative chat completion carries no logprobs
//! through `generate_async`, and no calibration evidence backs a number
//! invented from the text, so every answer this decider returns has
//! `confidence = None` and `DecisionSource::GenerativeFallback`. A seam
//! that narrows a destructive path on `is_confident_at_least` therefore
//! takes its conservative branch on a generative answer — which is the
//! correct posture for a model that was not asked for a probability.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::Url;

use crate::decision::{
    AbstainReason, Choice, DecisionProvider, DecisionSource, Judgement, ScoreRange, Scored,
};
use crate::llm::OllamaClient;

use super::{
    DEBUG_FIELD_BUDGET, DEBUG_FIELD_ENDPOINT, DEBUG_FIELD_PROVIDER, JUDGE_OPTIONS, OutboundCheck,
    strict_option_match, strict_score,
};

/// Provenance every answer from this decider carries.
const SOURCE: DecisionSource = DecisionSource::GenerativeFallback;

/// The instruction that turns a chat model into a decision function.
const SYSTEM_PREAMBLE: &str = "You are a decision function. Reply with exactly one value and nothing else: no \
     explanation, no punctuation, no preamble. A reply containing anything else is discarded.";

/// The closed-vocabulary decider over the existing generative client.
pub struct GenerativeFallbackDecider {
    provider_id: String,
    client: Arc<OllamaClient>,
    endpoint: Url,
    outbound: OutboundCheck,
    timeout: Duration,
}

// Manual `Debug`: `OllamaClient` holds the credential inside its
// provider enum, so it is never rendered; the endpoint is reduced to its
// redacted origin (#3648 / #3688).
impl fmt::Debug for GenerativeFallbackDecider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenerativeFallbackDecider")
            .field(DEBUG_FIELD_PROVIDER, &self.provider_id)
            .field("model", &self.client.model_name())
            .field(
                DEBUG_FIELD_ENDPOINT,
                &crate::url_display::url_origin(self.endpoint.as_str()),
            )
            .field(DEBUG_FIELD_BUDGET, &self.timeout.as_secs())
            .finish()
    }
}

impl GenerativeFallbackDecider {
    /// Wrap an already-constructed generative client.
    ///
    /// `endpoint` is the `[llm]` chat endpoint the client was built
    /// against; it is what the outbound check is asked about before each
    /// delegated call. It is passed explicitly rather than read off the
    /// client because the caller — W1b's boot chokepoint — already holds
    /// the resolved `[llm]` view that produced the client, and because
    /// `src/llm.rs` is at its module-size ceiling.
    ///
    /// `timeout` is `[decision].timeout_secs`: the generative leg is
    /// held to the DECISION budget, not to the 30-second generative one,
    /// so falling back cannot turn a bounded seam into an unbounded one.
    ///
    /// # Errors
    /// When `endpoint` is not a valid `http`/`https` URL.
    pub fn new(
        client: Arc<OllamaClient>,
        endpoint: &str,
        outbound: OutboundCheck,
        timeout: Duration,
    ) -> Result<Self> {
        let endpoint = super::endpoint_url(endpoint, "")?;
        Ok(Self {
            provider_id: format!("generative:{}", client.provider_label()),
            client,
            endpoint,
            outbound,
            timeout,
        })
    }

    /// The endpoint, rendered through the redaction funnel.
    #[must_use]
    pub fn endpoint_origin(&self) -> String {
        crate::url_display::url_origin(self.endpoint.as_str())
    }

    /// Ask the generative backend one question and return its raw text.
    ///
    /// The outbound check runs first: `fallback = "generative"` must not
    /// become a way to reach a destination the decision lane's egress
    /// posture refused.
    async fn ask(&self, prompt: &str, system: &str) -> Result<String, AbstainReason> {
        if (self.outbound)(&self.endpoint).is_err() {
            let display_url = self.endpoint_origin();
            tracing::warn!(
                provider = %self.provider_id,
                endpoint = %display_url,
                "generative fallback refused by the outbound egress check"
            );
            return Err(AbstainReason::EgressRefused);
        }
        match tokio::time::timeout(
            self.timeout,
            self.client.generate_async(prompt, Some(system)),
        )
        .await
        {
            Err(_elapsed) => Err(AbstainReason::Timeout),
            // The generative client's error already went through the
            // `[llm]` redaction funnel; it is dropped here rather than
            // carried, because a seam must be handed a reason, not text.
            //
            // #3806 R1 — this is [`AbstainReason::Unavailable`], NOT
            // `Unusable`. The model never ANSWERED: the transport
            // failed, or the response was not a completion at all. As
            // `Unusable` it classified as a DECLINE, which is terminal
            // under the 2026-09-19 ruling, so `fallback = "refuse"`
            // returned `Conservative` during an outage — failing OPEN on
            // the exact failure that posture exists to refuse. The
            // module header of `crate::decision_seams` has always listed
            // "transport error" under CASE 2; the doc was right and the
            // code was wrong.
            Ok(Err(_transport_or_parse)) => Err(AbstainReason::Unavailable),
            Ok(Ok(text)) => Ok(text),
        }
    }

    /// The system instruction naming a closed vocabulary.
    fn vocabulary_system(options: &[&str]) -> String {
        format!("{SYSTEM_PREAMBLE} Allowed values: {}.", options.join(" | "))
    }
}

#[async_trait::async_trait]
impl DecisionProvider for GenerativeFallbackDecider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn choose(&self, prompt: &str, options: &[&str]) -> Choice {
        if options.is_empty() {
            return Choice::abstain(AbstainReason::Unusable, SOURCE);
        }
        let system = Self::vocabulary_system(options);
        let text = match self.ask(prompt, &system).await {
            Ok(text) => text,
            Err(reason) => return Choice::abstain(reason, SOURCE),
        };
        match strict_option_match(&text, options) {
            Some(label) => Choice::decided(label.to_string(), None, SOURCE),
            None => Choice::abstain(AbstainReason::Unusable, SOURCE),
        }
    }

    async fn score(&self, prompt: &str, range: ScoreRange) -> Scored {
        let system = format!(
            "{SYSTEM_PREAMBLE} Answer with a single number between {} and {}.",
            range.min(),
            range.max()
        );
        let text = match self.ask(prompt, &system).await {
            Ok(text) => text,
            Err(reason) => return Scored::abstain(reason, SOURCE),
        };
        match strict_score(&text, range) {
            Some(value) => Scored::decided(value, None, SOURCE),
            None => Scored::abstain(AbstainReason::Unusable, SOURCE),
        }
    }

    async fn judge(&self, prompt: &str) -> Judgement {
        let system = Self::vocabulary_system(&JUDGE_OPTIONS);
        let text = match self.ask(prompt, &system).await {
            Ok(text) => text,
            Err(reason) => return Judgement::abstain(reason, SOURCE),
        };
        match strict_option_match(&text, &JUDGE_OPTIONS) {
            Some(token) => Judgement::decided(token == super::VERDICT_YES, None, SOURCE),
            None => Judgement::abstain(AbstainReason::Unusable, SOURCE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_prompt_names_the_closed_vocabulary() {
        let system = GenerativeFallbackDecider::vocabulary_system(&JUDGE_OPTIONS);
        assert!(
            system.contains("yes | no"),
            "vocabulary must reach the model"
        );
        assert!(
            system.contains("exactly one value"),
            "the instruction must forbid prose: {system}"
        );
    }

    #[test]
    fn the_generative_source_is_never_the_decision_model() {
        // A seam and `/capabilities` must be able to tell a generative
        // guess from a decision-model verdict.
        assert_eq!(SOURCE.as_str(), "generative_fallback");
        assert_ne!(SOURCE, DecisionSource::DecisionModel);
    }
}
