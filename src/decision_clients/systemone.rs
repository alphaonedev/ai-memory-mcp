// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1c — the direct `POST /v1/systemone` decision adapter.
//!
//! ## An explicit, reviewable assumption
//!
//! The #3806 design fixes the ROUTE for this provider — `POST
//! /v1/systemone` — and nothing else: no request body, no response
//! shape, no field names. Guessing those silently is precisely the
//! failure mode this programme exists to remove, so they are not
//! guessed silently. The wire shape lives behind [`SystemOneWire`],
//! whose whole contract is TWO functions: one builds the request body,
//! one reads the answer out of the response. [`DefaultSystemOneWire`] is
//! this repository's ASSUMPTION about that shape, documented below,
//! pinned by a golden test, and replaceable in one line
//! ([`SystemOneDecider::with_wire`]) the moment the vendor publishes the
//! real one — with no change to the decider, the factory, the egress
//! hook, or any seam.
//!
//! **The assumed shape.** Request:
//!
//! ```json
//! {
//!   "model": "<[decision].model>",
//!   "task": "choose" | "judge" | "score",
//!   "input": "<prompt>",
//!   "options": ["a", "b"],
//!   "range": {"min": 0.0, "max": 1.0},
//!   "temperature": 0.0,
//!   "seed": 3806
//! }
//! ```
//!
//! `options` is present for `choose` and `judge` (where it is the
//! yes/no vocabulary) and absent for `score`; `range` is present only
//! for `score`. Response:
//!
//! ```json
//! {"decision": "a", "probability": 0.82}
//! ```
//!
//! `decision` is a string for `choose`, a string from the yes/no
//! vocabulary OR a JSON boolean for `judge`, and a number for `score`.
//! **`probability` is OPTIONAL and its absence is an absent confidence,
//! never a `1.0`** — the same rule the chat client applies to a missing
//! `logprobs` block. A `probability` outside `0.0..=1.0` is treated as
//! absent rather than clamped.
//!
//! Everything else in this file is shape-independent: the outbound check
//! still runs before every request, the timeout is still
//! `[decision].timeout_secs`, an off-vocabulary answer is still an
//! abstain with [`AbstainReason::Unusable`] (a body with no decision field
//! at all is no answer — [`AbstainReason::Unavailable`]), and the credential
//! is still redacted in `Debug` and zeroized on `Drop`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use reqwest::Url;
use serde_json::{Value, json};

use crate::decision::{AbstainReason, Choice, DecisionProvider, Judgement, ScoreRange, Scored};
use crate::decision_config::ResolvedDecision;

use super::{
    DEBUG_FIELD_BUDGET, DEBUG_FIELD_ENDPOINT, DEBUG_FIELD_PROVIDER, DECISION_SEED,
    DECISION_TEMPERATURE, DecisionTask, HttpCall, JUDGE_OPTIONS, NETWORK_SOURCE, OutboundCheck,
    SecretKey, VERDICT_YES, decision_http_client, endpoint_url, post_json, strict_option_match,
};

/// Request field carrying the decision-model identifier.
const FIELD_MODEL: &str = "model";
/// Request field carrying which question is being asked.
const FIELD_TASK: &str = "task";
/// Request field carrying the prompt.
const FIELD_INPUT: &str = "input";
/// Request field carrying the closed vocabulary.
const FIELD_OPTIONS: &str = "options";
/// Request field carrying the admissible numeric interval.
const FIELD_RANGE: &str = "range";
/// Response field carrying the decision itself.
const FIELD_DECISION: &str = "decision";
/// Response field carrying the probability, when the endpoint reports
/// one. Its ABSENCE is an absent confidence.
const FIELD_PROBABILITY: &str = "probability";

/// `task` token for a closed-set choice.
const TASK_CHOOSE: &str = "choose";
/// `task` token for a yes/no judgement.
const TASK_JUDGE: &str = "judge";
/// `task` token for a continuous score.
const TASK_SCORE: &str = "score";

/// What the adapter reads out of a response, before it is interpreted
/// for the specific question that was asked.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemOneAnswer {
    /// The raw decision value. A string, a boolean or a number
    /// depending on the task.
    pub decision: Value,
    /// The endpoint's own probability for that decision, when it
    /// reported one. `None` is an ABSENT confidence, never a `1.0`.
    pub probability: Option<f64>,
}

/// The request/response shape of the direct decision route.
///
/// Implement this to bind a customer or vendor endpoint whose body
/// differs from [`DefaultSystemOneWire`]; nothing else in the client
/// changes.
pub trait SystemOneWire: fmt::Debug + Send + Sync {
    /// The route appended to `[decision].base_url`.
    fn route(&self) -> &str;

    /// Build the request body for one question.
    fn request_body(&self, model: &str, prompt: &str, task: &DecisionTask<'_>) -> Value;

    /// Read the decision out of a 2xx response body. `None` means the body
    /// is not the documented envelope at all — no model answer — which the
    /// caller turns into [`AbstainReason::Unavailable`] (an outage, case 2).
    /// A decision value the caller cannot match to the closed vocabulary is
    /// the DECLINE, [`AbstainReason::Unusable`].
    fn read_answer(&self, response: &Value) -> Option<SystemOneAnswer>;
}

/// This repository's documented ASSUMPTION about the direct decision
/// route's body. See the module documentation for the exact shape and
/// why it is an assumption rather than a specification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefaultSystemOneWire;

impl DefaultSystemOneWire {
    /// The route the #3806 design names.
    pub const ROUTE: &'static str = "/v1/systemone";
}

impl SystemOneWire for DefaultSystemOneWire {
    fn route(&self) -> &str {
        Self::ROUTE
    }

    fn request_body(&self, model: &str, prompt: &str, task: &DecisionTask<'_>) -> Value {
        let mut body = json!({
            FIELD_MODEL: model,
            FIELD_INPUT: prompt,
            "temperature": DECISION_TEMPERATURE,
            "seed": DECISION_SEED,
        });
        match task {
            DecisionTask::Choose { options } => {
                body[FIELD_TASK] = json!(TASK_CHOOSE);
                body[FIELD_OPTIONS] = json!(options);
            }
            DecisionTask::Judge => {
                body[FIELD_TASK] = json!(TASK_JUDGE);
                body[FIELD_OPTIONS] = json!(JUDGE_OPTIONS);
            }
            DecisionTask::Score { range } => {
                body[FIELD_TASK] = json!(TASK_SCORE);
                body[FIELD_RANGE] = json!({"min": range.min(), "max": range.max()});
            }
        }
        body
    }

    fn read_answer(&self, response: &Value) -> Option<SystemOneAnswer> {
        let decision = response.get(FIELD_DECISION)?.clone();
        // An absent, null, non-numeric or out-of-range probability is an
        // ABSENT confidence — the field is evidence or it is nothing.
        let probability = response
            .get(FIELD_PROBABILITY)
            .and_then(Value::as_f64)
            .filter(|p| p.is_finite() && (0.0..=1.0).contains(p));
        Some(SystemOneAnswer {
            decision,
            probability,
        })
    }
}

/// The direct decision-route client.
pub struct SystemOneDecider {
    provider_id: String,
    model: String,
    endpoint: Url,
    api_key: SecretKey,
    http: reqwest::Client,
    timeout: Duration,
    outbound: OutboundCheck,
    wire: Arc<dyn SystemOneWire>,
}

// Manual `Debug`: credential present/absent only, endpoint reduced to
// its redacted origin (#3648 / #3688).
impl fmt::Debug for SystemOneDecider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemOneDecider")
            .field(DEBUG_FIELD_PROVIDER, &self.provider_id)
            .field("model", &self.model)
            .field(
                DEBUG_FIELD_ENDPOINT,
                &crate::url_display::url_origin(self.endpoint.as_str()),
            )
            .field("api_key", &self.api_key)
            .field(DEBUG_FIELD_BUDGET, &self.timeout.as_secs())
            .field("wire", &self.wire)
            .finish()
    }
}

impl SystemOneDecider {
    /// Build a client using [`DefaultSystemOneWire`].
    ///
    /// # Errors
    /// When `base_url` does not join to a valid `http`/`https` URL, or
    /// when the HTTP pool cannot be built.
    pub fn new(resolved: &ResolvedDecision, outbound: OutboundCheck) -> Result<Self> {
        Self::new_pinned(resolved, outbound, None)
    }

    /// [`Self::new`] with the `internal-only` egress pin (#3822).
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_pinned(
        resolved: &ResolvedDecision,
        outbound: OutboundCheck,
        pin: Option<&crate::egress::PinnedTarget>,
    ) -> Result<Self> {
        Self::build(resolved, outbound, Arc::new(DefaultSystemOneWire), pin)
    }

    /// Build a client against a caller-supplied wire shape.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn with_wire(
        resolved: &ResolvedDecision,
        outbound: OutboundCheck,
        wire: Arc<dyn SystemOneWire>,
    ) -> Result<Self> {
        Self::build(resolved, outbound, wire, None)
    }

    fn build(
        resolved: &ResolvedDecision,
        outbound: OutboundCheck,
        wire: Arc<dyn SystemOneWire>,
        pin: Option<&crate::egress::PinnedTarget>,
    ) -> Result<Self> {
        let timeout = resolved.timeout();
        Ok(Self {
            provider_id: resolved.provider.clone(),
            model: resolved.model.clone(),
            endpoint: endpoint_url(&resolved.base_url, wire.route())?,
            api_key: SecretKey::new(resolved.api_key()),
            http: decision_http_client(timeout, pin)?,
            timeout,
            outbound,
            wire,
        })
    }

    /// Whether a credential was resolved for this endpoint.
    #[must_use]
    pub fn has_credential(&self) -> bool {
        self.api_key.is_present()
    }

    /// The resolved request URL, rendered through the redaction funnel.
    #[must_use]
    pub fn endpoint_origin(&self) -> String {
        crate::url_display::url_origin(self.endpoint.as_str())
    }

    /// Ask one question.
    async fn call(
        &self,
        prompt: &str,
        task: &DecisionTask<'_>,
    ) -> Result<SystemOneAnswer, AbstainReason> {
        let body = self.wire.request_body(&self.model, prompt, task);
        let response = post_json(HttpCall {
            client: &self.http,
            endpoint: &self.endpoint,
            api_key: self.api_key.expose(),
            body: &body,
            timeout: self.timeout,
            outbound: &self.outbound,
            provider_id: &self.provider_id,
        })
        .await
        .map_err(super::CallFailure::reason)?;
        // f1 F6 parity (#3806): `read_answer` is `None` only when the body
        // is not the documented envelope (no decision field at all) — no
        // answer, so an OUTAGE. A decision value outside the closed
        // vocabulary is refused by the caller as the DECLINE (`Unusable`).
        self.wire
            .read_answer(&response)
            .ok_or(AbstainReason::Unavailable)
    }
}

#[async_trait::async_trait]
impl DecisionProvider for SystemOneDecider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn choose(&self, prompt: &str, options: &[&str]) -> Choice {
        if options.is_empty() {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        }
        let answer = match self.call(prompt, &DecisionTask::Choose { options }).await {
            Ok(answer) => answer,
            Err(reason) => return Choice::abstain(reason, NETWORK_SOURCE),
        };
        let Some(raw) = answer.decision.as_str() else {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        let Some(label) = strict_option_match(raw, options) else {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        Choice::decided(label.to_string(), answer.probability, NETWORK_SOURCE)
    }

    async fn score(&self, prompt: &str, range: ScoreRange) -> Scored {
        let answer = match self.call(prompt, &DecisionTask::Score { range }).await {
            Ok(answer) => answer,
            Err(reason) => return Scored::abstain(reason, NETWORK_SOURCE),
        };
        let Some(value) = answer.decision.as_f64() else {
            return Scored::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        Scored::in_range(value, range, answer.probability, NETWORK_SOURCE)
    }

    async fn judge(&self, prompt: &str) -> Judgement {
        let answer = match self.call(prompt, &DecisionTask::Judge).await {
            Ok(answer) => answer,
            Err(reason) => return Judgement::abstain(reason, NETWORK_SOURCE),
        };
        // The route may answer with the vocabulary token or with a JSON
        // boolean; both are accepted, anything else abstains.
        let verdict = match &answer.decision {
            Value::Bool(flag) => Some(*flag),
            Value::String(raw) => {
                strict_option_match(raw, &JUDGE_OPTIONS).map(|token| token == VERDICT_YES)
            }
            _ => None,
        };
        match verdict {
            Some(flag) => Judgement::decided(flag, answer.probability, NETWORK_SOURCE),
            None => Judgement::abstain(AbstainReason::Unusable, NETWORK_SOURCE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_assumed_request_body_is_golden_for_each_task() {
        let wire = DefaultSystemOneWire;
        let options = ["Fact", "Decision"];
        let choose = wire.request_body(
            "model-x",
            "classify this",
            &DecisionTask::Choose { options: &options },
        );
        assert_eq!(
            choose,
            json!({
                "model": "model-x",
                "input": "classify this",
                "temperature": 0.0,
                "seed": 3806,
                "task": "choose",
                "options": ["Fact", "Decision"],
            }),
            "the assumed choose body is the reviewable artefact"
        );

        let judge = wire.request_body("model-x", "do these conflict?", &DecisionTask::Judge);
        assert_eq!(
            judge,
            json!({
                "model": "model-x",
                "input": "do these conflict?",
                "temperature": 0.0,
                "seed": 3806,
                "task": "judge",
                "options": ["yes", "no"],
            })
        );

        let score = wire.request_body(
            "model-x",
            "how similar?",
            &DecisionTask::Score {
                range: ScoreRange::unit(),
            },
        );
        assert_eq!(
            score,
            json!({
                "model": "model-x",
                "input": "how similar?",
                "temperature": 0.0,
                "seed": 3806,
                "task": "score",
                "range": {"min": 0.0, "max": 1.0},
            })
        );
        assert_eq!(wire.route(), "/v1/systemone");
    }

    #[test]
    fn an_absent_or_impossible_probability_is_an_absent_confidence() {
        let wire = DefaultSystemOneWire;
        // PRESENCE: a well-formed probability survives.
        let present = wire
            .read_answer(&json!({"decision": "Fact", "probability": 0.82}))
            .expect("a decision with a probability");
        assert_eq!(present.probability, Some(0.82));
        // ABSENCE, on the same sink: the field is missing, null, or not
        // a probability at all.
        for body in [
            json!({"decision": "Fact"}),
            json!({"decision": "Fact", "probability": Value::Null}),
            json!({"decision": "Fact", "probability": 1.5}),
            json!({"decision": "Fact", "probability": -0.1}),
            json!({"decision": "Fact", "probability": "high"}),
        ] {
            let answer = wire.read_answer(&body).expect("still a decision");
            assert_eq!(
                answer.probability, None,
                "an unusable probability must be ABSENT, never repaired: {body}"
            );
        }
        // A body with no decision at all is not an answer.
        assert!(wire.read_answer(&json!({"probability": 0.9})).is_none());
    }
}
