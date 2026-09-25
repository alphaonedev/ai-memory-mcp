// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1c — the STRUCTURED OpenAI-compatible decision client.
//!
//! The generative bodies in `src/llm.rs` send `{model, messages,
//! stream}` and nothing else: no `response_format`, no `logprobs`, no
//! `temperature`, no `seed`. That is correct for prose and wrong for a
//! decision — it means the answer arrives as free text that a
//! `starts_with` has to guess at, with no probability attached and no
//! reproducibility between two calls with the same prompt.
//!
//! This client sends all four:
//!
//! - `response_format = {type: "json_schema", …, strict: true}` with a
//!   schema whose single property is an `enum` over the closed
//!   vocabulary (or a `number` with `minimum`/`maximum` for a score), so
//!   an off-vocabulary answer is refused by the ENDPOINT before it is
//!   refused again by our parser;
//! - `logprobs = true`, the only evidence that licenses a confidence;
//! - `temperature = 0` and a fixed `seed`, so the same question gets the
//!   same answer and a calibration figure measured once still describes
//!   the system later.
//!
//! ## Confidence attribution
//!
//! A confidence is emitted ONLY when exactly one contiguous run of
//! returned tokens concatenates to the decided label EXACTLY. The
//! probability is then `exp(Σ logprob)` over that run — the joint
//! probability of emitting that label. Every other case reports NO
//! confidence:
//!
//! - the endpoint returned no `logprobs` block (many do not);
//! - no token run reconstructs the label (the tokenizer split it across
//!   a boundary that also swallowed a quote or a brace);
//! - more than one run reconstructs it (the label also appears in the
//!   schema's key, so which occurrence carries the decision is not
//!   knowable);
//! - any logprob is positive or non-finite (not a probability);
//! - the request did not ASK for logprobs (the capability latch below),
//!   so anything in that field was volunteered by the endpoint or by a
//!   proxy in front of it and cannot be vouched for.
//!
//! Each of those is a case where a number COULD be produced and would be
//! a guess. The #3548 lesson is that a guessed confidence is worse than
//! none, because the guess is what a destructive seam thresholds on.
//!
//! ## The `logprobs` capability latch
//!
//! Not every OpenAI-compatible endpoint accepts `logprobs`; some answer
//! `400`. Rather than make the whole provider unusable, the client
//! latches the parameter OFF after one client-error response and retries
//! that call once without it. The retry re-runs the outbound check, and
//! from then on the provider answers with NO confidence — a degradation,
//! never a fabrication. The latch is per-provider and one-way: it never
//! re-enables itself, so the behaviour cannot oscillate under load.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::Url;
use serde_json::{Value, json};

use crate::decision::{AbstainReason, Choice, DecisionProvider, Judgement, ScoreRange, Scored};
use crate::decision_config::ResolvedDecision;

use super::{
    CallFailure, DEBUG_FIELD_BUDGET, DEBUG_FIELD_ENDPOINT, DEBUG_FIELD_PROVIDER, DECISION_SEED,
    DECISION_TEMPERATURE, DecisionTask, HttpCall, JUDGE_OPTIONS, NETWORK_SOURCE, OutboundCheck,
    SecretKey, decision_http_client, endpoint_url, post_json, strict_option_match,
};

/// The chat-completions route appended to an alias `base_url` (which
/// already carries the vendor's `/v1` prefix, exactly as `src/llm.rs`
/// assembles it).
const CHAT_ROUTE: &str = "/chat/completions";

/// The chat-completions route for the local Ollama server, whose
/// `base_url` is the server root. Ollama's NATIVE `/api/chat` carries
/// neither `response_format: json_schema` nor `logprobs`, so the
/// decision client uses its OpenAI-compatible surface instead.
const OLLAMA_CHAT_ROUTE: &str = "/v1/chat/completions";

/// Schema property that carries a closed-set choice.
const FIELD_CHOICE: &str = "choice";
/// Schema property that carries a yes/no verdict.
const FIELD_VERDICT: &str = "verdict";
/// Schema property that carries a continuous score.
const FIELD_SCORE: &str = "score";
/// JSON-Schema key holding the single decision property.
const SCHEMA_PROPERTIES: &str = "properties";
/// `response_format.json_schema.name`.
const SCHEMA_NAME: &str = "ai_memory_decision";

/// The instruction every decision prompt carries. Short on purpose: the
/// schema is the constraint, this is only for endpoints that treat
/// `response_format` as advisory.
const SYSTEM_PREAMBLE: &str = "You are a decision function. Answer only with the requested value, in the requested \
     JSON shape. Do not explain, apologise, or add any other field.";

/// A structured-decision client over the OpenAI chat-completions shape.
///
/// Covers the reference decision model on OpenRouter, every `[llm]`
/// vendor alias, a self-hosted `vllm`/`lmstudio`/`llama.cpp` server, the
/// local Ollama server's OpenAI surface, and any customer endpoint that
/// follows the spec (`provider = "openai-compatible"` plus an explicit
/// `base_url`).
pub struct OpenAiCompatibleDecider {
    provider_id: String,
    model: String,
    endpoint: Url,
    api_key: SecretKey,
    http: reqwest::Client,
    timeout: Duration,
    outbound: OutboundCheck,
    /// Whether `logprobs` is still believed to be accepted by this
    /// endpoint. One-way: latched off by a client-error response, never
    /// back on.
    logprobs: AtomicBool,
}

// Manual `Debug`: the credential is reported only as present/absent and
// the endpoint only as its redacted origin, so an accidental `{:?}` of a
// provider in an error context cannot leak either (#3648 / #3688).
impl fmt::Debug for OpenAiCompatibleDecider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompatibleDecider")
            .field(DEBUG_FIELD_PROVIDER, &self.provider_id)
            .field("model", &self.model)
            .field(
                DEBUG_FIELD_ENDPOINT,
                &crate::url_display::url_origin(self.endpoint.as_str()),
            )
            .field("api_key", &self.api_key)
            .field(DEBUG_FIELD_BUDGET, &self.timeout.as_secs())
            .field("logprobs", &self.logprobs.load(Ordering::Relaxed))
            .finish()
    }
}

impl OpenAiCompatibleDecider {
    /// Build a client from a resolved `[decision]` section.
    ///
    /// `outbound` is invoked with the resolved request URL before every
    /// request this client makes, including the `logprobs` retry.
    ///
    /// # Errors
    /// When `base_url` does not join to a valid `http`/`https` URL, or
    /// when the HTTP pool cannot be built.
    pub fn new(resolved: &ResolvedDecision, outbound: OutboundCheck) -> Result<Self> {
        Self::new_pinned(resolved, outbound, None)
    }

    /// [`Self::new`] with the `internal-only` egress pin (#3822): the
    /// client connects ONLY to the boot-resolved addresses in `pin`.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_pinned(
        resolved: &ResolvedDecision,
        outbound: OutboundCheck,
        pin: Option<&crate::egress::PinnedTarget>,
    ) -> Result<Self> {
        let route = if resolved.provider == crate::llm::BACKEND_OLLAMA {
            OLLAMA_CHAT_ROUTE
        } else {
            CHAT_ROUTE
        };
        let timeout = resolved.timeout();
        Ok(Self {
            provider_id: resolved.provider.clone(),
            model: resolved.model.clone(),
            endpoint: endpoint_url(&resolved.base_url, route)?,
            api_key: SecretKey::new(resolved.api_key()),
            http: decision_http_client(timeout, pin)?,
            timeout,
            outbound,
            logprobs: AtomicBool::new(true),
        })
    }

    /// The resolved request URL, rendered through the redaction funnel.
    /// Safe to log; never carries a credential.
    #[must_use]
    pub fn endpoint_origin(&self) -> String {
        crate::url_display::url_origin(self.endpoint.as_str())
    }

    /// Whether a credential was resolved for this endpoint. PRESENCE is
    /// the only property of a key that is safe to report; the bytes
    /// never leave [`SecretKey`].
    #[must_use]
    pub fn has_credential(&self) -> bool {
        self.api_key.is_present()
    }

    /// Whether this client still asks the endpoint for `logprobs`.
    /// `false` means the endpoint refused them and every answer from
    /// here on reports NO confidence.
    #[must_use]
    pub fn logprobs_enabled(&self) -> bool {
        self.logprobs.load(Ordering::Relaxed)
    }

    /// The JSON schema the endpoint must answer in.
    fn schema_for(task: &DecisionTask<'_>) -> (&'static str, Value) {
        match task {
            DecisionTask::Choose { options } => {
                (FIELD_CHOICE, json!({"type": "string", "enum": options}))
            }
            DecisionTask::Judge => (
                FIELD_VERDICT,
                json!({"type": "string", "enum": JUDGE_OPTIONS}),
            ),
            DecisionTask::Score { range } => (
                FIELD_SCORE,
                json!({
                    "type": "number",
                    "minimum": range.min(),
                    "maximum": range.max(),
                }),
            ),
        }
    }

    /// The system instruction, which restates the closed vocabulary for
    /// endpoints that treat `response_format` as advisory.
    fn system_prompt(task: &DecisionTask<'_>) -> String {
        match task.vocabulary() {
            Some(options) => {
                format!("{SYSTEM_PREAMBLE} Allowed values: {}.", options.join(" | "))
            }
            None => {
                let DecisionTask::Score { range } = task else {
                    return SYSTEM_PREAMBLE.to_string();
                };
                format!(
                    "{SYSTEM_PREAMBLE} Answer with a number between {} and {}.",
                    range.min(),
                    range.max()
                )
            }
        }
    }

    /// Assemble the request body. `with_logprobs` is the latch state, so
    /// the retry after a refusal differs from the first attempt in
    /// exactly one key.
    fn request_body(&self, prompt: &str, task: &DecisionTask<'_>, with_logprobs: bool) -> Value {
        let (field, property) = Self::schema_for(task);
        let mut body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": Self::system_prompt(task)},
                {"role": "user", "content": prompt},
            ],
            "stream": false,
            "temperature": DECISION_TEMPERATURE,
            "seed": DECISION_SEED,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": SCHEMA_NAME,
                    "strict": true,
                    "schema": {
                        "type": "object",
                        SCHEMA_PROPERTIES: {field: property},
                        "required": [field],
                        "additionalProperties": false,
                    },
                },
            },
        });
        if with_logprobs {
            body["logprobs"] = Value::Bool(true);
        }
        body
    }

    /// One HTTP attempt: build, send, and pull the schema field plus the
    /// token logprobs out of the response.
    async fn attempt(
        &self,
        prompt: &str,
        task: &DecisionTask<'_>,
        with_logprobs: bool,
        budget: Duration,
    ) -> Result<StructuredAnswer, CallFailure> {
        let body = self.request_body(prompt, task, with_logprobs);
        let response = post_json(HttpCall {
            client: &self.http,
            endpoint: &self.endpoint,
            api_key: self.api_key.expose(),
            body: &body,
            timeout: budget,
            outbound: &self.outbound,
            provider_id: &self.provider_id,
        })
        .await?;
        let (field, _) = Self::schema_for(task);
        let mut answer = read_structured_answer(&response, field).map_err(CallFailure::Abstain)?;
        if !with_logprobs {
            // We did not ASK for logprobs, so anything the endpoint (or a
            // proxy in front of it) volunteered in that field is evidence
            // we cannot vouch for. Confidence is licensed by evidence we
            // requested, or it is absent. This is what makes the latch a
            // one-way degradation: once `logprobs` is off, no answer from
            // this provider can carry a confidence again.
            answer.logprobs = None;
        }
        Ok(answer)
    }

    /// One logical call, including the one-shot `logprobs` latch retry.
    async fn call(
        &self,
        prompt: &str,
        task: &DecisionTask<'_>,
    ) -> Result<StructuredAnswer, AbstainReason> {
        // f1 F8 (#3806) — ONE deadline for the whole logical call. The
        // `logprobs` retry spends what is LEFT of `[decision].timeout_secs`,
        // never a fresh budget, so the documented per-call bound holds.
        let deadline = Instant::now() + self.timeout;
        let wanted_logprobs = self.logprobs_enabled();
        match self
            .attempt(prompt, task, wanted_logprobs, self.timeout)
            .await
        {
            Ok(answer) => Ok(answer),
            Err(CallFailure::Status(status)) if wanted_logprobs && status.is_client_error() => {
                // The endpoint rejected the request while `logprobs` was
                // on. Latch the parameter off and retry ONCE. If the
                // refusal was about something else the retry fails the
                // same way and the only lasting cost is an absent
                // confidence — the safe direction.
                self.logprobs.store(false, Ordering::Relaxed);
                tracing::warn!(
                    provider = %self.provider_id,
                    endpoint = %self.endpoint_origin(),
                    "decision endpoint refused `logprobs`; retrying without it, and every \
                     answer from this provider will now carry NO confidence"
                );
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(AbstainReason::Timeout);
                }
                self.attempt(prompt, task, false, remaining)
                    .await
                    .map_err(CallFailure::reason)
            }
            Err(failure) => Err(failure.reason()),
        }
    }

    /// Confidence for `label`, or `None` when it cannot be attributed.
    fn confidence_for(answer: &StructuredAnswer, label: &str) -> Option<f64> {
        label_probability(answer.logprobs.as_deref()?, label)
    }
}

#[async_trait::async_trait]
impl DecisionProvider for OpenAiCompatibleDecider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn choose(&self, prompt: &str, options: &[&str]) -> Choice {
        if options.is_empty() {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        }
        let task = DecisionTask::Choose { options };
        let answer = match self.call(prompt, &task).await {
            Ok(answer) => answer,
            Err(reason) => return Choice::abstain(reason, NETWORK_SOURCE),
        };
        let Some(raw) = answer.payload.as_str() else {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        let Some(label) = strict_option_match(raw, options) else {
            return Choice::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        let confidence = Self::confidence_for(&answer, label);
        Choice::decided(label.to_string(), confidence, NETWORK_SOURCE)
    }

    async fn score(&self, prompt: &str, range: ScoreRange) -> Scored {
        let task = DecisionTask::Score { range };
        let answer = match self.call(prompt, &task).await {
            Ok(answer) => answer,
            Err(reason) => return Scored::abstain(reason, NETWORK_SOURCE),
        };
        let Some(value) = answer.payload.as_f64() else {
            return Scored::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        // A continuous answer has no closed vocabulary, so no token run
        // can be attributed to it: a score NEVER carries a confidence.
        Scored::in_range(value, range, None, NETWORK_SOURCE)
    }

    async fn judge(&self, prompt: &str) -> Judgement {
        let task = DecisionTask::Judge;
        let answer = match self.call(prompt, &task).await {
            Ok(answer) => answer,
            Err(reason) => return Judgement::abstain(reason, NETWORK_SOURCE),
        };
        let Some(raw) = answer.payload.as_str() else {
            return Judgement::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        let Some(token) = strict_option_match(raw, &JUDGE_OPTIONS) else {
            return Judgement::abstain(AbstainReason::Unusable, NETWORK_SOURCE);
        };
        // Attribution is against the WIRE token the model emitted, not
        // against the `bool` we turn it into.
        let confidence = Self::confidence_for(&answer, token);
        Judgement::decided(token == super::VERDICT_YES, confidence, NETWORK_SOURCE)
    }
}

/// The two things a structured response carries: the schema field, and
/// the token logprobs that may license a confidence for it.
struct StructuredAnswer {
    payload: Value,
    logprobs: Option<Vec<Value>>,
}

/// Pull `field` out of `choices[0].message.content` (a JSON document
/// encoded as a string, per the OpenAI spec) plus the token logprobs.
///
/// Two failure classes, kept apart because the seam treats them
/// differently (f1 F6, #3806):
///
/// * [`AbstainReason::Unavailable`] — there is NO model answer: the body
///   is not a chat completion at all (`{}`, a proxy's JSON error, no
///   `choices[0].message.content` string). The provider never formed an
///   opinion, so this is an outage and `fallback` governs it (case 2).
/// * [`AbstainReason::Unusable`] — the model ANSWERED and the answer is
///   not a decision: an explicit `message.refusal`, content that is not a
///   JSON object, or a document without the schema field. That is the
///   decline, terminal under every posture (case 3).
///
/// Absent logprobs are NOT a failure; they are an absent confidence.
fn read_structured_answer(
    response: &Value,
    field: &str,
) -> Result<StructuredAnswer, AbstainReason> {
    let choice = response.get("choices").and_then(|c| c.get(0));
    let message = choice.and_then(|c| c.get("message"));
    let Some(content) = message
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
    else {
        // The OpenAI structured-output refusal: `content` is null and the
        // model's decline is in `message.refusal`. That IS an answer.
        let refused = message
            .and_then(|m| m.get("refusal"))
            .and_then(Value::as_str)
            .is_some();
        return Err(if refused {
            AbstainReason::Unusable
        } else {
            AbstainReason::Unavailable
        });
    };
    let payload = serde_json::from_str::<Value>(content)
        .ok()
        .and_then(|document| document.get(field).cloned())
        .ok_or(AbstainReason::Unusable)?;
    let logprobs = choice
        .and_then(|c| c.get("logprobs"))
        .and_then(|block| block.get("content"))
        .and_then(Value::as_array)
        .cloned();
    Ok(StructuredAnswer { payload, logprobs })
}

/// The probability the endpoint assigned to `label`, or `None` when it
/// cannot be attributed to exactly one token run.
///
/// `content` is the OpenAI `choices[0].logprobs.content` array of
/// `{token, logprob}` entries. The rule, stated once here and pinned in
/// the tests: find every contiguous run of tokens whose concatenation
/// equals `label` exactly; accept only if there is EXACTLY ONE such run;
/// the probability is `exp(Σ logprob)` over it.
fn label_probability(content: &[Value], label: &str) -> Option<f64> {
    if label.is_empty() || content.is_empty() {
        return None;
    }
    let mut tokens: Vec<(&str, f64)> = Vec::with_capacity(content.len());
    for entry in content {
        let token = entry.get("token")?.as_str()?;
        let logprob = entry.get("logprob")?.as_f64()?;
        // A logprob is the log of a probability: finite and <= 0. A
        // positive or NaN value is not evidence, it is a broken payload.
        if !logprob.is_finite() || logprob > 0.0 {
            return None;
        }
        tokens.push((token, logprob));
    }

    let mut runs: Vec<f64> = Vec::new();
    for start in 0..tokens.len() {
        let mut accumulated = String::new();
        let mut total = 0.0_f64;
        for (token, logprob) in &tokens[start..] {
            accumulated.push_str(token);
            total += *logprob;
            if accumulated.len() > label.len() {
                break;
            }
            if accumulated == label {
                runs.push(total);
                break;
            }
        }
    }
    if runs.len() != 1 {
        return None;
    }
    let probability = runs[0].exp();
    // `exp` of a non-positive sum is always <= 1.0, so this only rejects
    // a payload that lied about its logprobs; `Decision::decided` would
    // degrade such a value anyway, but refusing it here keeps the reason
    // in one place.
    (probability.is_finite() && (0.0..=1.0).contains(&probability)).then_some(probability)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn token(text: &str, logprob: f64) -> Value {
        json!({"token": text, "logprob": logprob})
    }

    fn decider_for_tests(base_url: &str, key: Option<&str>) -> OpenAiCompatibleDecider {
        OpenAiCompatibleDecider {
            provider_id: "openai-compatible".to_string(),
            model: "vendor/decision-1".to_string(),
            endpoint: endpoint_url(base_url, CHAT_ROUTE).expect("test base_url parses"),
            api_key: SecretKey::new(key),
            http: decision_http_client(Duration::from_secs(2), None).expect("test client builds"),
            timeout: Duration::from_secs(2),
            outbound: Arc::new(|_: &Url| Ok(())),
            logprobs: AtomicBool::new(true),
        }
    }

    #[test]
    fn a_confidence_is_attributed_to_exactly_one_token_run() {
        // PRESENCE: one run, split across two tokens, sums correctly.
        let content = [
            token("{\"verdict\":\"", -0.01),
            token("ye", -0.2),
            token("s", -0.3),
            token("\"}", -0.02),
        ];
        let probability =
            label_probability(&content, "yes").expect("a single aligned run must attribute");
        assert!(
            (probability - (-0.5_f64).exp()).abs() < 1e-12,
            "probability must be exp(sum of the run's logprobs): {probability}"
        );
    }

    #[test]
    fn an_ambiguous_or_unaligned_attribution_reports_no_confidence() {
        // TWO runs reconstruct the label: which one decided is unknowable.
        let ambiguous = [
            token("no", -0.1),
            token("{\"verdict\":\"", -0.01),
            token("no", -0.4),
            token("\"}", -0.02),
        ];
        assert_eq!(label_probability(&ambiguous, "no"), None, "ambiguous run");
        // The label is swallowed by a wider token: no aligned run exists.
        let unaligned = [token("{\"verdict\":\"yes\"}", -0.05)];
        assert_eq!(label_probability(&unaligned, "yes"), None, "unaligned");
        // A positive logprob is not evidence.
        let broken = [token("yes", 0.5)];
        assert_eq!(label_probability(&broken, "yes"), None, "positive logprob");
        // An entry missing its logprob is not evidence either.
        let partial = [json!({"token": "yes"})];
        assert_eq!(label_probability(&partial, "yes"), None, "missing logprob");
        assert_eq!(label_probability(&[], "yes"), None, "empty content");
    }

    #[test]
    fn a_structured_answer_needs_the_schema_field_and_tolerates_absent_logprobs() {
        let with_logprobs = json!({
            "choices": [{
                "message": {"content": "{\"choice\":\"Fact\"}"},
                "logprobs": {"content": [{"token": "Fact", "logprob": -0.1}]},
            }],
        });
        let answer =
            read_structured_answer(&with_logprobs, FIELD_CHOICE).expect("conformant response");
        assert_eq!(answer.payload.as_str(), Some("Fact"));
        assert_eq!(answer.logprobs.map(|c| c.len()), Some(1));

        // PRESENCE control for the absence: the same body without the
        // logprobs block still DECIDES, it just has no confidence.
        let no_logprobs = json!({
            "choices": [{"message": {"content": "{\"choice\":\"Fact\"}"}}],
        });
        let answer = read_structured_answer(&no_logprobs, FIELD_CHOICE)
            .unwrap_or_else(|r| panic!("logprobs are optional: {r}"));
        assert_eq!(answer.payload.as_str(), Some("Fact"));
        assert!(answer.logprobs.is_none(), "absent logprobs, not an error");

        // f1 F6 — NO model answer (not a chat completion) is an OUTAGE.
        for body in [
            json!({}),
            json!({"choices": []}),
            json!({"choices": [{"message": {}}]}),
            json!({"choices": [{"message": {"content": null}}]}),
            json!({"error": {"message": "upstream overloaded"}}),
        ] {
            assert_eq!(
                read_structured_answer(&body, FIELD_CHOICE).err(),
                Some(AbstainReason::Unavailable),
                "{body}"
            );
        }
        // ...while an ANSWER that is not a decision is the DECLINE.
        for body in [
            json!({"choices": [{"message": {"content": "not json"}}]}),
            json!({"choices": [{"message": {"content": "{\"other\":1}"}}]}),
            json!({"choices": [{"message": {"content": null, "refusal": "I can't."}}]}),
        ] {
            assert_eq!(
                read_structured_answer(&body, FIELD_CHOICE).err(),
                Some(AbstainReason::Unusable),
                "{body}"
            );
        }
    }

    #[test]
    fn the_request_body_carries_all_four_decision_parameters() {
        let decider = decider_for_tests("https://decide.example.net/v1", None);
        let options = ["Fact", "Decision"];
        let body = decider.request_body(
            "is this a fact?",
            &DecisionTask::Choose { options: &options },
            true,
        );
        assert_eq!(body["temperature"], json!(DECISION_TEMPERATURE));
        assert_eq!(body["seed"], json!(DECISION_SEED));
        assert_eq!(body["logprobs"], json!(true));
        assert_eq!(body["response_format"]["type"], json!("json_schema"));
        assert_eq!(
            body["response_format"]["json_schema"]["strict"],
            json!(true)
        );
        assert_eq!(
            body["response_format"]["json_schema"]["schema"][SCHEMA_PROPERTIES][FIELD_CHOICE]["enum"],
            json!(options),
            "the closed vocabulary must reach the endpoint as an enum"
        );
        assert_eq!(
            body["response_format"]["json_schema"]["schema"]["additionalProperties"],
            json!(false)
        );
        // The latched-off variant differs in exactly one key.
        let without = decider.request_body(
            "is this a fact?",
            &DecisionTask::Choose { options: &options },
            false,
        );
        assert!(without.get("logprobs").is_none(), "latched off");
        assert_eq!(without["response_format"], body["response_format"]);
    }

    #[test]
    fn debug_never_echoes_the_key_or_the_full_endpoint() {
        const SECRET: &str = "sk-w1c-chat-debug-3806";
        let decider = decider_for_tests("https://decide.example.net/v1?token=leaky", Some(SECRET));
        let rendered = format!("{decider:?} {decider:#?}");
        assert!(!rendered.contains(SECRET), "Debug leaked the credential");
        assert!(
            !rendered.contains("leaky"),
            "Debug leaked the URL query: {rendered}"
        );
        // PRESENCE control: the constructor really did take the key.
        assert!(decider.api_key.is_present());
        assert!(rendered.contains(crate::REDACTED_PLACEHOLDER));
    }

    #[test]
    fn the_ollama_alias_uses_the_openai_compatible_route() {
        assert_eq!(
            endpoint_url("http://127.0.0.1:11434", OLLAMA_CHAT_ROUTE)
                .expect("route parses")
                .path(),
            OLLAMA_CHAT_ROUTE,
            "the native /api/chat shape carries neither json_schema nor logprobs"
        );
    }
}
