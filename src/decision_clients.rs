// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1c — the `[decision]` provider CLIENTS.
//!
//! W1a gave the substrate a decision TYPE (`src/decision.rs`: a value
//! that may be honestly ABSENT, a confidence that exists only where
//! evidence for it exists) and a resolved CONFIGURATION
//! (`src/decision_config.rs`). This module gives it the three things
//! that actually talk to an endpoint, plus the factory W1b's boot
//! chokepoint calls:
//!
//! 1. [`chat::OpenAiCompatibleDecider`] — a STRUCTURED chat-completions
//!    call (`response_format` = `json_schema`, `logprobs`,
//!    `temperature = 0`, `seed`). This covers the reference decision
//!    model on OpenRouter and any `[llm]` alias or customer endpoint
//!    that follows the OpenAI chat spec. The existing generative bodies
//!    in `src/llm.rs` carry NONE of those four parameters, which is why
//!    the structured request is built here rather than there.
//! 2. [`systemone::SystemOneDecider`] — the direct adapter for the
//!    vendor's own decision route (`POST /v1/systemone`).
//! 3. [`fallback::GenerativeFallbackDecider`] — the closed-vocabulary
//!    prompt over the EXISTING generative client, for
//!    `[decision].fallback = "generative"`.
//!
//! plus [`calibration::CalibrationRow`], the adapter that renders any
//! decision into the preregistered calibration-harness input shape, and
//! [`construct`], the one entry point that turns a
//! [`ResolvedDecision`] into a `Box<dyn DecisionProvider>`.
//!
//! ## The four rules every client in this tree obeys
//!
//! 1. **A failure is an ABSTAIN, never a `false`.** No method returns a
//!    `Result`; a timeout, a transport error, a non-2xx status, a
//!    malformed body, an off-vocabulary answer and an egress refusal
//!    each become an abstain carrying the reason. There is no shape in
//!    which a seam can coerce an error into a verdict.
//! 2. **Confidence only where logprobs say so.** A confidence is emitted
//!    ONLY when the endpoint returned token logprobs AND exactly one
//!    token run in them reconstructs the decided label. Anything else —
//!    no logprobs, an ambiguous attribution, a token that straddles the
//!    label — reports NO confidence. A fabricated `1.0` would sail
//!    through every `confidence < threshold` guard downstream.
//! 3. **Every request passes the caller's outbound check first.** The
//!    [`OutboundCheck`] hook is invoked with the fully-resolved request
//!    URL before a socket is opened, on EVERY call including a retry and
//!    including the generative fallback leg. A refusal yields
//!    [`AbstainReason::EgressRefused`] and NO request leaves the
//!    process. An egress refusal is the one abstain that never falls
//!    back — routing around a refused destination would be the egress
//!    bypass the gate exists to prevent.
//! 4. **The key never reaches a `Debug` or a log line.** Credentials
//!    live in [`SecretKey`], whose `Debug` is the redaction placeholder
//!    and whose `Drop` zeroizes; every log line renders the endpoint
//!    through the URL redaction funnel.
//!
//! ## What this module deliberately does NOT do
//!
//! It does not wire a seam (W2-W4), it does not touch the egress class
//! or the boot path (W1b), and it records no metrics series: the
//! `decision_outcome` / `decision_latency_seconds` surface belongs with
//! the seams that own the call sites. Nothing here is reachable until
//! W1b calls [`construct`].

// The item names below intentionally echo their module names
// (`chat::OpenAiCompatibleDecider`, `calibration::CalibrationRow`) so a
// `use` at a call site reads as the thing it constructs.
#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use reqwest::Url;
use serde_json::Value;

use crate::decision::{
    AbstainReason, DecisionCapability, DecisionProvider, DecisionSource, ScoreRange,
};
use crate::decision_config::{
    DecisionFallback, PROVIDER_LOCAL_NLI, PROVIDER_SYSTEMONE, ResolvedDecision, fallback_phrase,
};

pub mod calibration;
pub mod chat;
pub mod fallback;
pub mod systemone;

/// The yes token of the judge vocabulary.
pub const VERDICT_YES: &str = "yes";
/// The no token of the judge vocabulary.
pub const VERDICT_NO: &str = "no";

/// The closed vocabulary every `judge` implementation answers in. A
/// judgement is a two-option `choose` wearing a `bool`, so the same
/// strict parser serves both.
pub const JUDGE_OPTIONS: [&str; 2] = [VERDICT_YES, VERDICT_NO];

/// `Debug` field name for a client's provider alias. Named rather than
/// repeated so the three client `Debug` impls cannot drift apart (and so
/// the literal is not scattered — pm-v3.1).
pub(crate) const DEBUG_FIELD_PROVIDER: &str = "provider_id";

/// `Debug` field name for a client's per-call budget.
pub(crate) const DEBUG_FIELD_BUDGET: &str = "timeout_secs";

/// `Debug` field name for a client's endpoint, always rendered through
/// the URL redaction funnel.
pub(crate) const DEBUG_FIELD_ENDPOINT: &str = "endpoint";

/// Sampling temperature for every decision request.
///
/// A decision is not a creative act: the same prompt must yield the same
/// verdict on the retry, on the replay and on the second node, or a
/// calibration figure measured on Monday says nothing about Tuesday.
pub const DECISION_TEMPERATURE: f64 = 0.0;

/// Sampling seed sent with every decision request, for the endpoints
/// that honour it. Fixed (not random, not time-derived) for the same
/// reproducibility reason as [`DECISION_TEMPERATURE`]; the value is the
/// issue number, so a captured request body is traceable to its design.
pub const DECISION_SEED: u64 = 3806;

/// A per-call outbound check, invoked with the fully-resolved request
/// URL before ANY request leaves the process.
///
/// W1b's boot chokepoint supplies the real one (the
/// `EgressClass::InferenceDecision` posture check plus its audited
/// refusal row); a caller that has already gated the destination
/// supplies a permissive closure. `Arc` because one hook is shared by
/// the primary provider and its fallback leg.
pub type OutboundCheck = Arc<dyn Fn(&Url) -> Result<()> + Send + Sync>;

/// A credential that cannot be printed and does not linger on the heap.
///
/// Mirrors the `[llm]` contract (`LlmProvider` / `ResolvedDecision`):
/// `Debug` renders the redaction placeholder, `Drop` zeroizes the
/// buffer, and the only way to the bytes is [`SecretKey::expose`], whose
/// doc says where it may be used.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretKey(Option<String>);

impl SecretKey {
    /// Wrap an optional credential.
    #[must_use]
    pub fn new(key: Option<&str>) -> Self {
        Self(key.map(str::to_string))
    }

    /// The credential bytes. Use ONLY to set an `Authorization` header;
    /// never log, format or return the result.
    #[must_use]
    pub fn expose(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Whether a credential is present. This is the only property of a
    /// key that is safe to report.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.0.is_some()
    }

    /// Zeroize the buffer in place. Idempotent; `Drop` delegates here so
    /// the zero-on-loss contract has one source of truth.
    pub fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        if let Some(key) = self.0.as_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(_) => f.write_str(crate::REDACTED_PLACEHOLDER),
            None => f.write_str("None"),
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

/// Which of the three `DecisionProvider` questions is being asked.
///
/// The clients share one request/response pipeline and differ only in
/// the schema they demand and the field they read back, so the task
/// travels as a value rather than as three near-duplicate methods.
#[derive(Debug, Clone, Copy)]
pub enum DecisionTask<'a> {
    /// Pick exactly one of `options`.
    Choose {
        /// The closed vocabulary. An empty slice is always an abstain.
        options: &'a [&'a str],
    },
    /// Answer yes or no.
    Judge,
    /// Produce a number inside `range`.
    Score {
        /// The admissible interval; a value outside it abstains rather
        /// than being clamped into a plausible-looking number.
        range: ScoreRange,
    },
}

impl DecisionTask<'_> {
    /// The closed vocabulary for this task, or `None` for a continuous
    /// score (which has no vocabulary and therefore no logprob-derived
    /// confidence).
    #[must_use]
    pub fn vocabulary(&self) -> Option<&[&str]> {
        match self {
            Self::Choose { options } => Some(options),
            Self::Judge => Some(&JUDGE_OPTIONS),
            Self::Score { .. } => None,
        }
    }
}

/// Normalise a raw model answer before matching it against a closed
/// vocabulary: trim whitespace, strip one layer of surrounding quoting,
/// and drop a single trailing sentence period.
///
/// This is the ONLY latitude a strict parser gets. Everything else — a
/// preamble, a justification, a second sentence, a markdown bullet —
/// fails to match and becomes an abstain. That is the whole point: the
/// defect this programme exists to remove is `detect_contradiction`'s
/// `starts_with("yes")`, which turns a refusal and a rambling
/// "yes, but actually no" alike into a verdict.
#[must_use]
pub fn normalize_answer(answer: &str) -> &str {
    let trimmed = answer.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .or_else(|| {
            trimmed
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
        })
        .unwrap_or(trimmed);
    unquoted.strip_suffix('.').unwrap_or(unquoted).trim()
}

/// Match `answer` against the closed vocabulary `options`, returning the
/// matched option VERBATIM (so the caller reports the vocabulary's
/// spelling, never the model's).
///
/// An exact match wins outright. Failing that, a UNIQUE
/// ASCII-case-insensitive match is accepted. An ambiguous match (two
/// options that differ only in case) or no match at all returns `None`,
/// which every caller turns into [`AbstainReason::Unusable`].
#[must_use]
pub fn strict_option_match<'o>(answer: &str, options: &[&'o str]) -> Option<&'o str> {
    let candidate = normalize_answer(answer);
    if candidate.is_empty() {
        return None;
    }
    if let Some(exact) = options.iter().find(|option| **option == candidate) {
        return Some(exact);
    }
    let mut folded = options
        .iter()
        .filter(|option| option.eq_ignore_ascii_case(candidate));
    let first = folded.next()?;
    if folded.next().is_some() {
        return None;
    }
    Some(first)
}

/// Strictly read a yes/no verdict. Anything outside [`JUDGE_OPTIONS`] —
/// prose, a refusal, an empty body — is `None`, i.e. an abstain.
#[must_use]
pub fn strict_verdict(answer: &str) -> Option<bool> {
    match strict_option_match(answer, &JUDGE_OPTIONS)? {
        VERDICT_YES => Some(true),
        _ => Some(false),
    }
}

/// Strictly read a score: the whole normalised answer must parse as a
/// finite number AND lie inside `range`. An out-of-range value is an
/// abstain, never a clamp.
#[must_use]
pub fn strict_score(answer: &str, range: ScoreRange) -> Option<f64> {
    let value: f64 = normalize_answer(answer).parse().ok()?;
    if range.contains(value) {
        Some(value)
    } else {
        None
    }
}

/// Why one HTTP attempt did not produce a body.
///
/// Kept separate from [`AbstainReason`] so a caller can see the HTTP
/// status — the one piece of an unsuccessful response that is ours, not
/// the vendor's text — without the status escaping into a seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallFailure {
    /// Map straight onto this abstain reason.
    Abstain(AbstainReason),
    /// The endpoint answered with a non-2xx status.
    Status(reqwest::StatusCode),
}

impl CallFailure {
    /// The abstain reason a seam sees.
    ///
    /// A non-2xx status is [`AbstainReason::Unavailable`], NOT
    /// `Unusable`: the endpoint was reachable but the MODEL never
    /// answered — a 429, a 500, an expired key. Nothing declined, so a
    /// seam may fall back to the instrument it used before
    /// ([`AbstainReason::is_unavailable`], #3806 W2 case 2). `Unusable`
    /// is reserved for an answer the model actually gave.
    pub(crate) fn reason(self) -> AbstainReason {
        match self {
            Self::Abstain(reason) => reason,
            Self::Status(_) => AbstainReason::Unavailable,
        }
    }
}

/// Classify a transport error WITHOUT carrying the vendor's text.
///
/// `reqwest`'s `Display` can embed the request URL (#3648 / #3688), so
/// the error is reduced to one of our own enum values here and dropped.
fn transport_abstain(error: &reqwest::Error) -> AbstainReason {
    // Reached only for a transport failure that is NOT the per-call
    // deadline (that one is the `tokio::time::timeout` arm in
    // `post_json`): a refused connection, a DNS failure, a TLS failure.
    // Classified into one of our own values and then dropped.
    if error.is_timeout() {
        AbstainReason::Timeout
    } else {
        // A refused connection, a DNS failure, a TLS failure: the model
        // was never reached, so this is UNAVAILABILITY and not a
        // decline (#3806 W2 case 2).
        AbstainReason::Unavailable
    }
}

/// One outbound decision request.
pub(crate) struct HttpCall<'a> {
    /// The pooled client to send on.
    pub(crate) client: &'a reqwest::Client,
    /// The fully-resolved request URL. This exact value is handed to the
    /// outbound check.
    pub(crate) endpoint: &'a Url,
    /// Bearer credential, if the endpoint takes one.
    pub(crate) api_key: Option<&'a str>,
    /// The JSON request body.
    pub(crate) body: &'a Value,
    /// The whole-call budget (`[decision].timeout_secs`).
    pub(crate) timeout: Duration,
    /// The caller's per-call egress gate.
    pub(crate) outbound: &'a OutboundCheck,
    /// Provider alias, for the log line. Never a credential.
    pub(crate) provider_id: &'a str,
}

/// Send one decision request and return its parsed JSON body.
///
/// The outbound check runs FIRST and a refusal returns before any socket
/// is opened. The whole call — send, status check and capped body read —
/// is bounded by `timeout`, so a server that accepts a connection and
/// then goes silent abstains on time rather than parking the seam.
pub(crate) async fn post_json(call: HttpCall<'_>) -> Result<Value, CallFailure> {
    // The refusal itself is W1b's to audit (it owns the signed refusal
    // row and the posture that produced it). What this layer must
    // guarantee is the ABSENCE: no request is built, no socket is
    // opened, and the seam is told EgressRefused rather than a verdict.
    if (call.outbound)(call.endpoint).is_err() {
        let display_url = crate::url_display::url_origin(call.endpoint.as_str());
        tracing::warn!(
            provider = call.provider_id,
            endpoint = %display_url,
            "decision call refused by the outbound egress check"
        );
        return Err(CallFailure::Abstain(AbstainReason::EgressRefused));
    }

    // ONE authority for the deadline. `reqwest`'s own per-request timer
    // is deliberately NOT set here: two timers armed at the same instant
    // race, and the winner decides whether the seam is told `Timeout` or
    // `Unusable`. A racy abstain REASON is worse than a slow one — it
    // makes the `decision_outcome` series lie about why a seam had no
    // answer. The pool keeps a longer backstop (see
    // `decision_http_client`) in case this future is never polled again.
    let mut request = call.client.post(call.endpoint.clone()).json(call.body);
    if let Some(key) = call.api_key {
        request = request.bearer_auth(key);
    }

    let attempt = tokio::time::timeout(call.timeout, async {
        let response = request
            .send()
            .await
            .map_err(|e| CallFailure::Abstain(transport_abstain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CallFailure::Status(status));
        }
        crate::llm::read_capped_json(response)
            .await
            // A body that is not JSON is not an ANSWER: a proxy error
            // page, a truncated response. Unavailability, not a decline.
            .map_err(|_| CallFailure::Abstain(AbstainReason::Unavailable))
    })
    .await;

    match attempt {
        Err(_elapsed) => Err(CallFailure::Abstain(AbstainReason::Timeout)),
        Ok(outcome) => outcome,
    }
}

/// Build the HTTP pool every network decision client uses.
///
/// Two transport rules the carrier's inference egress plane applies to the
/// `[llm]` / embedding lanes, applied here too (#3822 / #3823):
///
/// * **No redirect is ever followed, in every posture.** The per-call
///   outbound check approves the ORIGIN of the URL this client builds; a
///   `307` / `308` would have reqwest re-POST the same body (memory
///   content) to wherever `Location` points AFTER that check ran — to an
///   origin no gate saw, possibly in plaintext. A redirect is therefore
///   not followed; it surfaces as a non-2xx status, which is an OUTAGE
///   (`Unavailable`, case 2), never a verdict.
/// * **Under `internal-only`, the pin is the destination.** `pin` is the
///   target the boot chokepoint resolved and admitted; the client
///   connects ONLY to those addresses (`resolve_to_addrs`, closing the
///   DNS-rebind window) and never through a proxy, which would connect on
///   its own terms and defeat the pin.
fn decision_http_client(
    timeout: Duration,
    pin: Option<&crate::egress::PinnedTarget>,
) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    let builder = match pin {
        Some(pin) => builder.resolve_to_addrs(&pin.host, &pin.addrs).no_proxy(),
        None => builder,
    };
    builder
        // Strictly LONGER than the per-call `tokio::time::timeout`, so the
        // authoritative guard in `post_json` always wins the race and the
        // abstain reason is deterministic. This is a backstop against a
        // future that stops being polled, not the deadline.
        //
        // NO `connect_timeout` either, for the same reason: a connect
        // timer shorter than the deadline is a THIRD racer, and the one
        // that wins decides whether the seam is told `Timeout` or
        // `Unusable`. A blackholed host is still bounded — it abstains at
        // `[decision].timeout_secs` — and a host that REFUSES the
        // connection still abstains immediately, because a refusal is an
        // error rather than a timer.
        .timeout(timeout.saturating_mul(2))
        .build()
        .map_err(|_| anyhow!("could not build the [decision] HTTP client"))
}

/// Join a configured `base_url` and a route into a request URL.
///
/// Fails closed: a base URL that does not parse, or that parses to
/// something other than `http`/`https`, is a refusal at construction
/// rather than a surprise at the first call.
fn endpoint_url(base_url: &str, route: &str) -> Result<Url> {
    let joined = format!("{}{route}", base_url.trim_end_matches('/'));
    let url = Url::parse(&joined)
        .map_err(|_| anyhow!("[decision].base_url is not a valid URL (route {route})"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("[decision].base_url must be an http or https URL (route {route})");
    }
    Ok(url)
}

/// A decider that consults a second provider when the first has no
/// opinion — the `[decision].fallback = "generative"` shape.
///
/// **The one abstain that never falls back is
/// [`AbstainReason::EgressRefused`].** A refused destination must not be
/// reachable by asking a different endpoint the same question; that
/// would turn the egress posture into a suggestion.
/// [`AbstainReason::NoProvider`] is likewise terminal — a constructed
/// client never reports it, so seeing it means the chain itself is the
/// absent-provider path.
///
/// The cost an operator opts into with `fallback = "generative"` is a
/// worst case of TWO `timeout_secs` budgets on a seam whose primary
/// timed out, and a second endpoint's latency on every abstain.
#[derive(Debug)]
pub struct FallbackChain {
    primary: Box<dyn DecisionProvider>,
    secondary: fallback::GenerativeFallbackDecider,
}

impl FallbackChain {
    /// Chain `secondary` behind `primary`.
    #[must_use]
    pub fn new(
        primary: Box<dyn DecisionProvider>,
        secondary: fallback::GenerativeFallbackDecider,
    ) -> Self {
        Self { primary, secondary }
    }

    /// Whether an abstain for `reason` may be re-asked of the fallback.
    ///
    /// Three terminal reasons, for three different arguments:
    ///
    /// * [`AbstainReason::Unusable`] — the provider ANSWERED and
    ///   declined. Re-asking the question of a second model turns a
    ///   deliberate refusal into somebody's opinion, which is the
    ///   defect #3806 exists to remove rather than to relocate
    ///   (Conductor ruling, W2 case 3; see
    ///   [`AbstainReason::is_unavailable`]).
    /// * [`AbstainReason::EgressRefused`] — a destination the posture
    ///   refused must not be reachable by asking a different endpoint.
    /// * [`AbstainReason::NoProvider`] — a constructed client never
    ///   reports it, so seeing it means the chain IS the absent path.
    #[must_use]
    pub fn may_fall_back(reason: AbstainReason) -> bool {
        match reason {
            AbstainReason::EgressRefused | AbstainReason::NoProvider | AbstainReason::Unusable => {
                false
            }
            AbstainReason::Timeout | AbstainReason::Unavailable | AbstainReason::Unsupported => {
                true
            }
        }
    }
}

#[async_trait::async_trait]
impl DecisionProvider for FallbackChain {
    fn provider_id(&self) -> &str {
        self.primary.provider_id()
    }

    /// A chain answers with its PRIMARY's capabilities: the fallback leg
    /// covers unavailability, never a question the primary cannot ask.
    fn supports(&self, capability: DecisionCapability) -> bool {
        self.primary.supports(capability)
    }

    async fn choose(&self, prompt: &str, options: &[&str]) -> crate::decision::Choice {
        let first = self.primary.choose(prompt, options).await;
        match first.abstain_reason() {
            Some(reason) if Self::may_fall_back(reason) => {
                self.secondary.choose(prompt, options).await
            }
            _ => first,
        }
    }

    async fn score(&self, prompt: &str, range: ScoreRange) -> crate::decision::Scored {
        let first = self.primary.score(prompt, range).await;
        match first.abstain_reason() {
            Some(reason) if Self::may_fall_back(reason) => {
                self.secondary.score(prompt, range).await
            }
            _ => first,
        }
    }

    async fn judge(&self, prompt: &str) -> crate::decision::Judgement {
        let first = self.primary.judge(prompt).await;
        match first.abstain_reason() {
            Some(reason) if Self::may_fall_back(reason) => self.secondary.judge(prompt).await,
            _ => first,
        }
    }
}

/// #3806 R6 — the capabilities the WIRED seams ask of a provider:
/// `classify_kind` chooses, `detect_contradiction` judges. A unit that
/// wires a new seam adds its capability here, so the boot chokepoint
/// refuses a provider that could never answer it.
pub const SEAM_CAPABILITIES: [DecisionCapability; 2] =
    [DecisionCapability::Choose, DecisionCapability::Judge];

/// #3806 R6 — refuse, BY NAME and at construction, a provider that cannot
/// answer a capability a wired seam requires.
///
/// The vote (4d3ea1c5, R6): `Unsupported` is a PERMANENT capability
/// mismatch, so it belongs at the boot chokepoint with the `local-nli`
/// refusal below, not rediscovered as a per-call abstain on every seam
/// call. A refused construction leaves the handle on the always-
/// abstaining `NullDecider` and reports `configured`, so every seam takes
/// its `fallback` branch (case 2) — visibly, once, at boot.
///
/// # Errors
/// Names every seam capability `provider` does not support.
pub fn require_seam_capabilities(provider: &dyn DecisionProvider) -> Result<()> {
    let missing: Vec<&str> = SEAM_CAPABILITIES
        .into_iter()
        .filter(|capability| !provider.supports(*capability))
        .map(DecisionCapability::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "[decision].provider = {:?} cannot answer {} — a question a wired seam asks. \
         Refused at construction so every seam takes its `fallback` branch rather than \
         abstaining `unsupported` on every call (#3806)",
        provider.provider_id(),
        missing.join(", ")
    )
}

/// Build the decision provider a seam will consult.
///
/// This is the single constructor W1b's boot chokepoint calls. It reads
/// the credential through `ResolvedDecision::api_key` and nowhere else,
/// and it stores `outbound` so the caller's per-call egress check runs
/// before EVERY request the returned provider makes — including the
/// generative fallback leg.
///
/// Routing:
/// - `provider = "systemone"` → [`systemone::SystemOneDecider`];
/// - `provider = "local-nli"` → a REFUSAL: the in-process cross-encoder
///   lands in W1d, and constructing a network client for it would send
///   a prompt to an endpoint the operator explicitly asked not to have;
/// - everything else → [`chat::OpenAiCompatibleDecider`].
///
/// `fallback = "generative"` wraps the result in a [`FallbackChain`];
/// `"abstain"` and `"refuse"` return the primary unwrapped, because the
/// difference between those two is what the SEAM does with an abstain,
/// not what the provider returns (`ResolvedDecision::fallback` travels
/// to the seam for exactly that reason).
///
/// # Errors
/// Returns an error — never a half-configured provider — when the
/// provider is not one this build can construct, when `base_url` does
/// not parse as an `http`/`https` URL, when the HTTP pool cannot be
/// built, or when `fallback = "generative"` was requested without a
/// generative backend to fall back to.
pub fn construct(
    resolved: &ResolvedDecision,
    outbound: OutboundCheck,
    generative: Option<fallback::GenerativeFallbackDecider>,
) -> Result<Box<dyn DecisionProvider>> {
    construct_pinned(resolved, outbound, generative, None)
}

/// [`construct`] with the `internal-only` egress pin (#3822): `pin` is
/// the boot-resolved target the chokepoint admitted, and every network
/// client this builds connects ONLY to those addresses (no proxy, no
/// redirect). `None` is the name-based postures' shape.
///
/// # Errors
/// As [`construct`].
pub fn construct_pinned(
    resolved: &ResolvedDecision,
    outbound: OutboundCheck,
    generative: Option<fallback::GenerativeFallbackDecider>,
    pin: Option<&crate::egress::PinnedTarget>,
) -> Result<Box<dyn DecisionProvider>> {
    if resolved.provider == PROVIDER_LOCAL_NLI {
        bail!(
            "[decision].provider = \"{PROVIDER_LOCAL_NLI}\" is not available in this build; \
             the in-process decision provider lands separately (#3806 W1d)"
        );
    }

    let primary: Box<dyn DecisionProvider> = if resolved.provider == PROVIDER_SYSTEMONE {
        Box::new(systemone::SystemOneDecider::new_pinned(
            resolved,
            Arc::clone(&outbound),
            pin,
        )?)
    } else {
        Box::new(chat::OpenAiCompatibleDecider::new_pinned(
            resolved,
            Arc::clone(&outbound),
            pin,
        )?)
    };

    // #3806 R6 — a permanent capability mismatch is a boot refusal.
    require_seam_capabilities(primary.as_ref())?;

    match resolved.fallback {
        DecisionFallback::Generative => {
            let secondary = generative.ok_or_else(|| {
                anyhow!(
                    "a generative fallback is configured but no generative [llm] backend \
                     exists to fall back to: {}",
                    fallback_phrase(DecisionFallback::Generative)
                )
            })?;
            Ok(Box::new(FallbackChain::new(primary, secondary)))
        }
        DecisionFallback::Abstain | DecisionFallback::Refuse => Ok(primary),
    }
}

/// The source every network decision client reports.
pub(crate) const NETWORK_SOURCE: DecisionSource = DecisionSource::DecisionModel;

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider that can judge and score but never choose.
    #[derive(Debug)]
    struct JudgeOnly;

    #[async_trait::async_trait]
    impl DecisionProvider for JudgeOnly {
        fn provider_id(&self) -> &str {
            "stub-provider"
        }
        async fn choose(&self, _p: &str, _o: &[&str]) -> crate::decision::Choice {
            crate::decision::Choice::abstain(AbstainReason::Unsupported, NETWORK_SOURCE)
        }
        async fn score(&self, _p: &str, _r: ScoreRange) -> crate::decision::Scored {
            crate::decision::Scored::abstain(AbstainReason::Unusable, NETWORK_SOURCE)
        }
        async fn judge(&self, _p: &str) -> crate::decision::Judgement {
            crate::decision::Judgement::abstain(AbstainReason::Unusable, NETWORK_SOURCE)
        }
        fn supports(&self, capability: DecisionCapability) -> bool {
            capability != DecisionCapability::Choose
        }
    }

    /// #3806 R6 — a PERMANENT capability mismatch is refused at the boot
    /// chokepoint, by name, instead of surfacing as `Unsupported` on every
    /// seam call. PRESENCE control: a provider that supports every wired
    /// capability passes the same gate, so the refusal is the mismatch's
    /// doing and not a gate that refuses everything.
    #[test]
    fn a_provider_missing_a_seam_capability_is_refused_at_construction() {
        let refusal = require_seam_capabilities(&JudgeOnly)
            .expect_err("a provider that cannot `choose` must not back the classify_kind seam");
        let text = refusal.to_string();
        assert!(text.contains("choose"), "names the capability: {text}");
        assert!(
            !text.contains("judge"),
            "names ONLY the missing one: {text}"
        );
        assert!(require_seam_capabilities(&crate::decision::NullDecider).is_ok());
        // The wired set is exactly the two W2 seams' questions.
        assert_eq!(
            SEAM_CAPABILITIES,
            [DecisionCapability::Choose, DecisionCapability::Judge]
        );
    }

    #[test]
    fn a_strict_parser_accepts_the_vocabulary_and_refuses_prose() {
        // PRESENCE: the exact token, a quoted token and a trailing
        // period all resolve to the vocabulary's own spelling.
        assert_eq!(strict_verdict("yes"), Some(true), "bare token");
        assert_eq!(strict_verdict("  \"no\" "), Some(false), "quoted token");
        assert_eq!(strict_verdict("YES."), Some(true), "case + period");
        // ABSENCE: the `starts_with("yes")` defect class.
        assert_eq!(strict_verdict("yes, because the two overlap"), None);
        assert_eq!(strict_verdict("Sure!"), None);
        assert_eq!(strict_verdict(""), None);
        assert_eq!(strict_verdict("I cannot answer that."), None);
    }

    #[test]
    fn an_option_match_returns_the_vocabularys_spelling_not_the_models() {
        let options = ["Fact", "Decision"];
        assert_eq!(strict_option_match("fact", &options), Some("Fact"));
        assert_eq!(strict_option_match("Decision", &options), Some("Decision"));
        assert_eq!(strict_option_match("Preference", &options), None);
        // An ambiguous case-fold is NOT resolved by guessing.
        let ambiguous = ["fact", "FACT"];
        assert_eq!(strict_option_match("Fact", &ambiguous), None);
        // ... but an exact match still wins outright.
        assert_eq!(strict_option_match("FACT", &ambiguous), Some("FACT"));
    }

    #[test]
    fn a_score_outside_the_range_abstains_rather_than_clamping() {
        let range = ScoreRange::unit();
        assert_eq!(strict_score("0.25", range), Some(0.25));
        assert_eq!(strict_score(" 1 ", range), Some(1.0));
        assert_eq!(strict_score("1.5", range), None, "out of range");
        assert_eq!(strict_score("NaN", range), None, "non-finite");
        assert_eq!(strict_score("about 0.5", range), None, "prose");
    }

    #[test]
    fn a_secret_key_is_redacted_in_debug_and_zeroized_on_loss() {
        const SECRET: &str = "sk-w1c-debug-probe-3806";
        let mut key = SecretKey::new(Some(SECRET));
        let rendered = format!("{key:?} {key:#?}");
        assert!(
            !rendered.contains(SECRET),
            "Debug MUST NOT echo the credential"
        );
        assert!(
            rendered.contains(crate::REDACTED_PLACEHOLDER),
            "Debug must say a credential is present: {rendered}"
        );
        // PRESENCE control: the accessor still yields the real bytes,
        // so the absence assertion above is not vacuous.
        assert_eq!(key.expose(), Some(SECRET));
        assert!(key.is_present());
        key.zeroize_secrets();
        assert_ne!(key.expose(), Some(SECRET), "zeroize must clear the buffer");
        assert_eq!(format!("{:?}", SecretKey::new(None)), "None");
    }

    #[test]
    fn a_refusal_and_a_decline_never_fall_back_but_unavailability_does() {
        assert!(
            !FallbackChain::may_fall_back(AbstainReason::EgressRefused),
            "a refused destination must not be reachable via a second endpoint"
        );
        assert!(!FallbackChain::may_fall_back(AbstainReason::NoProvider));
        assert!(
            !FallbackChain::may_fall_back(AbstainReason::Unusable),
            "#3806 W2 case 3: the provider ANSWERED and declined, so the question is \
             terminal — re-asking it of a second model manufactures a definite answer \
             out of a deliberate refusal"
        );
        // PRESENCE control on the same predicate: every UNAVAILABILITY
        // does fall back, so the three refusals above are a property of
        // those reasons and not of a predicate that always says no.
        assert!(FallbackChain::may_fall_back(AbstainReason::Timeout));
        assert!(FallbackChain::may_fall_back(AbstainReason::Unavailable));
        assert!(FallbackChain::may_fall_back(AbstainReason::Unsupported));
        // The two classes partition the enum, with no third answer.
        for reason in [
            AbstainReason::NoProvider,
            AbstainReason::Timeout,
            AbstainReason::EgressRefused,
            AbstainReason::Unavailable,
            AbstainReason::Unusable,
            AbstainReason::Unsupported,
        ] {
            assert_eq!(
                reason.is_unavailable(),
                reason != AbstainReason::Unusable,
                "`Unusable` is the ONLY decline: {reason}"
            );
        }
    }

    #[test]
    fn an_endpoint_url_refuses_a_non_http_scheme() {
        assert!(endpoint_url("https://decide.example.net/v1", "/chat/completions").is_ok());
        assert!(endpoint_url("http://127.0.0.1:8080", "/v1/systemone").is_ok());
        assert!(endpoint_url("file:///etc/passwd", "/v1/systemone").is_err());
        assert!(endpoint_url("not a url", "/chat/completions").is_err());
    }
}
