// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1a — the `[decision]` provider seam: a typed, structured
//! DECISION class beside the generative `[llm]` backend.
//!
//! ## Why a second class of model
//!
//! Several substrate operations are classification or scoring wearing an
//! LLM costume, and none of them emits a calibrated number today:
//! `memory_detect_contradiction` turns any preamble, refusal or garbage
//! into `false`; the synthesis verb (`Add`/`Update`/`Delete`/`NoOp`)
//! drives automated deletes with no probability and no abstain;
//! `classify_kind` chooses over a closed set from a prompt naming 8 of
//! the 16 kinds. This module is the type-level answer: a decision is a
//! value that may be ABSENT, and a confidence is a number that only
//! exists where evidence for it exists.
//!
//! ## The three invariants this module makes unrepresentable
//!
//! 1. **Abstain is a first-class value, never a default `false`.** The
//!    decision itself is `Option<T>`; `None` means "no opinion", and it
//!    is paired with an [`AbstainReason`] so a seam can tell a timeout
//!    from an absent provider from an unusable answer. A caller can only
//!    obtain a decision by asking for it — there is no `unwrap_or(false)`
//!    shape anywhere in the type.
//! 2. **Confidence exists only where evidence exists.** `confidence` is
//!    `Option<f64>`, `None` whenever the endpoint returned no logprobs
//!    and no calibration evidence backs the number (the #3548 lesson).
//!    It is also range-validated: a non-finite or out-of-`0.0..=1.0`
//!    value DEGRADES to absent rather than being stored as a fabricated
//!    number, and it can never be attached to an abstain.
//! 3. **Provenance travels with the answer.** Every result carries a
//!    [`DecisionSource`], so `/capabilities`, the metrics surface and
//!    the seams report honestly whether a verdict came from the decision
//!    model, the generative fallback, or a deterministic path.
//!
//! ## Hard constraints (Conductor, #3806)
//!
//! The decider may only NARROW a destructive path, never widen one; it
//! never sits in `Permissions::evaluate` or the federation LWW merge;
//! the verdict is ADVICE and the deterministic pipeline stays
//! authoritative. Nothing in this module performs I/O — the boot
//! chokepoint (`build_decision_provider`, W1b) and the network clients
//! (W1c) land separately, and the seam wiring (W2-W4) after them.
//!
//! ## What implements this trait
//!
//! The trait is deliberately narrow and `async`, so an OpenAI-compatible
//! client (OpenRouter `response_format` + `logprobs`), a SystemOne
//! adapter (`POST /v1/systemone`), a local NLI cross-encoder on candle
//! (`provider = "local-nli"`, zero sockets) and a
//! `GenerativeFallbackDecider` over the existing chat client can each
//! implement it without the trait changing. It is object-safe through
//! `async_trait`, because the boot chokepoint hands the seams one
//! `Arc<dyn DecisionProvider>`.

use std::fmt;

/// Where a decision came from. Carried on every result so no surface
/// can report a generative guess as a decision-model verdict.
/// #3294 / API-07 — `#[non_exhaustive]` so a later provenance is a
/// non-breaking change. `pub mod decision` is public API and the crate
/// ships `rlib`/`staticlib`/`cdylib`, so an external `match` on this
/// enum must carry a wildcard. Adding the attribute AFTER release is
/// itself a breaking change, so it is cheap exactly once: now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecisionSource {
    /// The configured `[decision]` provider answered.
    DecisionModel,
    /// The `[llm]` generative backend answered in the decision model's
    /// place (`fallback = "generative"`).
    GenerativeFallback,
    /// No model was consulted: a deterministic in-process path produced
    /// the result. This is what the absent-provider path reports.
    Deterministic,
}

impl DecisionSource {
    /// The canonical wire / metrics token for this source.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecisionModel => "decision_model",
            Self::GenerativeFallback => "generative_fallback",
            Self::Deterministic => "deterministic",
        }
    }
}

impl fmt::Display for DecisionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a decision is absent. Present on EVERY abstain and absent on
/// every decision, so "no opinion" is always accountable and the
/// `decision_outcome` metric (W1c) has a stable label vocabulary.
/// #3294 / API-07 — `#[non_exhaustive]` so a later reason is a
/// non-breaking change. This enum grew 5 -> 6 in #3806 W2
/// (`Unavailable`), which is precisely the axis the attribute exists to
/// keep non-breaking, and post-GA that growth would be semver-major.
/// Adding the attribute later is itself breaking, so it is cheap
/// exactly once: now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AbstainReason {
    /// `[decision]` is unset, or the boot chokepoint refused to build a
    /// provider. The v1.0.0-unchanged path.
    NoProvider,
    /// The call exceeded `[decision].timeout_secs`. A timeout is an
    /// ABSTAIN, never a `false`.
    Timeout,
    /// The egress posture refused the outbound call.
    EgressRefused,
    /// The provider could not be reached, or did not answer with a
    /// decision RESPONSE at all: a connection failure, a TLS failure, a
    /// non-2xx status, a body that is not the documented envelope.
    ///
    /// Distinct from [`Self::Unusable`] on purpose — see
    /// [`Self::is_unavailable`]. The provider never formed an opinion
    /// here, so a seam may legitimately fall back to whatever
    /// instrument it used before.
    Unavailable,
    /// The endpoint ANSWERED, and its answer was not a decision: a
    /// refusal, a preamble, a hedge, a value outside the closed option
    /// set, a score outside the range.
    ///
    /// This is the DECLINE, and it is the only one. It is terminal: see
    /// [`Self::is_unavailable`].
    Unusable,
    /// The provider cannot answer this question at all (e.g. a local
    /// NLI cross-encoder asked for a continuous score).
    Unsupported,
}

impl AbstainReason {
    /// The canonical wire / metrics token for this reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoProvider => "no_provider",
            Self::Timeout => "timeout",
            Self::EgressRefused => "egress_refused",
            Self::Unavailable => "unavailable",
            Self::Unusable => "unusable",
            Self::Unsupported => "unsupported",
        }
    }
}

impl AbstainReason {
    /// Whether the provider NEVER ANSWERED — so a seam's `fallback`
    /// applies — rather than ANSWERED AND DECLINED, which is terminal.
    ///
    /// **Conductor ruling, #3806 W2 (2026-09-19), in three cases:**
    ///
    /// 1. `[decision]` UNSET — the v1.0.0 path runs entirely, text parse
    ///    and all. The feature is off; that is what byte-identical means.
    /// 2. `[decision]` SET, provider UNAVAILABLE — no provider
    ///    constructed, egress refused, timeout, transport error. This is
    ///    what `fallback` governs: `generative` means the old path,
    ///    `abstain` means abstain, `refuse` means error. The provider
    ///    never answered, so falling back to the previous instrument is
    ///    legitimate.
    /// 3. `[decision]` SET, provider ABSTAINED — the provider DID
    ///    answer, and its answer was "I decline". **That is terminal.**
    ///    The seam takes its conservative branch and the question is
    ///    never re-asked. `fallback` does not apply, because there is
    ///    nothing to fall back FROM.
    ///
    /// Case 3 is why this predicate exists rather than a comment. An
    /// abstain is information, not an absence of information; re-asking
    /// the same question of a weaker reader manufactures a definite
    /// answer out of a deliberate refusal, which is how a system learns
    /// to be confidently wrong. [`Self::Unusable`] is the only DECLINE,
    /// and everything else is unavailability.
    #[must_use]
    pub fn is_unavailable(self) -> bool {
        !matches!(self, Self::Unusable)
    }
}

impl fmt::Display for AbstainReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated probability in `0.0..=1.0`.
///
/// Confidence is the number a destructive seam will threshold on, so an
/// unvalidated `f64` is a data-integrity hazard: `NaN` compares false
/// against every threshold (so a `NaN` confidence would sail through a
/// `conf < 0.8` collapse-to-NoOp guard), and a fabricated `1.0` from an
/// endpoint that returned no logprobs is a lie. This newtype makes both
/// unrepresentable — construction is the only way in, and it rejects
/// rather than clamps.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(f64);

impl Confidence {
    /// Build a confidence from a raw probability. Returns `None` for a
    /// non-finite value (`NaN`, `inf`) or one outside `0.0..=1.0` — the
    /// caller then reports NO confidence rather than a wrong one.
    #[must_use]
    pub fn new(probability: f64) -> Option<Self> {
        if probability.is_finite() && (0.0..=1.0).contains(&probability) {
            Some(Self(probability))
        } else {
            None
        }
    }

    /// The underlying probability.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

/// The numeric interval a [`DecisionProvider::score`] answer must fall
/// in. Validated at construction so a provider cannot be handed an
/// empty or `NaN` range.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreRange {
    min: f64,
    max: f64,
}

impl ScoreRange {
    /// The unit interval `0.0..=1.0` — the default scoring scale.
    #[must_use]
    pub fn unit() -> Self {
        Self { min: 0.0, max: 1.0 }
    }

    /// Build a range. Returns `None` unless both bounds are finite and
    /// `min < max`.
    #[must_use]
    pub fn new(min: f64, max: f64) -> Option<Self> {
        if min.is_finite() && max.is_finite() && min < max {
            Some(Self { min, max })
        } else {
            None
        }
    }

    /// Lower bound (inclusive).
    #[must_use]
    pub fn min(self) -> f64 {
        self.min
    }

    /// Upper bound (inclusive).
    #[must_use]
    pub fn max(self) -> f64 {
        self.max
    }

    /// Whether `value` lies within the range. A non-finite value is
    /// never contained.
    #[must_use]
    pub fn contains(self, value: f64) -> bool {
        value.is_finite() && value >= self.min && value <= self.max
    }
}

impl Default for ScoreRange {
    fn default() -> Self {
        Self::unit()
    }
}

/// One decision, or the accountable absence of one.
///
/// The three public shapes are the type aliases [`Choice`], [`Scored`]
/// and [`Judgement`]. Fields are private and the only constructors are
/// [`Decision::decided`] and [`Decision::abstain`], which is what makes
/// the module's invariants structural:
///
/// - `value.is_some()` **iff** `abstain_reason.is_none()`;
/// - `confidence.is_some()` implies `value.is_some()`;
/// - a stored confidence is always a finite probability in `0.0..=1.0`.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision<T> {
    value: Option<T>,
    confidence: Option<Confidence>,
    source: DecisionSource,
    abstain_reason: Option<AbstainReason>,
}

impl<T> Decision<T> {
    /// A decision WITH a value.
    ///
    /// `confidence` is the raw probability the provider reported, or
    /// `None` when the endpoint returned no logprobs and no calibration
    /// evidence. An out-of-range or non-finite probability is DEGRADED
    /// to `None` (honest absence) rather than stored — degrade, never
    /// corrupt.
    #[must_use]
    pub fn decided(value: T, confidence: Option<f64>, source: DecisionSource) -> Self {
        Self {
            value: Some(value),
            confidence: confidence.and_then(Confidence::new),
            source,
            abstain_reason: None,
        }
    }

    /// An ABSTAIN: no opinion, with the reason attached. This is a
    /// first-class answer, never a stand-in for `false`.
    #[must_use]
    pub fn abstain(reason: AbstainReason, source: DecisionSource) -> Self {
        Self {
            value: None,
            confidence: None,
            source,
            abstain_reason: Some(reason),
        }
    }

    /// The decision, or `None` when the provider abstained.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// The calibrated confidence, or `None` when no evidence for one
    /// exists. Never present on an abstain.
    #[must_use]
    pub fn confidence(&self) -> Option<f64> {
        self.confidence.map(Confidence::get)
    }

    /// Where this answer came from.
    #[must_use]
    pub fn source(&self) -> DecisionSource {
        self.source
    }

    /// Why the provider abstained, or `None` when it decided.
    #[must_use]
    pub fn abstain_reason(&self) -> Option<AbstainReason> {
        self.abstain_reason
    }

    /// Whether this is an abstain. Equivalent to `value().is_none()`.
    #[must_use]
    pub fn is_abstain(&self) -> bool {
        self.value.is_none()
    }

    /// Whether the decision is present AND its confidence is known to be
    /// at least `floor`. An absent confidence is NOT above any floor —
    /// a seam that narrows a destructive path on this predicate degrades
    /// to the conservative branch when calibration evidence is missing.
    #[must_use]
    pub fn is_confident_at_least(&self, floor: f64) -> bool {
        self.value.is_some() && self.confidence.is_some_and(|c| c.get() >= floor)
    }
}

/// A closed-set choice: the chosen option label, or an abstain.
pub type Choice = Decision<String>;

/// A continuous score inside a [`ScoreRange`], or an abstain.
pub type Scored = Decision<f64>;

/// A yes/no judgement, or an abstain. The `None` verdict is the whole
/// point: `memory_detect_contradiction` currently turns a refusal into
/// `false`.
pub type Judgement = Decision<bool>;

impl Choice {
    /// The chosen option label, or `None` on abstain.
    #[must_use]
    pub fn chosen(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Scored {
    /// The score, or `None` on abstain.
    #[must_use]
    pub fn score(&self) -> Option<f64> {
        self.value
    }

    /// Build a scored answer that is only DECIDED when `value` lies
    /// inside `range`; an out-of-range or non-finite score abstains with
    /// [`AbstainReason::Unusable`] rather than being clamped into a
    /// plausible-looking number.
    #[must_use]
    pub fn in_range(
        value: f64,
        range: ScoreRange,
        confidence: Option<f64>,
        source: DecisionSource,
    ) -> Self {
        if range.contains(value) {
            Self::decided(value, confidence, source)
        } else {
            Self::abstain(AbstainReason::Unusable, source)
        }
    }
}

impl Judgement {
    /// The verdict, or `None` on abstain.
    #[must_use]
    pub fn verdict(&self) -> Option<bool> {
        self.value
    }
}

/// A structured-decision backend.
///
/// Every method returns an answer rather than a `Result`: a transport
/// error, a timeout, an egress refusal or an unparseable body is an
/// ABSTAIN carrying the reason, because a seam must never be handed an
/// error it could accidentally coerce into a `false`. Implementations
/// are responsible for enforcing `[decision].timeout_secs` themselves
/// and for reporting [`AbstainReason::Timeout`] when it elapses.
///
/// Implementations MUST NOT fabricate a confidence: when the endpoint
/// returns no logprobs and no calibration evidence backs a number, pass
/// `None`.
#[async_trait::async_trait]
pub trait DecisionProvider: fmt::Debug + Send + Sync {
    /// The resolved provider alias (`openrouter`, `systemone`,
    /// `local-nli`, ...) for metrics labels and operator diagnostics.
    /// Never contains a credential.
    fn provider_id(&self) -> &str;

    /// Choose exactly one of `options` for `prompt`.
    ///
    /// The returned label MUST be one of `options` verbatim; a provider
    /// that cannot match its answer back to the closed set abstains with
    /// [`AbstainReason::Unusable`]. An empty `options` slice is always
    /// an abstain.
    async fn choose(&self, prompt: &str, options: &[&str]) -> Choice;

    /// Score `prompt` on the continuous `range`.
    async fn score(&self, prompt: &str, range: ScoreRange) -> Scored;

    /// Judge `prompt` yes/no.
    async fn judge(&self, prompt: &str) -> Judgement;
}

/// The absent-provider path: a decider that ALWAYS abstains.
///
/// This is what a seam consults when `[decision]` is unset, when the
/// boot chokepoint refused to build a provider under the egress posture,
/// or when `fallback = "refuse"` forbids substituting the generative
/// backend. Every answer is `None` with [`AbstainReason::NoProvider`]
/// and [`DecisionSource::Deterministic`], so a seam that treats an
/// abstain conservatively is byte-identical to v1.0.0 behaviour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NullDecider;

impl NullDecider {
    /// The `provider_id` an absent provider reports.
    pub const PROVIDER_ID: &'static str = "none";
}

#[async_trait::async_trait]
impl DecisionProvider for NullDecider {
    fn provider_id(&self) -> &str {
        Self::PROVIDER_ID
    }

    async fn choose(&self, _prompt: &str, _options: &[&str]) -> Choice {
        Choice::abstain(AbstainReason::NoProvider, DecisionSource::Deterministic)
    }

    async fn score(&self, _prompt: &str, _range: ScoreRange) -> Scored {
        Scored::abstain(AbstainReason::NoProvider, DecisionSource::Deterministic)
    }

    async fn judge(&self, _prompt: &str) -> Judgement {
        Judgement::abstain(AbstainReason::NoProvider, DecisionSource::Deterministic)
    }
}

/// The process-wide absent-provider singleton.
pub static NULL_DECIDER: NullDecider = NullDecider;

/// Resolve an optional provider to something a seam can always call.
/// `None` yields the always-abstaining [`NULL_DECIDER`], so no seam
/// needs an `if let Some(..)` arm that could drift from the abstain
/// contract.
#[must_use]
pub fn decider_or_null(provider: Option<&dyn DecisionProvider>) -> &dyn DecisionProvider {
    provider.unwrap_or(&NULL_DECIDER)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decided fixture: the PRESENCE control for every absence
    /// assertion below (a sink that can carry a value proves the
    /// abstain assertions are not vacuous).
    #[derive(Debug)]
    struct AlwaysDecides;

    #[async_trait::async_trait]
    impl DecisionProvider for AlwaysDecides {
        fn provider_id(&self) -> &str {
            "always-decides"
        }
        async fn choose(&self, _prompt: &str, options: &[&str]) -> Choice {
            Choice::decided(
                options[0].to_string(),
                Some(0.9),
                DecisionSource::DecisionModel,
            )
        }
        async fn score(&self, _prompt: &str, range: ScoreRange) -> Scored {
            Scored::in_range(range.min(), range, Some(0.5), DecisionSource::DecisionModel)
        }
        async fn judge(&self, _prompt: &str) -> Judgement {
            Judgement::decided(true, Some(0.75), DecisionSource::DecisionModel)
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime builds")
            .block_on(f)
    }

    // ---- PIN (b): absent provider => abstain, presence + absence on
    // the same sink. -------------------------------------------------
    #[test]
    fn null_decider_abstains_on_every_method_and_the_control_decides() {
        let null = NullDecider;
        let control = AlwaysDecides;
        let options = ["fact", "preference"];

        // ABSENCE half.
        let c = block_on(null.choose("p", &options));
        assert!(c.is_abstain(), "absent provider must abstain, got {c:?}");
        assert_eq!(c.chosen(), None);
        assert_eq!(c.confidence(), None, "an abstain carries no confidence");
        assert_eq!(c.abstain_reason(), Some(AbstainReason::NoProvider));
        assert_eq!(c.source(), DecisionSource::Deterministic);

        let j = block_on(null.judge("p"));
        assert_eq!(j.verdict(), None, "an abstain is NOT a default false");
        assert_ne!(j.verdict(), Some(false));
        assert_eq!(j.abstain_reason(), Some(AbstainReason::NoProvider));

        let s = block_on(null.score("p", ScoreRange::unit()));
        assert_eq!(s.score(), None);
        assert_eq!(s.abstain_reason(), Some(AbstainReason::NoProvider));

        // PRESENCE half — the same sinks carry a real decision.
        let c = block_on(control.choose("p", &options));
        assert_eq!(c.chosen(), Some("fact"));
        assert_eq!(c.confidence(), Some(0.9));
        assert_eq!(c.abstain_reason(), None);
        assert_eq!(c.source(), DecisionSource::DecisionModel);
        assert_eq!(block_on(control.judge("p")).verdict(), Some(true));
        assert_eq!(
            block_on(control.score("p", ScoreRange::unit())).score(),
            Some(0.0)
        );
    }

    #[test]
    fn decider_or_null_falls_back_to_the_abstaining_provider() {
        let control = AlwaysDecides;
        assert_eq!(
            decider_or_null(None).provider_id(),
            NullDecider::PROVIDER_ID
        );
        assert_eq!(
            decider_or_null(Some(&control)).provider_id(),
            "always-decides"
        );
        assert!(block_on(decider_or_null(None).judge("p")).is_abstain());
    }

    // ---- confidence is evidence-gated, never fabricated -------------
    #[test]
    fn confidence_rejects_nan_infinity_and_out_of_range() {
        assert_eq!(Confidence::new(f64::NAN), None);
        assert_eq!(Confidence::new(f64::INFINITY), None);
        assert_eq!(Confidence::new(-0.01), None);
        assert_eq!(Confidence::new(1.01), None);
        assert!(Confidence::new(0.0).is_some());
        assert!(Confidence::new(1.0).is_some());
    }

    #[test]
    fn an_unusable_confidence_degrades_to_absent_never_to_a_number() {
        let d = Judgement::decided(true, Some(f64::NAN), DecisionSource::DecisionModel);
        assert_eq!(d.verdict(), Some(true));
        assert_eq!(d.confidence(), None, "NaN must not become a confidence");
        assert!(
            !d.is_confident_at_least(0.0),
            "NaN must not clear any floor"
        );

        let d = Judgement::decided(true, Some(7.0), DecisionSource::DecisionModel);
        assert_eq!(d.confidence(), None);

        // Presence control on the same sink.
        let d = Judgement::decided(true, Some(0.8), DecisionSource::DecisionModel);
        assert_eq!(d.confidence(), Some(0.8));
        assert!(d.is_confident_at_least(0.8));
        assert!(!d.is_confident_at_least(0.81));
    }

    #[test]
    fn an_abstain_never_clears_a_confidence_floor() {
        let a = Judgement::abstain(AbstainReason::Timeout, DecisionSource::DecisionModel);
        assert!(!a.is_confident_at_least(0.0));
        assert_eq!(a.confidence(), None);
    }

    #[test]
    fn score_outside_the_range_abstains_rather_than_clamping() {
        let range = ScoreRange::new(0.0, 1.0).expect("valid range");
        let out = Scored::in_range(1.5, range, Some(0.9), DecisionSource::DecisionModel);
        assert_eq!(out.score(), None);
        assert_eq!(out.abstain_reason(), Some(AbstainReason::Unusable));
        let inside = Scored::in_range(0.5, range, Some(0.9), DecisionSource::DecisionModel);
        assert_eq!(inside.score(), Some(0.5));
    }

    #[test]
    fn score_range_rejects_empty_and_non_finite_bounds() {
        assert_eq!(ScoreRange::new(1.0, 0.0), None);
        assert_eq!(ScoreRange::new(0.0, 0.0), None);
        assert_eq!(ScoreRange::new(f64::NAN, 1.0), None);
        assert_eq!(ScoreRange::default(), ScoreRange::unit());
        assert!(!ScoreRange::unit().contains(f64::NAN));
    }

    #[test]
    fn source_and_reason_tokens_are_stable() {
        assert_eq!(DecisionSource::DecisionModel.as_str(), "decision_model");
        assert_eq!(
            DecisionSource::GenerativeFallback.as_str(),
            "generative_fallback"
        );
        assert_eq!(DecisionSource::Deterministic.as_str(), "deterministic");
        assert_eq!(AbstainReason::NoProvider.as_str(), "no_provider");
        assert_eq!(AbstainReason::Timeout.as_str(), "timeout");
        assert_eq!(AbstainReason::EgressRefused.as_str(), "egress_refused");
        assert_eq!(AbstainReason::Unusable.as_str(), "unusable");
        assert_eq!(AbstainReason::Unsupported.as_str(), "unsupported");
    }

    #[test]
    fn the_trait_is_object_safe_so_the_boot_chokepoint_can_hand_out_one_handle() {
        let provider: std::sync::Arc<dyn DecisionProvider> = std::sync::Arc::new(NullDecider);
        assert_eq!(provider.provider_id(), NullDecider::PROVIDER_ID);
        assert!(block_on(provider.judge("p")).is_abstain());
    }
}
