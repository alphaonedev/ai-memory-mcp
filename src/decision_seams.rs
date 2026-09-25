// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W2 — the first two DECISION SEAMS, and the only place a gated
//! decider is attached to a surface.
//!
//! ## What a seam is
//!
//! A seam is a call position where the substrate already asks a model a
//! question whose answer is a DECISION over a closed vocabulary. W1a-W1c
//! built the typed answer ([`crate::decision`]), the boot chokepoint
//! ([`crate::decision_boot`]) and the clients
//! ([`crate::decision_clients`]); until this unit nothing consumed any of
//! them. This module is what consumes them, for the two lowest-risk
//! positions:
//!
//! * `classify_kind` — a 16-way closed choice that a prompt naming
//!   **8** of the 16 [`MemoryKind`] variants had been answering;
//! * `detect_contradiction` — a yes/no judgement that
//!   `answer.starts_with("yes")` had been answering, so a refusal
//!   ("I'm sorry, I can't help with that"), a preamble ("Yes, because
//!   …" on a model that then argues itself to no) and a hedge all
//!   became a VERDICT.
//!
//! ## THE THREE CASES (Conductor ruling, 2026-09-19 — binding)
//!
//! `[decision].fallback` governs **unavailability, not abstention.**
//! That distinction is the whole unit, so it is an executable invariant
//! ([`AbstainReason::is_unavailable`]) and not a comment:
//!
//! **Case 1 — `[decision]` UNSET.** The v1.0.0 path runs entirely, text
//! parse and all. No handle is attached, the seam returns
//! [`SeamOutcome::RunLegacy`], nothing else in this module executes and
//! no metric series is created. That is what byte-identical means, and
//! it is correct: the feature is off.
//!
//! **Case 2 — `[decision]` SET, provider UNAVAILABLE.** No provider
//! constructed, egress refused, timeout, transport error, non-2xx
//! status. The provider never answered, so falling back to the
//! instrument used before is legitimate, and this is exactly what
//! `fallback` governs:
//!
//! | `fallback` | case 2 ⇒ the seam |
//! |---|---|
//! | `abstain` (default) | conservative NON-ACTION branch |
//! | `generative` | [`SeamOutcome::RunLegacy`] — the old path |
//! | `refuse` | `Err`, naming the abstain reason |
//!
//! **Case 3 — `[decision]` SET, provider ABSTAINED.** The provider DID
//! answer, and its answer was "I decline" — a refusal, a preamble, a
//! hedge, a label outside the closed vocabulary. **That is terminal.**
//! The seam takes its conservative branch, the question is never
//! re-asked, and `fallback` does not apply because there is nothing to
//! fall back FROM.
//!
//! Case 3 is the reason this unit exists. Re-asking the same model the
//! same question and then reading the reply with `starts_with("yes")`
//! would reintroduce the exact defect W2 removes — and do something
//! worse than the original, because it would manufacture a definite
//! answer out of a deliberate refusal. An abstain is information, not an
//! absence of information. Overriding it with a weaker reader is how a
//! system learns to be confidently wrong. The same reasoning bars the
//! provider-level chain from re-asking
//! ([`crate::decision_clients::FallbackChain::may_fall_back`]), so a
//! decline costs exactly ONE model call and never two.
//!
//! The conservative branch is a non-action, never a fabricated verdict:
//! `classify_kind` keeps the caller's existing kind (`Ok(None)` — the
//! abstain this API has always had), and `detect_contradiction` asserts
//! NO contradiction edge (`Ok(false)` — the same non-action its F-L1
//! subject-overlap pre-check has always taken). Neither deletes anything,
//! neither widens a destructive path, and the two are distinguishable on
//! the wire because [`crate::metrics::record_decision`] labels the
//! outcome (`abstained` / `timeout` / `egress_refused` / `fallback` /
//! `decided`) rather than leaving "no opinion" indistinguishable from
//! "decided no".
//!
//! An EGRESS REFUSAL is case 2 at the SEAM (the `[llm]` lane passed its
//! own #1963 boot gate, and under `deny` there is no `[llm]` client to
//! reach at all) and terminal INSIDE the decision plane (the chain never
//! answers a refused destination from a second endpoint). Those are two
//! different questions about two different clients, and the answers
//! differ for that reason.
//!
//! ## Attachment — the chokepoint monopoly in code
//!
//! [`attach_decider`] is the ONLY function that turns a
//! [`crate::decision_boot::DecisionProviderHandle`] into something a
//! seam can reach, and it obtains that handle from the boot chokepoint
//! and nowhere else. It runs the chokepoint EXACTLY once per surface —
//! whether or not that surface has an `[llm]` client — because the
//! `/capabilities` snapshot and the signed egress-refusal row are boot
//! effects of the DECISION lane and must not become conditional on the
//! chat lane. The three surfaces that can reach a seam call it:
//! the HTTP daemon (`daemon_runtime::bootstrap_serve`), the MCP stdio
//! surface and its between-request reload
//! (`reload::resolve_and_build_mcp_llm`), and the CLI one-shot curator
//! (`cli::curator::build_curator_llm`).
//!
//! **`cli/commands/expand.rs` and `cli/commands/atomise.rs` are
//! deliberately NOT routed.** Their clients reach `expand_query` and
//! `Curator::decompose`, neither of which is a seam — so routing them
//! would not wire anything: it would require BUILDING a seam at those
//! call positions first, which is scope this unit does not have. As it
//! stands, routing them would construct a decision provider nothing
//! consumes and (under `deny`) write a signed refusal row on every CLI
//! invocation.
//!
//! That exclusion is stated here, and asserted by
//! `tests/decision_unset_byte_identical_3806.rs`, which pins the routed
//! set in BOTH directions. An absence that is asserted is a decision; an
//! absence that is silent is a hole, and the next person auditing seam
//! coverage would find two call sites with no decider and no reason.
//!
//! ## The reference cycle, made unrepresentable
//!
//! `fallback = "generative"` needs a decider holding an
//! `Arc<OllamaClient>`. If that were the same client the handle is
//! attached to, the graph would be
//! `client -> seams -> handle -> FallbackChain -> decider -> client`:
//! a leak. [`attach_decider`] hands the fallback a RETARGETED clone
//! ([`OllamaClient::with_model`] — shared reqwest pool, fresh breaker,
//! no second `/api/tags` probe), and `with_model` deliberately does not
//! copy the decider field. The cycle is therefore unrepresentable rather
//! than avoided by call order.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use crate::config::AppConfig;
use crate::decision::{AbstainReason, Decision, DecisionOutcome, DecisionSource};
use crate::decision_boot::{DecisionBootOutcome, DecisionProviderHandle, build_decision_provider};
use crate::decision_clients::calibration::CalibrationSeam;
use crate::decision_config::{DecisionFallback, fallback_phrase};
use crate::llm::OllamaClient;
use crate::models::MemoryKind;

/// Slack added to `[decision].timeout_secs` when a SYNC seam crosses the
/// sync->async bridge. The provider enforces the operator's budget
/// itself; this is only the bridge's own ceiling, so a provider that
/// honours its deadline always reports [`AbstainReason::Timeout`]
/// rather than being cut off by the bridge with a less specific error.
const SEAM_BRIDGE_SLACK: Duration = Duration::from_secs(1);

/// #3806 vote R9 — consecutive UNAVAILABILITY abstains (timeout,
/// transport failure, non-2xx) after which a surface's seams stop
/// dialling the decision endpoint for [`BREAKER_COOLDOWN`]. Mirrors the
/// generative client's own breaker (3 / 30 s).
pub const BREAKER_THRESHOLD: u32 = 3;

/// #3806 vote R9 — how long an open breaker short-circuits before one
/// probe call is allowed through.
pub const BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

/// What a seam should do with the decider's answer.
///
/// Three arms, not two, because "there is no decider" and "the decider
/// had no opinion" are different facts with different correct
/// behaviours — collapsing them is how `[decision]` unset would stop
/// being byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeamOutcome<T> {
    /// A verdict. Use it; do not consult any text parse.
    Decided(T),
    /// No decider is attached (`[decision]` unset, or the chokepoint
    /// refused to build one). Run the v1.0.0 body UNCHANGED.
    RunLegacy,
    /// A decider is attached and produced no verdict. Take the seam's
    /// conservative non-action branch.
    Conservative,
}

/// The gated decision seams a surface carries.
///
/// A thin, deliberately opaque wrapper: it exists so `src/llm.rs` can
/// hold the attachment without naming
/// [`crate::decision_boot::DecisionProviderHandle`], which keeps the
/// handle type's reviewed file list to the chokepoint that defines it
/// and the module that consumes it.
/// What a surface's seams actually have.
///
/// #3806 R2 — two states, not one, and the second is the whole point.
/// `[decision]` CONFIGURED with no provider built (the egress gate
/// refused the endpoint, or the section did not resolve) used to be
/// indistinguishable from `[decision]` UNSET: `attach_decider` returned
/// the client untouched, every seam answered `RunLegacy`, and the
/// v1.0.0 generative path ran. That made a PERMANENT refusal quieter
/// and more permissive than a two-second blip — the strongest posture
/// producing the most permissive outcome, unsurfaced — and it bypassed
/// `fallback` entirely, including `refuse`.
#[derive(Debug)]
enum SeamState {
    /// A provider the boot chokepoint constructed and gated.
    Gated(Box<DecisionProviderHandle>),
    /// `[decision]` is configured and NO provider exists. Permanent,
    /// and CASE 2: `fallback` governs it exactly as it governs a
    /// transient outage, because in both the provider never answered.
    NoProvider { fallback: DecisionFallback },
}

#[derive(Debug)]
pub struct DecisionSeams {
    state: SeamState,
    /// #3806 vote R9 — per-surface circuit breaker over the decision
    /// endpoint. See [`SeamBreaker`].
    breaker: SeamBreaker,
}

/// #3806 vote R9 — a circuit breaker over UNAVAILABILITY.
///
/// `classify_kind` runs inside the curator's batch loop; with the
/// endpoint down every row paid a full attempt (up to
/// `[decision].timeout_secs`). After [`BREAKER_THRESHOLD`] consecutive
/// timeouts / transport failures / non-2xx answers the breaker opens and
/// the seam short-circuits to the SAME `unavailable` abstain the call
/// would have produced, for [`BREAKER_COOLDOWN`]; then one probe is let
/// through. It can only shorten an outage's cost: `fallback` still
/// governs the short-circuited abstain exactly as it governs a real one
/// (case 2). A DECLINE is an answer — it resets the count, as a decision
/// does — and an egress refusal or a capability mismatch costs no socket
/// and leaves it untouched.
///
/// A `std::sync::Mutex` held only for the few instructions of a read or
/// an update, never across an `.await` (CONCURRENCY-20); a poisoned lock
/// is recovered, because the state is two plain fields with no invariant
/// a panic could half-write (CONCURRENCY-18).
#[derive(Debug, Default)]
struct SeamBreaker {
    state: std::sync::Mutex<BreakerState>,
}

#[derive(Debug, Default)]
struct BreakerState {
    consecutive_unavailable: u32,
    opened_at: Option<Instant>,
}

impl SeamBreaker {
    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a call made at `now` must be short-circuited.
    fn is_open(&self, now: Instant) -> bool {
        let state = self.lock();
        state.consecutive_unavailable >= BREAKER_THRESHOLD
            && state
                .opened_at
                .is_some_and(|opened| now.saturating_duration_since(opened) < BREAKER_COOLDOWN)
    }

    /// Fold one real call's result into the breaker.
    fn observe(&self, reason: Option<AbstainReason>, now: Instant) {
        let mut state = self.lock();
        match reason {
            // An answer — a decision or a decline — closes the breaker.
            None | Some(AbstainReason::Unusable) => {
                state.consecutive_unavailable = 0;
                state.opened_at = None;
            }
            Some(AbstainReason::Timeout | AbstainReason::Unavailable) => {
                state.consecutive_unavailable = state.consecutive_unavailable.saturating_add(1);
                if state.consecutive_unavailable >= BREAKER_THRESHOLD {
                    if state.opened_at.is_none() {
                        tracing::warn!(
                            threshold = BREAKER_THRESHOLD,
                            cooldown_secs = BREAKER_COOLDOWN.as_secs(),
                            "[decision] endpoint unavailable on consecutive calls; seams \
                             short-circuit to `unavailable` (their `fallback` branch) until \
                             the cooldown elapses (#3806 R9)"
                        );
                    }
                    state.opened_at = Some(now);
                }
            }
            // No socket was spent (egress refusal, capability mismatch,
            // no provider): nothing to learn about the endpoint.
            Some(_) => {}
        }
    }
}

impl DecisionSeams {
    /// The gated handle, or `None` when `[decision]` is configured and
    /// no provider was ever built.
    fn gated(&self) -> Option<&DecisionProviderHandle> {
        match &self.state {
            SeamState::Gated(handle) => Some(handle),
            SeamState::NoProvider { .. } => None,
        }
    }

    /// The operator's declared `fallback`, in either state.
    fn fallback(&self) -> DecisionFallback {
        match &self.state {
            SeamState::Gated(handle) => handle.fallback(),
            SeamState::NoProvider { fallback } => *fallback,
        }
    }

    /// The CASE 2 outcome when `[decision]` is configured and no
    /// provider was ever built.
    ///
    /// Recorded on the operator surface like any other abstain, so a
    /// permanent boot refusal is VISIBLE rather than silent — it was
    /// the absence of this record that let the condition hide.
    ///
    /// # Errors
    /// Under `fallback = "refuse"`, which is the posture this repairs.
    fn no_provider<T>(&self, seam: CalibrationSeam) -> Result<SeamOutcome<T>> {
        record(
            seam,
            DecisionOutcome::Abstained(AbstainReason::NoProvider),
            Instant::now(),
        );
        self.on_abstain(AbstainReason::NoProvider)
    }

    /// #3806 R9 — the open-breaker outcome: exactly the `unavailable`
    /// abstain a real call to a dead endpoint produces, recorded the same
    /// way, with `fallback` governing it the same way. No socket.
    ///
    /// # Errors
    /// Under `fallback = "refuse"`, as for any unavailability.
    fn short_circuit<T>(&self, seam: CalibrationSeam, started: Instant) -> Result<SeamOutcome<T>> {
        record(
            seam,
            DecisionOutcome::Abstained(AbstainReason::Unavailable),
            started,
        );
        self.on_abstain(AbstainReason::Unavailable)
    }

    /// The whole-call ceiling for a seam that must cross the
    /// sync->async bridge.
    fn bridge_budget(&self) -> Duration {
        let timeout = self
            .gated()
            .map_or(SEAM_BRIDGE_SLACK, DecisionProviderHandle::timeout);
        timeout.saturating_add(SEAM_BRIDGE_SLACK)
    }

    /// What this seam does when the decider produced no verdict — the
    /// module header's cases 2 and 3, as executable logic.
    ///
    /// # Errors
    /// Under `fallback = "refuse"` AND case 2 only: the operator asked
    /// for the operation to fail when the decision instrument is
    /// unavailable. A DECLINE is never an error, because the instrument
    /// worked and gave its answer.
    fn on_abstain<T>(&self, reason: AbstainReason) -> Result<SeamOutcome<T>> {
        // CASE 3 — the provider ANSWERED and declined. Terminal, under
        // EVERY posture: `fallback` governs unavailability, not
        // abstention, and there is nothing here to fall back from.
        if !reason.is_unavailable() {
            return Ok(SeamOutcome::Conservative);
        }
        // CASE 2 — the provider never answered, whether because a call
        // failed or because one was never built. `fallback` governs.
        match self.fallback() {
            DecisionFallback::Refuse => Err(anyhow!(
                "the decision provider was unavailable ({reason}) and this deployment \
                 refuses to proceed without a decision: {} (#3806)",
                fallback_phrase(DecisionFallback::Refuse)
            )),
            // The old instrument, exactly as v1.0.0 ran it.
            DecisionFallback::Generative => Ok(SeamOutcome::RunLegacy),
            DecisionFallback::Abstain => Ok(SeamOutcome::Conservative),
        }
    }
}

/// The outcome for one answer the seam USED. Total over [`Decision`],
/// so no answer can go unlabelled.
fn outcome_of<T>(decision: &Decision<T>) -> DecisionOutcome {
    match decision.abstain_reason() {
        None => match decision.source() {
            DecisionSource::GenerativeFallback => DecisionOutcome::Fallback,
            DecisionSource::DecisionModel | DecisionSource::Deterministic => {
                DecisionOutcome::Decided
            }
        },
        Some(reason) => DecisionOutcome::Abstained(reason),
    }
}

/// Record one seam call.
///
/// `outcome` is passed rather than derived, so the label is always the
/// one the seam ACTED on: a decided answer the seam could not use
/// degrades to an abstain, and the metric must degrade with it. A
/// series that claims a decision the seam did not take is worse than no
/// series at all.
///
/// Both series are created lazily by the first observation, so an
/// unconfigured deployment's `/metrics` gains nothing — which is half of
/// "unset is byte-identical".
fn record(seam: CalibrationSeam, outcome: DecisionOutcome, started: Instant) {
    crate::metrics::record_decision(seam, outcome, started.elapsed().as_secs_f64());
}

/// The closed vocabulary `classify_kind` chooses over: EVERY
/// [`MemoryKind`] variant, derived from [`MemoryKind::all`] so a
/// variant added later cannot silently fall out of the option set the
/// way the 8-of-16 prompt did.
fn kind_options() -> Vec<&'static str> {
    MemoryKind::all().iter().map(MemoryKind::as_str).collect()
}

/// #3806 W2 seam 1 — `classify_kind` as a closed 16-way CHOICE.
///
/// Returns [`SeamOutcome::RunLegacy`] when no decider is attached, so
/// `[decision]` unset runs the v1.0.0 generative classifier unchanged.
///
/// # Errors
/// Only under `fallback = "refuse"`, and only on an abstain.
pub(crate) fn classify_kind(
    client: &OllamaClient,
    title: &str,
    content: &str,
) -> Result<SeamOutcome<MemoryKind>> {
    let Some(seams) = client.decider() else {
        return Ok(SeamOutcome::RunLegacy);
    };
    let Some(handle) = seams.gated() else {
        return seams.no_provider(CalibrationSeam::ClassifyKind);
    };
    let started = Instant::now();
    if seams.breaker.is_open(started) {
        return seams.short_circuit(CalibrationSeam::ClassifyKind, started);
    }
    let options = kind_options();
    let prompt = crate::llm::classify_kind_prompt(title, content);
    // The provider enforces `[decision].timeout_secs` itself; the bridge
    // budget is the outer ceiling for the sync call position. A bridge
    // failure is an ABSTAIN, never a guess.
    let decision = crate::llm::block_on_local_bounded(seams.bridge_budget(), || {
        handle.provider().choose(&prompt, &options)
    })
    .unwrap_or_else(|_| Decision::abstain(AbstainReason::Timeout, DecisionSource::Deterministic));
    seams
        .breaker
        .observe(decision.abstain_reason(), Instant::now());

    // The client returns the VOCABULARY's spelling, so this parse cannot
    // fail for a decided answer; if it somehow did, an unmappable label
    // DEGRADES to an abstain rather than becoming a wrong kind — and is
    // RECORDED as one, because a metric that claims a decision the seam
    // did not take is exactly the confusion these series exist to end.
    if let Some(kind) = decision.chosen().and_then(MemoryKind::from_str) {
        record(
            CalibrationSeam::ClassifyKind,
            outcome_of(&decision),
            started,
        );
        return Ok(SeamOutcome::Decided(kind));
    }
    let reason = decision.abstain_reason().unwrap_or(AbstainReason::Unusable);
    record(
        CalibrationSeam::ClassifyKind,
        DecisionOutcome::Abstained(reason),
        started,
    );
    seams.on_abstain(reason)
}

/// #3806 W2 seam 2 — `detect_contradiction` as a yes/no JUDGEMENT.
///
/// This is the call position `answer.starts_with("yes")` used to answer.
/// With a decider attached the verdict comes from a strictly parsed,
/// closed-vocabulary answer and a refusal / preamble / hedge is an
/// ABSTAIN; the loose parse is reachable only when `[decision]` is
/// unset, where it is the v1.0.0 behaviour this unit must not change.
///
/// # Errors
/// Only under `fallback = "refuse"`, and only on an abstain.
pub(crate) async fn judge_contradiction(
    client: &OllamaClient,
    prompt: &str,
) -> Result<SeamOutcome<bool>> {
    let Some(seams) = client.decider() else {
        return Ok(SeamOutcome::RunLegacy);
    };
    let Some(handle) = seams.gated() else {
        return seams.no_provider(CalibrationSeam::DetectContradiction);
    };
    let started = Instant::now();
    if seams.breaker.is_open(started) {
        return seams.short_circuit(CalibrationSeam::DetectContradiction, started);
    }
    let decision = handle.provider().judge(prompt).await;
    seams
        .breaker
        .observe(decision.abstain_reason(), Instant::now());

    if let Some(verdict) = decision.verdict() {
        record(
            CalibrationSeam::DetectContradiction,
            outcome_of(&decision),
            started,
        );
        return Ok(SeamOutcome::Decided(verdict));
    }
    let reason = decision.abstain_reason().unwrap_or(AbstainReason::Unusable);
    record(
        CalibrationSeam::DetectContradiction,
        DecisionOutcome::Abstained(reason),
        started,
    );
    seams.on_abstain(reason)
}

// ---------------------------------------------------------------------------
// #3806 W4 — the consolidation MERGE JUDGE: a NARROWING third gate.
// ---------------------------------------------------------------------------

/// The confidence a decided **yes** must carry before the merge judge
/// PERMITS a consolidation (a calibrated probability in `0.0..=1.0`, as
/// [`crate::decision::Confidence`] defines it).
///
/// A destructive path deletes the sources it merges, so the vote's
/// through-line applies with full force here: *a calibrated number or
/// nothing*. A yes that carries no confidence at all (the endpoint
/// returned no `logprobs`) is treated as an ABSTAIN and blocks; a yes
/// below this floor blocks. Only `verdict == Some(true)` with a present
/// confidence at or above the floor permits — and permitting only ever
/// admits a cluster the Jaccard AND cosine gates had already admitted.
///
/// **Preregistered default, pending calibration evidence.** W5's harness
/// preregisters an ECE ceiling (0.10) and a coverage floor (0.50) for the
/// `consolidation_merge` seam but no permit floor; this value is the
/// conservative starting point and, like every threshold in that
/// harness, it tightens and never loosens. Stated in
/// `docs/CONFIG_SCHEMA.md` (`[decision]`).
pub const CONSOLIDATION_MERGE_CONFIDENCE_FLOOR: f64 = 0.80;

/// Per-member cap on the content the merge judge is shown. The judge
/// answers a yes/no over a closed vocabulary; it does not need the whole
/// row, and a bounded prompt keeps the per-cluster cost predictable.
const MERGE_JUDGE_MEMBER_CHARS: usize = 2_000;

/// Why the merge judge BLOCKED a cluster. Total, so a report can label
/// every block; the wire tokens are stable. (`PartialEq` only: the
/// low-confidence arm carries the reported `f64`.)
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum MergeBlockReason {
    /// The provider never answered (no provider, egress refused,
    /// timeout, transport). Case 2 — and on THIS seam `fallback` does not
    /// re-open the path: there is no legacy judge to fall back to.
    Unavailable(AbstainReason),
    /// The provider answered and declined (refusal, prose, hedge). Case
    /// 3 — terminal.
    Abstained(AbstainReason),
    /// The provider decided **no**.
    DecidedNo,
    /// The provider decided **yes** but carried no confidence, or one
    /// below [`CONSOLIDATION_MERGE_CONFIDENCE_FLOOR`]. Treated as an
    /// abstain: on a delete-the-sources path an uncalibrated yes is not
    /// a yes.
    LowConfidence {
        /// The confidence that was reported, if any.
        confidence: Option<f64>,
    },
    /// The seam's [`CalibrationSeam::confidence_floor`] is `None` — a
    /// destructive seam with no declared floor is a CONTRACT FAILURE and
    /// fails CLOSED (GOD ruling, 3806-W3W4-DESIGN-RULINGS): nothing merges,
    /// whatever the judge said.
    NoFloor,
}

impl MergeBlockReason {
    /// A stable token for logs and pass reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable(_) => "unavailable",
            Self::Abstained(_) => "abstained",
            Self::DecidedNo => "decided_no",
            Self::LowConfidence { .. } => "low_confidence",
            Self::NoFloor => "no_floor",
        }
    }
}

impl fmt::Display for MergeBlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) | Self::Abstained(reason) => {
                write!(f, "{} ({reason})", self.as_str())
            }
            Self::LowConfidence {
                confidence: Some(c),
            } => write!(
                f,
                "{} ({c:.3} < {CONSOLIDATION_MERGE_CONFIDENCE_FLOOR})",
                self.as_str()
            ),
            Self::LowConfidence { confidence: None } => {
                write!(f, "{} (no confidence reported)", self.as_str())
            }
            Self::DecidedNo => f.write_str(self.as_str()),
            Self::NoFloor => write!(
                f,
                "{} (a destructive seam declared no confidence floor — contract failure, fails closed)",
                self.as_str()
            ),
        }
    }
}

/// #3806 W4 — the merge judge's counters for ONE funnel run, as the
/// reports carry them. `None` on the report whenever `[decision]` is unset
/// (the judge is never consulted, so there is nothing to report and the
/// unset output stays byte-identical); `Some` the moment a judge answered
/// or was found unavailable. A DRY run carries it under `judge_preview`
/// — a preview of what the judge WOULD say, labelled by DecisionSource and
/// block reason, and NOT a claim that the hook would permit (D4).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MergeJudgeReport {
    /// Clusters the judge BLOCKED after Jaccard and cosine admitted them.
    pub blocked: usize,
    /// Clusters the judge PERMITTED (a decided yes at or above the floor).
    pub permitted: usize,
    /// WHO answered, per judge call: the [`DecisionSource`] token → count.
    pub sources: std::collections::BTreeMap<String, usize>,
    /// WHY each blocked cluster was blocked: the [`MergeBlockReason`]
    /// token → count, so an outage and a model's `no` are separable.
    pub block_reasons: std::collections::BTreeMap<String, usize>,
}

impl MergeJudgeReport {
    /// Fold one judgement into `slot`, creating the report on the FIRST
    /// judge answer. [`MergeJudgement::NoDecider`] folds NOTHING and
    /// creates nothing — that is what keeps an unset `[decision]` run's
    /// serialized report free of the key.
    pub fn note(slot: &mut Option<Self>, judgement: &MergeJudgement) {
        match judgement {
            MergeJudgement::NoDecider => {}
            MergeJudgement::Permit { source, .. } => {
                let report = slot.get_or_insert_with(Self::default);
                report.permitted += 1;
                *report
                    .sources
                    .entry(source.as_str().to_string())
                    .or_default() += 1;
            }
            MergeJudgement::Block { reason, source } => {
                let report = slot.get_or_insert_with(Self::default);
                report.blocked += 1;
                *report
                    .sources
                    .entry(source.as_str().to_string())
                    .or_default() += 1;
                *report
                    .block_reasons
                    .entry(reason.as_str().to_string())
                    .or_default() += 1;
            }
        }
    }
}

/// The merge judge's answer for ONE cluster, as the consolidation funnels
/// consume it.
///
/// Three arms for the same reason [`SeamOutcome`] has three: "there is no
/// judge" and "the judge said no" are different facts. `NoDecider` is
/// the `[decision]`-unset arm and means the funnel runs exactly its
/// v1.0.0 body; the other two carry the [`DecisionSource`] so a dry-run
/// report can say WHO decided, not just what.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum MergeJudgement {
    /// No decider is attached: the merge proceeds as v1.0.0 did
    /// (byte-identical). This is NOT a permit — it is the absence of a
    /// judge, and it is only reachable when `[decision]` is unset or the
    /// boot chokepoint refused to build a provider.
    NoDecider,
    /// A decided yes at or above the floor. The merge may proceed —
    /// which only ever confirms what the two fixed gates already
    /// decided.
    Permit {
        /// The calibrated confidence that cleared the floor.
        confidence: f64,
        /// Who decided.
        source: DecisionSource,
    },
    /// The merge does NOT proceed. Sources untouched.
    Block {
        /// Why.
        reason: MergeBlockReason,
        /// Who (for an abstain, the source the provider reported).
        source: DecisionSource,
    },
}

impl MergeJudgement {
    /// Whether the funnel may consolidate this cluster.
    #[must_use]
    pub fn permits(&self) -> bool {
        matches!(self, Self::NoDecider | Self::Permit { .. })
    }

    /// The source label for a report, if a judge answered at all.
    #[must_use]
    pub fn source(&self) -> Option<DecisionSource> {
        match self {
            Self::NoDecider => None,
            Self::Permit { source, .. } | Self::Block { source, .. } => Some(*source),
        }
    }
}

/// The prompt the merge judge answers. A closed yes/no question over the
/// cluster's members, each capped at [`MERGE_JUDGE_MEMBER_CHARS`]
/// characters on a char boundary.
///
/// Public within the crate so the `OllamaClient` trait impl and the
/// tests build the identical prompt.
#[must_use]
pub(crate) fn merge_judge_prompt(members: &[(String, String)]) -> String {
    let mut prompt = String::from(
        "You are the merge judge for a memory store. The memories below were selected \
         as near-duplicates by lexical and embedding similarity. Answer yes ONLY if \
         they assert the SAME fact, so that replacing all of them with one summary \
         loses no distinct claim, entity, number, date or decision. Answer no if any \
         memory carries information the others do not.\n\n",
    );
    for (idx, (title, content)) in members.iter().enumerate() {
        let capped: String = content.chars().take(MERGE_JUDGE_MEMBER_CHARS).collect();
        prompt.push_str(&format!("Memory {}: {title}\n{capped}\n\n", idx + 1));
    }
    prompt.push_str("Do these memories assert the same fact? (yes/no)");
    prompt
}

impl DecisionSeams {
    /// A DESTRUCTIVE seam's case-2/case-3 mapping. It differs from
    /// [`Self::on_abstain`] on purpose: that helper's `RunLegacy` arm
    /// means "run the v1.0.0 instrument", and on this seam the v1.0.0
    /// instrument is *no judge at all* — falling back to it would WIDEN
    /// the destructive path relative to the configured judge. So:
    ///
    /// * case 3 (the provider declined) — block, terminal;
    /// * case 2 (the provider never answered) — block under `abstain`
    ///   AND `generative`; `Err` under `refuse`, because the operator
    ///   asked for the operation to fail loudly rather than proceed
    ///   without a decision. Either way the sources are untouched.
    ///
    /// # Errors
    /// Under `fallback = "refuse"` AND case 2 only.
    fn on_destructive_abstain(&self, reason: AbstainReason) -> Result<MergeBlockReason> {
        if !reason.is_unavailable() {
            return Ok(MergeBlockReason::Abstained(reason));
        }
        match self.fallback() {
            DecisionFallback::Refuse => Err(anyhow!(
                "the decision provider was unavailable ({reason}) and this deployment \
                 refuses to consolidate without a merge judgement: {} (#3806)",
                fallback_phrase(DecisionFallback::Refuse)
            )),
            DecisionFallback::Generative | DecisionFallback::Abstain => {
                Ok(MergeBlockReason::Unavailable(reason))
            }
        }
    }
}

/// Map one judge answer onto a DESTRUCTIVE seam's verdict — the shared
/// contract every seam that deletes or merges data consults (W4's
/// consolidation merge today; W3's synthesis delete calls the same
/// function), recording the metric for what the seam ACTED on.
///
/// Seam-agnostic on purpose (f2r, W4 D4 pre-review): `seam` and `floor`
/// are parameters, so `NoFloor` fail-closed, the confidence gate through
/// `is_confident_at_least`, and the case-2/case-3 mapping are INHERITED
/// by the next destructive seam rather than re-implemented — GOD's ruling
/// ("a destructive seam whose floor is `None` fails closed") holds
/// structurally, not per seam.
///
/// A decided yes the seam cannot use (no confidence, or below the floor)
/// is recorded as an abstain with reason `unusable`, per the rule the
/// other seams follow: a series that claims a decision the seam did not
/// take is worse than no series at all.
///
/// # Errors
/// Under `fallback = "refuse"` AND case 2 only.
pub(crate) fn destructive_judgement_of(
    seams: &DecisionSeams,
    seam: CalibrationSeam,
    decision: &crate::decision::Judgement,
    floor: Option<f64>,
    started: Instant,
) -> Result<MergeJudgement> {
    // CONTRACT FAILURE — a destructive seam with no declared floor fails
    // CLOSED, before any verdict is read: a `yes` at 0.99 cannot merge
    // when nobody said what "confident enough" means (GOD ruling).
    let Some(floor) = floor else {
        record(
            seam,
            DecisionOutcome::Abstained(AbstainReason::Unusable),
            started,
        );
        return Ok(MergeJudgement::Block {
            reason: MergeBlockReason::NoFloor,
            source: decision.source(),
        });
    };
    // DEFENCE IN DEPTH. `judge_merge` asks the provider through
    // `judge_primary`, so through the shipped chain a generative stand-in
    // can never answer here; this arm exists for a provider whose
    // `judge_primary` forwards to the WRONG method (a wrapper writing
    // `inner.judge(..)` — the one residual the compiler cannot catch).
    // Should it fire: a stand-in never permits on this seam (the v1.0.0
    // instrument was NO judge, so a generative verdict would WIDEN the
    // destructive path), it is reported as what it is (unavailable,
    // source `generative_fallback`) rather than as a low-confidence
    // verdict, and recorded as `outcome="fallback"`.
    if decision.source() == DecisionSource::GenerativeFallback {
        record(seam, outcome_of(decision), started);
        return Ok(MergeJudgement::Block {
            reason: MergeBlockReason::Unavailable(AbstainReason::Unavailable),
            source: DecisionSource::GenerativeFallback,
        });
    }
    match decision.verdict() {
        Some(true) if decision.is_confident_at_least(floor) => {
            record(seam, outcome_of(decision), started);
            Ok(MergeJudgement::Permit {
                // `is_confident_at_least` is true only when a confidence
                // is present, so this cannot be reached with `None`.
                confidence: decision.confidence().unwrap_or(0.0),
                source: decision.source(),
            })
        }
        Some(true) => {
            let reason = AbstainReason::Unusable;
            record(seam, DecisionOutcome::Abstained(reason), started);
            Ok(MergeJudgement::Block {
                reason: MergeBlockReason::LowConfidence {
                    confidence: decision.confidence(),
                },
                source: decision.source(),
            })
        }
        Some(false) => {
            record(seam, outcome_of(decision), started);
            Ok(MergeJudgement::Block {
                reason: MergeBlockReason::DecidedNo,
                source: decision.source(),
            })
        }
        None => {
            let reason = decision.abstain_reason().unwrap_or(AbstainReason::Unusable);
            record(seam, DecisionOutcome::Abstained(reason), started);
            let reason = seams.on_destructive_abstain(reason)?;
            Ok(MergeJudgement::Block {
                reason,
                source: decision.source(),
            })
        }
    }
}

/// #3806 — the ONE destructive-judgement entry (GOD ruling,
/// 3806-SHARED-DESTRUCTIVE-JUDGEMENT-RULING): every seam that deletes or
/// merges data asks its yes/no question THROUGH here and nowhere else.
/// W4's consolidation merge is [`judge_merge`]; W3's synthesis delete
/// calls this with [`CalibrationSeam::SynthesisVerdict`] and its own
/// prompt. The whole destructive contract lives in this function:
///
/// * PRIMARY-ONLY — the provider is asked through
///   [`DecisionProvider::judge_primary`], never `judge`, so the generative
///   stand-in is never consulted on a destructive path (5-agent vote
///   `4d3ea1c5`); a caller cannot reach the chain's fallback leg from here;
/// * a configured-but-unbuilt provider (egress refused at boot) is a
///   PERMANENT case 2: recorded, blocked, `refuse` errors — never legacy;
/// * the per-surface R9 breaker: an open breaker is the same
///   `unavailable` block a dead endpoint produces, without the socket;
/// * a bridge failure is an ABSTAIN (`Timeout`, case 2), never a permit;
/// * then [`destructive_judgement_of`]: `None` floor fails CLOSED before
///   any verdict is read; permit ONLY on an explicit `yes` with a
///   validated confidence at or above the seam's floor (NaN / infinity /
///   out-of-range degrade to absent and block); the [`DecisionSource`]
///   is carried on every answer.
///
/// Returns [`MergeJudgement::NoDecider`] when no decider is attached, so
/// `[decision]` unset leaves the caller's v1.0.0 body byte-identical.
///
/// One SYNC form: the autonomy Pass-1 `consolidate_cluster` is a sync
/// call position, and the SAL `ConsolidationPass::run` reaches the trait
/// method from an async body, where [`crate::llm::block_on_local_bounded`]
/// takes the `block_in_place` arm on a multi-thread runtime and a scoped
/// bridge thread otherwise — the same bridge `classify_kind` crosses.
///
/// # Errors
/// Only under `fallback = "refuse"`, and only when the provider was
/// unavailable (case 2).
pub(crate) fn destructive_judge(
    client: &OllamaClient,
    seam: CalibrationSeam,
    prompt: &str,
) -> Result<MergeJudgement> {
    let Some(seams) = client.decider() else {
        return Ok(MergeJudgement::NoDecider);
    };
    let started = Instant::now();
    // `[decision]` configured, no provider ever built (egress refused at
    // boot): CASE 2, permanent. Recorded like any other abstain so the
    // boot refusal is visible on this seam too; `fallback` governs.
    let Some(handle) = seams.gated() else {
        record(
            seam,
            DecisionOutcome::Abstained(AbstainReason::NoProvider),
            started,
        );
        let reason = seams.on_destructive_abstain(AbstainReason::NoProvider)?;
        return Ok(MergeJudgement::Block {
            reason,
            source: DecisionSource::Deterministic,
        });
    };
    // #3806 R9 — an open breaker is the same `unavailable` abstain a real
    // call to a dead endpoint would produce, without the socket.
    if seams.breaker.is_open(started) {
        record(
            seam,
            DecisionOutcome::Abstained(AbstainReason::Unavailable),
            started,
        );
        let reason = seams.on_destructive_abstain(AbstainReason::Unavailable)?;
        return Ok(MergeJudgement::Block {
            reason,
            source: DecisionSource::Deterministic,
        });
    }
    // `judge_primary`, not `judge`: under `fallback = "generative"` the
    // chain would otherwise re-ask the generative stand-in — a NETWORK
    // call carrying memory content — for an answer a destructive seam
    // discards by construction (5-agent vote `4d3ea1c5`, W4). The
    // primary's own abstain comes back instead and is blocked as case 2.
    let decision = crate::llm::block_on_local_bounded(seams.bridge_budget(), || {
        handle.provider().judge_primary(prompt)
    })
    .unwrap_or_else(|_| Decision::abstain(AbstainReason::Timeout, DecisionSource::Deterministic));
    seams
        .breaker
        .observe(decision.abstain_reason(), Instant::now());
    // The floor is the seam's, read through the ONE per-seam accessor
    // (`CalibrationSeam::confidence_floor`); `None` fails closed inside.
    destructive_judgement_of(seams, seam, &decision, seam.confidence_floor(), started)
}

/// #3806 W4 — the consolidation merge judge: [`destructive_judge`] on
/// [`CalibrationSeam::ConsolidationMerge`] with the merge prompt.
///
/// Runs strictly downstream of the Jaccard and cosine gates: the caller
/// only asks about a cluster those gates already admitted, and the
/// answer can only remove it.
///
/// # Errors
/// As [`destructive_judge`].
pub(crate) fn judge_merge(
    client: &OllamaClient,
    members: &[(String, String)],
) -> Result<MergeJudgement> {
    destructive_judge(
        client,
        CalibrationSeam::ConsolidationMerge,
        &merge_judge_prompt(members),
    )
}

/// Run the boot chokepoint for this surface and attach the resulting
/// gated decider to its `[llm]` client.
///
/// Called EXACTLY once per surface, and unconditionally — the chokepoint
/// records the `/capabilities` snapshot and (under a refusing posture)
/// the signed refusal row whether or not `llm` is `Some`, so those boot
/// effects never become a function of the chat lane's availability.
///
/// Returns `llm` unchanged when `[decision]` is unset or the chokepoint
/// refused to build a provider: the surface then has no decider, every
/// seam returns [`SeamOutcome::RunLegacy`], and behaviour is v1.0.0.
#[must_use]
pub fn attach_decider(
    llm: Option<OllamaClient>,
    cfg: &AppConfig,
    db_path: &Path,
) -> Option<OllamaClient> {
    let state = match build_decision_provider(cfg, db_path) {
        // CASE 1 — no `[decision]` section. Nothing is attached, no
        // seam runs, no metric series is created: byte-identical v1.0.0.
        DecisionBootOutcome::Absent => return llm,
        DecisionBootOutcome::Constructed(handle) => {
            // A RETARGETED clone, not this client: see the module
            // header's "reference cycle" section. `with_model` shares
            // the reqwest pool, takes a fresh breaker and does NOT copy
            // the decider field.
            let generative = llm
                .as_ref()
                .map(|client| Arc::new(client.with_model(client.model_name())));
            let endpoint = cfg.resolve_llm(None, None, None).base_url;
            SeamState::Gated(Box::new(handle.attach_client(generative, &endpoint)))
        }
        // CASE 2, PERMANENTLY (#3806 R2). The section EXISTS and no
        // provider was built — the egress gate refused the endpoint, or
        // it did not resolve. This used to return `llm` untouched, which
        // ran the v1.0.0 generative path and bypassed `fallback`
        // altogether: a permanent refusal was more permissive than a
        // transient blip, and `refuse` could not refuse. The operator's
        // DECLARED fallback is read from the raw section, because a
        // section that failed to resolve still states its intent.
        outcome => {
            let fallback = cfg
                .decision
                .as_ref()
                .and_then(|section| section.fallback)
                .unwrap_or_default();
            tracing::warn!(
                state = outcome.state().as_str(),
                fallback = fallback.as_str(),
                "[decision] is configured but NO provider was built; every seam will take \
                 its `fallback` branch rather than silently running the v1.0.0 path (#3806)"
            );
            SeamState::NoProvider { fallback }
        }
    };
    llm.map(|client| {
        client.with_decider(Arc::new(DecisionSeams {
            state,
            breaker: SeamBreaker::default(),
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #3806 HARD CONSTRAINT, the W4 merge seam's own form: every
    /// no-verdict outcome of `on_destructive_abstain` is exhaustively a BLOCK
    /// or an error — never a permit, and never the v1.0.0 path (there is
    /// none on this seam: its v1.0.0 instrument was NO judge, so
    /// `generative` blocks exactly as `abstain` does). An error only under
    /// `refuse` AND case 2; a decline (case 3) is `Abstained` under every
    /// posture; every other unavailability is `Unavailable`.
    #[test]
    fn no_destructive_abstain_under_any_posture_can_permit_or_run_legacy() {
        for fallback in [
            DecisionFallback::Abstain,
            DecisionFallback::Generative,
            DecisionFallback::Refuse,
        ] {
            let seams = DecisionSeams {
                state: SeamState::NoProvider { fallback },
                breaker: SeamBreaker::default(),
            };
            for reason in AbstainReason::all() {
                match seams.on_destructive_abstain(reason) {
                    Err(_) => assert!(
                        fallback == DecisionFallback::Refuse && reason.is_unavailable(),
                        "{fallback:?}/{reason}: only case 2 under `refuse` may error"
                    ),
                    Ok(MergeBlockReason::Abstained(r)) => {
                        assert!(
                            !reason.is_unavailable() && r == reason,
                            "{fallback:?}/{reason}: a decline is `Abstained`, verbatim"
                        );
                    }
                    Ok(MergeBlockReason::Unavailable(r)) => {
                        assert!(
                            reason.is_unavailable() && r == reason,
                            "{fallback:?}/{reason}: an outage is `Unavailable`, verbatim, under \
                             `abstain` AND `generative` alike"
                        );
                    }
                    Ok(other) => {
                        panic!("{fallback:?}/{reason}: an abstain mapped to {other:?}")
                    }
                }
            }
            // PRESENCE — the `refuse` arm is reachable, so the loop is not
            // vacuously all-Ok.
            let case2 = seams.on_destructive_abstain(AbstainReason::Unavailable);
            if fallback == DecisionFallback::Refuse {
                assert!(case2.is_err());
            } else {
                assert!(matches!(
                    case2,
                    Ok(MergeBlockReason::Unavailable(AbstainReason::Unavailable))
                ));
            }
        }
    }

    /// #3806 HARD CONSTRAINT — "the decider may only NARROW a destructive
    /// path, never widen one". At the seam, every no-verdict outcome is
    /// exhaustively one of: the conservative NON-ACTION, the v1.0.0 path
    /// exactly as it ran without a decider (`generative`, case 2 only), or
    /// an error (`refuse`, case 2 only). No abstain, under any posture,
    /// can produce a verdict — so a decider can never cause an action the
    /// v1.0.0 path would not also have taken — and a DECLINE never
    /// re-opens the v1.0.0 text parse (case 3).
    #[test]
    fn no_abstain_under_any_posture_can_act_or_reask_a_decline() {
        for fallback in [
            DecisionFallback::Abstain,
            DecisionFallback::Generative,
            DecisionFallback::Refuse,
        ] {
            let seams = DecisionSeams {
                state: SeamState::NoProvider { fallback },
                breaker: SeamBreaker::default(),
            };
            for reason in AbstainReason::all() {
                let outcome = seams.on_abstain::<bool>(reason);
                match outcome {
                    Ok(SeamOutcome::Decided(_)) => {
                        panic!("{fallback:?}/{reason}: an abstain produced a verdict")
                    }
                    Ok(SeamOutcome::RunLegacy) => {
                        assert!(
                            fallback == DecisionFallback::Generative && reason.is_unavailable(),
                            "{fallback:?}/{reason}: only case 2 under `generative` may run \
                             the v1.0.0 path"
                        );
                    }
                    Err(_) => assert!(
                        fallback == DecisionFallback::Refuse && reason.is_unavailable(),
                        "{fallback:?}/{reason}: only case 2 under `refuse` may error"
                    ),
                    Ok(SeamOutcome::Conservative) => {}
                }
            }
            // PRESENCE — each posture's own branch is reachable, so the
            // loop above is not vacuously all-Conservative.
            let expected_case2 = seams.on_abstain::<bool>(AbstainReason::Unavailable);
            match fallback {
                DecisionFallback::Abstain => {
                    assert!(matches!(expected_case2, Ok(SeamOutcome::Conservative)));
                }
                DecisionFallback::Generative => {
                    assert!(matches!(expected_case2, Ok(SeamOutcome::RunLegacy)));
                }
                DecisionFallback::Refuse => assert!(expected_case2.is_err()),
            }
            assert!(matches!(
                seams.on_abstain::<bool>(AbstainReason::Unusable),
                Ok(SeamOutcome::Conservative)
            ));
        }
    }

    /// #3806 R9 — the breaker's state machine, on explicit instants: it
    /// opens at the threshold, stays open for the cooldown, lets ONE
    /// probe through after it, re-opens if that probe fails, and closes
    /// on any answer (a decline included). Egress refusals leave it
    /// untouched: they cost no socket.
    #[test]
    fn the_breaker_opens_cools_down_probes_and_closes() {
        let breaker = SeamBreaker::default();
        let t0 = Instant::now();
        for _ in 0..BREAKER_THRESHOLD - 1 {
            breaker.observe(Some(AbstainReason::Unavailable), t0);
            assert!(!breaker.is_open(t0), "below the threshold stays closed");
        }
        breaker.observe(Some(AbstainReason::EgressRefused), t0);
        assert!(!breaker.is_open(t0), "an egress refusal is not an outage");
        breaker.observe(Some(AbstainReason::Timeout), t0);
        assert!(breaker.is_open(t0), "the threshold-th outage opens it");
        let later = t0 + BREAKER_COOLDOWN - Duration::from_millis(1);
        assert!(breaker.is_open(later), "open for the whole cooldown");
        let probe = t0 + BREAKER_COOLDOWN;
        assert!(
            !breaker.is_open(probe),
            "after the cooldown one probe is allowed"
        );
        breaker.observe(Some(AbstainReason::Unavailable), probe);
        assert!(breaker.is_open(probe), "a failed probe re-opens it");
        breaker.observe(Some(AbstainReason::Unusable), probe);
        assert!(!breaker.is_open(probe), "a decline is an answer: closed");
        for _ in 0..BREAKER_THRESHOLD {
            breaker.observe(Some(AbstainReason::Unavailable), probe);
        }
        breaker.observe(None, probe);
        assert!(!breaker.is_open(probe), "a decision closes it");
    }

    /// #3806 W4 — f1's acceptance cells for the merge seam, on the exact
    /// verdict→disposition mapping with a hand-built judgement (no wire):
    /// confidently TRUE at the floor permits; below the floor, absent,
    /// NaN, +inf, out-of-range (7.0, -0.1) all BLOCK as low-confidence
    /// (the constructor degrades an unusable confidence to ABSENT — never
    /// to a number that clears a floor); confidently FALSE blocks as
    /// `decided_no`; an abstain keeps its reason and source; and a
    /// destructive seam whose floor is `None` fails CLOSED on a 0.99 yes.
    #[test]
    fn merge_acceptance_cells_permit_only_a_confident_yes_at_the_floor() {
        use crate::decision::Judgement;
        let seams = DecisionSeams {
            state: SeamState::NoProvider {
                fallback: DecisionFallback::Abstain,
            },
            breaker: SeamBreaker::default(),
        };
        let floor = CalibrationSeam::ConsolidationMerge.confidence_floor();
        assert_eq!(floor, Some(CONSOLIDATION_MERGE_CONFIDENCE_FLOOR));
        let yes = |c: Option<f64>| Judgement::decided(true, c, DecisionSource::DecisionModel);
        let at = |j: &Judgement| {
            destructive_judgement_of(
                &seams,
                CalibrationSeam::ConsolidationMerge,
                j,
                floor,
                Instant::now(),
            )
            .expect("abstain posture")
        };

        // PERMIT — the one cell that merges.
        assert!(matches!(
            at(&yes(Some(CONSOLIDATION_MERGE_CONFIDENCE_FLOOR))),
            MergeJudgement::Permit {
                source: DecisionSource::DecisionModel,
                ..
            }
        ));
        assert!(matches!(
            at(&yes(Some(0.99))),
            MergeJudgement::Permit { .. }
        ));
        // BLOCK — below the floor, by one hundredth.
        assert!(matches!(
            at(&yes(Some(CONSOLIDATION_MERGE_CONFIDENCE_FLOOR - 0.01))),
            MergeJudgement::Block {
                reason: MergeBlockReason::LowConfidence {
                    confidence: Some(_)
                },
                ..
            }
        ));
        // BLOCK — absent, NaN, +inf, out-of-range: all ABSENT at the seam.
        for c in [
            None,
            Some(f64::NAN),
            Some(f64::INFINITY),
            Some(7.0),
            Some(-0.1),
        ] {
            let j = yes(c);
            assert_eq!(j.confidence(), None, "{c:?} must degrade to absent");
            assert!(
                matches!(
                    at(&j),
                    MergeJudgement::Block {
                        reason: MergeBlockReason::LowConfidence { confidence: None },
                        ..
                    }
                ),
                "{c:?} must block as a confidence-less yes"
            );
        }
        // BLOCK — confidently FALSE is a decided no, never a permit.
        assert!(matches!(
            at(&Judgement::decided(
                false,
                Some(0.99),
                DecisionSource::DecisionModel
            )),
            MergeJudgement::Block {
                reason: MergeBlockReason::DecidedNo,
                ..
            }
        ));
        // BLOCK — an abstain keeps its reason and its source.
        assert!(matches!(
            at(&Judgement::abstain(
                AbstainReason::Unusable,
                DecisionSource::DecisionModel
            )),
            MergeJudgement::Block {
                reason: MergeBlockReason::Abstained(AbstainReason::Unusable),
                source: DecisionSource::DecisionModel,
            }
        ));
        assert!(matches!(
            at(&Judgement::abstain(
                AbstainReason::Timeout,
                DecisionSource::DecisionModel
            )),
            MergeJudgement::Block {
                reason: MergeBlockReason::Unavailable(AbstainReason::Timeout),
                source: DecisionSource::DecisionModel,
            }
        ));
        // FAIL CLOSED — no floor declared: a 0.99 yes still blocks.
        let no_floor = destructive_judgement_of(
            &seams,
            CalibrationSeam::ConsolidationMerge,
            &yes(Some(0.99)),
            None,
            Instant::now(),
        )
        .expect("abstain posture");
        assert!(
            matches!(
                no_floor,
                MergeJudgement::Block {
                    reason: MergeBlockReason::NoFloor,
                    ..
                }
            ),
            "a destructive seam with no floor is a contract failure: {no_floor:?}"
        );
        assert!(!no_floor.permits());
    }
}
