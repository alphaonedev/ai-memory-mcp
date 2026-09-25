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
}
