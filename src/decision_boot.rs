// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3806 W1b — the `[decision]` **boot chokepoint** and the per-call
//! egress seam, mirroring [`crate::daemon_runtime::build_llm_client`]
//! one inference endpoint over.
//!
//! ## Why this module exists at all
//!
//! #1963 gated the inference plane at its BOOT chokepoints: under
//! `AI_MEMORY_INFERENCE_EGRESS=deny` (or `loopback-only` against a
//! remote target) the outbound client is never CONSTRUCTED, so the
//! enforcement is the absence of the egress path rather than a per-
//! request check somebody can forget. `[decision]` adds a SECOND
//! inference endpoint. If it were constructed anywhere else, an
//! air-gapped deployment would silently regain an egress lane — which
//! is exactly the defect #3808 found in `[llm.auto_tag]` (a second
//! endpoint documented, never wired, and had it been wired it would
//! have bypassed `build_llm_client`'s gate).
//!
//! So [`build_decision_provider`] is the ONLY way to obtain a
//! [`DecisionProviderHandle`]: the struct's fields are private, it has
//! no public constructor, and W1c's clients attach to an ALREADY-GATED
//! handle through [`DecisionProviderHandle::with_provider`]. A client
//! that wanted to skip the gate would have to add a constructor to this
//! file, which is a reviewable act rather than an oversight.
//!
//! ## The three postures, at boot
//!
//! | posture | remote `[decision]` | `local-nli` |
//! |---|---|---|
//! | `allow` (default) | constructed | constructed |
//! | `loopback-only` | constructed iff the resolved `base_url` is loopback | constructed |
//! | `internal-only` (#3822) | constructed iff EVERY address the endpoint resolves to is internal; the addresses are PINNED into the client | constructed |
//! | `deny` | REFUSED — no handle, signed refusal row | constructed |
//!
//! Every posture also refuses a non-loopback plaintext `http` endpoint
//! (#3823) — at config time in `decision_config::plan`, and again here
//! as the egress backstop.
//!
//! `local-nli` runs in process and its `base_url` is EMPTY by
//! construction (`src/decision_config.rs` refuses one), so the gate is
//! SKIPPED for it — because there is nothing to check, never to WAIVE a
//! check. That is also the presence control for the deny pin: if `deny`
//! produced no provider at all, "deny refuses the remote provider"
//! could pass for the wrong reason.
//!
//! ## Per call
//!
//! Boot-time absence is the hard enforcement, but a posture can change
//! under a long-lived daemon (the operator edits the unit file and the
//! process is re-execed, or a future reload re-reads the env), and W1c's
//! clients hold a handle for the process lifetime. Every outbound
//! request therefore re-checks through
//! [`DecisionEgressGuard::check_outbound`], which returns a `Result` the
//! compiler will not let a client ignore. A refusal is an ABSTAIN
//! ([`AbstainReason::EgressRefused`]), never an error a seam could
//! coerce into a `false`.
//!
//! ## What `/capabilities` reports
//!
//! [`boot_report`] is the snapshot the capability surface renders, in
//! the same read-only-boot-snapshot shape as
//! [`crate::federation::peer_posture::boot_report`]. Its `state` comes
//! from the CLOSED vocabulary [`DecisionProviderState`] — `absent` /
//! `configured` / `refused_by_egress` / `constructed` — so an operator
//! asking "did my egress posture actually stop the second endpoint?"
//! gets a token they can match on, never free text.
//!
//! **`[decision]` unset stays byte-identical v1.0.0**: the chokepoint
//! returns [`DecisionBootOutcome::Absent`] before it resolves anything,
//! records NO snapshot, and the capability key is therefore omitted from
//! the wire exactly as it was before this commit.

use std::path::Path;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::decision::{AbstainReason, DecisionProvider, decider_or_null};
use crate::decision_config::{
    DecisionFallback, ResolvedDecision, fallback_phrase, resolve_decision,
};
use crate::egress::{
    EgressClass, EgressDecision, InferenceEgressMode, PinnedTarget, admit_inference_target,
    evaluate_inference_egress, evaluate_inference_egress_resolved,
};

/// The CLOSED vocabulary for the decision-provider boot state.
///
/// A closed enum rather than a string because this is an INSTRUMENT: a
/// fleet orchestrator branches on it to decide whether an air-gapped
/// node is actually air-gapped. Free text drifts; an unexpected variant
/// then renders as something a matcher silently ignores. Serialized in
/// `snake_case`, and deserialization of an unknown token FAILS rather
/// than falling back to a "safe-looking" value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionProviderState {
    /// No `[decision]` section: no provider was asked for. The
    /// byte-identical v1.0.0 path.
    Absent,
    /// A `[decision]` section exists but yielded no provider for a
    /// reason that is NOT the egress posture — the resolver refused it
    /// (an `AppConfig` built in memory that never crossed the loader's
    /// `validate`), or, from W1c on, client construction failed.
    Configured,
    /// The resolved endpoint was refused by the inference-plane egress
    /// gate. No provider exists and a signed refusal row was attempted.
    RefusedByEgress,
    /// A gated provider handle exists.
    Constructed,
}

impl DecisionProviderState {
    /// The canonical wire / audit token for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Configured => "configured",
            Self::RefusedByEgress => "refused_by_egress",
            Self::Constructed => "constructed",
        }
    }

    /// Every token in the closed vocabulary, in ladder order. Exists so
    /// a test can assert the set is exactly these four and a doc can
    /// render them without re-typing the list.
    #[must_use]
    pub fn all() -> [Self; 4] {
        [
            Self::Absent,
            Self::Configured,
            Self::RefusedByEgress,
            Self::Constructed,
        ]
    }
}

impl std::fmt::Display for DecisionProviderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Content-free boot snapshot rendered by `/capabilities`.
///
/// Carries NO credential and NO endpoint URL. The base URL is
/// deliberately withheld: the signed refusal row already records the
/// target for the operator who can read the audit chain, whereas
/// `/capabilities` is a broadly-readable surface and a `base_url` may
/// carry userinfo. What a caller needs here is the POSTURE, not the
/// address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBootReport {
    /// One token from the closed [`DecisionProviderState`] vocabulary.
    pub state: DecisionProviderState,
    /// The resolved provider alias (`openrouter`, `systemone`,
    /// `local-nli`, ...). Never a credential.
    pub provider: String,
    /// The resolved decision-model identifier.
    pub model: String,
    /// Whether the provider runs in process and opens no socket.
    pub local: bool,
    /// The inference-plane egress posture observed at the chokepoint
    /// (`allow` / `loopback-only` / `deny`).
    pub egress_mode: String,
}

/// A refused outbound decision call.
///
/// Returned by [`DecisionEgressGuard::check_outbound`] inside a
/// `Result`, so a W1c client cannot proceed past a refusal by ignoring a
/// bool. Carries no credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionEgressRefused {
    target: String,
    reason: String,
}

impl DecisionEgressRefused {
    /// The abstain a seam must record for this refusal. Fixed, not a
    /// caller choice: an egress refusal is never a `false`.
    #[must_use]
    pub fn abstain_reason(&self) -> AbstainReason {
        AbstainReason::EgressRefused
    }

    /// The refused target base URL (config-class, never a secret).
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The operator-facing explanation from the shared egress gate.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for DecisionEgressRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (target={})", self.reason, self.target)
    }
}

impl std::error::Error for DecisionEgressRefused {}

/// The per-call egress hook. W1c's clients MUST call
/// [`Self::check_outbound`] immediately before every outbound request.
///
/// Holds the resolved target so the check cannot be run against a
/// different URL than the one the client is about to POST to, and
/// re-resolves the POSTURE on every call so a tightened posture takes
/// effect without waiting for a restart. (It can only ever TIGHTEN in
/// effect: boot already refused to construct anything the boot posture
/// forbade.)
#[derive(Clone, Debug)]
pub struct DecisionEgressGuard {
    base_url: String,
    local: bool,
    /// #3822 — the boot-resolved addresses admitted under
    /// `internal-only`, which the client pins. `None` under the
    /// name-based postures (byte-identical legacy shape).
    pin: Option<PinnedTarget>,
}

impl DecisionEgressGuard {
    fn for_resolved(resolved: &ResolvedDecision, pin: Option<PinnedTarget>) -> Self {
        Self {
            base_url: resolved.base_url.clone(),
            local: resolved.is_local(),
            pin,
        }
    }

    /// The target this guard checks (config-class, never a secret).
    #[must_use]
    pub fn target(&self) -> &str {
        &self.base_url
    }

    /// The boot-resolved addresses pinned under `internal-only` (#3822):
    /// the ONLY addresses a client built from this handle connects to.
    #[must_use]
    pub fn pinned(&self) -> Option<&PinnedTarget> {
        self.pin.as_ref()
    }

    /// Check whether an outbound decision call may proceed RIGHT NOW.
    ///
    /// A local provider returns `Ok(())` without consulting the gate —
    /// because it opens no socket, so there is nothing to check. That is
    /// a skip, not a waiver: the gate governs egress, and a provider
    /// with no egress has none to govern.
    ///
    /// # Errors
    ///
    /// [`DecisionEgressRefused`] when the live posture forbids this
    /// target. The caller MUST abstain with
    /// [`DecisionEgressRefused::abstain_reason`] rather than fall back to
    /// any default verdict.
    pub fn check_outbound(&self) -> Result<(), DecisionEgressRefused> {
        self.check_outbound_under(InferenceEgressMode::resolve())
    }

    /// [`Self::check_outbound`] against an EXPLICIT posture.
    ///
    /// Crate-private on purpose: the public entry point resolves the
    /// posture itself, so no caller outside this crate can hand the gate
    /// a weaker mode than the operator configured. It exists so the pins
    /// can exercise every posture WITHOUT mutating the process-global
    /// environment, which is unsound under the parallel-threaded lib
    /// test binary (#3475 / #2127) — the readers are the victims there,
    /// and they do not take a lock.
    pub(crate) fn check_outbound_under(
        &self,
        mode: InferenceEgressMode,
    ) -> Result<(), DecisionEgressRefused> {
        if self.local {
            return Ok(());
        }
        // #3822 — under `internal-only` the client connects to the PINNED
        // addresses, so those are what the per-call check classifies (no
        // DNS at call time). With no pin — a handle built under a
        // name-based posture that has since TIGHTENED to `internal-only`
        // — the name-based arm refuses a hostname it cannot classify:
        // fail closed, never a lookup the client would not then honour.
        let decision = match (mode, &self.pin) {
            (InferenceEgressMode::InternalOnly, Some(pin)) => evaluate_inference_egress_resolved(
                mode,
                EgressClass::InferenceDecision,
                &self.base_url,
                &pin.addrs,
            ),
            _ => evaluate_inference_egress(mode, EgressClass::InferenceDecision, &self.base_url),
        };
        match decision {
            EgressDecision::Allow => Ok(()),
            EgressDecision::Refuse { target, reason, .. } => {
                Err(DecisionEgressRefused { target, reason })
            }
        }
    }
}

/// A gated decision-provider handle.
///
/// Obtainable ONLY from [`build_decision_provider`] (private fields, no
/// public constructor), so every handle in the process has passed the
/// inference-plane egress gate for its own resolved endpoint. W1c/W1d
/// attach their client with [`Self::with_provider`]; until one is
/// attached the handle answers through
/// [`crate::decision::NullDecider`], which always abstains — so a seam
/// wired ahead of its client degrades to abstain, never to a fabricated
/// verdict.
#[derive(Debug)]
pub struct DecisionProviderHandle {
    resolved: ResolvedDecision,
    guard: DecisionEgressGuard,
    provider: Option<Arc<dyn DecisionProvider>>,
}

impl DecisionProviderHandle {
    /// The resolved provider alias.
    #[must_use]
    pub fn provider_alias(&self) -> &str {
        &self.resolved.provider
    }

    /// The resolved decision-model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.resolved.model
    }

    /// The resolved endpoint base URL — the one the gate approved and
    /// the one a client must POST to. EMPTY for a local provider.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.resolved.base_url
    }

    /// The resolved API key. Use only when constructing a client; never
    /// log or `{:?}` the result.
    #[must_use]
    pub fn api_key(&self) -> Option<&str> {
        self.resolved.api_key()
    }

    /// The per-call timeout. A timeout is an ABSTAIN, never a `false`.
    #[must_use]
    pub fn timeout(&self) -> std::time::Duration {
        self.resolved.timeout()
    }

    /// What the seam does when the provider cannot answer.
    #[must_use]
    pub fn fallback(&self) -> DecisionFallback {
        self.resolved.fallback
    }

    /// Whether this provider runs in process and opens no socket.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.resolved.is_local()
    }

    /// The per-call egress hook. Call [`DecisionEgressGuard::check_outbound`]
    /// before EVERY outbound request.
    #[must_use]
    pub fn egress(&self) -> &DecisionEgressGuard {
        &self.guard
    }

    /// The decider a seam consults. Falls back to the always-abstaining
    /// [`crate::decision::NULL_DECIDER`] until W1c/W1d attach a client.
    #[must_use]
    pub fn provider(&self) -> &dyn DecisionProvider {
        decider_or_null(self.provider.as_deref())
    }

    /// Whether a real client has been attached yet.
    #[must_use]
    pub fn has_client(&self) -> bool {
        self.provider.is_some()
    }

    /// Attach the constructed client (W1c's OpenAI-compatible /
    /// SystemOne clients, W1d's `local-nli` provider). Consumes and
    /// returns the handle so the gate stays upstream of the client: the
    /// only way to reach this method is to already hold a gated handle.
    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn DecisionProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// #3806 W2 — build and attach the CLIENT this handle's own
    /// resolution implies.
    ///
    /// The chokepoint owns construction end to end:
    /// [`crate::decision_clients::construct`] is handed the
    /// already-resolved, already-egress-gated section that only this
    /// module holds, plus a per-call outbound hook bound to the endpoint
    /// the boot gate APPROVED — so "the URL the gate approved is the URL
    /// the client POSTs to" is enforced rather than assumed.
    ///
    /// `generative` is the `[llm]` client the `fallback = "generative"`
    /// leg delegates to. It must NOT be the client this handle is then
    /// attached to; pass a retarget (see
    /// [`crate::decision_seams::attach_decider`], the only caller).
    ///
    /// On failure the handle is returned UNCHANGED — still answering
    /// through [`crate::decision::NullDecider`], so every seam abstains
    /// rather than receiving a fabricated verdict — and the
    /// `/capabilities` snapshot is corrected from `constructed` to
    /// `configured`, because a handle with no client is not a
    /// constructed provider and must not claim to be one.
    #[must_use]
    pub fn attach_client(
        self,
        generative: Option<Arc<crate::llm::OllamaClient>>,
        generative_endpoint: &str,
    ) -> Self {
        let secondary = match (self.resolved.fallback, generative) {
            (DecisionFallback::Generative, Some(client)) => {
                // The fallback leg POSTs to the `[llm]` endpoint and
                // ONLY there, so that endpoint is the WHOLE of its
                // approved set — not the decision endpoint, which this
                // client must never reach. `[llm]` passed its own #1963
                // boot gate at construction; the decision lane's LIVE
                // posture is still consulted before every call.
                match crate::decision_clients::fallback::GenerativeFallbackDecider::new(
                    client,
                    generative_endpoint,
                    self.outbound_check(&[generative_endpoint]),
                    self.resolved.timeout(),
                ) {
                    Ok(decider) => Some(decider),
                    Err(_) => {
                        // Our own text only: the error carries the [llm]
                        // endpoint, which is not ours to log here.
                        tracing::warn!(
                            "could not bind the [llm] endpoint for {}; construction will \
                             refuse rather than answer without the fallback the operator \
                             asked for (#3806)",
                            fallback_phrase(DecisionFallback::Generative)
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        // The PRIMARY client POSTs to the gated decision endpoint and
        // only there.
        let outbound = self.outbound_check(&[self.resolved.base_url.as_str()]);
        match crate::decision_clients::construct_pinned(
            &self.resolved,
            outbound,
            secondary,
            self.guard.pinned(),
        ) {
            Ok(provider) => self.with_provider(Arc::from(provider)),
            Err(e) => {
                tracing::warn!(
                    "[decision] endpoint passed the egress gate but its client could not be \
                     constructed; EVERY seam will abstain and the capability surface reports \
                     `configured`, not `constructed` (#3806): {e:#}"
                );
                record_client_attach_failure(&self.resolved);
                self
            }
        }
    }

    /// The per-call egress hook handed to every client this handle
    /// builds.
    ///
    /// Two conditions, both of which must hold before a socket is
    /// opened:
    ///
    /// 1. the request URL's ORIGIN is one of `approved` — so a
    ///    mis-joined path, a redirected base or a future client bug
    ///    cannot send memory content to an endpoint no gate ever saw;
    /// 2. the LIVE decision posture still permits this provider, so a
    ///    posture tightened after boot takes effect without a restart.
    ///
    /// `approved` is ONE origin per client: the gated decision endpoint
    /// for the primary, the `[llm]` endpoint for the generative fallback
    /// leg. Neither client is ever handed the other's.
    fn outbound_check(&self, approved: &[&str]) -> crate::decision_clients::OutboundCheck {
        let approved: Vec<String> = approved
            .iter()
            .map(|url| crate::url_display::url_origin(url))
            .collect();
        let guard = self.guard.clone();
        Arc::new(move |url: &reqwest::Url| {
            let origin = crate::url_display::url_origin(url.as_str());
            if !approved.iter().any(|a| *a == origin) {
                anyhow::bail!(
                    "the decision request target is not an endpoint the egress gate \
                     approved; refusing to send (#3806)"
                );
            }
            // Our own reason string, never the vendor's text and never
            // the URL (#3648 / #3688).
            guard
                .check_outbound()
                .map_err(|refusal| anyhow::anyhow!("{}", refusal.reason()))
        })
    }
}

/// Correct the `/capabilities` snapshot when a GATED handle could not
/// obtain a client.
///
/// The egress decision already happened and is unchanged; what changes
/// is the honest state of the provider. Reported as `configured` — a
/// section exists, no provider answers — which is exactly what a seam
/// will observe.
fn record_client_attach_failure(resolved: &ResolvedDecision) {
    let egress_mode = boot_report().map(|r| r.egress_mode).unwrap_or_default();
    record(Some(DecisionBootReport {
        state: DecisionProviderState::Configured,
        provider: resolved.provider.clone(),
        model: resolved.model.clone(),
        local: resolved.is_local(),
        egress_mode,
    }));
}

/// What the boot chokepoint decided.
///
/// `#[must_use]`: dropping this silently would discard both the
/// enforcement outcome and the operator's only signal.
#[derive(Debug)]
#[must_use = "the boot outcome carries the egress decision; record or consume it"]
pub enum DecisionBootOutcome {
    /// No `[decision]` section. Nothing was resolved, nothing recorded.
    Absent,
    /// A section exists but yielded no provider for a non-egress reason.
    Configured,
    /// The egress gate refused the resolved endpoint. No handle; a
    /// signed refusal row was attempted.
    RefusedByEgress,
    /// A gated handle.
    Constructed(Box<DecisionProviderHandle>),
}

impl DecisionBootOutcome {
    /// The closed-vocabulary state for this outcome.
    #[must_use]
    pub fn state(&self) -> DecisionProviderState {
        match self {
            Self::Absent => DecisionProviderState::Absent,
            Self::Configured => DecisionProviderState::Configured,
            Self::RefusedByEgress => DecisionProviderState::RefusedByEgress,
            Self::Constructed(_) => DecisionProviderState::Constructed,
        }
    }

    /// The gated handle, when one was constructed.
    #[must_use]
    pub fn handle(&self) -> Option<&DecisionProviderHandle> {
        match self {
            Self::Constructed(h) => Some(h),
            _ => None,
        }
    }

    /// Take the gated handle, when one was constructed.
    #[must_use]
    pub fn into_handle(self) -> Option<DecisionProviderHandle> {
        match self {
            Self::Constructed(h) => Some(*h),
            _ => None,
        }
    }
}

/// Snapshot of the last completed in-process decision-provider boot.
///
/// `None` means the chokepoint has not run in this process, OR it ran
/// and found no `[decision]` section — in both cases the capability key
/// is omitted from the wire, which is what keeps an unconfigured
/// deployment byte-identical to v1.0.0. A reload that REMOVES the
/// section clears the snapshot back to `None` rather than leaving a
/// stale `constructed` claim standing.
static BOOT_REPORT: RwLock<Option<DecisionBootReport>> = RwLock::new(None);

/// The snapshot `/capabilities` renders. See [`BOOT_REPORT`].
#[must_use]
pub fn boot_report() -> Option<DecisionBootReport> {
    BOOT_REPORT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn record(report: Option<DecisionBootReport>) {
    *BOOT_REPORT
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = report;
}

/// THE boot chokepoint for `[decision]`.
///
/// Resolves the section, runs the inference-plane egress gate for the
/// resolved endpoint, and either returns a gated
/// [`DecisionProviderHandle`] or refuses — writing a best-effort signed
/// refusal row to `db_path` exactly as
/// [`crate::daemon_runtime::build_llm_client`] does for the chat
/// endpoint. Records the `/capabilities` snapshot as a side effect.
///
/// Synchronous and makes zero decision calls by construction: its only
/// I/O is the refusal-row append on the refuse arm and, under
/// `internal-only` alone, the one DNS resolution the carrier's
/// resolve-then-pin gate performs (which fails CLOSED). "The boot path
/// makes zero decision calls" is a property of the code shape, not of a
/// timeout. W1c attaches its client to the returned handle after
/// constructing it asynchronously.
pub fn build_decision_provider(cfg: &AppConfig, db_path: &Path) -> DecisionBootOutcome {
    build_decision_provider_under(InferenceEgressMode::resolve(), cfg, db_path)
}

/// [`build_decision_provider`] against an EXPLICIT posture.
///
/// Crate-private for the same reason as
/// [`DecisionEgressGuard::check_outbound_under`]: the public chokepoint
/// resolves the posture itself, so nothing outside this crate can hand
/// the boot gate a weaker mode than the operator configured, and the
/// pins can still exercise `deny` / `loopback-only` / `allow` without
/// mutating the process-global environment.
pub(crate) fn build_decision_provider_under(
    mode: InferenceEgressMode,
    cfg: &AppConfig,
    db_path: &Path,
) -> DecisionBootOutcome {
    // Byte-identical-when-unset, structurally: with no `[decision]`
    // section we return before resolving anything and record NOTHING,
    // so the capability key is absent from the wire as before.
    if cfg.decision.is_none() {
        record(None);
        return DecisionBootOutcome::Absent;
    }

    let Some(resolved) = resolve_decision(cfg) else {
        // The section is present but unresolvable. `resolve_decision`
        // and the loader's `validate` share ONE acceptance predicate,
        // so a config that reached a live loader never lands here; an
        // `AppConfig` built in memory can, and it gets NO provider
        // rather than a half-configured one.
        tracing::warn!(
            "[decision] is configured but did not resolve to a usable endpoint; \
             no decision provider (seams abstain). Run `ai-memory config check` (#3806)"
        );
        record(Some(DecisionBootReport {
            state: DecisionProviderState::Configured,
            provider: String::new(),
            model: String::new(),
            local: false,
            egress_mode: mode.as_str().to_string(),
        }));
        return DecisionBootOutcome::Configured;
    };

    // #1963 (R68/D14) extended to the SECOND inference endpoint. A local
    // provider is SKIPPED, not waived: it opens no socket and its
    // `base_url` is empty by construction, so there is no egress to
    // govern. Everything else is gated on the endpoint it will POST to.
    //
    // #3822 — through the carrier's RESOLVE-THEN-PIN entry point, the one
    // every `[llm]` / embedding chokepoint uses: under `internal-only` it
    // refuses off-host plaintext first, resolves the target (DNS fails
    // CLOSED), requires EVERY resolved address to be internal, and hands
    // back the addresses the client must pin. Under the name-based
    // postures it is exactly `evaluate_inference_egress` with no pin.
    let mut pin = None;
    if !resolved.is_local() {
        match admit_inference_target(mode, EgressClass::InferenceDecision, &resolved.base_url) {
            Ok(admitted) => pin = admitted,
            Err(EgressDecision::Allow) => {}
            Err(EgressDecision::Refuse {
                class,
                target,
                reason,
            }) => {
                tracing::warn!(
                    "[decision] provider DISABLED by the inference-plane egress gate \
                 (provider={} model={} target={target} mode={}); {reason} (#1963/#3806)",
                    resolved.provider,
                    resolved.model,
                    mode.as_str()
                );
                record(Some(DecisionBootReport {
                    state: DecisionProviderState::RefusedByEgress,
                    provider: resolved.provider.clone(),
                    model: resolved.model.clone(),
                    local: false,
                    egress_mode: mode.as_str().to_string(),
                }));
                // #1991 — audit against the operator-resolved db_path.
                crate::egress::refuse_inference_egress_audited(db_path, class, &target, &reason);
                return DecisionBootOutcome::RefusedByEgress;
            }
        }
    }

    tracing::info!(
        "[decision] provider gated and ready — provider={} model={} local={} \
         timeout={}s fallback={} egress={} (#3806)",
        resolved.provider,
        resolved.model,
        resolved.is_local(),
        resolved.timeout_secs,
        resolved.fallback.as_str(),
        mode.as_str()
    );
    record(Some(DecisionBootReport {
        state: DecisionProviderState::Constructed,
        provider: resolved.provider.clone(),
        model: resolved.model.clone(),
        local: resolved.is_local(),
        egress_mode: mode.as_str().to_string(),
    }));
    let guard = DecisionEgressGuard::for_resolved(&resolved, pin);
    DecisionBootOutcome::Constructed(Box::new(DecisionProviderHandle {
        resolved,
        guard,
        provider: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every posture is driven through the crate-private `*_under`
    /// seams, so NOTHING here mutates the process-global environment.
    /// `src/**` compiles into ONE lib test binary whose tests run in
    /// parallel threads: a `set_var` there is unsound AND globally
    /// visible, and serializing the mutators does not help because the
    /// victims are the concurrent READERS (#3475 / #2127). The pin that
    /// the PUBLIC entry points actually read `AI_MEMORY_INFERENCE_EGRESS`
    /// lives in its own process: `tests/decision_boot_egress_3806.rs`.
    /// The `/capabilities` snapshot ([`BOOT_REPORT`]) is process-global,
    /// and EVERY pin here writes it by calling the chokepoint. These
    /// tests run in parallel threads of the one lib test binary, so
    /// they take this lock for the whole body. Unlike the `$HOME`
    /// defect class (#2127), a file-local lock is SUFFICIENT here and
    /// provably so: within this binary the only writer is
    /// [`record`] — reachable only through the chokepoint — and the
    /// only reader is [`boot_report`], and every call site of both is
    /// inside this module. A reader elsewhere would make this
    /// insufficient, which is why the production reader
    /// (`build_capabilities_overlay`) is in another binary entirely.
    static SNAPSHOT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the snapshot lock, ignoring poisoning from an unrelated
    /// failing test (we only need mutual exclusion, not invariants).
    fn snapshot_guard() -> std::sync::MutexGuard<'static, ()> {
        SNAPSHOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    const DENY: InferenceEgressMode = InferenceEgressMode::Deny;
    const LOOPBACK: InferenceEgressMode = InferenceEgressMode::LoopbackOnly;
    const ALLOW: InferenceEgressMode = InferenceEgressMode::Allow;

    /// A `[decision]` section pointed at an EXTERNAL endpoint.
    fn remote_cfg(base_url: &str) -> AppConfig {
        toml::from_str(&format!(
            "schema_version = 2\ntier = \"autonomous\"\n\n\
             [decision]\nprovider = \"openai-compatible\"\n\
             model = \"vendor/decider-1\"\nbase_url = \"{base_url}\"\n"
        ))
        .expect("corpus parses")
    }

    /// The W1d in-process provider: no socket, no base_url.
    fn local_cfg() -> AppConfig {
        toml::from_str(
            "schema_version = 2\ntier = \"autonomous\"\n\n\
             [decision]\nprovider = \"local-nli\"\nmodel = \"nli-small\"\n",
        )
        .expect("corpus parses")
    }

    /// A config with NO `[decision]` section — the v1.0.0 path.
    fn unset_cfg() -> AppConfig {
        toml::from_str("schema_version = 2\ntier = \"autonomous\"\n").expect("corpus parses")
    }

    /// Per-test db directory under `.local-runs/` (project no-`/tmp` rule).
    fn fresh_db(label: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local-runs")
            .join("issue-3806-w1b");
        std::fs::create_dir_all(&root).ok();
        let holder = tempfile::Builder::new()
            .prefix(&format!("{label}-"))
            .tempdir_in(&root)
            .expect("tempdir under .local-runs");
        let db = holder.path().join("operator-chosen.db");
        (holder, db)
    }

    /// Count the signed egress-refusal rows in `db`. A db file that was
    /// never created counts as zero — which is itself the assertion for
    /// the arms that must write nothing.
    fn refusal_rows(db: &std::path::Path) -> i64 {
        if !db.exists() {
            return 0;
        }
        let conn = crate::db::open(db).expect("open db for post-hoc assertion");
        conn.query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [crate::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
            |r| r.get(0),
        )
        .expect("count signed_events rows")
    }

    // PIN — `deny` refuses the remote decision endpoint: NO provider is
    // constructed AND a signed refusal row is written. Paired in the same
    // body with its PRESENCE control (`loopback-only` + a loopback
    // base_url DOES construct, and writes NO row), so "no provider" can
    // never pass because the chokepoint builds nothing at all.
    #[test]
    fn deny_refuses_a_remote_provider_and_records_a_signed_refusal_3806() {
        let _snapshot = snapshot_guard();
        // --- ABSENCE: deny => no handle + exactly one refusal row.
        let (_hold_a, db_a) = fresh_db("deny-remote");
        let cfg = remote_cfg("https://decide.internal.example.net/v1");
        let outcome = build_decision_provider_under(DENY, &cfg, &db_a);
        assert_eq!(outcome.state(), DecisionProviderState::RefusedByEgress);
        assert!(
            outcome.handle().is_none(),
            "deny must not construct a remote decision provider (#3806/#1963)"
        );
        assert_eq!(
            refusal_rows(&db_a),
            1,
            "deny must write exactly one signed egress-refusal row"
        );
        assert_eq!(
            boot_report().map(|r| r.state),
            Some(DecisionProviderState::RefusedByEgress)
        );

        // --- PRESENCE: loopback-only + a loopback target => constructed,
        // and NOTHING is written to the audit chain.
        let (_hold_b, db_b) = fresh_db("loopback-ok");
        let cfg = remote_cfg("http://127.0.0.1:11434/v1");
        let outcome = build_decision_provider_under(LOOPBACK, &cfg, &db_b);
        assert_eq!(outcome.state(), DecisionProviderState::Constructed);
        let handle = outcome.handle().expect("loopback target is constructed");
        assert_eq!(handle.base_url(), "http://127.0.0.1:11434/v1");
        assert_eq!(
            refusal_rows(&db_b),
            0,
            "a permitted target must write no refusal row"
        );

        // --- The discriminator: the SAME loopback-only posture against a
        // REMOTE target still refuses, so the presence control above is
        // not passing because loopback-only is a no-op.
        let (_hold_c, db_c) = fresh_db("loopback-remote");
        let cfg = remote_cfg("https://decide.internal.example.net/v1");
        let outcome = build_decision_provider_under(LOOPBACK, &cfg, &db_c);
        assert_eq!(outcome.state(), DecisionProviderState::RefusedByEgress);
        assert_eq!(refusal_rows(&db_c), 1);
    }

    // PIN — `local-nli` opens zero sockets and is ALWAYS constructible:
    // under `deny` it is constructed AND writes no refusal row. This is
    // the presence control that makes the deny pin above discriminating.
    #[test]
    fn local_nli_is_constructed_under_deny_and_writes_no_refusal_row_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("deny-local");
        let cfg = local_cfg();
        let outcome = build_decision_provider_under(DENY, &cfg, &db);
        assert_eq!(
            outcome.state(),
            DecisionProviderState::Constructed,
            "a local provider opens no socket, so `deny` has nothing to refuse"
        );
        let handle = outcome.handle().expect("local provider is constructed");
        assert!(handle.is_local());
        assert_eq!(handle.base_url(), "", "a local provider has no endpoint");
        assert_eq!(
            refusal_rows(&db),
            0,
            "constructing local-nli must write NO egress-refusal row"
        );
        // And its per-call hook permits under the same deny posture,
        // because there is no egress to govern.
        assert!(handle.egress().check_outbound_under(DENY).is_ok());
    }

    // PIN — the resolved, NON-DEFAULT `base_url` reaches the constructed
    // handle. A false mapping in an instrument is worse than a missing
    // one: a handle that silently carried the alias default would send
    // memory content to a host the operator never named, and the egress
    // gate would have approved a DIFFERENT URL than the one POSTed to.
    #[test]
    fn a_non_default_base_url_reaches_the_constructed_handle_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("base-url");

        for url in [
            "https://decide.a.example.net/v1",
            "https://decide.b.example.net/v1",
        ] {
            let cfg = remote_cfg(url);
            let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
            let handle = outcome.handle().expect("allow constructs");
            assert_eq!(
                handle.base_url(),
                url,
                "the handle must carry the RESOLVED url"
            );
            // The guard checks the SAME url the client will POST to.
            assert_eq!(handle.egress().target(), url);
            assert_eq!(handle.model(), "vendor/decider-1");
            assert_eq!(handle.provider_alias(), "openai-compatible");
        }
        // Presence control: the two urls produced DIFFERENT handles, so
        // the assertion above is not satisfied by a constant.
        let a = build_decision_provider_under(
            ALLOW,
            &remote_cfg("https://decide.a.example.net/v1"),
            &db,
        );
        let b = build_decision_provider_under(
            ALLOW,
            &remote_cfg("https://decide.b.example.net/v1"),
            &db,
        );
        assert_ne!(
            a.handle().map(DecisionProviderHandle::base_url),
            b.handle().map(DecisionProviderHandle::base_url)
        );
    }

    // PIN — the capability vocabulary is CLOSED. Every state renders one
    // of exactly four snake_case tokens, each round-trips through serde,
    // and an unexpected token FAILS to deserialize rather than becoming
    // a value a matcher would silently ignore.
    #[test]
    fn the_decision_provider_state_vocabulary_is_closed_3806() {
        let _snapshot = snapshot_guard();
        let expected = ["absent", "configured", "refused_by_egress", "constructed"];
        let rendered: Vec<&str> = DecisionProviderState::all()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(rendered, expected);

        for (state, token) in DecisionProviderState::all().iter().zip(expected) {
            let json = serde_json::to_string(state).expect("serialize");
            assert_eq!(json, format!("\"{token}\""));
            let back: DecisionProviderState = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *state);
            // Never free text: Display and the wire agree.
            assert_eq!(state.to_string(), token);
        }

        // ABSENCE half — an unexpected variant does not render.
        for unknown in [
            "\"degraded\"",
            "\"CONSTRUCTED\"",
            "\"refused-by-egress\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<DecisionProviderState>(unknown).is_err(),
                "{unknown} must NOT deserialize into the closed vocabulary"
            );
        }
    }

    // PIN — `[decision]` unset: the chokepoint returns Absent, resolves
    // nothing, records NO capability snapshot (so the wire key stays
    // omitted, byte-identical v1.0.0) and makes zero decision calls —
    // structurally, because it never touches the db path at all.
    #[test]
    fn decision_unset_returns_absent_records_nothing_and_touches_no_db_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("unset");

        for mode in [DENY, LOOPBACK, ALLOW] {
            let cfg = unset_cfg();
            let outcome = build_decision_provider_under(mode, &cfg, &db);
            assert_eq!(outcome.state(), DecisionProviderState::Absent);
            assert!(outcome.handle().is_none());
            assert!(
                boot_report().is_none(),
                "an unconfigured deployment must record NO capability snapshot"
            );
            assert!(
                !db.exists(),
                "the unset path must not open or create a database"
            );
        }

        // PRESENCE control — the same helpers DO record and DO construct
        // when a section exists, so the absences above are not vacuous.
        let cfg = remote_cfg("http://127.0.0.1:11434/v1");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        assert_eq!(outcome.state(), DecisionProviderState::Constructed);
        assert!(boot_report().is_some());

        // ...and a reload that REMOVES the section clears the snapshot
        // rather than leaving a stale `constructed` claim standing.
        let cfg = unset_cfg();
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        assert_eq!(outcome.state(), DecisionProviderState::Absent);
        assert!(boot_report().is_none());
    }

    // PIN — the per-call hook W1c must call before every request. It
    // consults the posture at CALL time, so a posture tightened after
    // boot refuses subsequent calls on a handle that was legitimately
    // constructed; and it checks the handle's OWN target.
    #[test]
    fn check_outbound_refuses_per_call_and_permits_the_control_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("per-call");

        let cfg = remote_cfg("https://decide.internal.example.net/v1");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        let handle = outcome.handle().expect("allow constructs");

        // PRESENCE — under the posture it was built with, calls proceed.
        assert!(handle.egress().check_outbound_under(ALLOW).is_ok());

        // ABSENCE — the posture tightens under a live daemon; every
        // subsequent call is refused, and the refusal is an ABSTAIN.
        for mode in [DENY, LOOPBACK] {
            let refused = handle
                .egress()
                .check_outbound_under(mode)
                .expect_err("a tightened posture must refuse the outbound call");
            assert_eq!(refused.abstain_reason(), AbstainReason::EgressRefused);
            assert_eq!(refused.target(), "https://decide.internal.example.net/v1");
            assert!(!refused.reason().is_empty());
        }

        // Until W1c attaches a client the handle answers through the
        // always-abstaining NullDecider — never a fabricated verdict.
        assert!(!handle.has_client());
        assert_eq!(
            handle.provider().provider_id(),
            crate::decision::NullDecider::PROVIDER_ID
        );
        assert_eq!(handle.fallback(), DecisionFallback::Abstain);
        assert_eq!(
            handle.timeout().as_secs(),
            crate::decision_config::DEFAULT_TIMEOUT_SECS
        );
        assert!(handle.api_key().is_none());
    }

    const INTERNAL: InferenceEgressMode = InferenceEgressMode::InternalOnly;

    // PIN (#3822 posture 3, the decision lane) — under `internal-only`
    // the chokepoint uses the carrier's RESOLVE-THEN-PIN entry point, not
    // the name-based gate: a HOSTNAME that resolves to internal addresses
    // is admitted, the resolved addresses are carried on the handle for
    // the client to pin, and no refusal row is written. The name-based
    // gate refuses every hostname under `internal-only` (it cannot
    // classify without DNS), so before this the decision lane could not
    // serve posture 3 at all. ABSENCE on the same sink: a PUBLIC target
    // and a cloud-metadata literal are refused with a signed row. (An
    // off-host plaintext target never gets this far: `plan` refuses it
    // at config time, #3823.)
    #[test]
    fn internal_only_admits_and_pins_an_internal_hostname_3822() {
        let _snapshot = snapshot_guard();
        // PRESENCE — `localhost` is a hostname the name-based gate cannot
        // classify; it resolves to loopback, which is internal.
        let (_hold_a, db_a) = fresh_db("internal-host");
        let cfg = remote_cfg("https://localhost:8443/v1");
        let outcome = build_decision_provider_under(INTERNAL, &cfg, &db_a);
        assert_eq!(
            outcome.state(),
            DecisionProviderState::Constructed,
            "internal-only must admit a hostname that resolves internal (#3822)"
        );
        let handle = outcome.handle().expect("constructed");
        let pin = handle
            .egress()
            .pinned()
            .expect("internal-only carries the boot-resolved addresses to the client");
        assert_eq!(pin.host, "localhost");
        assert!(
            !pin.addrs.is_empty() && pin.addrs.iter().all(|a| a.ip().is_loopback()),
            "{:?}",
            pin.addrs
        );
        assert_eq!(refusal_rows(&db_a), 0, "an admitted target writes no row");

        // ABSENCE — a public target, and an off-host plaintext target.
        for (label, url) in [
            ("public", "https://8.8.8.8/v1"),
            ("metadata", "https://169.254.169.254/v1"),
        ] {
            let (_hold, db) = fresh_db(label);
            let outcome = build_decision_provider_under(INTERNAL, &remote_cfg(url), &db);
            assert_eq!(
                outcome.state(),
                DecisionProviderState::RefusedByEgress,
                "{label}"
            );
            assert_eq!(refusal_rows(&db), 1, "{label}: one signed refusal row");
        }

        // The name-based postures carry NO pin (byte-identical legacy).
        let (_hold_b, db_b) = fresh_db("allow-nopin");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db_b);
        assert!(outcome.handle().expect("allow").egress().pinned().is_none());
    }

    // PIN — the per-call re-check under `internal-only` classifies the
    // PINNED addresses (what the client will actually connect to), not
    // the hostname. Without the pin the name-based arm would refuse
    // every call to the host it just admitted.
    #[test]
    fn per_call_internal_only_checks_the_pinned_addresses_3822() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("internal-per-call");
        let cfg = remote_cfg("https://localhost:8443/v1");
        let outcome = build_decision_provider_under(INTERNAL, &cfg, &db);
        let handle = outcome.handle().expect("constructed");
        assert!(
            handle.egress().check_outbound_under(INTERNAL).is_ok(),
            "a pinned internal target must pass the per-call check"
        );
        // A handle built under `allow` has no pin; tightening the live
        // posture to `internal-only` refuses (fail closed, never a DNS
        // lookup at call time).
        let (_hold_b, db_b) = fresh_db("internal-tightened");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db_b);
        let refused = outcome
            .handle()
            .expect("allow")
            .egress()
            .check_outbound_under(INTERNAL)
            .expect_err("no pin => internal-only cannot classify a hostname => refuse");
        assert_eq!(refused.abstain_reason(), AbstainReason::EgressRefused);
    }

    // PIN — a `[decision]` section that cannot resolve yields NO
    // provider (not a half-configured one) and reports `configured`,
    // which is distinct from the never-configured `absent`.
    #[test]
    fn an_unresolvable_section_yields_no_provider_and_reports_configured_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("unresolvable");

        // `openai-compatible` has no compiled default base_url, so this
        // section refuses at the loader AND resolves to nothing here.
        let cfg: AppConfig = toml::from_str(
            "schema_version = 2\ntier = \"autonomous\"\n\n\
             [decision]\nprovider = \"openai-compatible\"\nmodel = \"vendor/decider-1\"\n",
        )
        .expect("corpus parses");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        assert_eq!(outcome.state(), DecisionProviderState::Configured);
        assert!(outcome.handle().is_none());
        assert_eq!(
            refusal_rows(&db),
            0,
            "a resolver refusal is not an egress refusal"
        );

        // PRESENCE control — the same corpus WITH the required key
        // resolves and constructs.
        let cfg = remote_cfg("https://decide.internal.example.net/v1");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        assert_eq!(outcome.state(), DecisionProviderState::Constructed);
    }

    // PIN — Debug on the handle never leaks the credential, and the
    // capability snapshot carries neither the credential nor the
    // endpoint.
    #[test]
    fn handle_debug_redacts_the_credential_3806() {
        let _snapshot = snapshot_guard();
        let (_hold, db) = fresh_db("redaction");
        let keyfile = _hold.path().join("decision.key");
        std::fs::write(&keyfile, "sk-decision-w1b-secret\n").expect("write key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key file");
        }
        let cfg: AppConfig = toml::from_str(&format!(
            "schema_version = 2\ntier = \"autonomous\"\n\n\
             [decision]\nprovider = \"openai-compatible\"\n\
             model = \"vendor/decider-1\"\n\
             base_url = \"https://decide.internal.example.net/v1\"\n\
             api_key_file = \"{}\"\n",
            keyfile.display()
        ))
        .expect("corpus parses");
        let outcome = build_decision_provider_under(ALLOW, &cfg, &db);
        let handle = outcome.handle().expect("allow constructs");
        // PRESENCE — the accessor really does return the secret, so the
        // absence assertion below is not vacuous.
        assert_eq!(handle.api_key(), Some("sk-decision-w1b-secret"));
        for rendered in [format!("{handle:?}"), format!("{handle:#?}")] {
            assert!(
                !rendered.contains("sk-decision-w1b-secret"),
                "the handle's Debug must never contain the key bytes"
            );
        }
        let report = boot_report().expect("recorded");
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(!json.contains("sk-decision-w1b-secret"));
        assert!(!json.contains("decide.internal.example.net"));
        assert_eq!(report.state, DecisionProviderState::Constructed);
    }
}
