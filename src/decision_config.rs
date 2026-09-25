// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1a — the `[decision]` configuration section, its resolver, and
//! the parse-time refusals that keep a decision endpoint from being
//! misconfigured silently. It does NOT touch `[llm.auto_tag]`: #3808
//! landed on the carrier as a boot WARN for that sibling's ignored
//! endpoint keys, and that behaviour is preserved verbatim here so a
//! config without `[decision]` loads byte-identically.
//!
//! Lives in its own module because `src/config.rs` is at its QUAL-10
//! ceiling; `config.rs` carries only the wiring (the `decision` field,
//! one `Debug` line, the validator call, and a thin resolver delegate).
//!
//! ## Wire format
//!
//! ```toml
//! [decision]
//! provider     = "openrouter"   # any [llm] alias, or systemone / local-nli
//! model        = "typesafe/jev-1.13"
//! base_url     = "https://decide.internal.example.net"  # REQUIRED for
//!                                                       # openai-compatible
//!                                                       # and systemone
//! api_key_file = "/etc/ai-memory/keys/decision.key"     # or api_key_env
//! timeout_secs = 2              # default 2; a timeout is an ABSTAIN
//! fallback     = "abstain"      # abstain (default) | generative | refuse
//! ```
//!
//! ## Posture
//!
//! - **Unset `[decision]` is byte-identical v1.0.0.**
//!   [`resolve_decision`] returns `None`, every seam consults
//!   [`crate::decision::NullDecider`], and no code path changes.
//! - **Fail closed, never half-configured.** [`plan`] is the ONE
//!   acceptance predicate: [`validate`] turns its rejection into a LOUD
//!   parse-time refusal naming the key, and [`resolve_decision`] turns
//!   the same rejection into NO provider. The two therefore cannot
//!   disagree about what is acceptable — a config that refuses at load
//!   can never resolve to a live endpoint in some other entry point.
//! - **Secrets.** Inline `api_key` is REJECTED at parse time exactly as
//!   for `[llm]`; `api_key_env` / `api_key_file` are mutually exclusive;
//!   the resolved key is private, redacted in `Debug`, and zeroized on
//!   `Drop`.
//! - **A key is never sent to an endpoint it was not issued for.** The
//!   parent `[llm]` credential is inherited ONLY when the decision
//!   endpoint is literally the same endpoint (same provider AND same
//!   resolved base URL), and there is deliberately no generic
//!   `AI_MEMORY_DECISION_API_KEY` catch-all. This is a deliberate
//!   TIGHTENING of the `resolve_llm_auto_tag` shape this resolver
//!   mirrors, which inherits on a backend-name match alone.

use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, ConfigSource, KeySource, ResolvedLlm, config_keys};
use crate::llm::BACKEND_OLLAMA;

/// Canonical selector for the TypeSafe SystemOne decision endpoint
/// (`POST /v1/systemone`). Requires an operator-supplied `base_url`:
/// the hosted address is not guessed in code.
pub const PROVIDER_SYSTEMONE: &str = "systemone";

/// Canonical selector for the in-process NLI cross-encoder decision
/// provider (W1d). Opens no socket, carries no credential, and resolves
/// its weights from a local path — so `base_url` and every `api_key_*`
/// key are REFUSED for it.
pub const PROVIDER_LOCAL_NLI: &str = "local-nli";

/// Default `[decision].timeout_secs`.
///
/// Operator-measured latency for the reference decision model over a
/// 3-day window, all locations: P50 0.23 s, P90 0.35 s, P99 0.59 s. Two
/// seconds is roughly 3.4x P99 — long enough that a slow-but-healthy
/// endpoint still answers, short enough that a seam's worst case is
/// bounded. A timeout is an ABSTAIN, never a `false`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 2;

/// The section name, used in every refusal message.
const SECTION: &str = "decision";

/// What a seam does when the decision provider cannot answer.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DecisionFallback {
    /// Return an abstain and let the seam take its conservative branch.
    /// The DEFAULT, and the only safe posture on a destructive seam.
    #[default]
    Abstain,
    /// Ask the `[llm]` generative backend instead, reporting
    /// [`crate::decision::DecisionSource::GenerativeFallback`].
    Generative,
    /// Fail the operation when the decision instrument is
    /// UNAVAILABLE, rather than proceed without it.
    ///
    /// Scope, precisely (#3806 R4): `fallback` governs unavailability,
    /// not abstention, so this posture fires on CASE 2 only — no
    /// provider was built, the egress gate refused the endpoint, the
    /// call timed out, the transport failed, the endpoint returned a
    /// non-2xx. It does NOT fire when the provider ANSWERED and
    /// declined (CASE 3), which is terminal under every posture: there
    /// the instrument worked and gave its answer, the seam takes its
    /// conservative NON-ACTION branch, and the operation proceeds.
    ///
    /// The previous wording — "refuse the operation outright rather
    /// than proceed without a decision" — was false for CASE 3, where
    /// the operation does proceed without one. See
    /// [`crate::decision::AbstainReason::is_unavailable`] for the
    /// partition, and `crate::decision_seams` for the three cases.
    Refuse,
}

/// The config key the `fallback` diagnostics name.
const FALLBACK_KEY: &str = "[decision].fallback";

/// Render `[decision].fallback = "<value>"` — the phrase three
/// production diagnostics quote.
///
/// One home since #3806 W2: the seam's `refuse` error, the client
/// factory's "no generative backend to fall back to" error and the boot
/// chokepoint's fallback-bind warning all name this key and its value,
/// and a magic string repeated on three production sites is exactly what
/// the pm-v3.1 literal gate exists to stop.
#[must_use]
pub(crate) fn fallback_phrase(fallback: DecisionFallback) -> String {
    format!("{FALLBACK_KEY} = \"{}\"", fallback.as_str())
}

impl DecisionFallback {
    /// The canonical config / metrics token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abstain => "abstain",
            Self::Generative => "generative",
            Self::Refuse => "refuse",
        }
    }
}

/// `[decision]` block of `config.toml`.
///
/// Mirrors [`crate::config::LlmSection`]'s shape, including the
/// write-only `api_key` trap field: it exists in the schema ONLY so an
/// inline secret is refused with a message that names the mistake,
/// instead of being reported as an unknown key (#3715).
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct DecisionSection {
    /// Provider selector: any `[llm]` backend alias, `openai-compatible`,
    /// `systemone`, or `local-nli`. Unset inherits `[llm].backend`.
    pub provider: Option<String>,
    /// Decision-model identifier, passed verbatim to the endpoint.
    /// REQUIRED unless `provider` resolves to the same backend as
    /// `[llm]`, in which case `[llm].model` is inherited.
    pub model: Option<String>,
    /// Endpoint base URL. REQUIRED for `openai-compatible` and
    /// `systemone`; pre-filled for every vendor alias that has a
    /// documented default; REFUSED for `local-nli`.
    pub base_url: Option<String>,
    /// Name of the process env var holding the API key. Mutually
    /// exclusive with `api_key_file`.
    pub api_key_env: Option<String>,
    /// Path to a `mode 0400` file holding the API key. Mutually
    /// exclusive with `api_key_env`.
    pub api_key_file: Option<String>,
    /// Write-only trap: an inline literal here is REFUSED at parse time.
    /// Never read by the resolver.
    pub api_key: Option<String>,
    /// Per-call timeout. Default [`DEFAULT_TIMEOUT_SECS`]; `0` is
    /// refused (it would make every call an instant abstain).
    pub timeout_secs: Option<u64>,
    /// What a seam does when the provider cannot answer. Default
    /// [`DecisionFallback::Abstain`].
    pub fallback: Option<DecisionFallback>,
}

// Manual `Debug` so a `{:?}` of a `DecisionSection` never echoes an
// inline secret, mirroring `LlmSection` / `ResolvedLlm`. `api_key_env` /
// `api_key_file` are NAMES, not secrets, and render verbatim.
impl std::fmt::Debug for DecisionSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionSection")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field(config_keys::API_KEY_ENV, &self.api_key_env)
            .field(config_keys::API_KEY_FILE, &self.api_key_file)
            .field(
                config_keys::API_KEY,
                &self.api_key.as_ref().map(|_| crate::REDACTED_PLACEHOLDER),
            )
            .field("timeout_secs", &self.timeout_secs)
            .field("fallback", &self.fallback)
            .finish()
    }
}

/// Canonical resolved `[decision]` configuration, produced by
/// [`resolve_decision`]. Its existence means an operator asked for a
/// decision provider AND the request was complete; `None` means no
/// provider, which is the v1.0.0-unchanged path.
///
/// **Secret handling.** `api_key` is private (access via
/// [`Self::api_key`]), redacted by the manual `Debug`, and zeroized by
/// the manual `Drop` — mirroring [`crate::llm::LlmProvider`]. The `Drop`
/// impl means this struct cannot be destructured or moved out of field
/// by field; consume it through its accessors.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedDecision {
    /// Resolved provider alias.
    pub provider: String,
    /// Resolved decision-model identifier.
    pub model: String,
    /// Resolved endpoint base URL. EMPTY for a local provider that
    /// opens no socket (`local-nli`).
    pub base_url: String,
    /// Resolved API key. Private so an accidental `{:?}` cannot leak it.
    api_key: Option<String>,
    /// Where the key came from, for the boot banner / `ai-memory doctor`.
    pub api_key_source: KeySource,
    /// Per-call timeout in seconds.
    pub timeout_secs: u64,
    /// Behaviour when the provider cannot answer.
    pub fallback: DecisionFallback,
    /// Which layer of the precedence ladder supplied the section.
    pub source: ConfigSource,
}

impl ResolvedDecision {
    /// Access the resolved API key. Use only when constructing the
    /// client; never log or `{:?}` the result.
    #[must_use]
    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    /// The per-call timeout as a [`std::time::Duration`].
    #[must_use]
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs)
    }

    /// Whether this provider runs in process and opens no socket. W1b's
    /// egress chokepoint uses this to skip the outbound check because
    /// there is nothing to check — never to WAIVE one.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.provider == PROVIDER_LOCAL_NLI
    }

    /// Display string for the boot banner: `<provider>:<model>`.
    #[must_use]
    pub fn display_label(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }

    /// Zeroize the `api_key` buffer in place. Idempotent; `Drop`
    /// delegates here so the zero-on-secret-loss contract has one
    /// source of truth and tests can observe the post-zeroize state of
    /// a still-live allocation (#1321).
    pub fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        if let Some(key) = self.api_key.as_mut() {
            key.zeroize();
        }
    }
}

impl std::fmt::Debug for ResolvedDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedDecision")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field(
                "api_key",
                &self.api_key.as_ref().map(|_| crate::REDACTED_PLACEHOLDER),
            )
            .field("api_key_source", &self.api_key_source)
            .field("timeout_secs", &self.timeout_secs)
            .field("fallback", &self.fallback)
            .field("source", &self.source)
            .finish()
    }
}

impl Drop for ResolvedDecision {
    /// Zeroize the Bearer token on scope exit so it does not linger on
    /// the heap (the [`crate::llm::LlmProvider`] contract).
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

/// Every provider selector accepted at GA, as one operator-facing
/// string. Assembled from [`crate::config::RECOGNIZED_LLM_BACKENDS`] so the
/// two lists cannot drift.
#[must_use]
pub fn recognized_providers() -> String {
    format!(
        "{}, {PROVIDER_SYSTEMONE}, {PROVIDER_LOCAL_NLI}",
        crate::config::RECOGNIZED_LLM_BACKENDS
    )
}

/// Whether `provider` is an accepted `[decision].provider` selector.
#[must_use]
pub fn is_recognized_provider(provider: &str) -> bool {
    provider == PROVIDER_SYSTEMONE
        || provider == PROVIDER_LOCAL_NLI
        || crate::config::is_recognized_llm_backend(provider)
}

/// The compiled default base URL for a decision provider, or `None`
/// when the operator must supply one (`openai-compatible`, `systemone`)
/// or when the provider has no endpoint at all (`local-nli`).
fn default_base_url(provider: &str) -> Option<&'static str> {
    if provider == BACKEND_OLLAMA {
        return Some(crate::config::backend_default_base_url(BACKEND_OLLAMA));
    }
    crate::llm::default_base_url_for_alias(provider)
}

/// Trim and drop an empty value — the filter every field in the ladder
/// shares (an empty string is not a configuration).
fn non_empty(value: Option<&String>) -> Option<&str> {
    value.map(String::as_str).filter(|s| !s.trim().is_empty())
}

/// The endpoint-shaped half of a resolved section: everything that can
/// be accepted or refused WITHOUT touching a credential. Produced by
/// [`plan`], the single acceptance predicate shared by [`validate`] and
/// [`resolve_decision`].
struct DecisionPlan {
    provider: String,
    model: String,
    base_url: String,
    local: bool,
    /// The decision endpoint is literally the parent `[llm]` endpoint
    /// (same provider AND same resolved base URL) — the ONLY condition
    /// under which the parent credential may be reused.
    same_endpoint_as_parent: bool,
    timeout_secs: u64,
    fallback: DecisionFallback,
}

/// Decide whether `[decision]` is acceptable, and what it means.
///
/// `Ok(None)` — no section, so no provider (the v1.0.0 path).
/// `Ok(Some(plan))` — a complete, acceptable section.
/// `Err(reason)` — an operator-facing refusal that NAMES the key.
///
/// Performs no I/O and reads no credential.
///
/// # Errors
///
/// The section is present but cannot be honoured exactly as written.
fn plan(cfg: &AppConfig, parent: &ResolvedLlm) -> anyhow::Result<Option<DecisionPlan>> {
    let Some(section) = cfg.decision.as_ref() else {
        return Ok(None);
    };

    // 1 — inline api_key literal (mirrors the [llm] rejection verbatim).
    if section.api_key.is_some() {
        anyhow::bail!(crate::config::secret_refusal::inline_key_refusal(SECTION));
    }

    // 2 — env vs file mutex.
    if section.api_key_env.is_some() && section.api_key_file.is_some() {
        anyhow::bail!(format!(
            "[{SECTION}].api_key_env and [{SECTION}].api_key_file are mutually \
             exclusive — set exactly one (or neither, to fall back to the \
             per-vendor env-var chain)."
        ));
    }

    // 3 — unknown provider selector, refused BY NAME so a typo can never
    // resolve to some other vendor's endpoint.
    // `resolve_llm` lower-cases its backend token, so the decision
    // selector is normalised the same way or `provider = "OpenRouter"`
    // would compare unequal to the parent backend.
    let provider = non_empty(section.provider.as_ref())
        .map_or_else(|| parent.backend.clone(), |p| p.trim().to_ascii_lowercase());
    if !is_recognized_provider(&provider) {
        anyhow::bail!(format!(
            "[{SECTION}].provider = {provider:?} is not a recognized decision \
             provider. Valid values: {}",
            recognized_providers()
        ));
    }
    let local = provider == PROVIDER_LOCAL_NLI;
    let inherits_backend = provider == parent.backend;

    // 4 — a local provider with a remote endpoint or a credential is a
    // misconfiguration, not a preference.
    if local {
        for (key, present) in [
            (config_keys::BASE_URL, section.base_url.is_some()),
            (config_keys::API_KEY_ENV, section.api_key_env.is_some()),
            (config_keys::API_KEY_FILE, section.api_key_file.is_some()),
        ] {
            if present {
                anyhow::bail!(format!(
                    "[{SECTION}].{key} is not valid for \
                     `provider = \"{PROVIDER_LOCAL_NLI}\"` — that provider runs in \
                     process, opens no socket and carries no credential. Remove \
                     the key, or choose a remote provider."
                ));
            }
        }
    }

    // 5 — a model we will not guess.
    let model = match non_empty(section.model.as_ref()) {
        Some(model) => model.to_string(),
        None if inherits_backend => parent.model.clone(),
        None => {
            anyhow::bail!(format!(
                "[{SECTION}].model is REQUIRED when `[{SECTION}].provider` differs \
                 from `[llm].backend` — the decision model is never inferred \
                 from the provider."
            ));
        }
    };

    // 6 — an endpoint we will not guess.
    let base_url = if local {
        String::new()
    } else {
        match non_empty(section.base_url.as_ref()) {
            Some(url) => url.to_string(),
            None if inherits_backend => parent.base_url.clone(),
            None => match default_base_url(&provider) {
                Some(url) => url.to_string(),
                None => {
                    anyhow::bail!(format!(
                        "[{SECTION}].base_url is REQUIRED for `provider = \
                         {provider:?}` — there is no compiled default endpoint \
                         for it, and one is never guessed."
                    ));
                }
            },
        }
    };

    // 6b — #3823: the carrier's transit floor, applied to the SECOND
    // inference endpoint. A non-loopback plaintext `http` endpoint would
    // ship memory content off the host UNENCRYPTED; it is refused here
    // whether the URL was written under `[decision]` or INHERITED from
    // `[llm]`, with the SAME predicate pair the `[llm]` / `[embeddings]`
    // config check and the boot egress backstop read
    // (`url_is_plaintext_http` + `target_is_loopback`). The refusal names
    // the key and the scheme, never the host. Loopback stays the pinned
    // allowed path (the loopback-included standard is #3824, deferred).
    if !local
        && crate::transit_encryption::url_is_plaintext_http(&base_url)
        && !crate::egress::target_is_loopback(&base_url)
    {
        let key = if non_empty(section.base_url.as_ref()).is_some() {
            format!("[{SECTION}].{}", config_keys::BASE_URL)
        } else {
            format!("[llm].{} (inherited by [{SECTION}])", config_keys::BASE_URL)
        };
        anyhow::bail!(format!(
            "inference endpoint `{key}` uses the plaintext `http` scheme to a \
             non-loopback host, so memory content would leave this host \
             UNENCRYPTED (#3823). Use an `https://` endpoint (or a local \
             TLS-terminating proxy); a loopback endpoint over http is permitted."
        ));
    }

    // 6c — W1c ruling 2: a `systemone` base URL that already carries the
    // route would POST to the route twice. Refused, naming the suffix.
    if provider == PROVIDER_SYSTEMONE {
        let route = crate::decision_clients::systemone::DefaultSystemOneWire::ROUTE;
        if base_url.trim_end_matches('/').ends_with(route) {
            anyhow::bail!(format!(
                "[{SECTION}].{} must be the server root, not the route: it ends in \
                 `{route}`, which the client appends itself, so every call would go to \
                 `{route}{route}`. Remove the `{route}` suffix.",
                config_keys::BASE_URL
            ));
        }
    }

    // 7 — a zero timeout would make every call an instant abstain.
    let timeout_secs = match section.timeout_secs {
        Some(0) => {
            anyhow::bail!(format!(
                "[{SECTION}].timeout_secs = 0 is refused — every call would abstain \
                 before it was made. Omit the key for the default of \
                 {DEFAULT_TIMEOUT_SECS}s, or set a positive value."
            ));
        }
        Some(secs) => secs,
        None => DEFAULT_TIMEOUT_SECS,
    };

    let same_endpoint_as_parent = !local && inherits_backend && base_url == parent.base_url;
    Ok(Some(DecisionPlan {
        provider,
        model,
        base_url,
        local,
        same_endpoint_as_parent,
        timeout_secs,
        fallback: section.fallback.unwrap_or_default(),
    }))
}

/// Resolve the `[decision]` provider configuration.
///
/// Returns `None` — meaning NO decision provider, the byte-identical
/// v1.0.0 path — when the section is absent, or when [`plan`] refuses
/// it. Staying total (rather than returning a `Result`) keeps every
/// caller on the fail-closed branch even for an `AppConfig` built in
/// memory that never crossed the loader's [`validate`] call.
///
/// Per-field ladder, mirroring the parent-fallback shape of
/// `AppConfig::resolve_llm_auto_tag`:
///
/// - `provider`: `[decision].provider` > `[llm].backend`.
/// - `model`: `[decision].model` > `[llm].model` **only when the
///   provider matches the parent backend** > refuse.
/// - `base_url`: `[decision].base_url` > `[llm].base_url` **only when
///   the provider matches the parent backend** > the alias default >
///   refuse (always empty for `local-nli`).
/// - `api_key`: the parent `[llm]` key **only when provider AND
///   base_url both match the parent endpoint** (it is then literally the
///   same endpoint) > per-vendor alias env > `[decision].api_key_env` >
///   `[decision].api_key_file` > none. There is deliberately no
///   `AI_MEMORY_DECISION_API_KEY`-style catch-all: a generic env var
///   would ship the chat credential to a different vendor's host.
#[must_use]
pub fn resolve_decision(cfg: &AppConfig) -> Option<ResolvedDecision> {
    let section = cfg.decision.as_ref()?;
    let parent = cfg.resolve_llm(None, None, None);
    let plan = plan(cfg, &parent).ok().flatten()?;

    let (api_key, api_key_source) = if plan.local {
        (None, KeySource::None)
    } else if plan.same_endpoint_as_parent {
        (
            parent.api_key().map(str::to_string),
            parent.api_key_source.clone(),
        )
    } else {
        crate::config::resolve_api_key_ladder(
            None,
            &plan.provider,
            non_empty(section.api_key_env.as_ref()),
            non_empty(section.api_key_file.as_ref()),
            SECTION,
        )
    };

    Some(ResolvedDecision {
        provider: plan.provider,
        model: plan.model,
        base_url: plan.base_url,
        api_key,
        api_key_source,
        timeout_secs: plan.timeout_secs,
        fallback: plan.fallback,
        source: ConfigSource::Config,
    })
}

impl AppConfig {
    /// #3806 — resolve the `[decision]` structured-decision provider.
    ///
    /// Delegates to [`resolve_decision`], which owns the ladder, the
    /// refusals and the key discipline. `None` means NO decision
    /// provider: the section is absent, or it is present but could not be
    /// honoured exactly as written — in which case the loader has already
    /// refused it by name. Lives here, not in `src/config.rs`, because that
    /// file is at its QUAL-10 ceiling. Independent of `[llm.auto_tag]`,
    /// whose ignored endpoint keys keep the #3808 boot WARN.
    #[must_use]
    pub fn resolve_decision(&self) -> Option<ResolvedDecision> {
        resolve_decision(self)
    }
}

/// Parse-time refusals for `[decision]`. Called from
/// `AppConfig::validate_secret_handling`, which both boot loaders reach.
///
/// Every refusal NAMES the offending key, because a config that is
/// accepted and then ignored is the defect this closes.
///
/// # Errors
///
/// Returns the operator-facing refusal text for the first violation.
pub(crate) fn validate(cfg: &AppConfig) -> anyhow::Result<()> {
    // Byte-identical-when-unset, structurally: with no `[decision]`
    // section this function does not even resolve the parent `[llm]`
    // view, so the load path executes exactly the instructions it did
    // before this commit.
    if cfg.decision.is_none() {
        return Ok(());
    }
    let parent = cfg.resolve_llm(None, None, None);
    plan(cfg, &parent).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmSection;
    use crate::llm::BACKEND_OPENAI_COMPATIBLE;

    fn parse(toml_src: &str) -> AppConfig {
        toml::from_str::<AppConfig>(toml_src).expect("fixture parses")
    }

    fn openrouter_section() -> DecisionSection {
        DecisionSection {
            provider: Some("openrouter".to_string()),
            model: Some("vendor/decider-1".to_string()),
            ..DecisionSection::default()
        }
    }

    /// Assert the section is refused and hand back the rendered text.
    fn expect_refusal(cfg: &AppConfig, why: &str) -> String {
        match validate(cfg) {
            Ok(()) => panic!("{why}"),
            Err(e) => e.to_string(),
        }
    }

    fn with_decision(section: DecisionSection) -> AppConfig {
        AppConfig {
            decision: Some(section),
            ..AppConfig::default()
        }
    }

    // ---- PIN (a): `[decision]` unset => no provider -----------------
    #[test]
    fn decision_unset_resolves_to_no_provider_and_set_resolves_to_one() {
        // ABSENCE — a default config and a populated non-decision config
        // both report NO provider.
        assert!(resolve_decision(&AppConfig::default()).is_none());
        let cfg = parse(
            "schema_version = 2\ntier = \"autonomous\"\n\n\
             [llm]\nbackend = \"ollama\"\nmodel = \"gemma3:4b\"\n",
        );
        assert!(cfg.decision.is_none());
        assert!(
            resolve_decision(&cfg).is_none(),
            "no [decision] section must mean NO decision provider"
        );
        assert!(validate(&cfg).is_ok());

        // PRESENCE control — the same sink carries a provider.
        let cfg = parse(
            "schema_version = 2\n\n[llm]\nbackend = \"ollama\"\n\n\
             [decision]\nprovider = \"openrouter\"\nmodel = \"vendor/decider-1\"\n",
        );
        let resolved = resolve_decision(&cfg).expect("a configured section resolves");
        assert_eq!(resolved.provider, "openrouter");
        assert_eq!(resolved.model, "vendor/decider-1");
        assert_eq!(resolved.source, ConfigSource::Config);
        assert_eq!(resolved.display_label(), "openrouter:vendor/decider-1");
    }

    // ---- PIN (g): timeout default is 2 ------------------------------
    #[test]
    fn timeout_defaults_to_two_seconds_and_an_explicit_value_wins() {
        let cfg = with_decision(openrouter_section());
        let resolved = resolve_decision(&cfg).expect("resolves");
        assert_eq!(resolved.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(resolved.timeout_secs, 2, "the GA default is 2s, not 5s");
        assert_eq!(resolved.timeout(), std::time::Duration::from_secs(2));

        let cfg = with_decision(DecisionSection {
            timeout_secs: Some(9),
            ..openrouter_section()
        });
        assert_eq!(resolve_decision(&cfg).expect("resolves").timeout_secs, 9);
    }

    // ---- PIN (f): fallback default is abstain; `refuse` parses ------
    #[test]
    fn fallback_defaults_to_abstain_and_every_token_parses() {
        let cfg = with_decision(openrouter_section());
        assert_eq!(
            resolve_decision(&cfg).expect("resolves").fallback,
            DecisionFallback::Abstain,
            "the default fallback on a destructive seam must be abstain"
        );

        for (token, expected) in [
            ("abstain", DecisionFallback::Abstain),
            ("generative", DecisionFallback::Generative),
            ("refuse", DecisionFallback::Refuse),
        ] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\nfallback = \"{token}\"\n"
            ));
            assert_eq!(
                resolve_decision(&cfg).expect("resolves").fallback,
                expected,
                "`fallback = {token:?}` must parse"
            );
            assert_eq!(expected.as_str(), token);
        }

        assert!(
            toml::from_str::<AppConfig>("[decision]\nfallback = \"maybe\"\n").is_err(),
            "an unknown fallback token must not parse"
        );
    }

    // ---- PIN (c): inline api_key refused, api_key_file accepted -----
    #[test]
    fn inline_api_key_is_refused_and_api_key_file_is_accepted() {
        let cfg =
            parse("[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\napi_key = \"sk-live\"\n");
        let err = expect_refusal(&cfg, "an inline key must be refused");
        assert!(err.contains("[decision]"), "{err}");
        assert!(err.contains("api_key"), "{err}");
        assert!(
            !err.contains("sk-live"),
            "the refusal must not echo the secret: {err}"
        );
        assert!(
            resolve_decision(&cfg).is_none(),
            "a refused section must never resolve to a live endpoint"
        );

        // PRESENCE control on the same sink.
        let cfg = parse(
            "[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\n\
             api_key_file = \"/etc/ai-memory/keys/decision.key\"\n",
        );
        assert!(validate(&cfg).is_ok(), "api_key_file must be accepted");
        assert!(resolve_decision(&cfg).is_some());
        let cfg = parse(
            "[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\napi_key_env = \"DECIDER_KEY\"\n",
        );
        assert!(validate(&cfg).is_ok(), "api_key_env must be accepted");
    }

    #[test]
    fn api_key_env_and_api_key_file_are_mutually_exclusive() {
        let cfg = parse(
            "[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\n\
             api_key_env = \"K\"\napi_key_file = \"/k\"\n",
        );
        let err = expect_refusal(&cfg, "the mutex must fire");
        assert!(err.contains("mutually"), "{err}");
        assert!(resolve_decision(&cfg).is_none());
    }

    // ---- PIN (d): unknown provider refused, every alias accepted ----
    #[test]
    fn every_ga_alias_parses_and_an_unknown_selector_is_refused() {
        let aliases: Vec<String> = recognized_providers()
            .split(',')
            .map(|a| a.trim().to_string())
            .collect();
        assert!(
            aliases.len() >= 18,
            "the GA alias set must not silently shrink: {aliases:?}"
        );

        for alias in &aliases {
            let mut section = DecisionSection {
                provider: Some(alias.clone()),
                model: Some("vendor/decider-1".to_string()),
                ..DecisionSection::default()
            };
            if alias == BACKEND_OPENAI_COMPATIBLE || alias == PROVIDER_SYSTEMONE {
                section.base_url = Some("https://decide.internal.example.net".to_string());
            }
            let cfg = with_decision(section);
            assert!(
                validate(&cfg).is_ok(),
                "alias {alias:?} must be accepted: {:?}",
                validate(&cfg)
            );
            assert!(
                resolve_decision(&cfg).is_some(),
                "alias {alias:?} must resolve to a provider"
            );
            assert!(is_recognized_provider(alias), "alias {alias:?}");
        }
        for required in [PROVIDER_SYSTEMONE, PROVIDER_LOCAL_NLI, "openrouter"] {
            assert!(
                aliases.iter().any(|a| a == required),
                "{required} must be a GA alias"
            );
        }

        // ABSENCE — a typo is refused BY NAME and resolves to nothing.
        let cfg = with_decision(DecisionSection {
            provider: Some("openrouterr".to_string()),
            model: Some("m".to_string()),
            ..DecisionSection::default()
        });
        let err = expect_refusal(&cfg, "an unknown provider must be refused");
        assert!(
            err.contains("openrouterr"),
            "the refusal must name the value: {err}"
        );
        assert!(
            err.contains(PROVIDER_SYSTEMONE),
            "the refusal must list the accepted set: {err}"
        );
        assert!(
            resolve_decision(&cfg).is_none(),
            "an unrecognized provider must never resolve to an endpoint"
        );
    }

    #[test]
    fn a_local_provider_refuses_a_base_url_or_a_credential() {
        for key in [
            "base_url = \"http://x\"",
            "api_key_env = \"K\"",
            "api_key_file = \"/k\"",
        ] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"local-nli\"\nmodel = \"nli\"\n{key}\n"
            ));
            let err = expect_refusal(&cfg, "this section must be refused");
            assert!(err.contains(PROVIDER_LOCAL_NLI), "{key}: {err}");
            assert!(
                resolve_decision(&cfg).is_none(),
                "{key}: a refused local provider must not resolve"
            );
        }

        // PRESENCE control.
        let cfg = parse("[decision]\nprovider = \"local-nli\"\nmodel = \"nli\"\n");
        assert!(validate(&cfg).is_ok());
        let resolved = resolve_decision(&cfg).expect("a bare local provider resolves");
        assert!(resolved.is_local());
        assert!(
            resolved.base_url.is_empty(),
            "a local provider has no endpoint"
        );
        assert_eq!(resolved.api_key(), None);
        assert_eq!(resolved.api_key_source, KeySource::None);
    }

    #[test]
    fn an_endpoint_without_a_compiled_default_must_be_named() {
        for provider in [BACKEND_OPENAI_COMPATIBLE, PROVIDER_SYSTEMONE] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"{provider}\"\nmodel = \"m\"\n"
            ));
            let err = expect_refusal(&cfg, "this section must be refused");
            assert!(err.contains("base_url"), "{provider}: {err}");
            assert!(resolve_decision(&cfg).is_none(), "{provider}");

            let cfg = parse(&format!(
                "[decision]\nprovider = \"{provider}\"\nmodel = \"m\"\n\
                 base_url = \"https://decide.internal.example.net\"\n"
            ));
            assert!(validate(&cfg).is_ok(), "{provider}");
            assert_eq!(
                resolve_decision(&cfg).expect("resolves").base_url,
                "https://decide.internal.example.net"
            );
        }
    }

    #[test]
    fn a_model_is_required_unless_the_parent_backend_is_inherited() {
        let cfg = parse("[llm]\nbackend = \"ollama\"\n\n[decision]\nprovider = \"openrouter\"\n");
        let err = expect_refusal(&cfg, "this section must be refused");
        assert!(err.contains("model"), "{err}");
        assert!(resolve_decision(&cfg).is_none());

        // PRESENCE control — the same provider as the parent inherits.
        // #3823: over a LOOPBACK endpoint, the pinned allowed path.
        let cfg = parse(
            "[llm]\nbackend = \"ollama\"\nmodel = \"gemma3:4b\"\n\
             base_url = \"http://127.0.0.1:11434\"\n\n\
             [decision]\nprovider = \"ollama\"\n",
        );
        assert!(validate(&cfg).is_ok());
        let resolved = resolve_decision(&cfg).expect("resolves");
        assert_eq!(resolved.model, "gemma3:4b");
        assert_eq!(resolved.base_url, "http://127.0.0.1:11434");
    }

    // ---- #3823: the two acceptances that encoded the defect ---------
    /// #3823 named these two values: W1a pinned that a NON-LOOPBACK
    /// plaintext `http` endpoint RESOLVES. They are now refusal pins —
    /// at config time (the loader names the key) AND in the resolver
    /// (an in-memory config never reaches a client) — whether the URL
    /// is written under `[decision]` or INHERITED from `[llm]`. The
    /// loopback and `https` spellings of the same endpoints are the
    /// allowed-path controls on the same sink.
    #[test]
    fn a_non_loopback_plaintext_decision_endpoint_is_refused_3823() {
        // Inherited from `[llm]` (the gpu.internal acceptance, inverted).
        let inherited = parse(
            "[llm]\nbackend = \"ollama\"\nmodel = \"gemma3:4b\"\n\
             base_url = \"http://gpu.internal:11434\"\n\n\
             [decision]\nprovider = \"ollama\"\n",
        );
        // Written under `[decision]` (the chat.internal acceptance, inverted).
        let explicit = parse(
            "[decision]\nprovider = \"lmstudio\"\nmodel = \"vendor/decider-1\"\n\
             base_url = \"http://chat.internal:1234/v1\"\n",
        );
        for (label, cfg) in [("inherited", &inherited), ("explicit", &explicit)] {
            let err = expect_refusal(cfg, "off-host plaintext must be refused");
            assert!(
                err.contains("base_url"),
                "{label}: must name the key: {err}"
            );
            assert!(err.contains("http"), "{label}: must name the scheme: {err}");
            assert!(
                !err.contains("gpu.internal") && !err.contains("chat.internal"),
                "{label}: the refusal names the key and scheme, not the host: {err}"
            );
            assert!(resolve_decision(cfg).is_none(), "{label}: no provider");
        }
        // ALLOWED-PATH controls: https off-host, and http on loopback.
        for url in [
            "https://chat.internal:1234/v1",
            "http://127.0.0.1:1234/v1",
            "http://localhost:1234/v1",
            "http://[::1]:1234/v1",
        ] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"lmstudio\"\nmodel = \"vendor/decider-1\"\n\
                 base_url = \"{url}\"\n"
            ));
            assert!(validate(&cfg).is_ok(), "{url} must be accepted");
            assert_eq!(resolve_decision(&cfg).expect("resolves").base_url, url);
        }
    }

    /// W1c ruling 2 (2026-09-19) — a `systemone` `base_url` that already
    /// ends in the route path would POST to `/v1/systemone/v1/systemone`.
    /// Refused at config time, naming the key and the offending suffix.
    #[test]
    fn a_systemone_base_url_carrying_the_route_is_refused() {
        for url in [
            "https://decide.example.net/v1/systemone",
            "https://decide.example.net/v1/systemone/",
        ] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"systemone\"\nmodel = \"m\"\nbase_url = \"{url}\"\n"
            ));
            let err = expect_refusal(&cfg, "a doubled route must be refused");
            assert!(err.contains("base_url"), "{err}");
            assert!(err.contains("/v1/systemone"), "names the suffix: {err}");
            assert!(resolve_decision(&cfg).is_none());
        }
        // ALLOWED-PATH control: the server root, and a prefix path.
        for url in [
            "https://decide.example.net",
            "https://decide.example.net/gw",
        ] {
            let cfg = parse(&format!(
                "[decision]\nprovider = \"systemone\"\nmodel = \"m\"\nbase_url = \"{url}\"\n"
            ));
            assert!(validate(&cfg).is_ok(), "{url}");
        }
    }

    #[test]
    fn a_zero_timeout_is_refused() {
        let cfg = parse("[decision]\nprovider = \"openrouter\"\nmodel = \"m\"\ntimeout_secs = 0\n");
        let err = expect_refusal(&cfg, "this section must be refused");
        assert!(err.contains("timeout_secs"), "{err}");
        assert!(resolve_decision(&cfg).is_none());
    }

    // ---- PIN (e): Debug never contains the key bytes ----------------
    #[test]
    fn debug_redacts_the_key_on_both_the_section_and_the_resolved_struct() {
        const SECRET: &str = "sk-decision-do-not-print";

        let section = DecisionSection {
            api_key: Some(SECRET.to_string()),
            ..openrouter_section()
        };
        let rendered = format!("{section:?}");
        assert!(
            !rendered.contains(SECRET),
            "section Debug leaked the key: {rendered}"
        );
        assert!(rendered.contains(crate::REDACTED_PLACEHOLDER), "{rendered}");

        let mut resolved = ResolvedDecision {
            provider: "openrouter".to_string(),
            model: "vendor/decider-1".to_string(),
            base_url: "https://openrouter.ai/api/v1".to_string(),
            api_key: Some(SECRET.to_string()),
            api_key_source: KeySource::ConfigFile("/etc/ai-memory/keys/decision.key".to_string()),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            fallback: DecisionFallback::Abstain,
            source: ConfigSource::Config,
        };
        for rendered in [format!("{resolved:?}"), format!("{resolved:#?}")] {
            assert!(
                !rendered.contains(SECRET),
                "resolved Debug leaked the key: {rendered}"
            );
            assert!(rendered.contains(crate::REDACTED_PLACEHOLDER), "{rendered}");
        }

        // PRESENCE control — the key IS reachable through the accessor,
        // so the absence assertions above are not vacuous.
        assert_eq!(resolved.api_key(), Some(SECRET));

        // Drop zeroizes; probe through the helper on a live allocation.
        resolved.zeroize_secrets();
        assert_ne!(resolved.api_key(), Some(SECRET));
        assert_eq!(
            resolved.api_key(),
            Some(""),
            "zeroize must clear the buffer in place"
        );
    }

    #[test]
    fn the_parent_credential_travels_only_to_the_parent_endpoint() {
        // `lmstudio` has NO per-vendor env fallback, so nothing in the
        // ambient process environment can supply this key: the only
        // channel is the parent's `api_key_file`.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("parent.key");
        std::fs::write(&key_path, "sk-parent-only\n").expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400))
                .expect("chmod 0400");
        }
        let key_path = key_path.display().to_string();

        let llm = LlmSection {
            backend: Some("lmstudio".to_string()),
            model: Some("vendor/chat-1".to_string()),
            base_url: Some("https://chat.internal:1234/v1".to_string()),
            api_key_env: None,
            api_key_file: Some(key_path),
            api_key: None,
            auto_tag: None,
        };

        // PRESENCE — the same endpoint inherits the parent credential.
        let cfg = AppConfig {
            llm: Some(llm.clone()),
            decision: Some(DecisionSection {
                provider: Some("lmstudio".to_string()),
                model: Some("vendor/decider-1".to_string()),
                ..DecisionSection::default()
            }),
            ..AppConfig::default()
        };
        let resolved = resolve_decision(&cfg).expect("resolves");
        assert_eq!(resolved.base_url, "https://chat.internal:1234/v1");
        assert!(
            resolved.api_key().is_some(),
            "the SAME endpoint inherits the parent credential"
        );

        // ABSENCE — a different endpoint does NOT.
        let cfg = AppConfig {
            llm: Some(llm),
            decision: Some(DecisionSection {
                provider: Some("lmstudio".to_string()),
                model: Some("vendor/decider-1".to_string()),
                base_url: Some("https://decide.internal:1234/v1".to_string()),
                ..DecisionSection::default()
            }),
            ..AppConfig::default()
        };
        let resolved = resolve_decision(&cfg).expect("resolves");
        assert_eq!(resolved.base_url, "https://decide.internal:1234/v1");
        assert_eq!(
            resolved.api_key(),
            None,
            "a DIFFERENT endpoint must never receive the parent's credential"
        );
    }

    // ---- #3808 stays a WARN, not a refusal (carrier semantics) -----
    #[test]
    fn auto_tag_endpoint_keys_are_not_refused_by_the_decision_validator() {
        // The carrier landed #3808 as a one-shot boot WARN; `[decision]`
        // must not tighten it into a refusal, or a config with no
        // `[decision]` section would stop loading (byte-identity).
        for key in [
            "backend = \"ollama\"",
            "base_url = \"http://127.0.0.1:11434\"",
            "api_key_env = \"K\"",
            "api_key_file = \"/k\"",
        ] {
            let cfg = parse(&format!(
                "[llm]\nbackend = \"ollama\"\n\n[llm.auto_tag]\n{key}\n"
            ));
            assert!(
                validate(&cfg).is_ok(),
                "{key} must still parse (#3808 WARN)"
            );
        }
    }

    #[test]
    fn the_accepted_leaf_set_carries_every_decision_key() {
        let leaves = crate::config::unknown_keys::accepted_leaf_keys();
        for key in [
            "decision.provider",
            "decision.model",
            "decision.base_url",
            "decision.api_key_env",
            "decision.api_key_file",
            "decision.api_key",
            "decision.timeout_secs",
            "decision.fallback",
        ] {
            assert!(
                leaves.contains(&key.to_string()),
                "{key} must be an accepted config key, else #3715 refuses it as unknown"
            );
        }
    }
}
