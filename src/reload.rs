// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Live `[llm]` configuration reload (#2166).
//!
//! The long-lived serve processes (the HTTP daemon and the MCP stdio
//! loop) resolve and build the `[llm]` client ONCE at boot. Before this
//! module the only way to change the MCP-invoked LLM model/provider was a
//! full `ai-memory serve` / MCP restart — the per-sweep curator path was
//! already effectively hot because it re-runs `AppConfig::load()` each
//! cycle, but the serve paths captured the boot client for the process
//! lifetime.
//!
//! This module hosts the **`[llm]`-only** hot-swap orchestration:
//!
//! - [`SwappableLlm`] — a concurrency-safe holder over the current
//!   `[llm]` client. It implements [`AutonomyLlm`] by resolving the
//!   CURRENT handle per call, so any consumer that is armed with it ONCE
//!   at boot always observes the live client with no re-arming
//!   (capture-inversion). Reads clone a cheap `Arc` under a read lock and
//!   drop the guard immediately, so NO lock guard is ever held across an
//!   `.await` (`async-no-lock-await` / `anti-lock-across-await`).
//! - [`Swappable`] — the generic sibling used for the resolved-model
//!   surface so `memory_capabilities` does not lie about the active model
//!   after a swap.
//! - [`resolve_and_build_mcp_llm`] — the shared synchronous MCP builder
//!   used at boot AND on reload (re-runs the #1963 inference-egress gate +
//!   provenance logging).
//! - [`reload_http_llm`] — the HTTP-daemon SIGHUP reload routine (reuses
//!   the async [`crate::daemon_runtime::build_llm_client`], which re-runs
//!   the egress gate for free).
//!
//! **Scope: `[llm]` client + the two per-op LLM handlers.** A reload
//! rebuilds the `[llm]` chat client, refreshes the `memory_capabilities`
//! model surface, AND — since #2172 — rebuilds the `memory_atomise`
//! (`LlmCurator`) and `memory_ingest_multistep` (`OllamaDispatch`) MCP
//! handlers from the freshly-resolved client, so EVERY per-op LLM consumer
//! resolves the CURRENT model after a swap (and the signed
//! `atomisation_complete` `curator_model` attests the client that actually
//! ran, never the boot string). The embedder is deliberately NOT
//! hot-swapped (changing the embedding model mid-corpus corrupts the shared
//! vector space; the sanctioned path stays `ai-memory reembed`), and the
//! reranker sits in a first-writer-wins `OnceLock` — neither is touched.
//!
//! **Restart-only sibling knobs (#2174).** A `[llm]` config edit can
//! co-move with a few sibling knobs that a reload deliberately does NOT
//! refresh (worst case: a stale sibling until restart — no data
//! corruption). Per-sibling disposition:
//!
//! - `auto_tag_model` (`[llm.auto_tag].model`) IS `[llm]`-family, but it is
//!   an `Arc<Option<String>>` `AppState` field constructed at ~140 call
//!   sites; hot-swapping it is a `Swappable` public-field migration
//!   tracked as a focused follow-up. Until then a changed auto-tag model
//!   override needs a restart — auto-tags are disposable/regenerable, so
//!   this is a convenience gap, not an integrity one.
//! - `llm_call_timeout` (`llm_call_timeout_secs`) is NOT part of `[llm]` —
//!   it is a separate top-level knob for the per-call wall-clock timeout,
//!   independent of which model/provider `[llm]` selects. Restart-only.
//! - `tier` is NOT `[llm]`-derived — it is a top-level knob that ALSO
//!   gates the embedder + reranker (which are deliberately not hot-swapped
//!   above). Refreshing it in an `[llm]`-only reload would half-apply a
//!   tier change (new tier for the LLM gate, boot tier for the other two
//!   planes) — an inconsistent state, so a `tier` change stays restart-only
//!   to re-tier all three planes together.
//!
//! **Validate-before-swap.** Reload resolves through
//! [`AppConfig::try_load`], which PROPAGATES a parse/validate error
//! instead of silently returning `AppConfig::default()` the way
//! `AppConfig::load_from` does. On failure the current client is KEPT and
//! a loud WARN is logged — a typo'd config can never swap in the
//! compiled-default model.
//!
//! Rule IDs applied: `own-arc-shared`, `own-rwlock-readers`,
//! `async-no-lock-await`, `anti-lock-across-await`, `err-no-unwrap-prod`,
//! `obs-structured-fields`, M-SERVICES-CLONE, M-TYPES-SEND,
//! M-STRONG-TYPES-GUARD.

use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::autonomy::AutonomyLlm;
use crate::config::{AppConfig, ConfigSource, ResolvedModels, TierConfig};
use crate::llm::OllamaClient;

/// Concurrency-safe swap holder for an immutable value shared across the
/// axum handler pool.
///
/// Reads outnumber writes by many orders of magnitude (a swap happens
/// only on SIGHUP / a config-mtime change), so an `RwLock` guarding an
/// `Arc<T>` is the right primitive (`own-rwlock-readers`). Every read
/// clones the inner `Arc` and drops the guard before returning, so a
/// caller never holds the lock across an `.await`
/// (`anti-lock-across-await`).
#[derive(Debug)]
pub struct Swappable<T> {
    inner: RwLock<Arc<T>>,
}

impl<T> Swappable<T> {
    /// Wrap an owned value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(Arc::new(value)),
        }
    }

    /// Snapshot the current value. Clones a cheap `Arc` and releases the
    /// read lock immediately (`M-SERVICES-CLONE`), so the returned handle
    /// may be held across an `.await` with no lock contention.
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Atomically replace the current value (the reload / SIGHUP path).
    pub fn store(&self, value: T) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(value);
    }
}

/// The single swap point for the `[llm]` client.
///
/// A newtype (`M-STRONG-TYPES-GUARD`) over `Swappable<Option<OllamaClient>>`
/// so it can carry the [`AutonomyLlm`] impl that resolves the CURRENT
/// client per call. `None` means "no LLM wired" (keyword/semantic tier,
/// unreachable backend, or the #1963 egress gate refused the target) —
/// exactly the degraded posture the substrate already tolerates, so each
/// trait method is a graceful no-op in that case.
///
/// No `Debug` derive: [`OllamaClient`] is not `Debug` (matching the
/// pre-#2166 `Arc<Option<OllamaClient>>` `AppState` field).
pub struct SwappableLlm {
    inner: Swappable<Option<OllamaClient>>,
}

impl SwappableLlm {
    /// Arm the swap point with the boot-resolved client (or `None`).
    #[must_use]
    pub fn new(client: Option<OllamaClient>) -> Self {
        Self {
            inner: Swappable::new(client),
        }
    }

    /// Snapshot the current client handle. Clones an `Arc` and releases
    /// the read lock immediately, so the handle can be carried across an
    /// `.await` boundary (`anti-lock-across-await`).
    #[must_use]
    pub fn current(&self) -> Arc<Option<OllamaClient>> {
        self.inner.current()
    }

    /// `true` when no client is currently wired.
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.inner.current().is_none()
    }

    /// Atomically replace the current client (SIGHUP / reload path). A
    /// `None` legitimately disables the client (egress `deny`, tier
    /// change).
    pub fn store(&self, client: Option<OllamaClient>) {
        self.inner.store(client);
    }
}

impl AutonomyLlm for SwappableLlm {
    fn auto_tag(&self, title: &str, content: &str) -> anyhow::Result<Vec<String>> {
        match self.current().as_ref() {
            Some(client) => AutonomyLlm::auto_tag(client, title, content),
            None => Ok(Vec::new()),
        }
    }

    fn detect_contradiction(&self, mem_a: &str, mem_b: &str) -> anyhow::Result<bool> {
        match self.current().as_ref() {
            Some(client) => AutonomyLlm::detect_contradiction(client, mem_a, mem_b),
            None => Ok(false),
        }
    }

    fn summarize_memories(&self, memories: &[(String, String)]) -> anyhow::Result<String> {
        match self.current().as_ref() {
            Some(client) => AutonomyLlm::summarize_memories(client, memories),
            None => Err(anyhow::anyhow!(
                "llm client not configured (hot-swap current handle is None)"
            )),
        }
    }

    fn classify_kind(
        &self,
        title: &str,
        content: &str,
    ) -> anyhow::Result<Option<crate::models::MemoryKind>> {
        match self.current().as_ref() {
            Some(client) => AutonomyLlm::classify_kind(client, title, content),
            None => Ok(None),
        }
    }
}

/// Resolve + build the synchronous MCP `[llm]` client from `app_config`.
///
/// Shared by the MCP boot path AND the between-request reload path so the
/// two can never drift. Re-runs the #1963 inference-plane egress gate
/// (so a reload can legitimately DISABLE the client when egress is
/// `deny`/`loopback-only` against an external vendor) and honours the
/// no-preset-tier short-circuit. `verbose_banner` selects operator-facing
/// `eprintln!` boot banners vs quiet `tracing` breadcrumbs on reload.
///
/// Returns `None` when the client is intentionally disabled or fails to
/// build — the substrate's degraded (LLM-absent) posture.
#[must_use]
pub fn resolve_and_build_mcp_llm(
    app_config: &AppConfig,
    tier_config: &TierConfig,
    db_path: &Path,
    verbose_banner: bool,
) -> Option<Arc<OllamaClient>> {
    let resolved_llm = app_config.resolve_llm(None, None, None);

    // v1.0.0 #1963 (R68/D14) — inference-plane egress gate. On refuse the
    // outbound client is NOT constructed so no memory content can be
    // POSTed to the vendor; a best-effort signed refusal is recorded.
    let egress_refused = match crate::egress::evaluate_inference_egress(
        crate::egress::InferenceEgressMode::resolve(),
        crate::egress::EgressClass::InferenceLlm,
        &resolved_llm.base_url,
    ) {
        crate::egress::EgressDecision::Refuse {
            class,
            target,
            reason,
        } => {
            if verbose_banner {
                eprintln!(
                    "ai-memory: LLM DISABLED by inference-plane egress gate \
                     (target={target}); {reason} (#1963)"
                );
            } else {
                tracing::warn!(
                    target = %target,
                    "[llm] reload: client DISABLED by inference-plane egress gate; {reason} (#1963)"
                );
            }
            crate::egress::refuse_inference_egress_audited(db_path, class, &target, &reason);
            true
        }
        crate::egress::EgressDecision::Allow => false,
    };

    if egress_refused
        || (tier_config.llm_model.is_none() && resolved_llm.source == ConfigSource::CompiledDefault)
    {
        // Keyword/semantic tier with no operator LLM config, OR the egress
        // gate refused the outbound target: LLM intentionally disabled.
        return None;
    }

    match OllamaClient::build_from_resolved(&resolved_llm) {
        Ok(Some(client)) => {
            if verbose_banner {
                eprintln!(
                    "ai-memory: LLM ready (backend={}, model={}, source={}, key_source={})",
                    resolved_llm.backend,
                    resolved_llm.model,
                    resolved_llm.source.as_str(),
                    resolved_llm.api_key_source.as_str(),
                );
            } else {
                tracing::info!(
                    backend = %resolved_llm.backend,
                    model = %resolved_llm.model,
                    source = %resolved_llm.source.as_str(),
                    "[llm] reload: client ready"
                );
            }
            // For ollama backends, exercise the pull step so first-run UX
            // (model not on disk) still emits the pull-progress hint. The
            // backend identifier comes from `crate::llm::BACKEND_OLLAMA`
            // per the vendor-monoculture lint gate (#1174).
            if resolved_llm.backend == crate::llm::BACKEND_OLLAMA {
                if let Err(e) = client.ensure_model() {
                    if verbose_banner {
                        eprintln!("ai-memory: model pull failed: {e} (LLM features disabled)");
                    } else {
                        tracing::warn!("[llm] reload: model pull failed: {e} (client disabled)");
                    }
                    None
                } else {
                    Some(Arc::new(client))
                }
            } else {
                Some(Arc::new(client))
            }
        }
        Ok(None) => {
            if verbose_banner {
                eprintln!(
                    "ai-memory: LLM disabled — resolver returned no client \
                     (backend={}, source={})",
                    resolved_llm.backend,
                    resolved_llm.source.as_str(),
                );
            } else {
                tracing::warn!(
                    backend = %resolved_llm.backend,
                    "[llm] reload: resolver returned no client"
                );
            }
            None
        }
        Err(e) => {
            if verbose_banner {
                eprintln!(
                    "ai-memory: LLM init failed (backend={}, source={}): {e} \
                     (LLM features disabled)",
                    resolved_llm.backend,
                    resolved_llm.source.as_str(),
                );
            } else {
                tracing::warn!(
                    backend = %resolved_llm.backend,
                    "[llm] reload: client init failed: {e} (client disabled)"
                );
            }
            None
        }
    }
}

/// Refresh ONLY the `[llm]` slice of a [`ResolvedModels`] surface from a
/// freshly-loaded config, leaving embeddings/reranker untouched (they are
/// not hot-swapped, so their reported values must not change).
#[must_use]
pub fn refresh_llm_model_surface(current: &ResolvedModels, cfg: &AppConfig) -> ResolvedModels {
    let mut next = current.clone();
    next.llm = cfg.resolve_llm(None, None, None);
    next
}

/// HTTP-daemon SIGHUP reload routine (#2166).
///
/// Re-resolves the `[llm]` client through the validate-before-swap
/// [`AppConfig::try_load`] path, rebuilds via the async
/// [`crate::daemon_runtime::build_llm_client`] (which re-runs the #1963
/// egress gate AND emits the provenance line for free), then atomically
/// swaps both the client and the `memory_capabilities` model surface.
///
/// On a parse/validate failure the CURRENT client is KEPT and a loud WARN
/// is logged — a broken config never swaps in the compiled-default model.
pub async fn reload_http_llm(
    llm: &SwappableLlm,
    models: &Swappable<ResolvedModels>,
    feature_tier: crate::config::FeatureTier,
    db_path: &Path,
) {
    let cfg = match AppConfig::try_load() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                "SIGHUP [llm] reload: config parse/validate FAILED — keeping current LLM \
                 client (#2166): {e:#}"
            );
            return;
        }
    };
    // Reuse the boot builder so the egress gate re-evaluation + provenance
    // logging come for free. A reload may legitimately resolve to `None`
    // (egress deny, tier change) — `None` swaps in and disables the client.
    let rebuilt = crate::daemon_runtime::build_llm_client(feature_tier, &cfg, db_path).await;
    let disabled = rebuilt.is_none();
    llm.store(rebuilt);
    models.store(refresh_llm_model_surface(&models.current(), &cfg));
    if disabled {
        tracing::info!("SIGHUP [llm] reload: client hot-swapped to DISABLED (#2166)");
    } else {
        tracing::info!("SIGHUP [llm] reload: client hot-swapped (#2166)");
    }
}
