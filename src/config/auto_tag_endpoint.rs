// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3808 + #3819 — the `[llm.auto_tag]` reality gap, as focused helpers on the
//! parent [`super::AppConfig`] / [`super::LlmAutoTagSection`].
//!
//! Production auto-tag threads exactly ONE knob from `[llm.auto_tag]`: the
//! MODEL, as a per-call model override on the PRIMARY LLM client
//! (`AppState.auto_tag_model` -> `background::auto_tag_worker` ->
//! `auto_tag_async`; also `handlers::power_consolidation`). The endpoint
//! override keys (`backend` / `base_url` / `api_key_env` / `api_key_file`) are
//! parsed but NOT consumed — `resolve_llm_auto_tag` (which would have honoured
//! them) has no caller, and wiring a second auto_tag endpoint at v1.0.0 would
//! bypass the `InferenceEgressMode` boot gate at `build_llm_client`, so it is
//! deliberately deferred to v1.1.0.
//!
//! This module makes the two truths honest:
//!
//! - **#3808** — [`super::AppConfig::warn_ignored_auto_tag_endpoint_keys`] emits a
//!   one-shot load-time WARN naming any set-but-ignored endpoint key, so a
//!   config that points auto_tag at a second endpoint is not SILENTLY dropped.
//!   The classifier [`super::LlmAutoTagSection::ignored_endpoint_keys`] is pure,
//!   so the presence/absence pin needs no stderr capture.
//! - **#3819** — [`super::AppConfig::effective_auto_tag_model`] makes
//!   `[llm.auto_tag].model` (the #1146 documented replacement) LIVE, winning
//!   over the legacy flat `auto_tag_model`. That is what stops `config migrate`
//!   (which rewrites `auto_tag_model` -> `[llm.auto_tag].model`) from silently
//!   discarding a working model override — the destination is no longer dead.

use std::path::Path;

impl super::LlmAutoTagSection {
    /// #3808 — names of the endpoint-override keys this section sets that
    /// production does NOT consume (everything except `model`). Empty iff the
    /// section is `model`-only (or empty). Pure.
    #[must_use]
    pub fn ignored_endpoint_keys(&self) -> Vec<&'static str> {
        let set = |o: &Option<String>| o.as_ref().is_some_and(|v| !v.trim().is_empty());
        let mut out = Vec::new();
        if set(&self.backend) {
            out.push("backend");
        }
        if set(&self.base_url) {
            out.push("base_url");
        }
        if set(&self.api_key_env) {
            out.push("api_key_env");
        }
        if set(&self.api_key_file) {
            out.push("api_key_file");
        }
        out
    }
}

impl super::AppConfig {
    /// #3819 — the auto_tag model override actually threaded to the auto_tag
    /// LLM call. `[llm.auto_tag].model` (the #1146 replacement) WINS over the
    /// legacy flat `auto_tag_model`; BOTH are a per-call model string on the
    /// PRIMARY client (no second endpoint, so the `InferenceEgressMode` gate is
    /// untouched). Consumed at the daemon `AppState` build so a config migrated
    /// per our own verb keeps its override.
    #[must_use]
    #[allow(deprecated)]
    pub fn effective_auto_tag_model(&self) -> Option<String> {
        self.llm
            .as_ref()
            .and_then(|l| l.auto_tag.as_ref())
            .and_then(|a| a.model.clone())
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.auto_tag_model.clone().filter(|s| !s.trim().is_empty()))
    }

    /// #3808 — one-shot stderr WARN when `[llm.auto_tag]` carries any
    /// endpoint-override key production ignores (see
    /// [`super::LlmAutoTagSection::ignored_endpoint_keys`]). A `model`-only
    /// section is silent. `eprintln!` (not `tracing::warn!`) because this fires
    /// during boot before file logging is initialised — the sibling of
    /// `warn_legacy_schema_drift`, called from the same load funnel.
    pub(crate) fn warn_ignored_auto_tag_endpoint_keys(&self, path: &Path) {
        if super::config_boot_warnings_suppressed() {
            return;
        }
        let Some(auto_tag) = self.llm.as_ref().and_then(|l| l.auto_tag.as_ref()) else {
            return;
        };
        let ignored = auto_tag.ignored_endpoint_keys();
        if ignored.is_empty() {
            return;
        }
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            eprintln!(
                "ai-memory: WARN — [llm.auto_tag] in {} sets {} which are IGNORED: \
                 production threads only [llm.auto_tag].model (a per-call model \
                 override on the primary LLM client). A separate auto_tag endpoint \
                 is not wired at v1.0.0 (it would bypass the inference-egress boot \
                 gate); it is deferred to v1.1.0 (#3808). Remove these keys, or set \
                 only `model`.",
                path.display(),
                ignored.join(", "),
            );
        });
    }
}
