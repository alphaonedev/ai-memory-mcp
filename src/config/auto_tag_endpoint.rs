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
            let label = crate::config_redact::config_label(path);
            eprintln!("{}", ignored_endpoint_keys_warn_line(&label, &ignored));
        });
    }
}

/// #3808 — the one-shot WARN text. #6584 (`CodeQL` `rust/cleartext-logging`):
/// the file is named by `config_label` (a label resolved from the environment,
/// never the caller's `path` value) and the keys are the `&'static str` NAMES
/// [`super::LlmAutoTagSection::ignored_endpoint_keys`] returns, never a value.
/// Pure, so the cell below needs no stderr capture.
fn ignored_endpoint_keys_warn_line(config_label: &str, ignored: &[&'static str]) -> String {
    format!(
        "ai-memory: WARN — [llm.auto_tag] in {config_label} sets {} which are IGNORED: \
         production threads only [llm.auto_tag].model (a per-call model \
         override on the primary LLM client). A separate auto_tag endpoint \
         is not wired at v1.0.0 (it would bypass the inference-egress boot \
         gate); it is deferred to v1.1.0 (#3808). Remove these keys, or set \
         only `model`.",
        ignored.join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// #6584 — the WARN names the ignored KEYS and a config label, and carries
    /// neither a key value nor a non-default caller path.
    #[test]
    fn ignored_endpoint_warn_carries_key_names_not_values_6584() {
        let section = super::super::LlmAutoTagSection {
            base_url: Some("https://placeholder.invalid/v1".to_string()),
            api_key_env: Some("FAKE_PLACEHOLDER_KEY_ENV".to_string()),
            api_key_file: Some("/placeholder/FAKE-KEY-FILE".to_string()),
            ..Default::default()
        };
        let path = Path::new("/placeholder/FAKE-PLACEHOLDER-secret.toml");
        let label = crate::config_redact::config_path_label(path, None);
        let line = ignored_endpoint_keys_warn_line(&label, &section.ignored_endpoint_keys());
        for name in ["base_url", "api_key_env", "api_key_file", "[llm.auto_tag]"] {
            assert!(line.contains(name), "WARN must still name `{name}`");
        }
        for value in [
            "FAKE-PLACEHOLDER-secret.toml",
            "FAKE_PLACEHOLDER_KEY_ENV",
            "FAKE-KEY-FILE",
            "placeholder.invalid",
        ] {
            assert!(
                !line.contains(value),
                "WARN must not carry the fixture value #{}",
                value.len()
            );
        }
        assert!(line.contains(crate::config_redact::NON_DEFAULT_CONFIG_LABEL));
    }

    /// #6584 — at the default location the WARN still names the file.
    #[test]
    fn ignored_endpoint_warn_names_the_default_config_file_6584() {
        let default = Path::new("/home/placeholder/.config/ai-memory/config.toml");
        let label = crate::config_redact::config_path_label(default, Some(default));
        let line = ignored_endpoint_keys_warn_line(&label, &["backend"]);
        assert!(line.contains("/home/placeholder/.config/ai-memory/config.toml"));
        assert!(line.contains("sets backend which are IGNORED"));
    }
}
