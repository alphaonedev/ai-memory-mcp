// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! v0.7.x #1146 / #1598 / #3806 — the key names `[llm]`, `[embeddings]` and
//! `[decision]` share, and the ONE inline-`api_key` refusal text.
//!
//! `[llm]`, `[embeddings]` and `[decision]` share it so the wording and the
//! repair instructions cannot drift per section, and so the string lives in
//! exactly one place (pm-v3.1 hardcoded-literal gate). A submodule because
//! `src/config.rs` is at its QUAL-10 ceiling.

/// `api_key_env`, shared by `[llm]` / `[embeddings]` / `[decision]`.
pub const API_KEY_ENV: &str = "api_key_env";
/// `api_key_file`, shared by the same three sections.
pub const API_KEY_FILE: &str = "api_key_file";
/// The inline `api_key` trap field, shared by the same three.
pub const API_KEY: &str = "api_key";
/// `base_url`, shared by the same three sections.
pub const BASE_URL: &str = "base_url";

/// The operator-facing refusal for an inline `api_key` literal in
/// `[section]`.
#[must_use]
pub(crate) fn inline_key_refusal(section: &str) -> String {
    format!(
        "inline `api_key = \"<literal>\"` in [{section}] is forbidden — \
         use `api_key_env = \"<ENV_VAR_NAME>\"` to reference a process \
         env var, or `api_key_file = \"/path/to/key\"` to reference a \
         file (mode 0400 enforced). Inline secrets in config.toml \
         (typically world-readable) are a credential leak."
    )
}
