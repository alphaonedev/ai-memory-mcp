// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S1 (D3-012, #1870) — conservative model-FAMILY
//! normalizer.
//!
//! [`family_of`] maps a `(provider, model_ref)` pair to a normalized
//! family token (`"llama"`, `"claude"`, `"gemma"`, …). It is
//! deliberately CONSERVATIVE: an unrecognized model resolves to `None`
//! and is NEVER guessed. This is the fail-safe direction — an
//! unattestable model must read as CLAIMED (no family), never be
//! laundered into a family it might not belong to.
//!
//! # Honest coverage
//!
//! This normalizer only ever sees models the substrate itself
//! constructs a client for (the three LLM-client construction sites).
//! Externally authored reflections never pass through here, so
//! loader-attested family coverage hard-caps at ~40% (ROADMAP.md:1229).
//! `loader_observed` attestation is a PROCESS-LIFETIME trusted-substrate
//! self-report — the daemon observed which model IT was configured to
//! call — NOT a per-write cryptographic provenance proof.

/// Normalize a `(provider, model_ref)` pair to a model-family token.
///
/// Matching is a case-insensitive prefix test against a fixed, curated
/// table. `provider` is accepted for forward-compatibility (a future
/// provider-scoped disambiguation) but the family is derived from the
/// model reference today. Returns `None` for any model that does not
/// match a known family — the conservative default that keeps an
/// unknown model CLAIMED rather than mis-attributed.
#[must_use]
pub fn family_of(provider: &str, model_ref: &str) -> Option<String> {
    let _ = provider;
    let m = model_ref.trim().to_ascii_lowercase();
    if m.is_empty() {
        return None;
    }
    // Ordered so the most specific prefixes win where families share a
    // stem. Each arm is a conservative, well-known family stem.
    const TABLE: &[(&str, &str)] = &[
        ("gemma", "gemma"),
        ("gemini", "gemini"),
        ("llama", "llama"),
        ("codellama", "llama"),
        ("claude", "claude"),
        ("anthropic", "claude"),
        ("grok", "grok"),
        ("gpt", "gpt"),
        ("deepseek", "deepseek"),
        ("qwen", "qwen"),
        ("mixtral", "mistral"),
        ("mistral", "mistral"),
    ];
    for (prefix, family) in TABLE {
        if m.starts_with(prefix) {
            return Some((*family).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_families_normalize() {
        assert_eq!(family_of("ollama", "llama3.1:8b").as_deref(), Some("llama"));
        assert_eq!(family_of("ollama", "gemma2:9b").as_deref(), Some("gemma"));
        assert_eq!(
            family_of("gemini", "gemini-2.5-pro").as_deref(),
            Some("gemini")
        );
        assert_eq!(
            family_of("anthropic", "claude-opus-4").as_deref(),
            Some("claude")
        );
        assert_eq!(family_of("xai", "grok-4").as_deref(), Some("grok"));
        assert_eq!(family_of("openai", "gpt-4o").as_deref(), Some("gpt"));
        assert_eq!(
            family_of("deepseek", "deepseek-chat").as_deref(),
            Some("deepseek")
        );
        assert_eq!(family_of("qwen", "qwen-max").as_deref(), Some("qwen"));
        assert_eq!(
            family_of("mistral", "mistral-large").as_deref(),
            Some("mistral")
        );
        assert_eq!(
            family_of("mistral", "mixtral-8x7b").as_deref(),
            Some("mistral")
        );
        assert_eq!(
            family_of("anthropic", "anthropic.claude-v2").as_deref(),
            Some("claude")
        );
    }

    #[test]
    fn case_insensitive_and_trimmed() {
        assert_eq!(family_of("x", "  LLaMA3  ").as_deref(), Some("llama"));
    }

    #[test]
    fn unknown_never_guessed() {
        assert_eq!(family_of("custom", "my-secret-model-9000"), None);
        assert_eq!(family_of("x", ""), None);
        assert_eq!(family_of("x", "   "), None);
        assert_eq!(family_of("x", "phi-3"), None);
    }
}
