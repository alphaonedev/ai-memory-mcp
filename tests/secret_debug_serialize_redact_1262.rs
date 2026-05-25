// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression test for issue #1262 — latent secret leaks via the
//! derived `Debug` / `Serialize` impls on `LlmProvider`,
//! `RuntimeContext`, `HooksSubscriptionConfig`, and `AppConfig`.
//!
//! For every secret-bearing type the v0.7.0 QC audit flagged:
//!
//! 1. The `Debug` format string MUST contain the literal `<redacted>`.
//! 2. The `Debug` format string MUST NOT contain the canary secret
//!    bytes.
//! 3. (Where applicable) the `serde_json::to_string` output MUST NOT
//!    contain the canary secret bytes — pinned via
//!    `#[serde(skip_serializing)]` on the secret field.
//!
//! Source-side discipline for this issue landed alongside the
//! #1258 zeroize-on-drop work in the sibling PR; this file pins the
//! invariant mechanically so a future refactor that absent-mindedly
//! re-derives `Debug` / removes the `skip_serializing` attr trips a
//! hard test failure.

use ai_memory::config::{AppConfig, HooksSubscriptionConfig};
use ai_memory::llm::LlmProvider;

/// #1262 — `LlmProvider::OpenAiCompatible::api_key` MUST NOT appear in
/// the `Debug` format output; the variant MUST render the field as
/// `<redacted>`.
#[test]
fn llm_provider_debug_redacts_api_key() {
    const SECRET: &str = "sk-1262-llm-debug-canary-2c7a";
    let provider = LlmProvider::OpenAiCompatible {
        api_key: SECRET.to_string(),
    };
    let debug = format!("{provider:?}");
    assert!(
        !debug.contains(SECRET),
        "#1262 — LlmProvider Debug output MUST NOT leak the api_key plaintext; got {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "#1262 — LlmProvider Debug output MUST contain `<redacted>` marker; got {debug}"
    );
}

/// #1262 — `HooksSubscriptionConfig::hmac_secret` MUST NOT appear in
/// the `Debug` format output.
#[test]
fn hooks_subscription_config_debug_redacts_hmac_secret() {
    const SECRET: &str = "hmac-1262-hooks-debug-canary-8b3e";
    let cfg = HooksSubscriptionConfig {
        hmac_secret: Some(SECRET.to_string()),
    };
    let debug = format!("{cfg:?}");
    assert!(
        !debug.contains(SECRET),
        "#1262 — HooksSubscriptionConfig Debug output MUST NOT leak the hmac_secret plaintext; got {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "#1262 — HooksSubscriptionConfig Debug output MUST contain `<redacted>` marker; got {debug}"
    );
}

/// #1262 — `HooksSubscriptionConfig::hmac_secret` MUST NOT appear in
/// the `serde_json::to_string` output.
#[test]
fn hooks_subscription_config_serialize_skips_hmac_secret() {
    const SECRET: &str = "hmac-1262-hooks-serialize-canary-4d2f";
    let cfg = HooksSubscriptionConfig {
        hmac_secret: Some(SECRET.to_string()),
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    assert!(
        !json.contains(SECRET),
        "#1262 — HooksSubscriptionConfig serialize MUST NOT leak the hmac_secret plaintext; got {json}"
    );
    assert!(
        !json.contains("hmac_secret"),
        "#1262 — HooksSubscriptionConfig serialize MUST skip the hmac_secret field entirely; got {json}"
    );
}

/// #1262 — `AppConfig::api_key` MUST NOT appear in the
/// `serde_json::to_string` output of `AppConfig`.
#[test]
#[allow(clippy::field_reassign_with_default)] // AppConfig owns sub-configs whose move-out isn't allowed; in-place mutation is the only working option here.
fn app_config_serialize_skips_api_key() {
    const SECRET: &str = "api-1262-app-config-serialize-canary-6e51";
    let mut cfg = AppConfig::default();
    cfg.api_key = Some(SECRET.to_string());
    let json = serde_json::to_string(&cfg).expect("serialize");
    assert!(
        !json.contains(SECRET),
        "#1262 — AppConfig serialize MUST NOT leak the api_key plaintext; got {json}"
    );
    assert!(
        !json.contains("api_key"),
        "#1262 — AppConfig serialize MUST skip the api_key field entirely; got {json}"
    );
}

/// #1262 — `RuntimeContext::hooks_hmac_secret` MUST NOT appear in
/// the `Debug` format output. We construct a fresh local instance
/// (NOT the global singleton, which is process-wide) so the test
/// can both set and inspect the field deterministically.
#[test]
fn runtime_context_debug_redacts_hooks_hmac_secret() {
    use ai_memory::runtime_context::RuntimeContext;
    const SECRET: &str = "hmac-1262-runtime-debug-canary-9a4b";
    let ctx = RuntimeContext::default();
    *ctx.hooks_hmac_secret.write().unwrap() = Some(SECRET.to_string());
    let debug = format!("{ctx:?}");
    assert!(
        !debug.contains(SECRET),
        "#1262 — RuntimeContext Debug output MUST NOT leak the hooks_hmac_secret plaintext; got {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "#1262 — RuntimeContext Debug output MUST contain `<redacted>` marker; got {debug}"
    );
}
