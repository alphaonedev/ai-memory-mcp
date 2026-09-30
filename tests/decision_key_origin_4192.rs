// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4192 — a `[decision]` vendor credential travels only to that vendor.
//!
//! Before #4192, the per-vendor alias env (e.g. `OPENROUTER_API_KEY`) was
//! consulted for ANY `[decision].base_url` whenever the endpoint differed from
//! the parent `[llm]` endpoint, and it shadowed the section's own
//! `api_key_env` / `api_key_file`. So `provider = "openrouter"` with a foreign
//! `base_url` sent the `OPENROUTER_API_KEY` value as a Bearer token to the foreign host.
//!
//! Only `OPENROUTER_API_KEY` is set through the env guard: two stacked
//! `EnvVarGuard`s self-deadlock on the shared lock. The section's own key
//! arrives through a 0400 `api_key_file` instead.
//!
//! Unix-only: the 0400 key file needs `std::os::unix` permissions, and the
//! loader enforces that mode only on Unix. The key-origin rule itself is
//! platform-independent.
#![cfg(unix)]

mod common;

use ai_memory::config::AppConfig;
use ai_memory::decision_config::{DecisionFallback, DecisionSection, resolve_decision};

const ALIAS_ENV: &str = "OPENROUTER_API_KEY";
const ALIAS_KEY: &str = "sk-or-alias-must-stay-with-openrouter";
const SECTION_KEY: &str = "sk-section-own-key";
const VENDOR_DEFAULT: &str = "https://openrouter.ai/api/v1";
const FOREIGN: &str = "https://other-host.example/v1";

fn resolved_key(base_url: &str, api_key_file: Option<String>) -> Option<String> {
    let cfg = AppConfig {
        decision: Some(DecisionSection {
            provider: Some("openrouter".to_string()),
            model: Some("vendor/decision-1".to_string()),
            base_url: Some(base_url.to_string()),
            api_key_env: None,
            api_key_file,
            api_key: None,
            timeout_secs: Some(5),
            fallback: Some(DecisionFallback::Abstain),
        }),
        ..AppConfig::default()
    };
    resolve_decision(&cfg)
        .expect("a complete [decision] section must resolve")
        .api_key()
        .map(str::to_string)
}

fn section_key_file(dir: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("decision.key");
    std::fs::write(&path, SECTION_KEY).expect("write key file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).expect("chmod 0400");
    path.to_string_lossy().into_owned()
}

/// RED on 65642b3cf (the foreign endpoint received the alias key, and the
/// alias shadowed the section's file). GREEN with the origin-bound rule.
#[test]
fn a_vendor_alias_key_travels_only_to_that_vendor_4192() {
    let _env = common::EnvVarGuard::set(ALIAS_ENV, ALIAS_KEY.to_string());
    let dir = tempfile::tempdir().expect("tempdir");

    // A foreign base_url with no section key: NO key goes out.
    assert_eq!(
        resolved_key(FOREIGN, None),
        None,
        "the openrouter alias key must never be sent to a foreign host"
    );

    // Control: the vendor's own default origin still gets the alias key.
    assert_eq!(
        resolved_key(VENDOR_DEFAULT, None).as_deref(),
        Some(ALIAS_KEY),
        "the vendor's own origin keeps the alias key"
    );

    // The section's own key wins, at a foreign host and at the vendor origin.
    let file = section_key_file(dir.path());
    for base_url in [FOREIGN, VENDOR_DEFAULT] {
        assert_eq!(
            resolved_key(base_url, Some(file.clone())).as_deref(),
            Some(SECTION_KEY),
            "{base_url}: [decision].api_key_file must win over the alias env"
        );
    }
}

/// Lifted from SECPROG L1's `l1_vendor_env_key_never_travels_to_a_foreign_decision_host`:
/// the [llm] parent uses the same vendor, and the section names its own key
/// through `api_key_env` (an env var, not a file). The section key wins, and
/// the vendor alias key never reaches the foreign decision host.
#[test]
fn a_section_api_key_env_wins_and_the_alias_never_travels_4192() {
    const SECTION_ENV: &str = "L1_DECIDER_KEY_4192";
    let _env = common::MultiEnvVarGuard::apply(&[
        (ALIAS_ENV, Some("sk-parent-l1")),
        (SECTION_ENV, Some("sk-decider-l1")),
    ]);
    let cfg = AppConfig {
        llm: Some(ai_memory::config::LlmSection {
            backend: Some("openrouter".into()),
            model: Some("m".into()),
            base_url: None,
            api_key_env: None,
            api_key_file: None,
            api_key: None,
            auto_tag: None,
        }),
        decision: Some(DecisionSection {
            provider: Some("openrouter".into()),
            model: Some("d".into()),
            base_url: Some(FOREIGN.into()),
            api_key_env: Some(SECTION_ENV.into()),
            ..DecisionSection::default()
        }),
        ..AppConfig::default()
    };
    let r = resolve_decision(&cfg).expect("resolves");
    assert_ne!(
        r.api_key(),
        Some("sk-parent-l1"),
        "vendor key shipped to a foreign host"
    );
    assert_eq!(
        r.api_key(),
        Some("sk-decider-l1"),
        "the section's api_key_env must win"
    );
}
