// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4192 — a `[decision]` vendor credential travels only to that vendor.
//!
//! Before #4192, the per-vendor alias env (e.g. `OPENROUTER_API_KEY`) was
//! consulted for ANY `[decision].base_url` whenever the endpoint differed from
//! the parent `[llm]` endpoint, and it shadowed the section's own
//! `api_key_env` / `api_key_file`. So `provider = "openrouter"` with a foreign
//! `base_url` sent the OpenRouter key as a Bearer token to the foreign host.
//!
//! Only `OPENROUTER_API_KEY` is set through the env guard: two stacked
//! `EnvVarGuard`s self-deadlock on the shared lock. The section's own key
//! arrives through a 0400 `api_key_file` instead.

mod common;

use ai_memory::config::AppConfig;
use ai_memory::decision_config::{DecisionFallback, DecisionSection, resolve_decision};

const ALIAS_ENV: &str = "OPENROUTER_API_KEY";
const ALIAS_KEY: &str = "sk-or-alias-must-stay-with-openrouter";
const SECTION_KEY: &str = "sk-section-own-key";
const VENDOR_DEFAULT: &str = "https://openrouter.ai/api/v1";
const FOREIGN: &str = "https://other-host.example/v1";

fn resolved_key(base_url: &str, api_key_file: Option<String>) -> Option<String> {
    let mut cfg = AppConfig::default();
    cfg.decision = Some(DecisionSection {
        provider: Some("openrouter".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(base_url.to_string()),
        api_key_env: None,
        api_key_file,
        api_key: None,
        timeout_secs: Some(5),
        fallback: Some(DecisionFallback::Abstain),
    });
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
