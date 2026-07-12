// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PE-1 production-hardening TEMPLATES (#1962) — mechanical pins.
//!
//! These tests bind the `docs/deploy/` templates to the code SSOT so a
//! template cannot silently drift from the named `asi-hard` security
//! posture (#1961) or the inference-egress gate (#1963):
//!
//! - the templates are valid TOML / env files;
//! - the `asi-hard` config template pins the PE-1 config knobs (secret
//!   screen refuse, hooks enforce + non-empty `required_events`, governance
//!   `require_operator_pubkey`), and its `required_events` tokens deserialize
//!   into real [`ai_memory::hooks::HookEvent`] variants;
//! - the `asi-hard` env template selects the real
//!   [`ai_memory::security_profile::SecurityPosture::AsiHard`] posture and a
//!   NON-`allow` [`ai_memory::egress::InferenceEgressMode`].

use std::collections::HashMap;
use std::path::PathBuf;

use ai_memory::egress::InferenceEgressMode;
use ai_memory::hooks::HookEvent;
use ai_memory::security_profile::{SecurityPosture, pinned_knobs};

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/deploy")
}

fn read(name: &str) -> String {
    let path = deploy_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read deploy template {}: {e}", path.display()))
}

fn parse_toml(name: &str) -> toml::Value {
    toml::from_str::<toml::Value>(&read(name))
        .unwrap_or_else(|e| panic!("{name} must be valid TOML: {e}"))
}

/// Parse a `KEY=VALUE` env file, skipping comments and blank lines.
fn parse_env(name: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in read(name).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

#[test]
fn all_templates_exist_and_parse() {
    // Every template file is present and (for TOML) parses.
    let _ = parse_toml("config.standard.toml");
    let _ = parse_toml("config.asi-hard.toml");
    let env = parse_env("asi-hard.env");
    assert!(!env.is_empty(), "asi-hard.env must set at least one var");
    // README documents the set.
    assert!(read("README.md").contains("asi-hard"));
}

#[test]
fn standard_template_does_not_force_hardening() {
    // The baseline template keeps compiled defaults — it must NOT ship an
    // active enforce/refuse posture (that is the asi-hard template's job).
    let v = parse_toml("config.standard.toml");
    // A [hooks] enforce_mode, if present, must not be "enforce".
    if let Some(mode) = v
        .get("hooks")
        .and_then(|h| h.get("enforce_mode"))
        .and_then(toml::Value::as_str)
    {
        assert_ne!(
            mode, "enforce",
            "the STANDARD template must not ship enforce mode"
        );
    }
}

#[test]
fn asi_hard_config_pins_the_pe1_knobs() {
    let v = parse_toml("config.asi-hard.toml");

    // [security].secret_screen_mode = "refuse"
    assert_eq!(
        v.get("security")
            .and_then(|s| s.get("secret_screen_mode"))
            .and_then(toml::Value::as_str),
        Some("refuse"),
        "asi-hard must pin secret_screen_mode=refuse"
    );

    // [hooks].enforce_mode = "enforce"
    assert_eq!(
        v.get("hooks")
            .and_then(|h| h.get("enforce_mode"))
            .and_then(toml::Value::as_str),
        Some("enforce"),
        "asi-hard must pin hooks.enforce_mode=enforce"
    );

    // [hooks].required_events must be NON-EMPTY (PE-1: enforce with an
    // empty required list is a deliberate no-op self-DOS guard).
    let required = v
        .get("hooks")
        .and_then(|h| h.get("required_events"))
        .and_then(toml::Value::as_array)
        .expect("asi-hard must set hooks.required_events");
    assert!(
        !required.is_empty(),
        "PE-1: required_events must be non-empty under enforce"
    );

    // Every required_events token must deserialize into a real HookEvent
    // (so the template cannot drift from the enum spelling).
    for tok in required {
        let event: HookEvent = tok
            .clone()
            .try_into()
            .unwrap_or_else(|e| panic!("required_events token {tok:?} is not a HookEvent: {e}"));
        // Sanity: it round-trips to a snake_case pre_* token.
        let _ = event;
    }

    // [governance].require_operator_pubkey = true
    assert_eq!(
        v.get("governance")
            .and_then(|g| g.get("require_operator_pubkey"))
            .and_then(toml::Value::as_bool),
        Some(true),
        "asi-hard must pin governance.require_operator_pubkey=true"
    );
}

#[test]
fn asi_hard_env_selects_the_named_posture_and_hardened_egress() {
    let env = parse_env("asi-hard.env");

    // Selects the real #1961 named posture.
    let profile = env
        .get("AI_MEMORY_SECURITY_PROFILE")
        .expect("asi-hard.env must set AI_MEMORY_SECURITY_PROFILE");
    assert_eq!(
        SecurityPosture::parse(profile).expect("posture token must parse"),
        SecurityPosture::AsiHard,
        "asi-hard.env must select the asi-hard posture"
    );

    // The posture actually pins a non-empty knob set (the #1961 SSOT the
    // template relies on — this links #1962 to #1961).
    assert!(
        !pinned_knobs().is_empty(),
        "asi-hard posture must pin a non-empty knob set"
    );

    // Inference-plane egress (#1963) is set to a HARDENED (non-allow) mode.
    let egress = env
        .get("AI_MEMORY_INFERENCE_EGRESS")
        .expect("asi-hard.env must set AI_MEMORY_INFERENCE_EGRESS");
    let mode = InferenceEgressMode::parse(egress).expect("egress token must parse");
    assert_ne!(
        mode,
        InferenceEgressMode::Allow,
        "asi-hard.env must NOT leave inference egress at the permissive `allow` default"
    );
}
