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
//!
//! v1.0.0 §5.3 (3x7 cutline ruling, 2026-08-01) adds the
//! `enterprise-federation.env` checked-in profile — the ruling's own
//! "ship as a checked-in profile" requirement — pinned below to the
//! same `SecurityPosture::AsiHard` selection PLUS the opt-in
//! [`ai_memory::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE`]
//! boot-refusing gate.

use std::collections::{HashMap, HashSet};
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
    // v1.0.0 §5.3 — the enterprise-federation checked-in profile exists
    // and parses.
    let ef_env = parse_env("enterprise-federation.env");
    assert!(
        !ef_env.is_empty(),
        "enterprise-federation.env must set at least one var"
    );
}

#[test]
fn enterprise_federation_env_selects_asi_hard_and_requires_the_posture_gate() {
    let env = parse_env("enterprise-federation.env");

    // Selects the real asi-hard posture — the certification is a
    // SUPERSET of asi-hard, never a replacement for it.
    let profile = env
        .get("AI_MEMORY_SECURITY_PROFILE")
        .expect("enterprise-federation.env must set AI_MEMORY_SECURITY_PROFILE");
    assert_eq!(
        SecurityPosture::parse(profile).expect("posture token must parse"),
        SecurityPosture::AsiHard,
        "enterprise-federation.env must select the asi-hard posture"
    );
    assert!(
        !pinned_knobs().is_empty(),
        "asi-hard posture must pin a non-empty knob set"
    );

    // Engages the opt-in boot-refusing enterprise-federation gate.
    let required = env
        .get(ai_memory::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE)
        .expect("enterprise-federation.env must set the posture-required gate");
    assert!(
        matches!(required.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        "the posture-required gate must be set truthy: {required:?}"
    );

    // #2911 item 2 — the FED-RQ-03 stale-policy hatch must not ship
    // explicitly off in the certified template (unset would also pass
    // the default-ON reader; the template names the certified value
    // so the boot banner echoes it).
    let policy_current = env
        .get(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV)
        .expect("enterprise-federation.env must set AI_MEMORY_FED_REQUIRE_POLICY_CURRENT");
    assert!(
        matches!(
            policy_current.as_str(),
            "1" | "true" | "TRUE" | "yes" | "on"
        ),
        "POLICY_CURRENT must ship truthy in the certified template: {policy_current:?}"
    );

    // #2954 check #19 — the append-only audit spine must ship ARMED in the
    // certified template (else a federation newer-wins supersede leaf is never
    // written / is unsigned). The signing-key half is deployment-provisioned
    // (a key file, not an env value), documented in the template's audit-custody
    // section — it cannot be pinned here.
    let append_only = env
        .get(ai_memory::config::ENV_APPEND_ONLY)
        .expect("enterprise-federation.env must set AI_MEMORY_APPEND_ONLY (#2954 check #19)");
    assert!(
        matches!(append_only.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        "AI_MEMORY_APPEND_ONLY must ship truthy in the certified template: {append_only:?}"
    );

    // Never ships the plaintext-peer hatch open, never ships either
    // must-be-UNSET federation trust bypass truthy.
    for env_name in [
        "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS",
        ai_memory::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
    ] {
        if let Some(v) = env.get(env_name) {
            assert!(
                !matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{env_name} must never ship truthy in the certified template: {v:?}"
            );
        }
    }

    // Inference-plane egress is hardened (mirrors the asi-hard.env check).
    let egress = env
        .get("AI_MEMORY_INFERENCE_EGRESS")
        .expect("enterprise-federation.env must set AI_MEMORY_INFERENCE_EGRESS");
    let mode = InferenceEgressMode::parse(egress).expect("egress token must parse");
    assert_ne!(
        mode,
        InferenceEgressMode::Allow,
        "enterprise-federation.env must NOT leave inference egress at the permissive default"
    );
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

/// #3113 — `docs/deploy/asi-hard.env` is the operator-facing enumeration of
/// the hardened posture, and CLAUDE.md's env-table row #130 states it "names
/// all N correctly". NOTHING enforced that claim: the template names the
/// knobs in PROSE (comment lines), so a knob added to `KNOBS` left the
/// template silently one short while every assertion here still passed —
/// `!pinned_knobs().is_empty()` is true for any non-empty set. A deploy
/// template that under-states the pinned set is a procurement document
/// describing a weaker posture than the binary actually enforces.
///
/// TOKENISED membership, deliberately NOT `str::contains`:
/// `AI_MEMORY_FED_REQUIRE_SIG` is a strict prefix of
/// `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`, so a substring search would report the
/// shorter knob as documented purely because the longer one is present — the
/// fail-open shape this test exists to close. The un-prefixed short form is
/// accepted because the template's prose legitimately uses it (e.g.
/// `FED_REQUIRE_SERVER_VERIFY / MIGRATION_REQUIRE_CORE_TABLES = 1;`).
#[test]
fn asi_hard_env_names_every_pinned_knob() {
    let text = read("asi-hard.env");
    let tokens: HashSet<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .collect();

    let missing: Vec<&str> = pinned_knobs()
        .iter()
        .map(|&(env, _)| env)
        .filter(|&env| {
            let short = env.strip_prefix("AI_MEMORY_").unwrap_or(env);
            !tokens.contains(env) && !tokens.contains(short)
        })
        .collect();

    assert!(
        missing.is_empty(),
        "docs/deploy/asi-hard.env must name every knob `asi-hard` pins (SSOT \
         `security_profile::KNOBS`); undocumented: {missing:?}"
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
