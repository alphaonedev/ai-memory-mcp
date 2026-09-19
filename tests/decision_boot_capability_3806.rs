// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1b, PIN — `/capabilities` reports the decision-provider state
//! from a CLOSED vocabulary, and reports NOTHING when `[decision]` is
//! unset.
//!
//! Two properties, paired presence/absence in ONE test body so neither
//! can pass because the other arm never ran (the whole file shares one
//! process-global boot snapshot, so splitting them would race):
//!
//! 1. **ABSENCE — byte-identical v1.0.0.** A daemon whose config has no
//!    `[decision]` section runs the chokepoint, records nothing, and its
//!    v2 / v3 capability payloads carry NO `decision_provider` key at
//!    all. An operator who never opted in sees the payload they saw
//!    before this commit.
//! 2. **PRESENCE — the key renders a closed token.** With a `[decision]`
//!    section that survives the egress gate, both v2 and v3 carry
//!    `decision_provider.state = "constructed"` — a member of the fixed
//!    four-token vocabulary, never free text — and they agree. v1 stays
//!    frozen.
//!
//! The posture is NOT mutated here: this file runs under the compiled
//! default (`AI_MEMORY_INFERENCE_EGRESS` unset ⇒ `allow`) and asserts
//! that precondition loudly, so it never races another test's env. The
//! deny / loopback-only arms are the in-module pins in
//! `src/decision_boot.rs`, which hold the crate env lock.

use ai_memory::config::FeatureTier;
use ai_memory::config::{AppConfig, ResolvedModels};
use ai_memory::decision_boot::{DecisionProviderState, build_decision_provider};
use ai_memory::mcp::{
    CapabilitiesAccept, handle_capabilities_with_conn, handle_capabilities_with_conn_v3,
};

/// The four tokens `decision_provider.state` may ever take.
const CLOSED_VOCABULARY: [&str; 4] = ["absent", "configured", "refused_by_egress", "constructed"];

fn render(accept: CapabilitiesAccept) -> serde_json::Value {
    let tier = FeatureTier::Keyword.config();
    let models = ResolvedModels::from_tier_preset(&tier);
    handle_capabilities_with_conn(&tier, &models, None, false, None, accept)
        .expect("capabilities render")
}

fn render_v3() -> serde_json::Value {
    let tier = FeatureTier::Keyword.config();
    let models = ResolvedModels::from_tier_preset(&tier);
    handle_capabilities_with_conn_v3(
        &tier,
        &models,
        None,
        false,
        None,
        &ai_memory::profile::Profile::core(),
        None,
        None,
        None,
    )
    .expect("capabilities v3 render")
}

#[test]
fn capabilities_report_the_decision_provider_from_a_closed_vocabulary_3806() {
    assert!(
        std::env::var_os("AI_MEMORY_INFERENCE_EGRESS").is_none(),
        "this pin runs under the compiled-default `allow` posture; unset \
         AI_MEMORY_INFERENCE_EGRESS before running it"
    );
    let db = std::env::current_dir()
        .expect("cwd")
        .join(".local-runs")
        .join("issue-3806-w1b-caps");
    std::fs::create_dir_all(&db).ok();
    let holder = tempfile::Builder::new()
        .prefix("caps-")
        .tempdir_in(&db)
        .expect("tempdir under .local-runs");
    let db_path = holder.path().join("operator-chosen.db");

    // --- ABSENCE: `[decision]` unset ⇒ the key is not on the wire.
    let unset: AppConfig =
        toml::from_str("schema_version = 2\ntier = \"autonomous\"\n").expect("corpus parses");
    let outcome = build_decision_provider(&unset, &db_path);
    assert_eq!(outcome.state(), DecisionProviderState::Absent);
    for (label, value) in [("v2", render(CapabilitiesAccept::V2)), ("v3", render_v3())] {
        assert!(
            value.get("decision_provider").is_none(),
            "{label}: an unconfigured deployment must see the v1.0.0 payload, \
             with no decision_provider key at all"
        );
    }

    // --- PRESENCE: a gated `[decision]` section ⇒ a closed token.
    let configured: AppConfig = toml::from_str(
        "schema_version = 2\ntier = \"autonomous\"\n\n\
         [decision]\nprovider = \"openai-compatible\"\n\
         model = \"vendor/decider-1\"\n\
         base_url = \"https://decide.internal.example.net/v1\"\n",
    )
    .expect("corpus parses");
    let outcome = build_decision_provider(&configured, &db_path);
    assert_eq!(outcome.state(), DecisionProviderState::Constructed);

    let v2 = render(CapabilitiesAccept::V2);
    let v3 = render_v3();
    for (label, value) in [("v2", &v2), ("v3", &v3)] {
        let report = value
            .get("decision_provider")
            .unwrap_or_else(|| panic!("{label}: decision_provider must render once configured"));
        let state = report["state"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: state must be a string token"));
        assert_eq!(state, "constructed", "{label}");
        assert!(
            CLOSED_VOCABULARY.contains(&state),
            "{label}: {state} is not in the closed vocabulary {CLOSED_VOCABULARY:?}"
        );
        assert_eq!(report["provider"], "openai-compatible", "{label}");
        assert_eq!(report["model"], "vendor/decider-1", "{label}");
        assert_eq!(report["local"], false, "{label}");
        assert_eq!(report["egress_mode"], "allow", "{label}");
        // The broadly-readable surface carries no endpoint and no
        // credential — only the posture.
        let rendered = report.to_string();
        assert!(
            !rendered.contains("decide.internal.example.net"),
            "{label}: the capability surface must not publish the endpoint"
        );
        assert!(!rendered.contains("api_key"), "{label}");
    }
    assert_eq!(v2["decision_provider"], v3["decision_provider"]);

    // v1 is frozen: it gained no key.
    let v1 = render(CapabilitiesAccept::V1);
    assert!(
        v1.get("decision_provider").is_none(),
        "the v1 wire shape remains frozen"
    );

    // Restore the process-global snapshot so a later test in this
    // binary cannot observe our recording.
    let outcome = build_decision_provider(&unset, &db_path);
    assert_eq!(outcome.state(), DecisionProviderState::Absent);
}
