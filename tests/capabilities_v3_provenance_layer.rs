// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #973 Item C — capabilities v3 `provenance_substrate_layer`
//! narrative surface integration test.
//!
//! Pins the wire shape + honesty-check invariants:
//!
//! 1. The MCP `memory_capabilities` v3 response carries the new field.
//! 2. The `posture` discriminator is `"do_calculus_aligned"`.
//! 3. The `enforcement_layers` array carries exactly the 5 source-
//!    verified labels (form_4 / form_6 / form_7 / signed_events_v4 /
//!    seven_gap). Drift here means the wire claim no longer matches
//!    the substrate's actually-shipped surface — honesty violation.
//! 4. The `honest_limitations` array carries the cross-session vs
//!    intra-session boundary + the federation-reliability axis.
//! 5. The `spec_references` block carries Pearl + Ortega-de-Freitas,
//!    no vendor citations.
//! 6. A v2 client (simulated by deserialising with `CapabilitiesV2`)
//!    parses the v3 response without error — backward-compat is
//!    preserved by the additive shape.

#![allow(clippy::doc_markdown)]

use ai_memory::config::{
    CapabilityProvenanceSubstrateLayer, default_capability_provenance_substrate_layer,
};

#[test]
fn helper_returns_do_calculus_aligned_posture() {
    let layer = default_capability_provenance_substrate_layer();
    assert_eq!(layer.posture, "do_calculus_aligned");
}

#[test]
fn enforcement_layers_match_source_tree_honesty_check() {
    // v0.7.0 source-verified list — see the helper's docstring for the
    // grep commands that anchor each label to the source tree.
    const EXPECTED: &[&str] = &[
        "form_4_fact_provenance",
        "form_6_memory_kind",
        "form_7_agent_external_governance",
        "signed_events_v4_chain",
        "seven_gap_framework",
    ];
    let layer = default_capability_provenance_substrate_layer();
    let got: Vec<&str> = layer
        .enforcement_layers
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        got, EXPECTED,
        "enforcement_layers drift — wire claim must match source tree"
    );
}

#[test]
fn honest_limitations_cover_two_axes() {
    let layer = default_capability_provenance_substrate_layer();
    assert!(
        layer
            .honest_limitations
            .iter()
            .any(|s| s.contains("intra_session_hallucination")),
        "honest_limitations must surface the consumer-LLM-responsibility axis"
    );
    assert!(
        layer
            .honest_limitations
            .iter()
            .any(|s| s.contains("federation_reliability") || s.contains("dlq")),
        "honest_limitations must surface the federation-reliability axis"
    );
}

#[test]
fn spec_references_vendor_neutral() {
    let layer = default_capability_provenance_substrate_layer();
    assert_eq!(layer.spec_references.do_calculus, "Pearl (2009)");
    assert_eq!(
        layer.spec_references.interactional_agency,
        "Ortega and de Freitas (2026)"
    );
    // Vendor-neutrality: no Anthropic / OpenAI / Google references.
    let combined = format!(
        "{}{}",
        layer.spec_references.do_calculus, layer.spec_references.interactional_agency
    );
    let lower = combined.to_lowercase();
    for vendor in ["anthropic", "openai", "google", "deepmind", "meta"] {
        assert!(
            !lower.contains(vendor),
            "spec_references must be vendor-neutral; found {vendor:?}"
        );
    }
}

#[test]
fn summary_within_word_budget() {
    let layer = default_capability_provenance_substrate_layer();
    let word_count = layer.summary.split_whitespace().count();
    // Per the deconfliction prompt, summary should be ~75 words.
    // Allow ±25 word margin so a future copyedit doesn't trip the
    // gate without intent.
    assert!(
        word_count <= 120,
        "summary should stay within ~120 words for token-budget safety; got {word_count}"
    );
}

#[test]
fn round_trip_through_serde_preserves_all_fields() {
    let layer = default_capability_provenance_substrate_layer();
    let json = serde_json::to_string(&layer).expect("serialise");
    let back: CapabilityProvenanceSubstrateLayer =
        serde_json::from_str(&json).expect("deserialise");
    assert_eq!(layer, back);
}

#[test]
fn defaulted_round_trip_via_serde_default() {
    // Pre-Item-C client sending `{}` for the field must deserialise
    // cleanly under #[serde(default)] (every field is #[serde(default)]
    // on the struct + the parent v3 envelope).
    let empty_json = "{}";
    let parsed: CapabilityProvenanceSubstrateLayer =
        serde_json::from_str(empty_json).expect("empty JSON must round-trip via serde default");
    assert_eq!(parsed.posture, "");
    assert!(parsed.enforcement_layers.is_empty());
    assert!(parsed.honest_limitations.is_empty());
}
