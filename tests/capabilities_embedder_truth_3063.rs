// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3063 — `memory_capabilities` / `GET /api/v1/capabilities` must report the
//! CONSTRUCTED embedder's model + dim, NOT the resolved-config default.
//!
//! Root cause: the `models.*` block is built by
//! [`ai_memory::config::build_capability_models`] from the resolver-derived
//! `ResolvedModels`. Under the operator-documented "embedding-guard-gap" the
//! embedder the process actually loaded can differ from what config resolved
//! (e.g. config resolves the nomic-768 tier preset while boot falls back to
//! the local MiniLM-384 embedder). Pre-fix, `/capabilities` advertised
//! nomic/768 while recall was actually MiniLM/384.
//!
//! These tests drive the pure reconciliation helpers + the REAL capabilities
//! `models.*` builder (the function that carried the bug), so no live embedder
//! construction (HF-Hub fetch / candle) is needed.

use ai_memory::config::{FeatureTier, ResolvedModels, build_capability_models};
use ai_memory::embeddings::{
    embedder_capability_mismatch, override_embedding_identity, reconcile_capability_models,
};

/// Resolved config for the nomic-768 tier preset — the value the capabilities
/// surface reported BEFORE #3063 regardless of what actually loaded.
fn nomic_768_resolved() -> ResolvedModels {
    let mut rm = ResolvedModels::default();
    rm.embeddings.model = "nomic-embed-text-v1.5".to_string();
    rm.embeddings.embedding_dim = Some(768);
    rm
}

#[test]
fn capabilities_report_constructed_minilm_not_config_nomic_3063() {
    // The guard-gap fallback: config says nomic-768, loaded embedder is
    // MiniLM-384. Capabilities MUST report 384.
    let resolved = nomic_768_resolved();
    let reconciled = override_embedding_identity(&resolved, "all-MiniLM-L6-v2", 384);

    // Flow it through the REAL capabilities `models.*` builder with an
    // embedding-enabled tier (autonomous). This is the function #3063 fixes.
    let tier = FeatureTier::Autonomous.config();
    let models = build_capability_models(&tier, &reconciled);

    assert_eq!(
        models.embedding_dim, 384,
        "capabilities must report the CONSTRUCTED embedder dim (384), not the config default (768)"
    );
    assert_eq!(
        models.embedding, "all-MiniLM-L6-v2",
        "capabilities must report the CONSTRUCTED embedder model, not the config default"
    );
}

#[test]
fn mismatch_detected_for_guard_gap_fallback_3063() {
    let resolved = nomic_768_resolved();
    // nomic-768 configured, MiniLM-384 loaded → mismatch (the case that WARNs).
    assert!(embedder_capability_mismatch(
        &resolved.embeddings,
        "all-MiniLM-L6-v2",
        384
    ));
}

#[test]
fn no_mismatch_when_loaded_matches_config_3063() {
    let resolved = nomic_768_resolved();
    // Same model (canonical id) + same dim → no mismatch, no spurious WARN.
    assert!(!embedder_capability_mismatch(
        &resolved.embeddings,
        "nomic-embed-text-v1.5",
        768
    ));
    // The org-prefixed HF id is the SAME model canonically → still no mismatch.
    assert!(!embedder_capability_mismatch(
        &resolved.embeddings,
        "nomic-ai/nomic-embed-text-v1.5",
        768
    ));
}

#[test]
fn matching_deployment_capabilities_unchanged_3063() {
    // When the loaded embedder matches config, the reported model + dim are
    // byte-identical to the pre-#3063 config-driven values.
    let resolved = nomic_768_resolved();
    let reconciled = override_embedding_identity(&resolved, "nomic-embed-text-v1.5", 768);
    let tier = FeatureTier::Autonomous.config();
    let models = build_capability_models(&tier, &reconciled);
    assert_eq!(models.embedding, "nomic-embed-text-v1.5");
    assert_eq!(models.embedding_dim, 768);
}

#[test]
fn no_embedder_leaves_config_values_intact_3063() {
    // Keyword tier / load failure: no embedder → config-resolved value stands.
    let resolved = nomic_768_resolved();
    let out = reconcile_capability_models(&resolved, None);
    assert_eq!(out.embeddings.model, "nomic-embed-text-v1.5");
    assert_eq!(out.embeddings.embedding_dim, Some(768));
}
