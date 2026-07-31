// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2576 — the cross-encoder is not constructed when it can never
//! fire, and the rerank tokenizer is configured once rather than per call.
//!
//! **R-203.** `cross_encoder_is_not_built_without_an_embedder_2576` FAILS
//! at the parent commit: both boot sites decided on `tier_config
//! .cross_encoder` ALONE, so `(autonomous, no embedder)` built the model.
//!
//! These assert the DECISION and the CONFIGURATION, never the resulting
//! `CrossEncoder` variant. That is deliberate: a CI host has no model
//! weights and no egress, so `CrossEncoder::new_neural()` always degrades
//! to the lexical variant there — a test that asserted the variant would
//! pass vacuously whether or not the fix were present.

use ai_memory::reranker::{RERANK_MAX_SEQ_DEFAULT, should_build_cross_encoder};

/// The gate: an autonomous tier with NO embedder must not build it.
///
/// Recall can only reach `mode == "hybrid"` when a query embedding was
/// produced, and the rerank stage only runs on `hybrid`. With no embedder
/// every recall returns `mode:keyword`, so the model load and its resident
/// memory would be paid for a stage that is structurally unreachable —
/// the observed cost on any `AI_MEMORY_INFERENCE_EGRESS=deny` (env #131)
/// or #1593-degraded deployment.
#[test]
fn cross_encoder_is_not_built_without_an_embedder_2576() {
    assert!(
        !should_build_cross_encoder(true, false),
        "an autonomous tier with NO embedder must NOT build the cross-encoder: \
         recall degrades to keyword, so the rerank stage is unreachable (#2576)"
    );
}

/// The gate does not over-reach: with an embedder present, an
/// autonomous tier still builds it (byte-identical to pre-#2576).
#[test]
fn cross_encoder_is_still_built_when_the_embedder_is_present_2576() {
    assert!(
        should_build_cross_encoder(true, true),
        "the #2576 gate must not change the healthy autonomous posture"
    );
}

/// A non-autonomous tier never builds it, embedder or not — the gate is
/// an AND, so it can only ever REMOVE a construction, never add one.
#[test]
fn a_non_autonomous_tier_never_builds_the_cross_encoder_2576() {
    assert!(!should_build_cross_encoder(false, true));
    assert!(!should_build_cross_encoder(false, false));
}

/// The `max_seq` default is UNCHANGED at 256.
///
/// #2576 proposed lowering it to 64 for a measured ~30% latency win. That
/// was REFUSED by the 5-agent vote (`4d3ea1c5`) on measured evidence, and
/// this pin is the guard against it being "optimised" later without that
/// evidence:
///
/// * the batch is padded `BatchLongest` — to the longest sequence IN THE
///   BATCH, never to `max_seq` — so the 256 cap costs nothing on a corpus
///   of short memories. On the #2576 reference corpus (7,855 rows, content
///   avg 391 B / p95 593 B) it truncates **0.0%** of pairs and the batch
///   pads to ~135 tokens.
/// * `max_seq` is therefore a TRUNCATION bound, not a pad width. Lowering
///   it to 64 truncates **91.8%** of pairs and discards ~28% of the median
///   document before the cross-encoder ever scores it.
///
/// A latency win bought by deleting the document is a recall-quality
/// regression sold as a performance fix.
#[test]
fn rerank_max_seq_default_stays_256_2576() {
    assert_eq!(
        RERANK_MAX_SEQ_DEFAULT, 256,
        "#2576: max_seq is a TRUNCATION cap under BatchLongest padding, not a \
         pad width. Lowering it buys latency by discarding document tokens \
         (91.8% of pairs truncated at 64 on the reference corpus). Do not \
         retune without a measured relevance A/B."
    );
}
