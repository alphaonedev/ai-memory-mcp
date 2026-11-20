// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! Coverage uplift for `src/reranker.rs`.
//!
//! ## Scope and limitations
//!
//! Most of the uncovered lines in `reranker.rs` belong to the
//! `CrossEncoder::Neural` variant (`new_neural` / `load_neural` /
//! `neural_score`). This file reaches them through the staged offline
//! cache of `cross-encoder/ms-marco-MiniLM-L-6-v2` (#9509, staged by
//! `scripts/ci/stage_hf_cache.py`), never through a download.
//!
//! What this file contributes from the public integration surface:
//! - the neural load and score paths on the staged model, each asserted
//!   neural;
//! - the neural constructor's degraded fallback over an empty hub,
//!   asserted degraded lexical.
//! - The `Default` and `new()` constructors and a few additional
//!   `score()` / `rerank()` shapes the `cfg(test)` unit tests don't
//!   already cover (mostly redundant insurance — small lift).
//! - Behavioural smoke tests on the **lexical** path through the
//!   public `CrossEncoder::score` / `CrossEncoder::rerank` API.

use ai_memory::models::ConfidenceSource;
use ai_memory::models::{Memory, Tier};
use ai_memory::reranker::CrossEncoder;

#[path = "common/staged_models.rs"]
mod staged_models;
use staged_models::{offline_cross_encoder_in, staged_cross_encoder};

fn make_memory(title: &str, content: &str) -> Memory {
    Memory {
        id: "test-id".to_string(),
        tier: Tier::Mid,
        namespace: "test".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

// ---------------------------------------------------------------------------
// Constructor and trait-impl coverage from integration surface.
// ---------------------------------------------------------------------------

#[test]
fn default_returns_lexical_variant() {
    let ce = CrossEncoder::default();
    assert!(!ce.is_neural());
}

#[test]
fn new_returns_lexical_variant() {
    let ce = CrossEncoder::new();
    assert!(!ce.is_neural());
}

// ---------------------------------------------------------------------------
// The neural constructor, one exact outcome per test (#9509/#9515).
//
// An empty hub yields exactly the degraded lexical encoder; the staged
// offline cache (scripts/ci/stage_hf_cache.py) yields exactly the neural
// encoder. Neither path can reach the network or the host's own cache, and
// no test here mutates the process environment.
// ---------------------------------------------------------------------------

#[test]
fn new_neural_fallback_when_offline_returns_lexical() {
    let hub = tempfile::tempdir().expect("empty hub");
    let ce = offline_cross_encoder_in(hub.path());
    assert!(
        !ce.is_neural(),
        "an empty hub must not build the neural encoder"
    );
    assert!(
        ce.is_degraded_lexical(),
        "an empty hub must degrade to the lexical encoder"
    );
}

#[test]
fn new_neural_with_local_cache_runs_load_path() {
    // The happy load arm: config parsing, tokenizer load, weight mmap and
    // the classifier-head parse, from the staged cache only.
    let ce = staged_cross_encoder();
    assert!(
        ce.is_neural(),
        "the staged cache must build the neural encoder"
    );
    assert!(!ce.is_degraded_lexical());
}

#[test]
fn neural_score_path_is_safe_if_neural_variant_present() {
    // `score()` runs through the neural_score branch on the staged model.
    let ce = staged_cross_encoder();
    assert!(
        ce.is_neural(),
        "the staged cache must build the neural encoder"
    );
    let s = ce.score(
        "machine learning models",
        "Deep learning fundamentals",
        "Transformers and attention mechanisms",
    );
    assert!((0.0..=1.0).contains(&s), "score {s} out of bounds");
    // Run a second call to stress the model.lock() / mutex re-acquire path
    // in the Neural variant.
    let s2 = ce.score(
        "different query",
        "another title",
        "another content for the model",
    );
    assert!((0.0..=1.0).contains(&s2));
}

#[test]
fn neural_rerank_full_path_if_available() {
    // Exercises rerank() through the neural dispatcher with multiple
    // candidates: neural_score runs for each one on the staged model.
    let ce = staged_cross_encoder();
    assert!(
        ce.is_neural(),
        "the staged cache must build the neural encoder"
    );
    let cands = vec![
        (
            make_memory("BERT models for NLP", "transformers attention"),
            0.4,
        ),
        (make_memory("recipe for cookies", "flour butter sugar"), 0.7),
        (
            make_memory("rust async runtime", "tokio futures executor"),
            0.5,
        ),
    ];
    let out = ce.rerank("transformer attention bert", cands);
    assert_eq!(out.len(), 3);
    for (_, s) in &out {
        assert!((0.0..=1.0).contains(s), "blend score {s} out of bounds");
    }
}

// ---------------------------------------------------------------------------
// score() public dispatcher — lexical path
// ---------------------------------------------------------------------------

#[test]
fn score_dispatch_lexical_handles_typical_input() {
    let ce = CrossEncoder::new();
    let s = ce.score(
        "rust async runtime",
        "Tokio: Rust async runtime",
        "Tokio is an async runtime for the Rust programming language.",
    );
    assert!((0.0..=1.0).contains(&s));
    assert!(s > 0.0, "expected positive score for matching content");
}

#[test]
fn score_dispatch_lexical_with_no_overlap_is_low() {
    let ce = CrossEncoder::new();
    let s = ce.score(
        "quantum chromodynamics",
        "Cookies and Cream",
        "ice cream sundae with sprinkles",
    );
    assert!(s < 0.10, "expected near-zero, got {s}");
}

#[test]
fn score_dispatch_lexical_empty_query() {
    let ce = CrossEncoder::new();
    let s = ce.score("", "title", "content");
    assert!(s.abs() < f32::EPSILON, "expected ~0.0, got {s}");
}

#[test]
fn score_dispatch_lexical_empty_title_and_content() {
    let ce = CrossEncoder::new();
    let s = ce.score("query", "", "");
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn score_dispatch_lexical_only_punct_query() {
    let ce = CrossEncoder::new();
    let s_punct = ce.score("!?.,;:", "title", "content");
    let s_ws = ce.score("   \t\n", "title", "content");
    assert!(s_punct.abs() < f32::EPSILON, "punct → ~0.0, got {s_punct}");
    assert!(s_ws.abs() < f32::EPSILON, "ws → ~0.0, got {s_ws}");
}

#[test]
fn score_dispatch_lexical_unicode_safe() {
    let ce = CrossEncoder::new();
    let s = ce.score(
        "café résumé d'oeuvre",
        "Le Café d'Oeuvre",
        "résumé du café avec d'oeuvre noté",
    );
    assert!((0.0..=1.0).contains(&s));
}

// ---------------------------------------------------------------------------
// rerank() public API — additional shapes on top of cfg(test) unit tests.
// ---------------------------------------------------------------------------

#[test]
fn rerank_empty_input_returns_empty() {
    let ce = CrossEncoder::new();
    let out = ce.rerank("anything", Vec::new());
    assert!(out.is_empty());
}

#[test]
fn rerank_single_candidate_preserved() {
    let ce = CrossEncoder::new();
    let m = make_memory("only one", "only one body");
    let out = ce.rerank("only", vec![(m.clone(), 0.42)]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.title, "only one");
    assert!(out[0].1 >= 0.0);
}

#[test]
fn rerank_descending_order_invariant() {
    let ce = CrossEncoder::new();
    let cands: Vec<(Memory, f64)> = (0..7)
        .map(|i| {
            (
                make_memory(
                    &format!("title-{i}"),
                    &format!("body number {i} contains some words"),
                ),
                f64::from(i) * 0.1,
            )
        })
        .collect();
    let out = ce.rerank("title body", cands);
    assert_eq!(out.len(), 7);
    for w in out.windows(2) {
        assert!(
            w[0].1 >= w[1].1,
            "rerank must be sorted descending: {} < {}",
            w[0].1,
            w[1].1
        );
    }
}

#[test]
fn rerank_weights_topical_candidate_above_off_topic() {
    let ce = CrossEncoder::new();
    let on_topic = make_memory("rust async runtime", "tokio rust async runtime");
    let off_topic = make_memory("grocery", "milk eggs bread cheese");
    // Equal original scores — CE-blend should re-order based on lexical fit.
    let out = ce.rerank(
        "rust async runtime",
        vec![(off_topic.clone(), 0.5), (on_topic.clone(), 0.5)],
    );
    assert_eq!(out[0].0.title, "rust async runtime");
}

#[test]
fn rerank_blend_in_bounds_for_extreme_scores() {
    let ce = CrossEncoder::new();
    let m = make_memory("alpha", "alpha alpha alpha");
    // Original score at boundary 1.0; CE blend must still be in [0, 1.0]
    // because both factors are bounded.
    let out = ce.rerank("alpha", vec![(m.clone(), 1.0)]);
    assert_eq!(out.len(), 1);
    let final_score = out[0].1;
    assert!(
        (0.0..=1.0).contains(&final_score),
        "final score out of bounds: {final_score}"
    );
}

#[test]
fn rerank_handles_empty_titles_and_content_in_candidates() {
    let ce = CrossEncoder::new();
    let cands = vec![
        (make_memory("", ""), 0.5),
        (make_memory("alpha", ""), 0.5),
        (make_memory("", "alpha words here"), 0.5),
    ];
    let out = ce.rerank("alpha", cands);
    assert_eq!(out.len(), 3);
    for (_, s) in &out {
        assert!((0.0..=1.0).contains(s));
    }
}

#[test]
fn rerank_is_stable_when_inputs_have_no_query_tokens() {
    // Empty query — every CE score is 0, so final = 0.6 * original.
    let ce = CrossEncoder::new();
    let cands = vec![
        (make_memory("a", "alpha"), 0.10),
        (make_memory("b", "beta"), 0.50),
        (make_memory("c", "gamma"), 0.30),
    ];
    let out = ce.rerank("", cands);
    assert_eq!(out.len(), 3);
    // Highest original first.
    assert_eq!(out[0].0.title, "b");
    // Final scores are 0.6 * original.
    assert!((out[0].1 - 0.30).abs() < 1e-9);
    assert!((out[1].1 - 0.18).abs() < 1e-9);
    assert!((out[2].1 - 0.06).abs() < 1e-9);
}

// ---------------------------------------------------------------------------
// L0.7-4 Tier C — BatchedReranker coverage closures
// ---------------------------------------------------------------------------
//
// The cfg(test) unit tests in src/reranker.rs cover most BatchedReranker
// paths but skip several integration scenarios — particularly the
// degraded-lexical signal, with_params, encoder() accessor, and
// multi-fire serialization. These tests close those gaps.

#[test]
fn batched_reranker_new_wraps_lexical_encoder_correctly() {
    use ai_memory::reranker::BatchedReranker;
    let br = BatchedReranker::new(CrossEncoder::new());
    assert!(!br.is_neural());
    assert!(!br.is_degraded_lexical());
}

#[test]
fn batched_reranker_with_params_uses_custom_batch_and_wait() {
    use ai_memory::reranker::BatchedReranker;
    // Force tiny max_batch + larger wait to test the with_params path.
    let br = BatchedReranker::with_params(CrossEncoder::new(), 4, 10);
    let cands = vec![
        (make_memory("alpha", "alpha alpha"), 0.5),
        (make_memory("beta", "beta beta"), 0.4),
    ];
    let out = br.rerank("alpha", cands);
    assert_eq!(out.len(), 2);
    for (_, s) in &out {
        assert!((0.0..=1.0).contains(s));
    }
}

#[test]
fn batched_reranker_encoder_accessor_returns_inner() {
    use ai_memory::reranker::BatchedReranker;
    let br = BatchedReranker::new(CrossEncoder::new());
    let inner = br.encoder();
    // Inner encoder is the lexical variant we constructed.
    assert!(!inner.is_neural());
}

#[test]
fn batched_reranker_is_degraded_lexical_proxy_to_encoder() {
    use ai_memory::reranker::BatchedReranker;
    // An intentionally degraded encoder: the neural constructor over an
    // empty hub yields exactly Lexical { degraded: true }.
    let hub = tempfile::tempdir().expect("empty hub");
    let br = BatchedReranker::new(offline_cross_encoder_in(hub.path()));
    assert!(
        br.is_degraded_lexical(),
        "BatchedReranker must mirror the degraded encoder"
    );
}

#[test]
fn batched_reranker_handles_empty_candidates() {
    use ai_memory::reranker::BatchedReranker;
    let br = BatchedReranker::new(CrossEncoder::new());
    let out = br.rerank("q", Vec::new());
    assert!(out.is_empty());
}

#[test]
fn batched_reranker_serializes_concurrent_calls() {
    // Multiple sequential rerank() calls through the same batcher
    // exercises the worker's batch-loop steady-state path.
    use ai_memory::reranker::BatchedReranker;
    let br = BatchedReranker::new(CrossEncoder::new());
    for i in 0..5 {
        let cands = vec![
            (make_memory(&format!("alpha-{i}"), "alpha body"), 0.5),
            (make_memory(&format!("beta-{i}"), "beta body"), 0.4),
        ];
        let out = br.rerank("alpha", cands);
        assert_eq!(out.len(), 2);
    }
}

#[test]
fn batched_reranker_drop_terminates_worker() {
    // Construct + drop several batchers to exercise the H2 shutdown path.
    use ai_memory::reranker::BatchedReranker;
    for _ in 0..3 {
        let br = BatchedReranker::with_params(CrossEncoder::new(), 16, 5);
        // Use it once so the worker hits the inner loop at least once.
        let _ = br.rerank("x", vec![(make_memory("a", "a"), 0.5)]);
    }
    // If Drop hung the test would time out, so we get here only when
    // every worker exited cleanly via the shutdown channel.
}

// ---------------------------------------------------------------------------
// is_degraded_lexical: cover both branches on CrossEncoder directly.
// ---------------------------------------------------------------------------

#[test]
fn cross_encoder_is_degraded_lexical_for_non_degraded_is_false() {
    let ce = CrossEncoder::new();
    assert!(
        !ce.is_degraded_lexical(),
        "freshly-constructed lexical is not degraded"
    );
}
