// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2608 — external-consumer proof that the pluggable [`PairScorer`] seam
//! and the pre-flight `AI_MEMORY_RERANK_BUDGET_MS` budget are reachable
//! through the crate's PUBLIC surface, and that a neural rerank degrades to
//! the pre-rerank hybrid ordering when its estimated forward exceeds the
//! budget — all WITHOUT a BERT model (a CI host degrades a real neural
//! cross-encoder to lexical, so the seam is the only CI-testable path).
//!
//! The exhaustive branch matrix (tri-state grammar, estimate, score-floor
//! interaction) lives co-located in `src/reranker.rs`
//! (`reranker_budget_seam_2608_tests`) with private-item access; this file
//! pins that the seam is not accidentally made crate-private.

use ai_memory::models::Memory;
use ai_memory::reranker::{BatchedReranker, PairScorer, RerankerScoreFloor, rerank_budget};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn mem(title: &str, content: &str) -> Memory {
    Memory {
        title: title.to_string(),
        content: content.to_string(),
        ..Memory::default()
    }
}

struct CountingNeuralStub {
    calls: AtomicUsize,
}

impl PairScorer for CountingNeuralStub {
    fn score_pairs(&self, _query: &str, candidates: &[(Memory, f64)]) -> Vec<f32> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        candidates.iter().map(|_| 1.0).collect()
    }
    fn scorer_is_neural(&self) -> bool {
        true
    }
}

#[test]
fn rerank_public_seam_degrades_over_budget_and_admits_under_budget() {
    let stub = Arc::new(CountingNeuralStub {
        calls: AtomicUsize::new(0),
    });
    let reranker =
        BatchedReranker::with_scorer(stub.clone() as Arc<dyn PairScorer>, RerankerScoreFloor::Off);
    let candidates = vec![(mem("a", "aaaa"), 0.2_f64), (mem("b", "bbbb"), 0.8_f64)];

    // Over budget (1 ms): the neural forward is skipped, hybrid order shipped.
    ai_memory::reranker::set_rerank_budget_for_test(Some(1));
    assert_eq!(rerank_budget().map(|d| d.as_millis()), Some(1));
    let degraded = reranker.rerank("query", candidates.clone());
    assert_eq!(
        stub.calls.load(Ordering::Relaxed),
        0,
        "forward skipped over budget"
    );
    assert_eq!(
        degraded[0].0.title, "b",
        "pre-rerank hybrid order (by original score)"
    );
    assert!(
        (degraded[0].1 - 0.8).abs() < 1e-9,
        "original score, not blended"
    );

    // Under budget (huge): the neural forward runs, scores are blended.
    ai_memory::reranker::set_rerank_budget_for_test(Some(10_000_000));
    let admitted = reranker.rerank("query", candidates);
    assert_eq!(
        stub.calls.load(Ordering::Relaxed),
        1,
        "forward ran within budget"
    );
    // ce = 1.0 for both ⇒ blended = 0.6*orig + 0.4 ⇒ b = 0.88, a = 0.52.
    let by_title = |out: &[(Memory, f64)], t: &str| {
        out.iter()
            .find(|(m, _)| m.title == t)
            .map(|(_, s)| *s)
            .unwrap()
    };
    assert!((by_title(&admitted, "b") - 0.88).abs() < 1e-9);
    assert!((by_title(&admitted, "a") - 0.52).abs() < 1e-9);

    // Explicit 0 disables the budget entirely (tri-state).
    ai_memory::reranker::set_rerank_budget_for_test(Some(0));
    assert!(rerank_budget().is_none(), "explicit 0 disables the budget");

    ai_memory::reranker::set_rerank_budget_for_test(None);
}
