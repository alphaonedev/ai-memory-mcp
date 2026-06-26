// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Clustering for the compaction pipeline.
//!
//! [`ConsolidationClustering`] is the single consolidation clusterer used by
//! `ConsolidationPass`. It is **reconciled to** `crate::autonomy::
//! find_consolidation_clusters` (#1740/#1741): a pair merges iff it passes
//! **BOTH a Jaccard pre-filter AND a cosine gate** — both must hold, and the
//! cosine gate requires a stored embedding on **each** side. When either
//! side's embedding is missing (no embedder wired, an embed failure, a
//! keyword-tier / never-embedded / oversize-skip row) the pair does **NOT**
//! merge (#1774, 5-agent vote 4d3ea1c5): a destructive consolidation merge is
//! never decided on lexical Jaccard overlap alone — the cosine safety gate is
//! mandatory. This exactly mirrors autonomy's per-pair contract. Greedy
//! single-link, namespace-scoped (never merges across namespaces, skips
//! reserved `_`-prefixed), and capped at [`MAX_CLUSTER_SIZE`].
//!
//! The per-pair decision is factored into the pure [`pair_merges`] function so
//! the AND-gate semantics are unit-tested deterministically WITHOUT a live
//! `Embedder` (the cold-model-cache CI hazard that would otherwise silently
//! degrade an embedder-dependent test to Jaccard-only — #1741).
//!
//! ## Visibility contract (R7)
//!
//! All items are at most `pub(crate)` — nothing escapes the crate boundary.

// The consolidation clusterer is exercised only by the SAL-gated curator
// passes; in a non-sal build the config-default threshold const is the only
// live item, so relax the dead-code lint there only — sal builds enforce it.
#![cfg_attr(not(feature = "sal"), allow(dead_code))]

use std::collections::HashSet;

use crate::embeddings::Embedder;
use crate::models::Memory;

use super::pipeline::MemoryId;

// ---------------------------------------------------------------------------
// Shared constants (kept equal to crate::autonomy::CONSOLIDATE_* — the
// `constants_match_autonomy` test pins the parity so the reconciled clusterer
// cannot silently drift from the live v0.6.x consolidation semantics.)
// ---------------------------------------------------------------------------

/// Minimum Jaccard overlap to place two memories in the same cluster.
/// Equals `crate::autonomy::CONSOLIDATE_JACCARD_THRESHOLD` (0.55).
pub(crate) const JACCARD_THRESHOLD: f64 = 0.55;

/// Maximum members per cluster — prevents pathological mega-merges.
/// Equals `crate::autonomy::CONSOLIDATE_MAX_CLUSTER_SIZE` (8).
pub(crate) const MAX_CLUSTER_SIZE: usize = 8;

/// Default cosine similarity threshold (the cosine gate). Memories whose
/// pairwise cosine similarity ≥ this value (and which also pass the Jaccard
/// pre-filter) are placed in the same cluster. Equals
/// `crate::autonomy::CONSOLIDATE_COSINE_THRESHOLD` (0.75). Also surfaced as
/// the `[curator.compaction].cosine_threshold` config default.
pub(crate) const DEFAULT_COSINE_THRESHOLD: f32 = 0.75;

// ---------------------------------------------------------------------------
// Per-pair merge decision (pure — deterministically testable, no Embedder)
// ---------------------------------------------------------------------------

/// Decide whether a candidate pair should merge, given their Jaccard overlap
/// and (optionally) their cosine similarity.
///
/// Mirrors `crate::autonomy::find_consolidation_clusters`'s per-pair contract
/// exactly: the Jaccard pre-filter is mandatory (`jaccard >= jaccard_threshold`),
/// then the cosine gate must ALSO hold (`Some(c) => c >= cosine_threshold`).
/// #1774 — when no embedding is available for one or both sides (`None`) the
/// pair does NOT merge: a destructive consolidation merge requires the cosine
/// safety gate, never Jaccard lexical overlap alone.
///
/// Pure + total, so the AND-gate is unit-tested without a live `Embedder`.
pub(crate) fn pair_merges(
    jaccard: f64,
    jaccard_threshold: f64,
    cos: Option<f64>,
    cosine_threshold: f64,
) -> bool {
    if jaccard < jaccard_threshold {
        return false;
    }
    match cos {
        Some(c) => c >= cosine_threshold,
        // #1774 (5-agent vote 4d3ea1c5 → A) — REQUIRE a cosine value (both
        // sides embedded) for a destructive merge. Pre-fix `None => true`
        // merged un-embedded rows (keyword-tier / never-embedded / oversize)
        // on Jaccard lexical overlap ALONE, bypassing the cosine safety gate
        // — a false-positive merge then merge-and-deletes a distinct memory.
        // Lexical overlap is not a safe basis for a destructive op (two
        // distinct memories can share high Jaccard, e.g. templated content),
        // and there is no defensible lexical-only threshold comparable to the
        // semantic gate. This mirrors the codebase's skip-on-missing-embedding
        // posture for the other DESTRUCTIVE path (proactive_conflict_check
        // filters `embedding IS NOT NULL`). Un-embedded corpora no longer
        // auto-consolidate (documented behavior change).
        None => false,
    }
}

// ---------------------------------------------------------------------------
// ConsolidationClustering — reconciled Jaccard-AND-cosine clusterer
// ---------------------------------------------------------------------------

/// The consolidation clusterer for `ConsolidationPass`, reconciled to
/// `crate::autonomy::find_consolidation_clusters` (#1741/#1743).
///
/// ## Algorithm (per namespace, greedy single-link)
///
/// 1. Group candidates by namespace; never merge across namespaces; skip
///    reserved (`_`-prefixed) namespaces.
/// 2. The caller supplies each member's **stored** embedding (read via
///    `MemoryStore::get_embedding`, NOT re-embedded live — matching autonomy's
///    `db::get_embedding` source exactly, #1743). A `None` entry means the row
///    has no stored embedding (keyword-tier / never-embedded / oversize-skip).
/// 3. For each unused seed, scan later members; a pair joins the cluster iff
///    [`pair_merges`] — the Jaccard pre-filter AND the cosine gate must BOTH
///    hold. When an embedding is absent on either side the pair does NOT merge
///    (#1774): a missing embedding means no cosine value, and a destructive
///    merge is never decided on Jaccard lexical overlap alone. Clusters are
///    capped at `max_cluster_size`.
/// 4. Singletons are discarded (only clusters of ≥ 2 are returned).
pub(crate) struct ConsolidationClustering {
    /// Jaccard pre-filter threshold. Defaults to [`JACCARD_THRESHOLD`].
    pub(crate) jaccard_threshold: f64,
    /// Cosine gate threshold. Defaults to [`DEFAULT_COSINE_THRESHOLD`].
    pub(crate) cosine_threshold: f64,
    /// Maximum members per cluster. Defaults to [`MAX_CLUSTER_SIZE`].
    pub(crate) max_cluster_size: usize,
}

impl Default for ConsolidationClustering {
    fn default() -> Self {
        Self {
            jaccard_threshold: JACCARD_THRESHOLD,
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: MAX_CLUSTER_SIZE,
        }
    }
}

impl ConsolidationClustering {
    /// Construct with the autonomy-matched default thresholds.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Partition `memories` into consolidation clusters. `embeddings` aligns
    /// 1:1 to `memories` (`embeddings[i]` is the stored vector for
    /// `memories[i]`, or `None`). Only groups with ≥ 2 members are returned.
    pub(crate) fn cluster_memories(
        &self,
        memories: &[Memory],
        embeddings: &[Option<Vec<f32>>],
    ) -> Vec<Vec<MemoryId>> {
        // Group by namespace (carrying the original index so the aligned
        // `embeddings` slice is addressable); never merge across namespace
        // boundaries; skip reserved `_`-prefixed namespaces.
        let mut by_ns: std::collections::HashMap<&str, Vec<usize>> =
            std::collections::HashMap::new();
        for (idx, m) in memories.iter().enumerate() {
            if m.namespace.starts_with('_') {
                continue;
            }
            by_ns.entry(&m.namespace).or_default().push(idx);
        }

        let mut clusters: Vec<Vec<MemoryId>> = Vec::new();
        for (_ns, idxs) in by_ns {
            let mut used = vec![false; idxs.len()];
            for a in 0..idxs.len() {
                if used[a] {
                    continue;
                }
                let i = idxs[a];
                let mut cluster = vec![memories[i].id.clone()];
                used[a] = true;
                for b in (a + 1)..idxs.len() {
                    if used[b] {
                        continue;
                    }
                    if cluster.len() >= self.max_cluster_size {
                        break;
                    }
                    let j = idxs[b];
                    let jac = jaccard_similarity(&memories[i].content, &memories[j].content);
                    let cos = match (embeddings[i].as_ref(), embeddings[j].as_ref()) {
                        (Some(x), Some(y)) => Some(f64::from(Embedder::cosine_similarity(x, y))),
                        _ => None,
                    };
                    if pair_merges(jac, self.jaccard_threshold, cos, self.cosine_threshold) {
                        cluster.push(memories[j].id.clone());
                        used[b] = true;
                    }
                }
                if cluster.len() >= 2 {
                    clusters.push(cluster);
                }
            }
        }
        clusters
    }
}

// ---------------------------------------------------------------------------
// Shared helper — Jaccard similarity on tokenised content
// ---------------------------------------------------------------------------

/// Compute the Jaccard similarity between two content strings.
///
/// Tokens are runs of ≥ 3 alphanumeric characters, lowercased.
/// Identical to the implementation extracted from `crate::autonomy`. Also used
/// by `crate::curator::reflection_pass`.
pub(super) fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let tokens = |s: &str| -> HashSet<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 3)
            .map(str::to_lowercase)
            .collect()
    };
    let ta = tokens(a);
    let tb = tokens(b);
    if ta.is_empty() && tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    if union == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let result = inter as f64 / union as f64;
        result
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, Tier};

    fn make_memory(id: &str, ns: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: id.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    // ---- constant parity (drift-guard vs autonomy) -------------------------

    #[cfg(feature = "sal")]
    #[test]
    fn constants_match_autonomy() {
        // The reconciled clusterer is only behavior-equivalent to the live
        // autonomy consolidation if the thresholds/cap stay identical. Pin it.
        assert!((JACCARD_THRESHOLD - crate::autonomy::CONSOLIDATE_JACCARD_THRESHOLD).abs() < 1e-9);
        assert!(
            (f64::from(DEFAULT_COSINE_THRESHOLD) - crate::autonomy::CONSOLIDATE_COSINE_THRESHOLD)
                .abs()
                < 1e-9
        );
        assert_eq!(
            MAX_CLUSTER_SIZE,
            crate::autonomy::CONSOLIDATE_MAX_CLUSTER_SIZE
        );
    }

    // ---- pair_merges — the AND-gate, proven without a live Embedder --------

    #[test]
    fn pair_merges_high_jaccard_high_cosine_merges() {
        // Both gates pass → merge.
        assert!(pair_merges(0.80, JACCARD_THRESHOLD, Some(1.0), 0.75));
    }

    #[test]
    fn pair_merges_high_jaccard_low_cosine_does_not_merge() {
        // THE AND-GATE PROOF: Jaccard passes but cosine fails → NO merge.
        // This is exactly the over-merge a Jaccard-only path would wrongly do.
        assert!(!pair_merges(0.80, JACCARD_THRESHOLD, Some(0.0), 0.75));
    }

    #[test]
    fn pair_merges_high_jaccard_missing_embedding_does_not_merge() {
        // #1774 — no cosine available (embedding absent on a side) → NO merge:
        // a destructive merge is never decided on Jaccard lexical overlap alone.
        assert!(!pair_merges(0.80, JACCARD_THRESHOLD, None, 0.75));
    }

    #[test]
    fn pair_merges_1774_missing_embedding_blocks_merge_present_embedding_merges() {
        // #1774 (5-agent vote 4d3ea1c5) focused pin: a missing embedding on a
        // side blocks the merge even at high Jaccard; both sides embedded and
        // above the cosine gate still merges.
        assert!(!pair_merges(0.9, JACCARD_THRESHOLD, None, 0.75));
        assert!(pair_merges(0.9, JACCARD_THRESHOLD, Some(0.8), 0.75));
    }

    #[test]
    fn pair_merges_low_jaccard_high_cosine_does_not_merge() {
        // Jaccard pre-filter is mandatory: fails it → NO merge even at cos=1.0.
        assert!(!pair_merges(0.10, JACCARD_THRESHOLD, Some(1.0), 0.75));
    }

    #[test]
    fn pair_merges_boundary_values_are_inclusive() {
        // `>=` on both gates (matches autonomy).
        assert!(pair_merges(
            JACCARD_THRESHOLD,
            JACCARD_THRESHOLD,
            Some(0.75),
            0.75
        ));
        assert!(!pair_merges(
            JACCARD_THRESHOLD - 1e-6,
            JACCARD_THRESHOLD,
            None,
            0.75
        ));
        assert!(!pair_merges(
            JACCARD_THRESHOLD,
            JACCARD_THRESHOLD,
            Some(0.75 - 1e-6),
            0.75
        ));
    }

    // ---- jaccard_similarity ------------------------------------------------

    #[test]
    fn jaccard_identical_strings() {
        let s = "kubernetes rolling canary deploy strategy kubernetes deploy";
        assert!((jaccard_similarity(s, s) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_disjoint_strings() {
        let a = "apple banana cherry";
        let b = "delta echo foxtrot";
        assert_eq!(jaccard_similarity(a, b), 0.0);
    }

    #[test]
    fn jaccard_partial_overlap() {
        let a = "rust programming language memory safety";
        let b = "rust language systems programming";
        let sim = jaccard_similarity(a, b);
        assert!(sim > 0.0 && sim < 1.0, "sim={sim}");
    }

    #[test]
    fn jaccard_empty_strings() {
        assert_eq!(jaccard_similarity("", ""), 0.0);
    }

    // ---- ConsolidationClustering (deterministic; injected stored vectors) --
    //
    // `embeddings` aligns 1:1 to `memories`; `None` = no stored vector. Per
    // #1774 a pair with a `None` on either side does NOT merge (the cosine
    // safety gate is mandatory for a destructive merge). No live `Embedder` is
    // constructed — these are fully deterministic and CI-cache-independent
    // (#1743).

    /// `None` embeddings of length `n` — the un-embedded / keyword-tier path.
    /// Per #1774 a pair lacking a stored vector on either side never merges.
    fn no_embs(n: usize) -> Vec<Option<Vec<f32>>> {
        vec![None; n]
    }

    /// Identical aligned stored vectors of length `n` (cosine = 1.0 for every
    /// pair) — drives the embedded merge path deterministically post-#1774,
    /// for tests whose subject is namespace/cap logic, not the missing-vector
    /// contract.
    fn aligned_embs(n: usize) -> Vec<Option<Vec<f32>>> {
        vec![Some(vec![1.0_f32, 0.0]); n]
    }

    #[test]
    fn clusters_no_stored_vectors_do_not_merge_1774() {
        // #1774 — un-embedded corpus: even near-identical (high-Jaccard)
        // content does NOT cluster without a cosine value on both sides.
        let strategy = ConsolidationClustering::new();
        let dup = "kubernetes rolling canary deploy strategy kubernetes deploy";
        let mems = [
            make_memory("a", "ns", dup),
            make_memory("b", "ns", dup),
            make_memory("c", "ns", "completely different unrelated content here"),
        ];
        let clusters = strategy.cluster_memories(&mems, &no_embs(3));
        assert!(
            clusters.is_empty(),
            "un-embedded pairs must not merge on Jaccard alone; got {clusters:?}"
        );
    }

    #[test]
    fn clusters_cosine_gate_splits_keyword_overlap_with_dissimilar_vectors() {
        // THE AND-GATE at clusterer level, deterministic: identical (high-Jaccard)
        // content but ORTHOGONAL stored vectors (cos=0 < 0.75) → NO merge — the
        // over-merge a Jaccard-only path would wrongly produce.
        let strategy = ConsolidationClustering::new();
        let dup = "kubernetes rolling canary deploy strategy kubernetes deploy";
        let mems = [make_memory("a", "ns", dup), make_memory("b", "ns", dup)];
        let orthogonal = vec![Some(vec![1.0_f32, 0.0]), Some(vec![0.0_f32, 1.0])];
        assert!(
            strategy.cluster_memories(&mems, &orthogonal).is_empty(),
            "cosine gate must block keyword-overlapping but vector-dissimilar pair"
        );
        // Same content, IDENTICAL vectors (cos=1.0 ≥ 0.75) → merge.
        let aligned = vec![Some(vec![1.0_f32, 0.0]), Some(vec![1.0_f32, 0.0])];
        let clusters = strategy.cluster_memories(&mems, &aligned);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 2);
    }

    #[test]
    fn clusters_missing_one_vector_does_not_merge_1774() {
        // #1774 — one side has no stored vector → no cosine value → NO merge,
        // even for identical (high-Jaccard) content. A destructive merge is
        // never decided on Jaccard lexical overlap alone.
        let strategy = ConsolidationClustering::new();
        let dup = "kubernetes rolling canary deploy strategy kubernetes deploy";
        let mems = [make_memory("a", "ns", dup), make_memory("b", "ns", dup)];
        let embs = vec![Some(vec![1.0_f32, 0.0]), None];
        let clusters = strategy.cluster_memories(&mems, &embs);
        assert!(
            clusters.is_empty(),
            "missing-vector pair must NOT merge; got {clusters:?}"
        );
    }

    #[test]
    fn clusters_never_merge_across_namespaces() {
        let strategy = ConsolidationClustering::new();
        let dup = "kubernetes rolling canary deploy strategy";
        let mems = [make_memory("a", "ns1", dup), make_memory("b", "ns2", dup)];
        let clusters = strategy.cluster_memories(&mems, &no_embs(2));
        assert!(
            clusters.is_empty(),
            "cross-ns must not cluster; got {clusters:?}"
        );
    }

    #[test]
    fn clusters_skip_reserved_namespaces() {
        let strategy = ConsolidationClustering::new();
        let dup = "kubernetes rolling canary deploy strategy";
        let mems = [
            make_memory("a", "_curator", dup),
            make_memory("b", "_curator", dup),
        ];
        let clusters = strategy.cluster_memories(&mems, &no_embs(2));
        assert!(clusters.is_empty(), "reserved ns must be skipped");
    }

    #[test]
    fn clusters_respect_max_cluster_size() {
        let strategy = ConsolidationClustering {
            jaccard_threshold: 0.0, // accept all on Jaccard
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: 3,
        };
        let mems: Vec<Memory> = (0..10)
            .map(|i| make_memory(&format!("m{i}"), "ns", "shared token content shared"))
            .collect();
        // Aligned stored vectors (cosine = 1.0) so pairs actually merge
        // post-#1774 — this test's subject is the size cap, not the
        // missing-vector contract.
        let clusters = strategy.cluster_memories(&mems, &aligned_embs(mems.len()));
        assert!(
            !clusters.is_empty(),
            "expected clusters to exercise the cap"
        );
        for c in &clusters {
            assert!(c.len() <= 3, "cluster size {}", c.len());
        }
    }

    #[test]
    fn clusters_empty_input_returns_empty() {
        let strategy = ConsolidationClustering::new();
        assert!(strategy.cluster_memories(&[], &[]).is_empty());
    }

    #[test]
    fn clusters_skip_already_used_member() {
        // a≈b≈c all share tokens → one cluster of 3; exercises the inner
        // `if used[b] { continue; }` branch.
        let strategy = ConsolidationClustering {
            jaccard_threshold: 0.3,
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: 10,
        };
        let s = "shared keyword tokens deployment plan strategy";
        let mems = [
            make_memory("a", "ns", s),
            make_memory("b", "ns", s),
            make_memory("c", "ns", s),
        ];
        // Aligned stored vectors (cosine = 1.0) so all three pairs merge
        // post-#1774 — this test's subject is the `used[b]` skip branch.
        let clusters = strategy.cluster_memories(&mems, &aligned_embs(3));
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 3);
    }
}
