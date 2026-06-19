// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Clustering for the compaction pipeline.
//!
//! [`ConsolidationClustering`] is the single consolidation clusterer used by
//! `ConsolidationPass`. It is **reconciled to** `crate::autonomy::
//! find_consolidation_clusters` (#1740/#1741): a pair merges iff it passes a
//! **Jaccard pre-filter AND a cosine gate** — both must hold when embeddings
//! are available; when either side's embedding is missing (no embedder wired,
//! or an embed failure) the pair falls back to **Jaccard-only**, exactly
//! mirroring autonomy's per-pair contract. Greedy single-link, namespace-
//! scoped (never merges across namespaces, skips reserved `_`-prefixed), and
//! capped at [`MAX_CLUSTER_SIZE`].
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
/// then the cosine gate applies **only when a cosine value is available**
/// (`Some(c) => c >= cosine_threshold`); when no embedding is available for one
/// or both sides (`None`) the pair clusters on the Jaccard signal alone.
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
        None => true,
    }
}

// ---------------------------------------------------------------------------
// ConsolidationClustering — reconciled Jaccard-AND-cosine clusterer
// ---------------------------------------------------------------------------

/// The consolidation clusterer for `ConsolidationPass`, reconciled to
/// `crate::autonomy::find_consolidation_clusters` (#1741).
///
/// ## Algorithm (per namespace, greedy single-link)
///
/// 1. Group candidates by namespace; never merge across namespaces; skip
///    reserved (`_`-prefixed) namespaces.
/// 2. Embed each member once (via `embedder`); a `None` embedder — or a
///    per-row embed failure — leaves that row's embedding absent.
/// 3. For each unused seed, scan later members; a pair joins the cluster iff
///    [`pair_merges`] (Jaccard pre-filter AND cosine gate, Jaccard-only when an
///    embedding is absent). Clusters are capped at `max_cluster_size`.
/// 4. Singletons are discarded (only clusters of ≥ 2 are returned).
pub(crate) struct ConsolidationClustering {
    /// Jaccard pre-filter threshold. Defaults to [`JACCARD_THRESHOLD`].
    pub(crate) jaccard_threshold: f64,
    /// Cosine gate threshold. Defaults to [`DEFAULT_COSINE_THRESHOLD`].
    pub(crate) cosine_threshold: f64,
    /// Maximum members per cluster. Defaults to [`MAX_CLUSTER_SIZE`].
    pub(crate) max_cluster_size: usize,
    /// Embedding engine. When `None`, every pair falls back to Jaccard-only
    /// (matching autonomy on a corpus with no stored embeddings).
    pub(crate) embedder: Option<Embedder>,
}

impl ConsolidationClustering {
    /// Construct with the autonomy-matched default thresholds and the given
    /// embedder (`None` ⇒ Jaccard-only).
    pub(crate) fn new(embedder: Option<Embedder>) -> Self {
        Self {
            jaccard_threshold: JACCARD_THRESHOLD,
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: MAX_CLUSTER_SIZE,
            embedder,
        }
    }

    /// Partition `memories` into consolidation clusters. Only groups with
    /// ≥ 2 members are returned.
    pub(crate) fn cluster_memories(&self, memories: &[Memory]) -> Vec<Vec<MemoryId>> {
        // Group by namespace — never merge across namespace boundaries; skip
        // reserved `_`-prefixed namespaces.
        let mut by_ns: std::collections::HashMap<&str, Vec<&Memory>> =
            std::collections::HashMap::new();
        for m in memories {
            if m.namespace.starts_with('_') {
                continue;
            }
            by_ns.entry(&m.namespace).or_default().push(m);
        }

        let mut clusters: Vec<Vec<MemoryId>> = Vec::new();
        for (_ns, group) in by_ns {
            // Embed each member once (None when no embedder or an embed
            // failure) — mirrors autonomy reading a possibly-absent stored
            // embedding per row.
            let embs: Vec<Option<Vec<f32>>> = group
                .iter()
                .map(|m| {
                    self.embedder
                        .as_ref()
                        .and_then(|e| e.embed(&m.content).ok())
                })
                .collect();

            let mut used = vec![false; group.len()];
            for i in 0..group.len() {
                if used[i] {
                    continue;
                }
                let mut cluster = vec![group[i].id.clone()];
                used[i] = true;
                for j in (i + 1)..group.len() {
                    if used[j] {
                        continue;
                    }
                    if cluster.len() >= self.max_cluster_size {
                        break;
                    }
                    let jac = jaccard_similarity(&group[i].content, &group[j].content);
                    let cos = match (embs[i].as_ref(), embs[j].as_ref()) {
                        (Some(a), Some(b)) => Some(f64::from(Embedder::cosine_similarity(a, b))),
                        _ => None,
                    };
                    if pair_merges(jac, self.jaccard_threshold, cos, self.cosine_threshold) {
                        cluster.push(group[j].id.clone());
                        used[j] = true;
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
    fn pair_merges_high_jaccard_missing_embedding_falls_back_to_jaccard() {
        // No cosine available → Jaccard-only fallback (autonomy's contract).
        assert!(pair_merges(0.80, JACCARD_THRESHOLD, None, 0.75));
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

    // ---- ConsolidationClustering (no-embedder ⇒ Jaccard-only, deterministic) -

    #[test]
    fn clusters_jaccard_only_groups_near_duplicates_without_embedder() {
        let strategy = ConsolidationClustering::new(None);
        let dup = "kubernetes rolling canary deploy strategy kubernetes deploy";
        let m1 = make_memory("a", "ns", dup);
        let m2 = make_memory("b", "ns", dup);
        let m3 = make_memory("c", "ns", "completely different unrelated content here");
        let clusters = strategy.cluster_memories(&[m1, m2, m3]);
        assert_eq!(clusters.len(), 1, "expected one cluster; got {clusters:?}");
        assert!(clusters[0].contains(&"a".to_string()));
        assert!(clusters[0].contains(&"b".to_string()));
        assert!(!clusters[0].contains(&"c".to_string()));
    }

    #[test]
    fn clusters_never_merge_across_namespaces() {
        let strategy = ConsolidationClustering::new(None);
        let dup = "kubernetes rolling canary deploy strategy";
        let m1 = make_memory("a", "ns1", dup);
        let m2 = make_memory("b", "ns2", dup);
        let clusters = strategy.cluster_memories(&[m1, m2]);
        assert!(
            clusters.is_empty(),
            "cross-ns must not cluster; got {clusters:?}"
        );
    }

    #[test]
    fn clusters_skip_reserved_namespaces() {
        let strategy = ConsolidationClustering::new(None);
        let dup = "kubernetes rolling canary deploy strategy";
        let m1 = make_memory("a", "_curator", dup);
        let m2 = make_memory("b", "_curator", dup);
        let clusters = strategy.cluster_memories(&[m1, m2]);
        assert!(clusters.is_empty(), "reserved ns must be skipped");
    }

    #[test]
    fn clusters_respect_max_cluster_size() {
        let strategy = ConsolidationClustering {
            jaccard_threshold: 0.0, // accept all on Jaccard
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: 3,
            embedder: None, // None ⇒ Jaccard-only, so the 0.0 threshold rules
        };
        let mems: Vec<Memory> = (0..10)
            .map(|i| make_memory(&format!("m{i}"), "ns", "shared token content shared"))
            .collect();
        let clusters = strategy.cluster_memories(&mems);
        for c in &clusters {
            assert!(c.len() <= 3, "cluster size {}", c.len());
        }
    }

    #[test]
    fn clusters_empty_input_returns_empty() {
        let strategy = ConsolidationClustering::new(None);
        assert!(strategy.cluster_memories(&[]).is_empty());
    }

    #[test]
    fn clusters_skip_already_used_member() {
        // a≈b≈c all share tokens → one cluster of 3; exercises the inner
        // `if used[j] { continue; }` branch.
        let strategy = ConsolidationClustering {
            jaccard_threshold: 0.3,
            cosine_threshold: f64::from(DEFAULT_COSINE_THRESHOLD),
            max_cluster_size: 10,
            embedder: None,
        };
        let s = "shared keyword tokens deployment plan strategy";
        let clusters = strategy.cluster_memories(&[
            make_memory("a", "ns", s),
            make_memory("b", "ns", s),
            make_memory("c", "ns", s),
        ]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 3);
    }

    // ---- ConsolidationClustering with a real Embedder (skip if model cold) -
    //
    // Deterministic AND-gate coverage lives in the `pair_merges_*` tests above;
    // this only exercises the live-embedder cosine path opportunistically on
    // hosts whose HF model cache is warm (early-returns otherwise).

    fn try_local_embedder() -> Option<Embedder> {
        Embedder::new_local().ok()
    }

    #[test]
    fn clusters_with_embedder_merge_similar_and_split_dissimilar() {
        let Some(embedder) = try_local_embedder() else {
            return;
        };
        let strategy = ConsolidationClustering::new(Some(embedder));
        // High Jaccard AND high cosine (identical content) → merge.
        let dup = "Kubernetes rolling canary deployment strategy notes";
        let clusters =
            strategy.cluster_memories(&[make_memory("a", "ns", dup), make_memory("b", "ns", dup)]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 2);
    }
}
