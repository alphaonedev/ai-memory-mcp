// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3435 — the ORDER-INDEPENDENT acyclicity verdict for a bulk
//! lineage import (`ai-memory migrate`, `ai-memory sync`).
//!
//! # The defect this closes
//!
//! The per-write lineage guard (Pass 0 of `validate_link_pre_create`, #1859)
//! keeps a SINGLE-NODE provenance graph acyclic without a traversal: every
//! `derived_from` / `reflects_on` / `derives_from` edge must point from a
//! STRICTLY NEWER `created_at` to a STRICTLY OLDER one, so following any
//! provenance path monotonically decreases the stamp and can never return
//! to its start. That proof is scoped to edges minted on ONE clock, one at a
//! time. A bulk import replays edges that were minted elsewhere: cross-node
//! clock skew, an operator-supplied `created_at`, or a historical import can
//! leave a genuinely-DAG edge whose source is wall-clock OLDER than its
//! target, and the per-write guard refuses it as a "reflection cycle". The
//! CLI validation sweep measured it: 12 of 289 provenance edges of a real
//! store were refused on `migrate`, and `sync` dropped the same shape
//! SILENTLY (`let _ = db::create_link(..)`).
//!
//! # The posture
//!
//! A bulk import is judged the way federation already is (the
//! `is_federation_import` bypass of Pass 0): every node lands first, every
//! edge is written through the inbound funnel that bypasses ONLY the
//! wall-clock heuristic, and acyclicity is asserted ONCE, structurally,
//! over the COMPLETE graph that will exist after the import — the union of
//! the destination's existing lineage edges and the incoming ones — BEFORE
//! any row is written. A valid DAG therefore round-trips independent of the
//! order `list_links` returns its edges in; a genuine cycle fails CLOSED for
//! the WHOLE import, with a typed error naming the nodes it could not
//! resolve, and never as a silently-dropped edge.
//!
//! Only the provenance relations in [`MemoryLinkRelation::LINEAGE`]
//! participate, matching Pass 0's scope: the other relations (`related_to`,
//! `contradicts`, ...) are allowed to cycle by design. Duplicate triples
//! collapse (both funnels are `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING`
//! on the unique key), and a self-loop is a cycle of length one.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use crate::models::{MemoryLink, MemoryLinkRelation};

/// How many unresolved node ids [`LineageCycle`] names in its message. The
/// full unresolved set can be the whole corpus (every node downstream of a
/// cycle is unresolved), so the message carries a bounded sample plus the
/// count.
const CYCLE_EXAMPLE_LIMIT: usize = 5;

/// The final imported lineage graph is NOT a DAG.
///
/// `unresolved` is the number of nodes the topological order could not
/// place — every node ON a cycle plus every node that can only be reached
/// THROUGH one. `examples` is a deterministic (lexicographically smallest)
/// sample of those ids, so the operator has a concrete place to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageCycle {
    /// Count of nodes left unresolved by the topological order.
    pub unresolved: usize,
    /// Up to [`CYCLE_EXAMPLE_LIMIT`] unresolved node ids, sorted.
    pub examples: Vec<String>,
}

impl std::fmt::Display for LineageCycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: the final imported lineage graph is not a DAG — {} node(s) lie on or \
             behind a provenance cycle (e.g. {}); refusing the whole import rather than \
             dropping edges",
            crate::storage::LINK_CYCLE_ERR_PREFIX,
            self.unresolved,
            self.examples.join(", "),
        )
    }
}

impl std::error::Error for LineageCycle {}

/// Assert that the lineage subgraph of `links` — the COMPLETE edge set a
/// bulk import will leave behind — is acyclic.
///
/// Pure and backend-blind: it reads only `(source_id, target_id, relation)`
/// and never consults a connection, so the sqlite and postgres importers
/// share ONE verdict. Kahn's algorithm over the deduplicated provenance
/// edges; `O(V + E)`.
///
/// # Errors
///
/// [`LineageCycle`] when at least one provenance cycle exists (a self-loop
/// counts). Non-lineage relations never contribute to the verdict.
pub fn validate_complete_lineage_dag<'a>(
    links: impl IntoIterator<Item = &'a MemoryLink>,
) -> Result<(), LineageCycle> {
    let mut seen: HashSet<(&str, &str, MemoryLinkRelation)> = HashSet::new();
    // BTreeMap keeps the ready-queue seeding and the unresolved sample
    // deterministic regardless of the input order — the whole point of an
    // order-independent verdict is that two runs over the same graph agree.
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut indegree: BTreeMap<&str, usize> = BTreeMap::new();

    for link in links {
        if !link.relation.is_lineage() {
            continue;
        }
        if !seen.insert((&link.source_id, &link.target_id, link.relation)) {
            continue;
        }
        adjacency
            .entry(link.source_id.as_str())
            .or_default()
            .push(link.target_id.as_str());
        indegree.entry(link.source_id.as_str()).or_insert(0);
        *indegree.entry(link.target_id.as_str()).or_insert(0) += 1;
    }

    let mut ready: VecDeque<&str> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(node, _)| *node)
        .collect();
    let mut placed = 0_usize;
    while let Some(node) = ready.pop_front() {
        placed += 1;
        let Some(targets) = adjacency.get(node) else {
            continue;
        };
        for target in targets {
            // Every target was registered with an indegree entry above, so
            // a miss here would be a bug in this function, not bad input.
            let Some(degree) = indegree.get_mut(target) else {
                continue;
            };
            *degree = degree.saturating_sub(1);
            if *degree == 0 {
                ready.push_back(target);
            }
        }
    }

    if placed == indegree.len() {
        return Ok(());
    }
    // Everything still carrying a positive indegree is on, or behind, a
    // cycle. Report a bounded, sorted sample plus the count.
    let unresolved: BTreeSet<&str> = indegree
        .iter()
        .filter(|(_, degree)| **degree > 0)
        .map(|(node, _)| *node)
        .collect();
    Err(LineageCycle {
        unresolved: unresolved.len(),
        examples: unresolved
            .iter()
            .take(CYCLE_EXAMPLE_LIMIT)
            .map(|id| (*id).to_string())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(source: &str, target: &str, relation: MemoryLinkRelation) -> MemoryLink {
        MemoryLink {
            source_id: source.to_string(),
            target_id: target.to_string(),
            relation,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    #[test]
    fn empty_and_non_lineage_graphs_are_trivially_acyclic() {
        validate_complete_lineage_dag(std::iter::empty()).expect("empty graph");
        // `related_to` / `contradicts` may cycle by design and never vote.
        let cyc = [
            edge("a", "b", MemoryLinkRelation::RelatedTo),
            edge("b", "a", MemoryLinkRelation::RelatedTo),
            edge("a", "b", MemoryLinkRelation::Contradicts),
            edge("b", "a", MemoryLinkRelation::Contradicts),
        ];
        validate_complete_lineage_dag(cyc.iter()).expect("non-lineage cycles are allowed");
    }

    #[test]
    fn valid_dag_is_accepted_in_every_edge_order() {
        // A diamond plus a long chain: a -> b -> d, a -> c -> d, d -> e.
        let edges = [
            edge("a", "b", MemoryLinkRelation::DerivedFrom),
            edge("b", "d", MemoryLinkRelation::ReflectsOn),
            edge("a", "c", MemoryLinkRelation::DerivesFrom),
            edge("c", "d", MemoryLinkRelation::DerivedFrom),
            edge("d", "e", MemoryLinkRelation::DerivedFrom),
            // A duplicate triple must collapse, not count twice.
            edge("d", "e", MemoryLinkRelation::DerivedFrom),
        ];
        validate_complete_lineage_dag(edges.iter()).expect("forward order");
        validate_complete_lineage_dag(edges.iter().rev()).expect("reverse order");
        // Every rotation: the verdict must not depend on which edge is seen
        // first (the property the per-write wall-clock guard lacks).
        for start in 0..edges.len() {
            let rotated = edges.iter().cycle().skip(start).take(edges.len());
            validate_complete_lineage_dag(rotated).expect("rotated order");
        }
    }

    #[test]
    fn genuine_cycle_is_refused_with_a_named_error() {
        let edges = [
            edge("a", "b", MemoryLinkRelation::DerivedFrom),
            edge("b", "c", MemoryLinkRelation::ReflectsOn),
            edge("c", "a", MemoryLinkRelation::DerivesFrom),
            // A node BEHIND the cycle is unresolved too, but the sample
            // is sorted, so the cycle members lead.
            edge("z", "a", MemoryLinkRelation::DerivedFrom),
        ];
        let err = validate_complete_lineage_dag(edges.iter()).expect_err("cycle");
        assert_eq!(
            err.unresolved, 3,
            "a, b, c are on the cycle; z feeds INTO it"
        );
        assert_eq!(err.examples, vec!["a", "b", "c"]);
        let msg = err.to_string();
        assert!(
            msg.starts_with(crate::storage::LINK_CYCLE_ERR_PREFIX),
            "message must carry the shared cycle prefix: {msg}"
        );
        assert!(msg.contains("refusing the whole import"), "{msg}");
    }

    #[test]
    fn self_loop_is_a_cycle_of_length_one() {
        let edges = [edge("a", "a", MemoryLinkRelation::DerivedFrom)];
        let err = validate_complete_lineage_dag(edges.iter()).expect_err("self-loop");
        assert_eq!(err.unresolved, 1);
        assert_eq!(err.examples, vec!["a"]);
    }

    #[test]
    fn unresolved_sample_is_bounded_and_sorted() {
        // A 2-cycle at the bottom with many nodes feeding into it: the
        // count is exact, the sample is capped at CYCLE_EXAMPLE_LIMIT and
        // lexicographically ordered regardless of input order.
        let mut edges = vec![
            edge("y", "z", MemoryLinkRelation::DerivedFrom),
            edge("z", "y", MemoryLinkRelation::DerivedFrom),
        ];
        for i in (0..20).rev() {
            edges.push(edge(
                &format!("n{i:02}"),
                "y",
                MemoryLinkRelation::ReflectsOn,
            ));
        }
        let err = validate_complete_lineage_dag(edges.iter()).expect_err("cycle");
        assert_eq!(
            err.unresolved, 2,
            "only y and z are unresolved (n* feed IN)"
        );
        assert_eq!(err.examples.len(), 2);

        // Now invert the feeders so they hang BELOW the cycle and are
        // unresolved too.
        let mut edges = vec![
            edge("y", "z", MemoryLinkRelation::DerivedFrom),
            edge("z", "y", MemoryLinkRelation::DerivedFrom),
        ];
        for i in (0..20).rev() {
            edges.push(edge(
                "z",
                &format!("n{i:02}"),
                MemoryLinkRelation::ReflectsOn,
            ));
        }
        let err = validate_complete_lineage_dag(edges.iter()).expect_err("cycle");
        assert_eq!(err.unresolved, 22);
        assert_eq!(err.examples.len(), CYCLE_EXAMPLE_LIMIT);
        assert_eq!(err.examples, vec!["n00", "n01", "n02", "n03", "n04"]);
    }
}
