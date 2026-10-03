// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 (option 1) — refuse, AT BIND TIME, a namespace-standard binding that
//! would push an explicit `parent_namespace` chain (every hop counted) past
//! [`GOVERNANCE_CHAIN_MAX_DEPTH`].
//!
//! #4477 makes an over-depth entitled chain refuse every governed operation
//! (fail closed) instead of truncating it. Without a bind-time check, a
//! principal who can bind an UNBOUND root segment could hang an over-depth
//! same-owner chain above it and so make ANOTHER principal's governed subtree
//! under that root refuse everything (#4492). The explicit walk starts at the
//! rootmost `/` segment of a namespace and follows each node's
//! `parent_namespace` link while the hop is entitled (#2542: the parent is
//! unowned, or owned by the declaring node's owner).
//!
//! The measure counts EVERY explicit `parent_namespace` hop, regardless of
//! who owns the standards along it (#4492 B1). Entitlement can change WITHOUT
//! a bind (a standard above the chain is deleted, reaped, expires or is
//! tombstoned, and an unentitled hop becomes an unowned, entitled one), so a
//! bound measured over CURRENT entitlement would not hold; the link structure
//! itself changes only through a bind, so a bound on every hop holds
//! permanently: no later entitlement change can push a stored chain past
//! [`GOVERNANCE_CHAIN_MAX_DEPTH`].
//!
//! A bind changes ONE node's link, so the decision is made on the whole link
//! graph with that link replaced: every walk that starts at a root segment and
//! passes through (or starts at) the bound node is re-measured, which covers
//! the bound namespace's own chain, chains extended at their TOP (a link added
//! above an existing chain), and chains below it (slash roots and
//! explicit-parent children whose walk reaches it). A bind is refused when
//! such a walk would exceed the bound AND be longer than it is today, so an
//! operator can always keep or shorten a pre-existing (pre-#4477) chain.
//!
//! Both backends load the same rows inside the bind's write transaction (under
//! the sqlite writer lock / the postgres bind advisory lock) and call this one
//! pure decision, so they cannot disagree and two binds cannot race past it.
//! The read is the whole `namespace_meta` link column (bounded by the table;
//! narrowing it to the affected subgraph is a follow-up).
//!
//! The walk is conservative: it ignores ownership and the resolver's
//! per-namespace "parent already in my own `/` hierarchy" stop, so it can only
//! count a hop the resolver would not follow, never miss one it would.

use std::collections::{HashMap, HashSet};

use crate::governance::chain_depth::GOVERNANCE_CHAIN_MAX_DEPTH;

/// The fixed, value-free refusal text (no namespace, owner or policy). The
/// same text on every funnel and both backends: HTTP 400 `{"error": TEXT}`,
/// MCP error TEXT, SAL `InvalidInput { detail: TEXT }`.
pub const BIND_CHAIN_OVER_DEPTH: &str = "this namespace standard binding would make an \
     explicit parent_namespace chain exceed the maximum governance depth; refusing the \
     bind (#4492)";

/// One `namespace_meta` row's explicit link, as the chain walk sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRow {
    /// The namespace the row binds.
    pub namespace: String,
    /// Its explicit `parent_namespace` link, if any.
    pub parent: Option<String>,
}

struct Graph<'a> {
    parent: HashMap<&'a str, &'a str>,
}

impl<'a> Graph<'a> {
    fn new(rows: &'a [LinkRow]) -> Self {
        let parent = rows
            .iter()
            .filter_map(|r| r.parent.as_deref().map(|p| (r.namespace.as_str(), p)))
            .collect();
        Self { parent }
    }

    /// The explicit walk from `start`, every hop counted: (hops, nodes).
    fn walk(&self, start: &'a str) -> (usize, Vec<&'a str>) {
        let mut visited: Vec<&'a str> = vec![start];
        let mut seen: HashSet<&'a str> = HashSet::from([start]);
        let mut current = start;
        let mut hops = 0usize;
        while let Some(&p) = self.parent.get(current) {
            if p == "*" || seen.contains(p) {
                break;
            }
            hops = hops.saturating_add(1);
            visited.push(p);
            seen.insert(p);
            current = p;
        }
        (hops, visited)
    }
}

/// #4715 — one stored explicit chain that already exceeds the bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverDepthChain {
    /// The root-segment namespace the walk starts at.
    pub root: String,
    /// Every explicit hop the walk counted (always greater than
    /// [`GOVERNANCE_CHAIN_MAX_DEPTH`]).
    pub hops: usize,
}

/// #4715 — every stored explicit chain (walked from root segments only, the
/// same walk and the same every-hop count as the bind check) that is already
/// past [`GOVERNANCE_CHAIN_MAX_DEPTH`], sorted by root. The bind-time check
/// (#4492) stops NEW over-depth chains; pre-#4477 data and imported rows can
/// still hold one, and #4477 refuses every governed operation under it.
#[must_use]
pub fn over_depth_chains(rows: &[LinkRow]) -> Vec<OverDepthChain> {
    let graph = Graph::new(rows);
    let mut found: Vec<OverDepthChain> = graph
        .parent
        .keys()
        .copied()
        .filter(|ns| !ns.contains('/'))
        .filter_map(|start| {
            let (hops, _) = graph.walk(start);
            (hops > GOVERNANCE_CHAIN_MAX_DEPTH).then(|| OverDepthChain {
                root: start.to_string(),
                hops,
            })
        })
        .collect();
    found.sort_by(|a, b| a.root.cmp(&b.root));
    found
}

/// Would binding `bound` with `new_parent` as its explicit link push an
/// explicit chain (every hop counted) past the bound? `rows` is the current
/// `namespace_meta` link graph.
#[must_use]
pub fn bind_exceeds_chain_depth(rows: &[LinkRow], bound: &str, new_parent: Option<&str>) -> bool {
    let old = Graph::new(rows);
    let mut replaced: Vec<LinkRow> = rows
        .iter()
        .filter(|r| r.namespace != bound)
        .cloned()
        .collect();
    replaced.push(LinkRow {
        namespace: bound.to_string(),
        parent: new_parent.map(str::to_string),
    });
    let new = Graph::new(&replaced);
    // Walks start at root segments only (the resolver prepends the explicit
    // chain of a namespace's ROOTMOST `/` segment).
    let starts: HashSet<&str> = new
        .parent
        .keys()
        .chain(old.parent.keys())
        .copied()
        .filter(|ns| !ns.contains('/'))
        .collect();
    starts.into_iter().any(|start| {
        let (new_hops, path) = new.walk(start);
        if new_hops <= GOVERNANCE_CHAIN_MAX_DEPTH || !path.contains(&bound) {
            return false;
        }
        let (old_hops, _) = old.walk(start);
        new_hops > old_hops
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ns: &str, parent: Option<&str>) -> LinkRow {
        LinkRow {
            namespace: ns.into(),
            parent: parent.map(str::to_string),
        }
    }

    /// `{prefix}{from}` .. `{prefix}{to}` linked upward.
    fn chain(prefix: &str, from: usize, to: usize) -> Vec<LinkRow> {
        (from..to)
            .map(|i| row(&format!("{prefix}{i}"), Some(&format!("{prefix}{}", i + 1))))
            .collect()
    }

    #[test]
    fn the_root_link_that_makes_nine_hops_is_refused_and_eight_is_admitted_4492() {
        // c1 -> c2 -> ... -> c9 exists (8 hops from c1); binding v -> c1 is 9.
        let rows = chain("c", 1, 9);
        assert!(bind_exceeds_chain_depth(&rows, "v", Some("c1")));
        // c1 -> ... -> c8 (7 hops); v -> c1 makes exactly 8: admitted.
        let rows = chain("c", 1, 8);
        assert!(!bind_exceeds_chain_depth(&rows, "v", Some("c1")));
    }

    #[test]
    fn a_link_added_at_the_top_is_refused_4492() {
        // v -> c1 -> ... -> c8 (8 hops from v); binding c8 -> c9 extends the TOP.
        let mut rows = vec![row("v", Some("c1"))];
        rows.extend(chain("c", 1, 8));
        assert!(bind_exceeds_chain_depth(&rows, "c8", Some("c9")));
    }

    /// B1: every hop counts, whoever owns it (a hop that is unentitled today
    /// becomes entitled when the standard above it is severed, with no bind).
    #[test]
    fn hops_count_regardless_of_ownership_and_existing_overdepth_may_shrink_4492() {
        let rows = chain("c", 1, 9);
        assert!(bind_exceeds_chain_depth(&rows, "v", Some("c1")));
        // A pre-existing over-depth chain (9 hops) may be shortened ...
        let mut rows = vec![row("v", Some("c1"))];
        rows.extend(chain("c", 1, 9));
        assert!(!bind_exceeds_chain_depth(&rows, "c5", None));
        // ... and keeping it unchanged does not newly push it.
        assert!(!bind_exceeds_chain_depth(&rows, "c5", Some("c6")));
        // A cycle is not a chain: it terminates.
        let rows = vec![row("a", Some("b")), row("b", Some("a"))];
        assert!(!bind_exceeds_chain_depth(&rows, "a", Some("b")));
    }

    /// #4715: nine hops from a root segment is flagged, eight is not, a
    /// slash-named node is never a walk start, and a cycle terminates.
    #[test]
    fn over_depth_chains_flags_nine_hops_not_eight_4715() {
        let nine = chain("c", 0, 9);
        let found = over_depth_chains(&nine);
        assert_eq!(
            found,
            vec![OverDepthChain {
                root: "c0".into(),
                hops: 9
            }]
        );
        assert!(over_depth_chains(&chain("c", 0, 8)).is_empty());
        let mut slashed = chain("c", 1, 10);
        slashed.push(row("x/y", Some("c1")));
        assert!(over_depth_chains(&slashed).iter().all(|c| c.root != "x/y"));
        let cycle = vec![row("a", Some("b")), row("b", Some("a"))];
        assert!(over_depth_chains(&cycle).is_empty());
    }
}
