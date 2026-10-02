// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 (option 1) — refuse, AT BIND TIME, a namespace-standard binding that
//! would push an ENTITLED explicit `parent_namespace` chain past
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
//! A bind changes ONE node's link and owner, so the decision is made on the
//! whole link graph with that node replaced: every walk that starts at a root
//! segment and passes through (or starts at) the bound node is re-measured,
//! which covers the bound namespace's own chain, chains extended at their TOP
//! (a link added above an existing chain), and chains below it (slash roots
//! and explicit-parent children whose walk reaches it). A bind is refused when
//! such a walk would exceed the bound AND be longer than it is today, so an
//! operator can always shorten or keep a pre-existing (pre-#4477) chain.
//!
//! Both backends load the same rows inside the bind's write transaction (under
//! the sqlite writer lock / the postgres bind advisory lock) and call this one
//! pure decision, so they cannot disagree and two binds cannot race past it.
//!
//! The walk is conservative in one respect: it does not apply the resolver's
//! per-namespace "parent already in my own `/` hierarchy" stop, so in a graph
//! that links back into a start's own subtree it may count a hop the resolver
//! would not. That can only refuse, never admit, an over-depth link.

use std::collections::{HashMap, HashSet};

use crate::governance::chain_depth::GOVERNANCE_CHAIN_MAX_DEPTH;

/// The fixed, value-free refusal text (no namespace, owner or policy). The
/// same text on every funnel and both backends: HTTP 400 `{"error": TEXT}`,
/// MCP error TEXT, SAL `InvalidInput { detail: TEXT }`.
pub const BIND_CHAIN_OVER_DEPTH: &str = "this namespace standard binding would make an \
     entitled explicit parent_namespace chain exceed the maximum governance depth; \
     refusing the bind (#4492)";

/// One `namespace_meta` row as the chain walk sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRow {
    /// The namespace the row binds.
    pub namespace: String,
    /// Its explicit `parent_namespace` link, if any.
    pub parent: Option<String>,
    /// The bound standard's concrete owner (`None` = unbound, severed,
    /// dangling or unowned), normalised exactly as the backend's own chain
    /// builder normalises it.
    pub owner: Option<String>,
}

struct Graph<'a> {
    parent: HashMap<&'a str, &'a str>,
    owner: HashMap<&'a str, Option<&'a str>>,
}

impl<'a> Graph<'a> {
    fn new(rows: &'a [LinkRow]) -> Self {
        let mut parent = HashMap::new();
        let mut owner = HashMap::new();
        for r in rows {
            if let Some(p) = r.parent.as_deref() {
                parent.insert(r.namespace.as_str(), p);
            }
            owner.insert(r.namespace.as_str(), r.owner.as_deref());
        }
        Self { parent, owner }
    }

    fn owner_of(&self, ns: &str) -> Option<&'a str> {
        self.owner.get(ns).copied().flatten()
    }

    /// The entitled explicit walk from `start`: (hops, nodes visited).
    fn walk(&self, start: &'a str) -> (usize, Vec<&'a str>) {
        let mut visited: Vec<&'a str> = vec![start];
        let mut seen: HashSet<&'a str> = HashSet::from([start]);
        let mut current = start;
        let mut hops = 0usize;
        while let Some(&p) = self.parent.get(current) {
            if p == "*" || seen.contains(p) {
                break;
            }
            let entitled = match self.owner_of(p) {
                None => true,
                Some(po) => self.owner_of(current) == Some(po),
            };
            if !entitled {
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

/// Would binding `bound` (with `new_parent` as its explicit link and
/// `new_owner` as its standard's owner) push an entitled chain past the
/// bound? `rows` is the current `namespace_meta` link graph.
#[must_use]
pub fn bind_exceeds_chain_depth(
    rows: &[LinkRow],
    bound: &str,
    new_parent: Option<&str>,
    new_owner: Option<&str>,
) -> bool {
    let old = Graph::new(rows);
    let mut replaced: Vec<LinkRow> = rows
        .iter()
        .filter(|r| r.namespace != bound)
        .cloned()
        .collect();
    replaced.push(LinkRow {
        namespace: bound.to_string(),
        parent: new_parent.map(str::to_string),
        owner: new_owner.map(str::to_string),
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

    fn row(ns: &str, parent: Option<&str>, owner: Option<&str>) -> LinkRow {
        LinkRow {
            namespace: ns.into(),
            parent: parent.map(str::to_string),
            owner: owner.map(str::to_string),
        }
    }

    /// `c{from}` .. `c{to}` linked upward, all owned by `o`.
    fn chain(prefix: &str, from: usize, to: usize, o: Option<&str>) -> Vec<LinkRow> {
        (from..to)
            .map(|i| {
                row(
                    &format!("{prefix}{i}"),
                    Some(&format!("{prefix}{}", i + 1)),
                    o,
                )
            })
            .collect()
    }

    #[test]
    fn the_root_link_that_makes_nine_hops_is_refused_and_eight_is_admitted_4492() {
        // c1 -> c2 -> ... -> c9 exists (8 hops from c1); binding v -> c1 is 9.
        let rows = chain("c", 1, 9, Some("b"));
        assert!(bind_exceeds_chain_depth(&rows, "v", Some("c1"), Some("b")));
        // c1 -> ... -> c8 (7 hops); v -> c1 makes exactly 8: admitted.
        let rows = chain("c", 1, 8, Some("b"));
        assert!(!bind_exceeds_chain_depth(&rows, "v", Some("c1"), Some("b")));
    }

    #[test]
    fn a_link_added_at_the_top_is_refused_4492() {
        // v -> c1 -> ... -> c8 (8 hops from v); binding c8 -> c9 extends the TOP.
        let mut rows = vec![row("v", Some("c1"), Some("b"))];
        rows.extend(chain("c", 1, 8, Some("b")));
        assert!(bind_exceeds_chain_depth(&rows, "c8", Some("c9"), Some("b")));
    }

    #[test]
    fn unentitled_links_do_not_count_and_existing_overdepth_may_shrink_4492() {
        // The top node is owned by someone else: the hop to it stops the walk.
        let mut rows = chain("c", 1, 9, Some("b"));
        rows.push(row("c9", None, Some("x")));
        assert!(!bind_exceeds_chain_depth(
            &rows,
            "c8",
            Some("c9"),
            Some("b")
        ));
        // A pre-existing over-depth chain (9 hops) may be shortened.
        let mut rows = vec![row("v", Some("c1"), Some("b"))];
        rows.extend(chain("c", 1, 9, Some("b")));
        assert!(!bind_exceeds_chain_depth(&rows, "c5", None, Some("b")));
        // ... and keeping it unchanged does not newly push it.
        assert!(!bind_exceeds_chain_depth(
            &rows,
            "c5",
            Some("c6"),
            Some("b")
        ));
    }

    #[test]
    fn an_owner_change_that_entitles_a_hop_is_measured_4492() {
        // v (owned b) -> c1 (owned x, so the hop is NOT entitled today).
        let mut rows = vec![row("v", Some("c1"), Some("b"))];
        rows.push(row("c1", Some("c2"), Some("x")));
        rows.extend(chain("c", 2, 10, Some("b")));
        // Re-binding c1 to a b-owned standard entitles v -> c1 -> ... -> c10.
        assert!(bind_exceeds_chain_depth(&rows, "c1", Some("c2"), Some("b")));
    }
}
