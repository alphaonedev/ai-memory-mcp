// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4477 — the ONE depth bound on the namespace governance chain, shared by
//! the sqlite (`storage::build_namespace_chain_view`) and postgres
//! (`store::postgres` chain builders) walks.
//!
//! Before #4477 postgres kept only the 5 most-specific `/`-derived levels and
//! 5 explicit-parent hops (`GOVERNANCE_INHERITANCE_DEPTH_CAP`, F-A2A1.2), while
//! sqlite kept the whole `/` hierarchy and 8 explicit hops. A governed ancestor
//! more than 5 levels above a namespace therefore governed nothing on postgres
//! (a stranger's depth-1 reflect at depth 7 was APPLIED there and PENDING on
//! sqlite), and both backends silently DROPPED any explicit ancestor beyond
//! their hop budget: a fail-open truncation of a governance layer.
//!
//! The rule, identical on both backends and both views:
//! - the walk is COMPLETE: no `/` level and no entitled explicit parent is ever
//!   dropped;
//! - it is bounded by [`crate::models::MAX_NAMESPACE_DEPTH`] (8) on each walk
//!   (the `/` segments of the namespace, and the explicit-parent hops above the
//!   rootmost segment), and a walk that would exceed the bound is REFUSED with
//!   [`ChainOverDepth`] (fail closed: the governed operation is refused, never
//!   resolved against a truncated chain).
//!
//! The deliberate stops are unchanged: the global `*`, a cycle (a parent
//! already on the chain, so nothing is lost) and the #2542 unentitled
//! cross-tenant graft.

/// The bound on each walk (the `/` segments, and the explicit-parent hops).
pub const GOVERNANCE_CHAIN_MAX_DEPTH: usize = crate::models::MAX_NAMESPACE_DEPTH;

/// A governance chain walk that would exceed [`GOVERNANCE_CHAIN_MAX_DEPTH`].
/// The text is fixed and value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOverDepth {
    /// The namespace itself has more `/` segments than the bound.
    SlashHierarchy,
    /// The explicit `parent_namespace` links above the rootmost segment need
    /// more hops than the bound.
    ExplicitParents,
}

impl ChainOverDepth {
    /// The fixed, value-free refusal text.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::SlashHierarchy => {
                "namespace governance chain exceeds the maximum depth (namespace segments); \
                 refusing rather than resolving a truncated chain (#4477)"
            }
            Self::ExplicitParents => {
                "namespace governance chain exceeds the maximum depth (explicit parent \
                 links); refusing rather than resolving a truncated chain (#4477)"
            }
        }
    }
}

impl std::fmt::Display for ChainOverDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for ChainOverDepth {}

/// The `/`-derived chain of `namespace`, TOP-DOWN (root first, the namespace
/// itself last), complete.
///
/// # Errors
///
/// [`ChainOverDepth::SlashHierarchy`] when the namespace has more segments
/// than [`GOVERNANCE_CHAIN_MAX_DEPTH`].
pub fn slash_chain(namespace: &str) -> Result<Vec<String>, ChainOverDepth> {
    let mut levels = crate::models::namespace_ancestors(namespace);
    if levels.len() > GOVERNANCE_CHAIN_MAX_DEPTH {
        return Err(ChainOverDepth::SlashHierarchy);
    }
    levels.reverse();
    Ok(levels)
}

/// Admit one more ENTITLED explicit parent above the rootmost segment, given
/// the parents already admitted. Called after the deliberate stops (`*`,
/// cycle, #2542 unentitled graft) so only a level that WOULD govern can trip
/// the bound.
///
/// # Errors
///
/// [`ChainOverDepth::ExplicitParents`] when the walk already holds
/// [`GOVERNANCE_CHAIN_MAX_DEPTH`] explicit parents.
pub fn admit_explicit_parent(explicit_above: &[String]) -> Result<(), ChainOverDepth> {
    if explicit_above.len() >= GOVERNANCE_CHAIN_MAX_DEPTH {
        return Err(ChainOverDepth::ExplicitParents);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_chain_is_complete_to_the_bound_and_refuses_beyond_4477() {
        let deep = "a/b/c/d/e/f/g/h";
        let chain = slash_chain(deep).expect("depth 8 is within the bound");
        assert_eq!(chain.len(), 8);
        assert_eq!(chain.first().map(String::as_str), Some("a"));
        assert_eq!(chain.last().map(String::as_str), Some(deep));
        assert_eq!(
            slash_chain("a/b/c/d/e/f/g/h/i"),
            Err(ChainOverDepth::SlashHierarchy)
        );
        assert_eq!(slash_chain("solo").expect("root"), vec!["solo".to_string()]);
    }

    #[test]
    fn explicit_walk_admits_the_bound_and_refuses_one_more_4477() {
        let mut above: Vec<String> = Vec::new();
        for i in 0..GOVERNANCE_CHAIN_MAX_DEPTH {
            admit_explicit_parent(&above).expect("within the bound");
            above.push(format!("p{i}"));
        }
        assert_eq!(
            admit_explicit_parent(&above),
            Err(ChainOverDepth::ExplicitParents)
        );
    }

    #[test]
    fn refusal_text_is_fixed_and_value_free_4477() {
        for e in [
            ChainOverDepth::SlashHierarchy,
            ChainOverDepth::ExplicitParents,
        ] {
            assert!(e.to_string().contains("#4477"));
        }
    }
}
