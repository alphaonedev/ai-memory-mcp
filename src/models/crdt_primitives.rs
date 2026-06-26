// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar-3 (#1719 / #1709) — formal CRDT primitive types.
//!
//! Extracts the two reusable conflict-free merge lattices that
//! [`crate::models::crdt_merge::merge_memory`] applies field-by-field,
//! so the per-field semantics live in named, independently-tested types
//! instead of inline `.max()` / union loops:
//!
//! * [`PnCounter`] — a monotonic max-register. The #224 "counter" fields
//!   (`priority` / `confidence` / `access_count` / `version` /
//!   `reflection_depth`) merge by taking the maximum, so a merge never
//!   rolls the value backwards.
//! * [`OrSet`] — an observed-remove-style union set. The #224 `tags`
//!   field merges by set-union, so two replicas that each appended a
//!   distinct tag both keep it after the merge.
//!
//! Both expose a pure `merge` whose result is **commutative, associative
//! and idempotent** — the convergence properties a CRDT needs (peers that
//! receive the same set of replicas in any order reach the same state).
//! The types are deliberately thin newtypes: `merge_memory` stays a
//! field-by-field reconciler (no `..rest` spread, so a new [`Memory`]
//! field still fails to compile until it is given an explicit rule), and
//! only the genuinely-lattice fields delegate here. Fields whose #224
//! rule is NOT a clean lattice (last-write-wins, prefer-non-null,
//! max-durability tier, null-wins `expires_at`, the `metadata`
//! sub-rules) deliberately stay in `crdt_merge` rather than being forced
//! into a primitive.

/// PN-Counter-style monotonic register: [`merge`](PnCounter::merge) takes
/// the maximum of the two operands, so a merge never rolls the value
/// backwards.
///
/// The merge is a `max` over [`PartialOrd`], which makes it:
/// * **commutative** — `max(a, b) == max(b, a)`;
/// * **associative** — `max(max(a, b), c) == max(a, max(b, c))`;
/// * **idempotent** — `max(a, a) == a`.
///
/// `T` only needs [`PartialOrd`] + [`Clone`], so the same type covers the
/// integer counters (`priority: i32`, `access_count: i64`, `version:
/// i64`, `reflection_depth: i32`) and the float `confidence: f64` (whose
/// values are validated to `0.0..=1.0`, so no `NaN` reaches the merge).
#[derive(Debug, Clone, Copy)]
pub struct PnCounter<T>(pub T);

impl<T: PartialOrd + Clone> PnCounter<T> {
    /// Wrap a value as a [`PnCounter`].
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Unwrap to the inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Merge two counters by taking the maximum. On a tie either operand
    /// carries the same value, so the result is identical regardless of
    /// argument order (commutative).
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        if other.0 > self.0 {
            Self(other.0.clone())
        } else {
            Self(self.0.clone())
        }
    }
}

/// OR-Set-style union set: [`merge`](OrSet::merge) is set-union with a
/// deterministic local-first stable surface order and exact-element
/// dedup.
///
/// Union is commutative, associative and idempotent **as a set**; the
/// surface ordering is `self`-first by construction (the caller's left
/// operand keeps its order, then the right operand's not-yet-seen
/// elements append). Callers that need order-independence compare the
/// result as a set (membership), which is what the federation merge
/// asserts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrSet<T>(pub Vec<T>);

impl<T: Clone + PartialEq> OrSet<T> {
    /// Wrap a vector of observed elements as an [`OrSet`].
    pub fn new(items: Vec<T>) -> Self {
        Self(items)
    }

    /// Borrow the observed elements.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Unwrap to the inner vector.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    /// Merge two sets by union: keep `self`'s elements in order, then
    /// append `other`'s elements not already present. Exact-element
    /// dedup; the result is order-independent as a set.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut out: Vec<T> = Vec::with_capacity(self.0.len() + other.0.len());
        for item in self.0.iter().chain(other.0.iter()) {
            if !out.iter().any(|seen| seen == item) {
                out.push(item.clone());
            }
        }
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PnCounter --------------------------------------------------

    #[test]
    fn pn_counter_merge_takes_max_i32() {
        assert_eq!(
            PnCounter::new(3_i32).merge(&PnCounter::new(9)).into_inner(),
            9
        );
        // Order-independent.
        assert_eq!(
            PnCounter::new(9_i32).merge(&PnCounter::new(3)).into_inner(),
            9
        );
    }

    #[test]
    fn pn_counter_merge_takes_max_i64() {
        assert_eq!(
            PnCounter::new(40_i64)
                .merge(&PnCounter::new(7))
                .into_inner(),
            40
        );
    }

    #[test]
    fn pn_counter_merge_takes_max_f64() {
        let merged = PnCounter::new(0.2_f64)
            .merge(&PnCounter::new(0.8))
            .into_inner();
        assert!((merged - 0.8).abs() < f64::EPSILON);
        // Commutative for floats too.
        let merged_rev = PnCounter::new(0.8_f64)
            .merge(&PnCounter::new(0.2))
            .into_inner();
        assert!((merged_rev - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn pn_counter_is_idempotent() {
        assert_eq!(
            PnCounter::new(5_i32).merge(&PnCounter::new(5)).into_inner(),
            5
        );
    }

    #[test]
    fn pn_counter_is_commutative() {
        for (a, b) in [(1_i32, 2), (10, 10), (7, 3), (-5, 4)] {
            let ab = PnCounter::new(a).merge(&PnCounter::new(b)).into_inner();
            let ba = PnCounter::new(b).merge(&PnCounter::new(a)).into_inner();
            assert_eq!(ab, ba, "commutative for ({a}, {b})");
        }
    }

    #[test]
    fn pn_counter_is_associative() {
        let (a, b, c) = (3_i32, 9, 5);
        let left = PnCounter::new(PnCounter::new(a).merge(&PnCounter::new(b)).into_inner())
            .merge(&PnCounter::new(c))
            .into_inner();
        let right = PnCounter::new(a)
            .merge(&PnCounter::new(
                PnCounter::new(b).merge(&PnCounter::new(c)).into_inner(),
            ))
            .into_inner();
        assert_eq!(left, right);
        assert_eq!(left, 9);
    }

    // ---- OrSet ------------------------------------------------------

    #[test]
    fn or_set_merge_unions_and_dedups() {
        let local = OrSet::new(vec!["x".to_string(), "shared".to_string()]);
        let remote = OrSet::new(vec!["shared".to_string(), "y".to_string()]);
        // Local-first stable order; "shared" deduped once.
        assert_eq!(local.merge(&remote).into_inner(), vec!["x", "shared", "y"]);
    }

    #[test]
    fn or_set_is_idempotent() {
        let s = OrSet::new(vec![1_i32, 2, 3]);
        assert_eq!(s.merge(&s).into_inner(), vec![1, 2, 3]);
    }

    #[test]
    fn or_set_is_commutative_as_a_set() {
        let a = OrSet::new(vec!["a".to_string(), "b".to_string()]);
        let b = OrSet::new(vec!["b".to_string(), "c".to_string()]);
        let mut ab = a.merge(&b).into_inner();
        let mut ba = b.merge(&a).into_inner();
        ab.sort();
        ba.sort();
        assert_eq!(ab, ba);
    }

    #[test]
    fn or_set_is_associative_as_a_set() {
        let a = OrSet::new(vec![1_i32, 2]);
        let b = OrSet::new(vec![2, 3]);
        let c = OrSet::new(vec![3, 4]);
        let mut left = OrSet::new(a.merge(&b).into_inner()).merge(&c).into_inner();
        let mut right = a.merge(&OrSet::new(b.merge(&c).into_inner())).into_inner();
        left.sort_unstable();
        right.sort_unstable();
        assert_eq!(left, right);
        assert_eq!(left, vec![1, 2, 3, 4]);
    }

    #[test]
    fn or_set_empty_merge_preserves() {
        let a = OrSet::new(vec![1_i32, 2]);
        let empty: OrSet<i32> = OrSet::default();
        assert_eq!(a.merge(&empty).into_inner(), vec![1, 2]);
        assert_eq!(empty.merge(&a).into_inner(), vec![1, 2]);
        assert_eq!(a.as_slice(), &[1, 2]);
    }
}
