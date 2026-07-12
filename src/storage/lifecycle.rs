// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Corpus-lifecycle EXPIRE / EVICT / DISTILL contract (#1965).
//!
//! Bounded growth under a *named pressure policy*: every live memory that
//! leaves the working corpus does so through exactly one of three named
//! transitions, each driven by a distinct, independently-observable
//! pressure. This module is the **spec + scoring layer** for that contract
//! — it names the three transitions, exposes the pure predicate that
//! decides which one applies to a candidate, and pins each predicate to the
//! live path that already implements it. It changes **no** eviction
//! behaviour (the issue's "spec/scoring only — no compaction / size-GC
//! default flips" constraint); the live `gc` / `size_gc` / consolidation
//! paths keep their exact triggers, and the parity tests below assert this
//! layer mirrors them.
//!
//! # The three transitions
//!
//! | Transition | Pressure | Trigger | Live path |
//! |------------|----------|---------|-----------|
//! | [`LifecycleTransition::Expire`]  | time (TTL) | `expires_at` is set and in the past | [`crate::storage::gc`] (`src/storage/mod.rs`) — SQL `expires_at IS NOT NULL AND expires_at < now` |
//! | [`LifecycleTransition::Distill`] | redundancy | a same-namespace near-duplicate exists (Jaccard **and** cosine gate) | [`crate::curator::cluster::pair_merges`] → `ConsolidationPass` (`src/curator/`) |
//! | [`LifecycleTransition::Evict`]   | capacity (bytes) | the namespace corpus exceeds its byte cap | [`crate::storage::size_gc`] (`src/storage/mod.rs`) |
//!
//! # Precedence
//!
//! A single row can be under more than one pressure at once. When it is,
//! [`classify_lifecycle_transition`] returns the highest-precedence
//! applicable transition, in the order **EXPIRE > DISTILL > EVICT**:
//!
//! 1. **EXPIRE first** — a TTL that has elapsed is *definitive*: the row's
//!    own declared lifetime ended, so no value judgement is needed and no
//!    cheaper transition can preserve it.
//! 2. **DISTILL before EVICT** — merging a near-duplicate *preserves the
//!    information* (the surviving cluster member carries it forward), while
//!    eviction is a lossy last resort. When both redundancy and capacity
//!    pressure apply, prefer the information-preserving transition.
//! 3. **EVICT last** — pure byte-capacity shedding, with no better option;
//!    the deterministic victim order is a separate ranking (see
//!    [`eviction_victim_key`], mirroring `SQL_SIZE_GC_NEXT_VICTIM`).
//!
//! `None` means the row is under no pressure and stays resident — the
//! bounded-growth policy only ever *removes* a row under a named pressure,
//! never speculatively.

use crate::models::Tier;

/// Canonical Jaccard pre-filter threshold for the DISTILL near-duplicate
/// gate — re-exported from the live clusterer so this spec layer cannot
/// drift from the behaviour it documents.
pub const DISTILL_JACCARD_THRESHOLD: f64 = crate::curator::cluster::JACCARD_THRESHOLD;

/// Canonical cosine gate threshold for the DISTILL near-duplicate gate,
/// re-exported from the live clusterer (`0.75` at v1.0.0, operator-tunable
/// via `[curator.compaction].cosine_threshold`).
pub const DISTILL_COSINE_THRESHOLD: f32 = crate::curator::cluster::DEFAULT_COSINE_THRESHOLD;

/// The three terminal corpus-lifecycle transitions a resident memory can
/// undergo. See the [module docs](self) for the full contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleTransition {
    /// TTL-driven removal — the row's `expires_at` has elapsed.
    /// Implemented by [`crate::storage::gc`].
    Expire,
    /// Capacity-driven removal — the namespace corpus exceeds its byte cap.
    /// Implemented by [`crate::storage::size_gc`].
    Evict,
    /// Redundancy-driven merge — a same-namespace near-duplicate exists.
    /// Implemented by the curator consolidation pass.
    Distill,
}

impl LifecycleTransition {
    /// Stable lower-case wire slug for the transition (`"expire"` /
    /// `"evict"` / `"distill"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expire => "expire",
            Self::Evict => "evict",
            Self::Distill => "distill",
        }
    }
}

/// A candidate row's per-row lifecycle signals — the inputs the two
/// row-local pressures (TTL, redundancy) are decided from.
#[derive(Debug, Clone, Copy)]
pub struct LifecycleCandidate<'a> {
    /// The row's `expires_at` (RFC3339), or `None` for a never-expiring
    /// (long-tier / TTL-cleared) row.
    pub expires_at: Option<&'a str>,
    /// Best lexical Jaccard overlap against a same-namespace neighbour
    /// (`0.0` when there is no candidate neighbour).
    pub best_jaccard: f64,
    /// Best cosine similarity against the same neighbour when **both** sides
    /// are embedded; `None` when either side has no stored embedding (a
    /// destructive merge is never decided on lexical overlap alone, #1774).
    pub best_cosine: Option<f64>,
}

/// The namespace-scoped capacity pressure a candidate sits under, plus the
/// reference clock the TTL predicate compares against.
#[derive(Debug, Clone, Copy)]
pub struct CorpusPressure<'a> {
    /// Reference "now" (RFC3339) the TTL predicate compares `expires_at`
    /// against — RFC3339 lexical order is chronological order, matching the
    /// `gc` SQL string comparison.
    pub now: &'a str,
    /// Live corpus byte size of the candidate's namespace (the
    /// `length(title)+length(content)+length(metadata)` sum that
    /// `size_gc` accounts).
    pub corpus_bytes: i64,
    /// The namespace byte cap, or `None` when no cap is configured
    /// (a non-positive cap is treated as disabled, matching `size_gc`).
    pub max_corpus_bytes: Option<i64>,
}

/// Time-pressure predicate (EXPIRE): the row's TTL has elapsed.
///
/// Mirrors the [`crate::storage::gc`] SQL predicate
/// `expires_at IS NOT NULL AND expires_at < now`. RFC3339 strings compare
/// lexically the same way they compare chronologically, so this matches the
/// SQL string comparison exactly (a `NULL` / `None` expiry never expires).
#[must_use]
pub fn is_expired(expires_at: Option<&str>, now: &str) -> bool {
    matches!(expires_at, Some(e) if e < now)
}

/// Redundancy-pressure predicate (DISTILL): a same-namespace near-duplicate
/// exists.
///
/// Delegates to the canonical [`crate::curator::cluster::pair_merges`] with
/// the canonical thresholds so this layer can never disagree with the live
/// consolidation gate: the Jaccard pre-filter **and** the cosine gate must
/// BOTH hold, and a cosine value MUST be present (both sides embedded).
#[must_use]
pub fn is_near_duplicate(best_jaccard: f64, best_cosine: Option<f64>) -> bool {
    crate::curator::cluster::pair_merges(
        best_jaccard,
        DISTILL_JACCARD_THRESHOLD,
        best_cosine,
        f64::from(DISTILL_COSINE_THRESHOLD),
    )
}

/// Capacity-pressure predicate (EVICT): the namespace corpus exceeds its
/// byte cap.
///
/// Mirrors the [`crate::storage::size_gc`] cap check: a non-positive cap is
/// "disabled" (no eviction), and eviction pressure is active only when a
/// positive cap is strictly exceeded (`corpus <= cap` is a no-op there).
#[must_use]
pub fn is_over_capacity(corpus_bytes: i64, max_corpus_bytes: Option<i64>) -> bool {
    matches!(max_corpus_bytes, Some(cap) if cap > 0 && corpus_bytes > cap)
}

/// Durability rank of a tier for eviction ordering: `Short = 0` (evicted
/// first), `Mid = 1`, `Long = 2` (evicted last). Mirrors the `CASE tier`
/// arm of `SQL_SIZE_GC_NEXT_VICTIM`.
#[must_use]
pub fn tier_durability_rank(tier: Tier) -> u8 {
    match tier {
        Tier::Short => 0,
        Tier::Mid => 1,
        Tier::Long => 2,
    }
}

/// Deterministic EVICT victim key — the tuple a namespace's rows are sorted
/// by to pick eviction victims. **Lower sorts earlier = evicted first.**
///
/// Mirrors the `SQL_SIZE_GC_NEXT_VICTIM` `ORDER BY`: least-durable tier
/// first, then lowest `priority`, then lowest `access_count`, then oldest
/// `last_accessed_at` (a `None` — never-accessed — sorts first because
/// `Option::None < Option::Some`, matching SQL `NULL`-sorts-first). So a
/// high-value long-tier frequently-accessed row is evicted last.
#[must_use]
pub fn eviction_victim_key<'a>(
    tier: Tier,
    priority: i32,
    access_count: i64,
    last_accessed_at: Option<&'a str>,
) -> (u8, i32, i64, Option<&'a str>) {
    (
        tier_durability_rank(tier),
        priority,
        access_count,
        last_accessed_at,
    )
}

/// Classify which lifecycle transition (if any) a candidate is subject to,
/// applying the **EXPIRE > DISTILL > EVICT** precedence from the [module
/// docs](self).
///
/// Returns `None` when the row is under no pressure (it stays resident).
#[must_use]
pub fn classify_lifecycle_transition(
    candidate: &LifecycleCandidate<'_>,
    pressure: &CorpusPressure<'_>,
) -> Option<LifecycleTransition> {
    if is_expired(candidate.expires_at, pressure.now) {
        return Some(LifecycleTransition::Expire);
    }
    if is_near_duplicate(candidate.best_jaccard, candidate.best_cosine) {
        return Some(LifecycleTransition::Distill);
    }
    if is_over_capacity(pressure.corpus_bytes, pressure.max_corpus_bytes) {
        return Some(LifecycleTransition::Evict);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-07-12T00:00:00+00:00";
    const PAST: &str = "2026-07-11T00:00:00+00:00";
    const FUTURE: &str = "2026-07-13T00:00:00+00:00";

    fn no_dup_candidate(expires_at: Option<&str>) -> LifecycleCandidate<'_> {
        LifecycleCandidate {
            expires_at,
            best_jaccard: 0.0,
            best_cosine: None,
        }
    }

    fn no_pressure() -> CorpusPressure<'static> {
        CorpusPressure {
            now: NOW,
            corpus_bytes: 0,
            max_corpus_bytes: None,
        }
    }

    // ── EXPIRE trigger ────────────────────────────────────────────────

    #[test]
    fn expired_row_classifies_expire() {
        let c = no_dup_candidate(Some(PAST));
        assert_eq!(
            classify_lifecycle_transition(&c, &no_pressure()),
            Some(LifecycleTransition::Expire)
        );
    }

    #[test]
    fn future_expiry_is_not_expired() {
        assert!(!is_expired(Some(FUTURE), NOW));
        let c = no_dup_candidate(Some(FUTURE));
        assert_eq!(classify_lifecycle_transition(&c, &no_pressure()), None);
    }

    #[test]
    fn null_expiry_never_expires() {
        assert!(!is_expired(None, NOW));
    }

    // ── EVICT trigger ─────────────────────────────────────────────────

    #[test]
    fn over_cap_non_expired_non_dup_classifies_evict() {
        let c = no_dup_candidate(None);
        let p = CorpusPressure {
            now: NOW,
            corpus_bytes: 2_000,
            max_corpus_bytes: Some(1_000),
        };
        assert_eq!(
            classify_lifecycle_transition(&c, &p),
            Some(LifecycleTransition::Evict)
        );
    }

    #[test]
    fn corpus_at_or_under_cap_is_not_evict() {
        // At cap is a no-op (size_gc contract: corpus <= cap early-returns).
        assert!(!is_over_capacity(1_000, Some(1_000)));
        assert!(!is_over_capacity(999, Some(1_000)));
    }

    #[test]
    fn nonpositive_cap_disables_evict() {
        assert!(!is_over_capacity(1_000_000, Some(0)));
        assert!(!is_over_capacity(1_000_000, Some(-1)));
        assert!(!is_over_capacity(1_000_000, None));
    }

    // ── DISTILL trigger ───────────────────────────────────────────────

    #[test]
    fn near_duplicate_classifies_distill() {
        let c = LifecycleCandidate {
            expires_at: None,
            best_jaccard: 0.9,
            best_cosine: Some(0.9),
        };
        assert_eq!(
            classify_lifecycle_transition(&c, &no_pressure()),
            Some(LifecycleTransition::Distill)
        );
    }

    #[test]
    fn high_jaccard_missing_cosine_is_not_distill() {
        // #1774 — a destructive merge requires the cosine gate; lexical
        // overlap alone never triggers DISTILL.
        assert!(!is_near_duplicate(0.99, None));
    }

    #[test]
    fn high_jaccard_low_cosine_is_not_distill() {
        assert!(!is_near_duplicate(0.99, Some(0.10)));
    }

    #[test]
    fn low_jaccard_high_cosine_is_not_distill() {
        assert!(!is_near_duplicate(0.10, Some(0.99)));
    }

    // ── Precedence ────────────────────────────────────────────────────

    #[test]
    fn expire_wins_over_distill_and_evict() {
        // All three pressures active → EXPIRE takes precedence.
        let c = LifecycleCandidate {
            expires_at: Some(PAST),
            best_jaccard: 0.9,
            best_cosine: Some(0.9),
        };
        let p = CorpusPressure {
            now: NOW,
            corpus_bytes: 2_000,
            max_corpus_bytes: Some(1_000),
        };
        assert_eq!(
            classify_lifecycle_transition(&c, &p),
            Some(LifecycleTransition::Expire)
        );
    }

    #[test]
    fn distill_wins_over_evict() {
        // Redundancy + capacity pressure, no TTL → DISTILL preserves info.
        let c = LifecycleCandidate {
            expires_at: None,
            best_jaccard: 0.9,
            best_cosine: Some(0.9),
        };
        let p = CorpusPressure {
            now: NOW,
            corpus_bytes: 2_000,
            max_corpus_bytes: Some(1_000),
        };
        assert_eq!(
            classify_lifecycle_transition(&c, &p),
            Some(LifecycleTransition::Distill)
        );
    }

    #[test]
    fn no_pressure_stays_resident() {
        let c = no_dup_candidate(Some(FUTURE));
        assert_eq!(classify_lifecycle_transition(&c, &no_pressure()), None);
    }

    // ── Victim ranking ────────────────────────────────────────────────

    #[test]
    fn tier_rank_orders_short_first_long_last() {
        assert_eq!(tier_durability_rank(Tier::Short), 0);
        assert_eq!(tier_durability_rank(Tier::Mid), 1);
        assert_eq!(tier_durability_rank(Tier::Long), 2);
    }

    #[test]
    fn victim_key_evicts_low_value_first() {
        // A cheap short-tier low-priority never-accessed row sorts BEFORE a
        // high-value long-tier frequently-accessed row.
        let cheap = eviction_victim_key(Tier::Short, 1, 0, None);
        let valuable = eviction_victim_key(Tier::Long, 9, 500, Some("2026-07-12T00:00:00+00:00"));
        assert!(cheap < valuable);
    }

    #[test]
    fn victim_key_null_last_accessed_sorts_first() {
        let never = eviction_victim_key(Tier::Mid, 5, 3, None);
        let accessed = eviction_victim_key(Tier::Mid, 5, 3, Some("2026-01-01T00:00:00+00:00"));
        assert!(never < accessed);
    }

    // ── Parity with the live consolidation gate ───────────────────────

    #[test]
    fn near_duplicate_parity_with_pair_merges() {
        // The DISTILL predicate must agree with the live clusterer across a
        // grid — pinning that this spec layer never drifts from behaviour.
        let jaccards = [0.0, 0.3, 0.55, 0.7, 0.99];
        let cosines = [None, Some(0.0), Some(0.5), Some(0.75), Some(0.99)];
        for &j in &jaccards {
            for &c in &cosines {
                let ours = is_near_duplicate(j, c);
                let live = crate::curator::cluster::pair_merges(
                    j,
                    DISTILL_JACCARD_THRESHOLD,
                    c,
                    f64::from(DISTILL_COSINE_THRESHOLD),
                );
                assert_eq!(ours, live, "drift at jaccard={j} cosine={c:?}");
            }
        }
    }

    #[test]
    fn transition_slugs_are_stable() {
        assert_eq!(LifecycleTransition::Expire.as_str(), "expire");
        assert_eq!(LifecycleTransition::Evict.as_str(), "evict");
        assert_eq!(LifecycleTransition::Distill.as_str(), "distill");
    }
}
