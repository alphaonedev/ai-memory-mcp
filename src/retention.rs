// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1829 (TRACT-gap G15) — the substrate's RETENTION-MODEL anchor.
//!
//! # What this is (and is NOT)
//!
//! TRACT L2 wants retention to be a **continuous cost-of-access (Landauer)
//! gradient** — a single cost that rises with archival depth/age and GOVERNS
//! eviction, replacing discrete tiers. The substrate's retention is instead a
//! **discrete 3-tier TTL** model (`Tier::Short` 6h / `Tier::Mid` 7d /
//! `Tier::Long` permanent); the gap is real (`docs/spec/TRACT-L1-CLAIM-CONTRACT.md`
//! §10). This module ships **no** cost gradient and changes **no** eviction
//! behavior.
//!
//! It does exactly one humble thing: it makes the retention posture resolvable
//! in ONE place so the §10 honesty claim cannot silently drift. The deliberate
//! ABSENCE of a cost-of-access variant on [`RetentionModel`] is the
//! machine-checked record of the gap.
//!
//! # Not a floating anchor
//!
//! [`crate::models::Tier::default_ttl_secs`] — the most-called TTL function,
//! read by every eviction / TTL-floor / archival / config-seed path — now
//! delegates through [`RetentionModel::current`] + [`RetentionModel::ttl_secs_for`].
//! So the enum has a REAL live consumer on the hot path (not a self-referential
//! tripwire): the `match` in [`RetentionModel::ttl_secs_for`] is exhaustive and
//! wildcard-free, so adding a `CostOfAccessGradient` variant hard-breaks the
//! build there (and in [`RetentionModel::label`]) until the new model is
//! consciously resolved AND the §10 ledger is updated. The wiring is provably
//! byte-identical — the `DiscreteTtlTiers` arm returns exactly
//! [`Tier::discrete_ttl_secs`] — so no eviction behavior changed.

use crate::models::Tier;

/// The retention posture the substrate ACTUALLY implements.
///
/// There is deliberately NO `CostOfAccessGradient` variant — the continuous
/// Landauer cost-of-access model (TRACT G15, #1829) is UNIMPLEMENTED. Adding one
/// breaks the exhaustive matches below until the new model is consciously
/// resolved AND the contract §10 ledger is updated (the drift-gate).
/// `#[non_exhaustive]` so out-of-crate matchers must also account for a future
/// model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionModel {
    /// Retention/eviction is a fixed set of discrete tiers, each with a static
    /// default TTL (`Tier::Short` 6h / `Tier::Mid` 7d / `Tier::Long` permanent),
    /// extended on access by a per-tier floor. This is the ONLY posture today.
    DiscreteTtlTiers,
}

impl RetentionModel {
    /// The substrate's live retention model. Constant today — the substrate has
    /// only [`DiscreteTtlTiers`](Self::DiscreteTtlTiers). A future continuous
    /// cost-of-access model (G15) would resolve here (e.g. from config), which
    /// is why callers route through this rather than hardcoding the posture.
    #[must_use]
    pub fn current() -> Self {
        RetentionModel::DiscreteTtlTiers
    }

    /// The default TTL (seconds) a `tier` receives UNDER THIS MODEL, or `None`
    /// for permanent. EXHAUSTIVE wildcard-free match — the drift-gate: a new
    /// [`RetentionModel`] variant hard-breaks the build here until it defines
    /// how retention resolves. The `DiscreteTtlTiers` arm is byte-identical to
    /// the pre-#1829 `Tier::default_ttl_secs` values.
    #[must_use]
    pub fn ttl_secs_for(self, tier: &Tier) -> Option<i64> {
        match self {
            Self::DiscreteTtlTiers => tier.discrete_ttl_secs(),
        }
    }

    /// A short, stable label. EXHAUSTIVE wildcard-free match — a second
    /// drift-gate site.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::DiscreteTtlTiers => "discrete-ttl-tiers",
        }
    }

    /// `true` iff retention is governed by a continuous cost-of-access gradient
    /// (the TRACT L2 ideal). Always `false` today — G15 is UNIMPLEMENTED. When a
    /// gradient variant is added it must return `true`, which is why this is an
    /// exhaustive match, not a hardcoded constant.
    #[must_use]
    pub fn is_cost_of_access_gradient(self) -> bool {
        match self {
            Self::DiscreteTtlTiers => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wiring is byte-identical: the live model resolves each tier's TTL to
    /// exactly the raw `discrete_ttl_secs` value. If this ever diverges, the
    /// #1829 anchor silently changed eviction behavior — a hard failure.
    #[test]
    fn model_ttl_matches_raw_discrete_values_for_every_tier() {
        for tier in [Tier::Short, Tier::Mid, Tier::Long] {
            assert_eq!(
                RetentionModel::current().ttl_secs_for(&tier),
                tier.discrete_ttl_secs(),
                "RetentionModel must resolve the SAME TTL as the raw discrete value"
            );
            // And Tier::default_ttl_secs (the public entry every caller uses)
            // routes through the model, so it too must match.
            assert_eq!(tier.default_ttl_secs(), tier.discrete_ttl_secs());
        }
    }

    /// #1829 / G15 honesty pin: the ONLY retention posture is discrete tiers;
    /// there is NO cost-of-access gradient. If a future edit adds a gradient
    /// variant, the exhaustive matches break the build and this must be revisited
    /// alongside the contract §10 ledger.
    #[test]
    fn g15_retention_is_discrete_tiers_no_gradient() {
        let m = RetentionModel::current();
        assert_eq!(m, RetentionModel::DiscreteTtlTiers);
        assert!(
            !m.is_cost_of_access_gradient(),
            "retention is discrete TTL tiers; the Landauer cost-of-access \
             gradient (G15) is UNIMPLEMENTED"
        );
        assert_eq!(m.label(), "discrete-ttl-tiers");
    }

    /// The concrete baseline values are preserved (the pre-#1829 contract).
    #[test]
    fn discrete_baseline_values_preserved() {
        assert_eq!(
            Tier::Short.default_ttl_secs(),
            Some(6 * crate::SECS_PER_HOUR)
        );
        assert_eq!(Tier::Mid.default_ttl_secs(), Some(crate::SECS_PER_WEEK));
        assert_eq!(Tier::Long.default_ttl_secs(), None);
    }
}
