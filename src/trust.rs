// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 R20 (#1958) — trust-tier ordering + min-propagation over the
//! v75 memory-derivation lineage-DAG.
//!
//! A derived / consolidated memory's effective trust tier is bounded by the
//! **minimum** trust tier along its recorded provenance chain (the subset
//! P = {`derived_from`, `reflects_on`, `derives_from`}). You cannot launder
//! low-trust source data into a high-trust derived record: `consolidate`
//! today mints its result at `confidence = 1.0`, so without this bound a
//! chain of unattested inputs silently produces a "trusted" summary.
//!
//! ## The per-memory trust signal
//!
//! The substrate's per-memory trust marker is the string
//! `metadata.attest_level` ([`crate::identity::verify::AttestLevel`] on the
//! store path — `agent_attested` / `claimed`; plus the federation
//! [`crate::models::AttestLevel::PeerAttested`] and the absent / `unsigned`
//! floor). Because that is an OPEN string set spread across two enums,
//! [`TrustTier`] collapses it into a CLOSED, TOTALLY-ORDERED three-tier
//! lattice so a `min` over a provenance chain is well-defined:
//!
//! ```text
//! Unattested  <  Claimed  <  Attested
//!   (floor)      (bare id)   (verified signature: agent- or peer-attested)
//! ```
//!
//! ## Honest boundary (ESTIMABLE)
//!
//! Propagation is only as complete as the **recorded** provenance DAG. An
//! un-recorded derivation (a memory hand-copied from another, or a
//! `derived_from` edge that was never written) is invisible to the walk, so
//! the propagated tier is an UPPER bound on the true laundering exposure,
//! not a proof. The guarantee is scoped: over the recorded lineage, no
//! derived record's surfaced trust exceeds the minimum of its recorded
//! sources.

use serde_json::Value;

/// Metadata key under which the write-time propagated (min) trust tier is
/// stamped on a derived record, and the read-time computed effective tier
/// is surfaced. One SSOT const so the value is never a re-spelled literal
/// (the `check-hardcoded-literals` gate blocks a ≥10-char literal on ≥3
/// production sites).
pub const PROPAGATED_TRUST_KEY: &str = "propagated_trust";

/// The `metadata.attest_level` key — the substrate's per-memory trust
/// marker read by [`TrustTier::of_metadata`].
pub const ATTEST_LEVEL_KEY: &str = "attest_level";

/// A closed, totally-ordered trust lattice collapsing the open
/// `metadata.attest_level` string set. `derive(Ord)` makes `min` /
/// comparisons well-defined; declaration order is the trust order
/// (`Unattested` is the floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    /// No attestation: `metadata.attest_level` is absent, `unsigned`, or an
    /// unrecognised value. The floor — an unattested source caps every
    /// record derived from it.
    Unattested,
    /// A bare `agent_id` claim with no verified signature
    /// ([`crate::identity::verify::AttestLevel::Claimed`]).
    Claimed,
    /// A cryptographically verified signature — either the store-path
    /// [`crate::identity::verify::AttestLevel::AgentAttested`] (verified
    /// against the agent's bound key) or the federation
    /// [`crate::models::AttestLevel::PeerAttested`] (verified against the
    /// enrolled peer key).
    Attested,
}

impl TrustTier {
    /// Stable wire string for [`Self`]. `Unattested` is the only new
    /// vocabulary; `Claimed` / `Attested` reuse the existing
    /// `AttestLevel::as_str` spellings so the propagated value speaks the
    /// same language as `metadata.attest_level`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unattested => "unattested",
            Self::Claimed => crate::identity::verify::AttestLevel::Claimed.as_str(),
            Self::Attested => crate::identity::verify::AttestLevel::AgentAttested.as_str(),
        }
    }

    /// Map a raw `metadata.attest_level` string to a tier. `agent_attested`
    /// and `peer_attested` both resolve to [`Self::Attested`]; `claimed` to
    /// [`Self::Claimed`]; everything else (absent, `unsigned`, unknown) to
    /// the [`Self::Unattested`] floor.
    #[must_use]
    pub fn from_attest_level(s: Option<&str>) -> Self {
        match s {
            Some(v)
                if v == crate::identity::verify::AttestLevel::AgentAttested.as_str()
                    || v == crate::models::AttestLevel::PeerAttested.as_str() =>
            {
                Self::Attested
            }
            Some(v) if v == crate::identity::verify::AttestLevel::Claimed.as_str() => Self::Claimed,
            _ => Self::Unattested,
        }
    }

    /// Inverse of [`Self::as_str`] — parse a stamped
    /// [`PROPAGATED_TRUST_KEY`] value. Unknown values decay to the floor.
    #[must_use]
    pub fn from_tier_str(s: Option<&str>) -> Self {
        match s {
            Some(v) if v == Self::Attested.as_str() => Self::Attested,
            Some(v) if v == Self::Claimed.as_str() => Self::Claimed,
            _ => Self::Unattested,
        }
    }

    /// The EFFECTIVE trust tier of a memory given its `metadata` object:
    /// the tier of its own `attest_level`, further bounded by any
    /// already-stamped [`PROPAGATED_TRUST_KEY`] (a derived source carries
    /// its own propagated min, so folding it in makes the bound transitive
    /// across multi-hop chains without re-walking each source's ancestry).
    #[must_use]
    pub fn of_metadata(meta: &Value) -> Self {
        let own = Self::from_attest_level(meta.get(ATTEST_LEVEL_KEY).and_then(Value::as_str));
        match meta.get(PROPAGATED_TRUST_KEY).and_then(Value::as_str) {
            Some(p) => own.min(Self::from_tier_str(Some(p))),
            None => own,
        }
    }

    /// The minimum tier over an iterator of tiers. An EMPTY iterator yields
    /// [`Self::Attested`] (the lattice top / `min` identity) so an empty
    /// source set imposes no cap; every real `consolidate` has ≥1 source.
    #[must_use]
    pub fn min_over<I: IntoIterator<Item = Self>>(tiers: I) -> Self {
        tiers.into_iter().min().unwrap_or(Self::Attested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tier_total_order_is_unattested_lt_claimed_lt_attested() {
        assert!(TrustTier::Unattested < TrustTier::Claimed);
        assert!(TrustTier::Claimed < TrustTier::Attested);
        assert_eq!(
            TrustTier::Unattested.min(TrustTier::Attested),
            TrustTier::Unattested
        );
    }

    #[test]
    fn from_attest_level_maps_every_bucket() {
        assert_eq!(
            TrustTier::from_attest_level(Some("agent_attested")),
            TrustTier::Attested
        );
        assert_eq!(
            TrustTier::from_attest_level(Some("peer_attested")),
            TrustTier::Attested
        );
        assert_eq!(
            TrustTier::from_attest_level(Some("claimed")),
            TrustTier::Claimed
        );
        // Absent / unsigned / unknown all collapse to the floor.
        assert_eq!(TrustTier::from_attest_level(None), TrustTier::Unattested);
        assert_eq!(
            TrustTier::from_attest_level(Some("unsigned")),
            TrustTier::Unattested
        );
        assert_eq!(
            TrustTier::from_attest_level(Some("bogus")),
            TrustTier::Unattested
        );
    }

    #[test]
    fn as_str_from_tier_str_round_trip() {
        for t in [
            TrustTier::Unattested,
            TrustTier::Claimed,
            TrustTier::Attested,
        ] {
            assert_eq!(TrustTier::from_tier_str(Some(t.as_str())), t);
        }
    }

    #[test]
    fn of_metadata_reads_attest_level_and_is_capped_by_prior_propagated() {
        // Bare agent_attested memory → Attested.
        assert_eq!(
            TrustTier::of_metadata(&json!({"attest_level": "agent_attested"})),
            TrustTier::Attested
        );
        // agent_attested own tier, but an already-stamped propagated_trust
        // of "claimed" (it laundered a claimed source) caps it.
        assert_eq!(
            TrustTier::of_metadata(&json!({
                "attest_level": "agent_attested",
                "propagated_trust": "claimed",
            })),
            TrustTier::Claimed
        );
        // No attest_level at all → floor.
        assert_eq!(
            TrustTier::of_metadata(&json!({"agent_id": "ai:x"})),
            TrustTier::Unattested
        );
    }

    #[test]
    fn min_over_takes_the_floor_and_empty_is_top() {
        // A high-trust derived record over low-trust sources = low.
        assert_eq!(
            TrustTier::min_over([TrustTier::Attested, TrustTier::Unattested]),
            TrustTier::Unattested
        );
        // Sibling merge takes the min.
        assert_eq!(
            TrustTier::min_over([TrustTier::Attested, TrustTier::Claimed, TrustTier::Attested]),
            TrustTier::Claimed
        );
        // Empty imposes no cap.
        assert_eq!(TrustTier::min_over([]), TrustTier::Attested);
    }
}
