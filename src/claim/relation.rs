// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1833 (TRACT-gap G19) — a PROVISIONAL, compile-time drift-gate mapping the
//! closed [`MemoryLinkRelation`] enum onto the TRACT L1 relation kernel.
//!
//! # This is NOT the open-predicate model
//!
//! TRACT L1 wants an OPEN predicate space over a small FIXED kernel: a caller
//! authors an arbitrary predicate as a content-addressed CID that is INVALID
//! unless its definition-Claim is reachable (spec §2 `links`,
//! `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §G19). The substrate instead has a
//! CLOSED 9-variant `MemoryLinkRelation` enum + a DB `CHECK` — new relations
//! need a migration + code change. That open-predicate redesign is
//! freeze-hostile / v1.x and is **UNBUILT** ([`OPEN_PREDICATES_SUPPORTED`] is
//! `false`).
//!
//! This module does exactly two humble things:
//! - [`classify`] maps each of the 9 variants onto a PROVISIONAL
//!   [`RelationKernel`] tag (proposed-kernel vs proposed-substrate-extra). The
//!   `match` is **exhaustive with no wildcard**, so it is a compile-time
//!   DRIFT-GATE: adding a 10th `MemoryLinkRelation` variant hard-breaks the
//!   build until an author consciously classifies it against the TRACT floor.
//! - it records the TRACT-kernel relations the substrate is MISSING
//!   ([`MISSING_TRACT_KERNEL_RELATIONS`]).
//!
//! ## The classification is PROPOSED, not normative
//!
//! The proposed-kernel/proposed-extra split is a **contestable design
//! judgment**, deliberately surfaced here (not settled). It bisects the
//! substrate's own coherent provenance grouping
//! [`MemoryLinkRelation::LINEAGE`] = `{DerivedFrom, ReflectsOn, DerivesFrom}`
//! (proposing `DerivedFrom` kernel while `ReflectsOn`/`DerivesFrom` are
//! extras); `ReflectsOn` is load-bearing (transcript replay, the curator
//! reflection-verify gate, forensic-bundle walks) despite having no TRACT home;
//! and `DecomposesInto` (parent→child) plausibly maps as the inverse of the
//! TRACT kernel `part_of` rather than a distinct extra. The v1.x open-predicate
//! model — which is the actual consumer — is AUTHORITATIVE over these; this
//! mapping's job is to force those tensions into the open now, not to freeze
//! them.

use crate::models::MemoryLinkRelation;

/// `true` only when the substrate implements TRACT's OPEN predicate space
/// (kernel floor + caller-authored CID predicates + definition-Claim
/// resolution). It does not at v1.0.0 — relations are a closed enum + DB CHECK.
/// Pinned as a const so the honesty state is machine-checked.
pub const OPEN_PREDICATES_SUPPORTED: bool = false;

/// The TRACT L1 kernel relations the substrate DOES NOT have as
/// `MemoryLinkRelation` variants (spec §2 kernel floor:
/// `supersedes·contradicts·derived_from·caused_by·attests·part_of·relates_to·invalidates`).
/// These have ZERO producers/consumers today; adding them is v1.x work (a bare
/// variant nothing emits would itself be dead vocabulary), tracked with the
/// open-predicate redesign.
pub const MISSING_TRACT_KERNEL_RELATIONS: &[&str] =
    &["caused_by", "attests", "part_of", "invalidates"];

/// The PROVISIONAL TRACT-kernel classification of a `MemoryLinkRelation`
/// (proposed, NOT normative — the v1.x open-predicate model is authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKernel {
    /// Proposed to map onto a TRACT L1 kernel relation (a load-bearing floor
    /// relation the verb algebra / federation / epistemics require).
    ProposedKernel,
    /// Proposed to become a caller-authored CID predicate under the v1.x open
    /// model (a substrate-specific relation outside the TRACT kernel floor).
    ProposedSubstrateExtra,
}

/// PROVISIONALLY classify a relation against the TRACT kernel. The `match` is
/// exhaustive with **no wildcard** — a new `MemoryLinkRelation` variant breaks
/// the build here until it is deliberately classified (the drift-gate).
///
/// The mapping is a PROPOSAL that surfaces contested edges (the `LINEAGE` trio
/// bisection, `ReflectsOn`'s TRACT-homelessness, `DecomposesInto` ↔ `part_of`),
/// NOT a normative decision — see the module docs.
#[must_use]
pub fn classify(relation: MemoryLinkRelation) -> RelationKernel {
    use MemoryLinkRelation as R;
    use RelationKernel::{ProposedKernel, ProposedSubstrateExtra};
    match relation {
        // Map onto TRACT kernel relates_to / supersedes / contradicts /
        // derived_from respectively.
        R::RelatedTo => ProposedKernel,
        R::Supersedes => ProposedKernel,
        R::Contradicts => ProposedKernel,
        R::DerivedFrom => ProposedKernel,
        // Substrate-specific — proposed to become authored-CID predicates.
        // (`ReflectsOn`/`DerivesFrom` are the other two thirds of the LINEAGE
        // trio; `DecomposesInto` overlaps the TRACT `part_of` kernel — both
        // CONTESTED, v1.x-authoritative.)
        R::ReflectsOn => ProposedSubstrateExtra,
        R::DerivesFrom => ProposedSubstrateExtra,
        R::DecomposesInto => ProposedSubstrateExtra,
        R::DependsOn => ProposedSubstrateExtra,
        R::Advances => ProposedSubstrateExtra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MemoryLinkRelation;

    // Drift-guard: every relation classifies (never panics) and the mapping is
    // total over the closed enum. This is a PROVISIONAL-mapping coverage check,
    // NOT a TRACT-conformance test.
    #[test]
    fn classification_is_total_over_the_closed_enum() {
        let all = MemoryLinkRelation::all();
        assert_eq!(
            all.len(),
            MemoryLinkRelation::COUNT,
            "the closed relation enum is COUNT-many"
        );
        assert_eq!(
            MemoryLinkRelation::COUNT,
            9,
            "G19 anchors the 9-variant enum"
        );
        let kernel = all
            .iter()
            .filter(|r| classify(**r) == RelationKernel::ProposedKernel)
            .count();
        let extra = all
            .iter()
            .filter(|r| classify(**r) == RelationKernel::ProposedSubstrateExtra)
            .count();
        assert_eq!(
            kernel + extra,
            MemoryLinkRelation::COUNT,
            "every variant classified"
        );
        // The proposed split as documented (4 kernel-ish, 5 extras). If a future
        // edit changes it, this fails and forces a spec + ledger update.
        assert_eq!(kernel, 4, "proposed-kernel count (see the contract §G19)");
        assert_eq!(extra, 5, "proposed-substrate-extra count");
    }

    #[test]
    fn open_predicates_are_not_implemented() {
        // Honesty pin: the open-predicate mechanism is v1.x, not v1.0.0.
        assert!(
            !OPEN_PREDICATES_SUPPORTED,
            "relations are a closed enum + DB CHECK; open predicates are v1.x"
        );
        assert_eq!(
            MISSING_TRACT_KERNEL_RELATIONS.len(),
            4,
            "4 TRACT-kernel relations are absent (caused_by/attests/part_of/invalidates)"
        );
    }

    #[test]
    fn the_lineage_trio_is_split_by_the_proposal_a_flagged_tension() {
        // Documents (as a test) the contested bisection: the substrate's own
        // LINEAGE grouping is one coherent set, but the proposed kernel map
        // splits it. This is deliberately surfaced, not resolved (v1.x-authoritative).
        let lineage = MemoryLinkRelation::LINEAGE;
        let kinds: Vec<RelationKernel> = lineage.iter().map(|r| classify(*r)).collect();
        assert!(
            kinds.contains(&RelationKernel::ProposedKernel)
                && kinds.contains(&RelationKernel::ProposedSubstrateExtra),
            "the proposal bisects the LINEAGE trio — a contested edge for v1.x"
        );
    }
}
