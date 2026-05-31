// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 multi-agent literal-sweep (scanner C, finding F-C2.x).
//!
//! Pre-sweep, the `MemoryLinkRelation` variant count was narrated as
//! "Six variants at v0.7.0 (was four at v0.6.x): `related_to`,
//! `supersedes`, `contradicts`, `derived_from`, `reflects_on`,
//! `derives_from`" across CLAUDE.md / README.md / ROADMAP.md /
//! release-notes with ZERO machine-checkable anchor. Adding a new
//! variant required a multi-file doc sweep PLUS updates to
//! `from_str`, `as_str`, the error message in `FromStr::from_str`,
//! and any external code that hand-rolls the list (kg traversal,
//! federation handshake, capability advertisement).
//!
//! This test pins the canonical count
//! (`MemoryLinkRelation::COUNT`) and the canonical enumeration
//! (`MemoryLinkRelation::all()`) so a missed parallel update fails
//! the build. Mirrors the
//! `tests/cli_subcommand_count_invariant.rs::cli_subcommand_count_*`
//! and `tests/route_count_invariant.rs::arch_14_route_count_invariant`
//! pattern.

use ai_memory::models::link::MemoryLinkRelation;

#[test]
fn memory_link_relation_count_matches_all_slice() {
    let all = MemoryLinkRelation::all();
    assert_eq!(
        all.len(),
        MemoryLinkRelation::COUNT,
        "MemoryLinkRelation drift: all().len() = {} but COUNT = {}. \
         When adding a variant: bump COUNT, append to all(), update \
         from_str/as_str match arms, update the FromStr error message \
         list, and run this test. Multi-agent sweep ref: scanner C \
         finding F-C2.x.",
        all.len(),
        MemoryLinkRelation::COUNT,
    );
}

#[test]
fn memory_link_relation_all_round_trips_through_from_str_as_str() {
    for variant in MemoryLinkRelation::all() {
        let s = variant.as_str();
        let parsed = MemoryLinkRelation::from_str(s).unwrap_or_else(|| {
            panic!(
                "as_str({variant:?}) = {s:?} but from_str({s:?}) returned None. \
                 from_str/as_str fell out of sync — both must list every variant."
            )
        });
        assert_eq!(
            parsed, *variant,
            "round-trip drift: {variant:?} → as_str() → {s:?} → from_str() → {parsed:?}"
        );
    }
}

#[test]
fn memory_link_relation_all_contains_default_relation() {
    let default = MemoryLinkRelation::default_relation();
    let all = MemoryLinkRelation::all();
    assert!(
        all.contains(&default),
        "default_relation() = {default:?} but `all()` does not contain it. \
         The default MUST be enumerated by all() so federation handshakes / \
         capability advertisements that filter on the canonical set never \
         omit the schema default."
    );
}
