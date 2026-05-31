// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 multi-agent literal-sweep (scanner B, finding F-B2.x).
//!
//! Adds typed-enum coverage to the existing `VALID_SCOPES` string
//! allowlist. The const continues to anchor the canonical string set;
//! the new `MemoryScope` enum gives ergonomic typed access for
//! consumers who do not need the raw string. This test pins the
//! cross-invariants so the two SSOTs cannot drift independently.
//!
//! Mirrors `tests/memory_link_relation_count_invariant.rs` +
//! `tests/cli_subcommand_count_invariant.rs` patterns.

use std::str::FromStr;

use ai_memory::models::namespace::{MemoryScope, VALID_SCOPES};

#[test]
fn memory_scope_count_matches_all_slice() {
    let all = MemoryScope::all();
    assert_eq!(
        all.len(),
        MemoryScope::COUNT,
        "MemoryScope drift: all().len() = {} but COUNT = {}.",
        all.len(),
        MemoryScope::COUNT,
    );
}

#[test]
fn memory_scope_count_matches_valid_scopes_const() {
    assert_eq!(
        MemoryScope::COUNT,
        VALID_SCOPES.len(),
        "SSOT drift: MemoryScope::COUNT = {} but VALID_SCOPES.len() = {}. \
         When adding a scope: bump both sides + as_str/from_str + the \
         visibility-policy dispatch in src/storage/mod.rs::is_visible. \
         Multi-agent sweep ref: scanner B finding F-B2.x.",
        MemoryScope::COUNT,
        VALID_SCOPES.len(),
    );
}

#[test]
fn memory_scope_all_strs_matches_valid_scopes_byte_for_byte() {
    let enum_strs = MemoryScope::all_strs();
    assert_eq!(
        enum_strs.len(),
        VALID_SCOPES.len(),
        "MemoryScope::all_strs len mismatch",
    );
    for (i, (a, b)) in enum_strs.iter().zip(VALID_SCOPES.iter()).enumerate() {
        assert_eq!(
            a, b,
            "MemoryScope::all_strs[{i}] = {a:?} but VALID_SCOPES[{i}] = {b:?}",
        );
    }
}

#[test]
fn memory_scope_all_round_trips_through_from_str_as_str() {
    for variant in MemoryScope::all() {
        let s = variant.as_str();
        let parsed = MemoryScope::from_str(s).unwrap_or_else(|| {
            panic!(
                "as_str({variant:?}) = {s:?} but from_str({s:?}) returned None. \
                 from_str/as_str fell out of sync — both must list every variant."
            )
        });
        assert_eq!(
            parsed, *variant,
            "round-trip drift: {variant:?} → {s:?} → {parsed:?}",
        );
    }
}

#[test]
fn memory_scope_default_is_private() {
    // The query layer's documented convention is "memories without a
    // `scope` field are treated as `private`". The Default impl must
    // match that convention.
    assert_eq!(MemoryScope::default(), MemoryScope::Private);
}

#[test]
fn memory_scope_fromstr_trait_rejects_unknown_with_helpful_message() {
    let err = <MemoryScope as FromStr>::from_str("bogus").expect_err("unknown scope should error");
    assert!(
        err.contains("'bogus'") && err.contains("private") && err.contains("collective"),
        "FromStr error should name the invalid value AND list valid scopes; got: {err}",
    );
}
