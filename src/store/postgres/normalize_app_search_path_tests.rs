// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `normalize_app_search_path`, moved out of `postgres.rs`
//! (QUAL-10 headroom; behaviour-neutral).

use super::normalize_app_search_path;

#[test]
fn public_beats_user_and_ag_catalog_on_the_age_default() {
    // The AGE-recommended database default: ag_catalog first + "$user"
    // ahead of public. Both are demoted so `public` wins the create target
    // (the CVE-2018-1058 `$user`-precedence split-brain fix); ag_catalog is
    // kept LAST for type resolution.
    assert_eq!(
        normalize_app_search_path("ag_catalog, \"$user\", public").as_deref(),
        Some("public, ag_catalog")
    );
    // The minor gap: a NON-leading ag_catalog that still precedes public.
    assert_eq!(
        normalize_app_search_path("\"$user\", ag_catalog, public").as_deref(),
        Some("public, ag_catalog")
    );
    // `$user` ahead of public even without AGE -> still forced to public.
    assert_eq!(
        normalize_app_search_path("\"$user\", public").as_deref(),
        Some("public")
    );
}

#[test]
fn caller_pinned_and_already_ordered_paths_are_unchanged() {
    // The #1381 per-test-schema harness pins its own path (no "$user", no
    // ag_catalog): MUST be left alone so unqualified CREATE lands in the
    // test schema.
    assert_eq!(normalize_app_search_path("test_x_ab12, public"), None);
    // An explicit non-$user app schema first is honoured (like the harness).
    assert_eq!(normalize_app_search_path("myapp, public"), None);
    // Already in order.
    assert_eq!(normalize_app_search_path("public, ag_catalog"), None);
    assert_eq!(normalize_app_search_path("public"), None);
    assert_eq!(normalize_app_search_path(""), None);
}

#[test]
fn dedupes_extra_ag_catalog_and_handles_degenerate_paths() {
    assert_eq!(
        normalize_app_search_path("ag_catalog, public, ag_catalog").as_deref(),
        Some("public, ag_catalog")
    );
    // All-special path -> fall back to public as the target.
    assert_eq!(
        normalize_app_search_path("\"$user\", ag_catalog").as_deref(),
        Some("public, ag_catalog")
    );
}
