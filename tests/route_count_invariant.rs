// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-14 (FX-C4-batch2, 2026-05-26) — HTTP route count invariant.
//!
//! Pins the daemon's HTTP-route table to a single canonical count
//! (`ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT`) by parsing
//! `src/lib.rs` and asserting that the `build_router_with_timeout`
//! body contains exactly the expected number of `.route(` calls in
//! its production scope plus the expected number of `#[cfg(test)]`
//! test routes. Any change to the route table requires a matching
//! bump to the constant so the docs (`docs/reference/ARCHITECTURE_REFERENCE.md` §"Architecture", the
//! release notes, integration docs) and the substrate move in
//! lockstep.
//!
//! Lineage: replaces the prose-only count drift the v2 review lane
//! ARCH lane surfaced (ARCH-14). The `awk` extraction trick the
//! `ARCHITECTURE_REFERENCE.md` text documents is now mechanically pinned by this test
//! rather than relying on a discoverer re-running the awk recipe.

use std::fs;

// #9367: the ONE resolver of what is test-only (#4198/#4200), never copied.
#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

#[test]
fn arch_14_route_count_invariant() {
    // Normalize CRLF → LF at read time. The static-text scan below
    // reads whole lines (the resolver matches `mod NAME {` line ends); on
    // Windows the runner checkout converts `\n` → `\r\n` via
    // `core.autocrlf=true`, so the literal `\n` patterns never match
    // and `.find(...)` returns None. Issue #1374 documents the
    // failure on the windows-latest Check job. Stripping `\r` makes
    // the test hermetic across every checkout configuration.
    let src = fs::read_to_string("src/lib.rs")
        .expect("read src/lib.rs")
        .replace("\r\n", "\n");

    // Locate the build_router_with_timeout fn — its body contains
    // every production route.
    let fn_start = src
        .find("pub fn build_router_with_timeout(")
        .expect("locate build_router_with_timeout");

    // The production block is every line from the fn on outside the
    // `cfg(test)` modules (the ONE resolver, #9367): a `#[cfg(test)]` item
    // inside production code does not end it, and production after a test
    // module still counts. Test routes are the `.route(` lines the resolver
    // removed (e.g. `/slow` in the inline `h7_timeout_tests` module).
    let from_fn = &src[fn_start..];
    let production_block = cfg_test_modules::strip_cfg_test_inline_mods(from_fn);
    let all_routes = from_fn
        .lines()
        .filter(|line| line.trim_start().starts_with(".route("))
        .count();

    let production_routes = production_block
        .lines()
        .filter(|line| line.trim_start().starts_with(".route("))
        .count();

    let test_routes = all_routes
        .checked_sub(production_routes)
        .expect("the resolver only removes lines, so production routes never exceed all routes");

    assert_eq!(
        production_routes,
        ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT,
        "ARCH-14 route count drift: production routes in build_router_with_timeout = {production_routes}, \
         but ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT = {}. \
         If a route was added/removed, update the constant AND the ARCHITECTURE_REFERENCE.md \
         §\"Architecture\" narrative in the same commit.",
        ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT,
    );

    assert_eq!(
        test_routes,
        ai_memory::EXPECTED_TEST_ROUTES_COUNT,
        "ARCH-14 test-route count drift: #[cfg(test)] routes after `mod tests` = {test_routes}, \
         but ai_memory::EXPECTED_TEST_ROUTES_COUNT = {}. \
         If a #[cfg(test)] route was added/removed, update the constant AND the test together.",
        ai_memory::EXPECTED_TEST_ROUTES_COUNT,
    );
}
