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
//! bump to the constant so the docs (CLAUDE.md §"Architecture", the
//! release notes, integration docs) and the substrate move in
//! lockstep.
//!
//! Lineage: replaces the prose-only count drift the v2 review lane
//! ARCH lane surfaced (ARCH-14). The `awk` extraction trick the
//! CLAUDE.md text documents is now mechanically pinned by this test
//! rather than relying on a discoverer re-running the awk recipe.

use std::fs;

#[test]
fn arch_14_route_count_invariant() {
    // Normalize CRLF → LF at read time. The static-text scan below
    // uses literal `\n` anchors (e.g. `"\n#[cfg(test)]\nmod "`); on
    // Windows the runner checkout converts `\n` → `\r\n` via
    // `core.autocrlf=true`, so the literal `\n` patterns never match
    // and `.find(...)` returns None. Issue #1374 documents the
    // failure on the windows-latest Check job. Stripping `\r` makes
    // the test hermetic across every checkout configuration.
    let src = fs::read_to_string("src/lib.rs")
        .expect("read src/lib.rs")
        .replace("\r\n", "\n");

    // Locate the build_router_with_timeout fn — its body contains
    // every production route. Then locate the `#[cfg(test)]\nmod
    // tests {` inline test module sentinel that demarcates the
    // production block from the test-only routes (e.g. `/slow`).
    let fn_start = src
        .find("pub fn build_router_with_timeout(")
        .expect("locate build_router_with_timeout");

    // The first `#[cfg(test)]` attribute that follows the fn
    // body marks the boundary between production routes (above)
    // and test-only routes (below). The inline test module name
    // is `h7_timeout_tests` at v0.7.0; using the cfg-attribute
    // sentinel rather than the mod name keeps the test stable if
    // the inline test module gets renamed.
    let test_mod_start = src[fn_start..]
        .find("\n#[cfg(test)]\nmod ")
        .expect("locate inline #[cfg(test)] mod sentinel after build_router_with_timeout");

    let production_block = &src[fn_start..fn_start + test_mod_start];
    let test_block_end = src.len();
    let test_block = &src[fn_start + test_mod_start..test_block_end];

    let production_routes = production_block
        .lines()
        .filter(|line| line.trim_start().starts_with(".route("))
        .count();

    let test_routes = test_block
        .lines()
        .filter(|line| line.trim_start().starts_with(".route("))
        .count();

    assert_eq!(
        production_routes,
        ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT,
        "ARCH-14 route count drift: production routes in build_router_with_timeout = {production_routes}, \
         but ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT = {}. \
         If a route was added/removed, update the constant AND the CLAUDE.md \
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
