// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 multi-agent literal-sweep (scanner A, finding F-A3.1).
//!
//! Pre-sweep, the CLI subcommand count was cited as `80` (default
//! build) / `82` (sal) in 24+ doc surfaces with ZERO machine-checkable
//! anchor. CLAUDE.md alone had 7 historical counts (40, 57, 58, 63,
//! 79, 80, 82); each tool/subcommand addition required a 24-27-file
//! doc sweep (v0.7.0 audit `docs/v0.7.0/test-campaign-2026-05-28-ship-
//! campaign/audience-sme-engineer.md:109` explicitly called out the
//! "CLI 57 → 79" drift class).
//!
//! This test pins the canonical counts (`ai_memory::EXPECTED_CLI_
//! SUBCOMMANDS_DEFAULT` + `EXPECTED_CLI_SUBCOMMANDS_SAL`) by parsing
//! `src/daemon_runtime.rs` and counting variants of the
//! `pub enum Command { ... }` declaration directly, mirroring the
//! existing `tests/route_count_invariant.rs::arch_14_route_count_invariant`
//! pattern.
//!
//! Variants gated by `#[cfg(feature = "sal")]` (`Migrate` +
//! `SchemaInit` at v0.7.0) count toward the SAL total but not the
//! default total. Adding a new variant requires a matching bump to
//! the appropriate const so the docs surface (CLAUDE.md §"Architecture",
//! release notes, audience pages) can never drift silently again.

use std::fs;

/// Returns (default_count, sal_count_total) — sal_count_total is
/// the FULL count when `--features sal` (or `sal-postgres`) is
/// active (default variants + sal-gated variants).
///
/// Matches the canonical CLAUDE.md §"Architecture" recipe:
/// `awk '/^pub enum Command/,/^}/' src/daemon_runtime.rs |
/// grep -E '^    [A-Z]' | wc -l`. That recipe counts every line
/// inside the `pub enum Command { ... }` body whose first 4 columns
/// are spaces and the 5th column is an uppercase ASCII letter — that
/// matches the rustfmt-canonical variant-declaration shape (whether
/// the variant is a unit, tuple, or struct variant). The recipe
/// returns 80 today; the sal-gate count uses the same shape on the
/// `#[cfg(feature = "sal")]` attribute lines.
fn count_command_variants() -> (usize, usize) {
    // Normalise CRLF → LF for hermeticity across Windows checkouts.
    let src = fs::read_to_string("src/daemon_runtime.rs")
        .expect("read src/daemon_runtime.rs")
        .replace("\r\n", "\n");

    let enum_start = src
        .find("pub enum Command {")
        .expect("locate `pub enum Command {` in src/daemon_runtime.rs");

    let after_open = &src[enum_start..];
    let close_offset = after_open
        .find("\n}\n")
        .expect("locate enum-body closing brace");
    let body = &after_open[..close_offset];

    // Recipe: line matches `^    [A-Z]` — four spaces of indent
    // then an uppercase ASCII letter. Matches every rustfmt-emitted
    // variant declaration regardless of variant kind (unit / tuple /
    // struct). Excludes attribute lines (`    #[...]` start with `#`),
    // doc-comment lines (`    ///` start with `/`), and nested
    // continuation lines (which start with deeper indent or `(`).
    let is_variant_line = |line: &str| -> bool {
        let bytes = line.as_bytes();
        bytes.len() >= 5 && &bytes[..4] == b"    " && (b'A'..=b'Z').contains(&bytes[4])
    };

    let lines: Vec<&str> = body.lines().collect();
    let mut total_count = 0usize;
    let mut sal_count = 0usize;
    for (i, line) in lines.iter().enumerate() {
        if !is_variant_line(line) {
            continue;
        }
        total_count += 1;

        // sal-gate check: walk backward over doc-comments + blank
        // lines to find the most-recent attribute or whitespace.
        // A `#[cfg(feature = "sal")]` (or `sal-postgres`) on the
        // immediately-preceding attribute line gates this variant.
        let mut sal_gated = false;
        let mut j = i;
        while j > 0 {
            j -= 1;
            let prev = lines[j].trim();
            if prev.is_empty() || prev.starts_with("///") || prev.starts_with("//") {
                continue;
            }
            if prev.contains("#[cfg(feature = \"sal\"")
                || prev.contains("#[cfg(any(feature = \"sal\"")
                || prev.contains("#[cfg(feature = \"sal-postgres\"")
            {
                sal_gated = true;
            }
            break;
        }
        if sal_gated {
            sal_count += 1;
        }
    }

    // default_count = total minus sal-gated variants (the sal-gated
    // ones are unlocked only under `--features sal` or `sal-postgres`).
    let default_count = total_count - sal_count;
    let sal_count_total = total_count;
    (default_count, sal_count_total)
}

#[test]
fn cli_subcommand_count_default_build_matches_ssot() {
    let (default_count, _sal_count) = count_command_variants();
    assert_eq!(
        default_count,
        ai_memory::EXPECTED_CLI_SUBCOMMANDS_DEFAULT,
        "CLI subcommand drift: default-build variants in `pub enum Command` = {default_count}, \
         but ai_memory::EXPECTED_CLI_SUBCOMMANDS_DEFAULT = {}. \
         If a subcommand was added/removed, update the constant AND the CLAUDE.md \
         §\"Architecture\" narrative in the same commit. Multi-agent sweep ref: \
         scanner A finding F-A3.1 (memory `f19f73be`).",
        ai_memory::EXPECTED_CLI_SUBCOMMANDS_DEFAULT,
    );
}

#[test]
fn cli_subcommand_count_sal_build_matches_ssot() {
    let (_default_count, sal_count) = count_command_variants();
    assert_eq!(
        sal_count,
        ai_memory::EXPECTED_CLI_SUBCOMMANDS_SAL,
        "CLI subcommand drift: sal-build variants in `pub enum Command` = {sal_count}, \
         but ai_memory::EXPECTED_CLI_SUBCOMMANDS_SAL = {}. \
         Sal-gated variants (e.g. `Migrate`, `SchemaInit`) count toward this total. \
         Multi-agent sweep ref: scanner A finding F-A3.1.",
        ai_memory::EXPECTED_CLI_SUBCOMMANDS_SAL,
    );
}
