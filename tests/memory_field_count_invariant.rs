// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 multi-agent literal-sweep (scanner B, finding F-B1.x).
//!
//! Pre-sweep, the `Memory` struct's field count was narrated as
//! "26-field struct at v0.7.0 (was 15 at v0.6.x)" across CLAUDE.md /
//! README.md / ROADMAP.md / release-notes with ZERO machine-checkable
//! anchor. Adding a new field required: bump the struct + the related
//! schema migration + every doc surface that cited the count + every
//! serialization/deserialization site + the auto-merge logic. No
//! mechanical pin meant doc drift was guaranteed on every field
//! addition.
//!
//! This test pins the canonical count (`Memory::FIELD_COUNT`) by
//! parsing `src/models/memory.rs` and counting `pub <name>: <type>`
//! field declarations between `pub struct Memory {` and the matching
//! closing brace. Mirrors `tests/cli_subcommand_count_invariant.rs`
//! and `tests/memory_link_relation_count_invariant.rs` parity-test
//! patterns.

use std::fs;

/// Parse src/models/memory.rs and count the declared field lines in
/// the `pub struct Memory { ... }` block. Matches lines of shape
/// `^    pub <ident>: <type>` (rustfmt-canonical), skips
/// attribute lines (`    #[...]`), doc-comments (`    ///`),
/// continuation lines (deeper indent), and the close-brace line.
fn count_memory_fields() -> usize {
    let src = fs::read_to_string("src/models/memory.rs")
        .expect("read src/models/memory.rs")
        .replace("\r\n", "\n");

    let start = src
        .find("\npub struct Memory {\n")
        .expect("locate `pub struct Memory {` in src/models/memory.rs");

    let after_open = &src[start..];
    // Find the FIRST `\n}\n` boundary (struct close). The closing
    // brace at column 0 marks the end of the struct body.
    let close_offset = after_open
        .find("\n}\n")
        .expect("locate struct-body closing brace");
    let body = &after_open[..close_offset];

    // Recipe: line matches `^    pub <ident>:` — four spaces of
    // indent then literal "pub ", then an identifier, then ":". This
    // is the rustfmt-canonical shape for a struct field. Attribute
    // lines start with `#`; doc-comments start with `/`; continuation
    // lines (generic type parameters wrapped across lines) start with
    // deeper indent or `>`. All are excluded.
    body.lines()
        .filter(|line| {
            line.starts_with("    pub ")
                && line.len() >= 9
                && line[8..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && line.contains(':')
        })
        .count()
}

#[test]
fn memory_field_count_matches_ssot() {
    let counted = count_memory_fields();
    assert_eq!(
        counted,
        ai_memory::models::memory::Memory::FIELD_COUNT,
        "Memory struct drift: counted {} `pub <name>: <type>` fields in \
         src/models/memory.rs, but ai_memory::models::memory::Memory::FIELD_COUNT = {}. \
         When adding or removing a Memory field, bump the const in the SAME commit. \
         Multi-agent sweep ref: scanner B finding F-B1.x.",
        counted,
        ai_memory::models::memory::Memory::FIELD_COUNT,
    );
}
