// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3620 — the `*_ALLOW_LAX_PERMS` escape hatches must be documented with the
//! grammar their readers actually use.
//!
//! Every lax-perms reader parses its env var through the house truthy grammar
//! (`security_profile::is_truthy`: `1`/`true`/`yes`/`on`, trimmed and
//! case-insensitive), but the environment-variable table in
//! `docs/reference/ARCHITECTURE_REFERENCE.md` still documented `bool
//! (1/true)`, and row #40 named only `--db-passphrase-file` although the same
//! hatch also opens the `[llm]` / `[embeddings]` `api_key_file` check. An
//! operator could not predict from the docs which values open a hatch or
//! which files it covers.

use std::path::Path;

/// The lax-perms hatches whose readers all go through `is_truthy`.
const HATCHES: [&str; 4] = [
    "AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS",
    "AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS",
    "AI_MEMORY_CAPABILITY_FILE_ALLOW_LAX_PERMS",
    "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS",
];

/// The documented type cell of the house truthy grammar.
const TRUTHY_GRAMMAR: &str = "`1`/`true`/`yes`/`on`";

fn reference_doc() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference/ARCHITECTURE_REFERENCE.md"),
    )
    .expect("read docs/reference/ARCHITECTURE_REFERENCE.md")
}

/// The env-table row (a `| <n> | `<VAR>` | <type> | ...` line) for `var`.
fn row<'a>(doc: &'a str, var: &str) -> &'a str {
    let cell = format!("| `{var}` |");
    doc.lines()
        .find(|l| l.starts_with('|') && l.contains(&cell))
        .unwrap_or_else(|| panic!("the env table documents {var}"))
}

#[test]
fn lax_perms_rows_document_the_house_truthy_grammar_3620() {
    let doc = reference_doc();
    for var in HATCHES {
        let row = row(&doc, var);
        let ty = row.split('|').nth(3).unwrap_or_default();
        assert!(
            ty.contains(TRUTHY_GRAMMAR),
            "#3620: {var} is read through is_truthy, so its type cell must document \
             {TRUTHY_GRAMMAR}; got {ty:?}"
        );
        assert!(
            ty.contains("case-insensitive"),
            "#3620: {var}'s type cell must say the grammar is case-insensitive; got {ty:?}"
        );
    }
}

#[test]
fn passphrase_hatch_row_names_every_file_it_covers_3620() {
    let doc = reference_doc();
    let row = row(&doc, HATCHES[0]);
    for covered in [
        "--db-passphrase-file",
        "[llm]",
        "[embeddings]",
        "api_key_file",
    ] {
        assert!(
            row.contains(covered),
            "#3620: the passphrase lax-perms hatch also covers {covered}; the row must \
             name it"
        );
    }
}
