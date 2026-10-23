// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7274 — regression: the Form 6 row of `docs/batman-active-mode.md`
//! states the size of the [`MemoryKind`] vocabulary and names its variants;
//! both must match the enum.
//!
//! The defect: the row said "10-variant enum" and listed 10 names while
//! `MemoryKind` has 16 variants (`docs/memory-kind-vocab.md`). This test
//! pins the documented count and the documented names to the enum, in the
//! same shape as `tests/claude_md_kind_vocab_1589.rs`.

use ai_memory::models::MemoryKind;

/// Opening of the Form 6 table row in `docs/batman-active-mode.md`.
const FORM_6_ROW_MARKER: &str = "| 6 \u{2014} MemoryKind vocabulary |";

/// Suffix that follows the documented variant count in the row.
const COUNT_SUFFIX: &str = "-variant enum";

fn form_6_row() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("batman-active-mode.md");
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "docs/batman-active-mode.md must exist ({}): {e}",
            path.display()
        )
    });
    doc.lines()
        .find(|l| l.starts_with(FORM_6_ROW_MARKER))
        .expect("batman-active-mode.md must carry the Form 6 MemoryKind row")
        .to_string()
}

/// The count written before `-variant enum` equals the enum's variant count.
#[test]
fn form_6_documented_variant_count_matches_enum_7274() {
    let row = form_6_row();
    let at = row
        .find(COUNT_SUFFIX)
        .expect("Form 6 row must state the variant count as `<N>-variant enum`");
    let digits: String = row[..at]
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let documented: usize = digits
        .parse()
        .expect("Form 6 row must carry a number before `-variant enum`");
    assert_eq!(
        documented,
        MemoryKind::all().len(),
        "docs/batman-active-mode.md Form 6 says {documented}-variant enum but \
         MemoryKind has {} variants (docs/memory-kind-vocab.md)",
        MemoryKind::all().len()
    );
}

/// Every enum variant is named (backticked, capitalised) in the Form 6 row.
#[test]
fn form_6_row_names_every_memory_kind_7274() {
    let row = form_6_row();
    for kind in MemoryKind::all() {
        let name = kind.as_str();
        let mut chars = name.chars();
        let capitalised: String = chars
            .next()
            .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
            .unwrap_or_default();
        assert!(
            row.contains(&format!("`{capitalised}`")),
            "Form 6 row does not name the {capitalised} variant"
        );
    }
}
