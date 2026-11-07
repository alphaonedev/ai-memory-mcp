// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8583 guard: no `CHANGELOG.md` bullet line may appear twice inside one
//! release (`## `) section.
//!
//! The `merge=union` attribute concatenates both sides of a conflicting hunk and
//! leaves duplicated bullets behind; this test fails on any such duplicate and
//! names the section and each duplicate. Repeats across different release
//! sections are legitimate history and are not flagged.

use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn changelog_has_no_duplicate_bullets_per_section_8583() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CHANGELOG.md");
    let text = std::fs::read_to_string(&path).expect("read CHANGELOG.md");
    let mut section = String::from("(before first release section)");
    let mut seen: BTreeMap<(String, &str), Vec<usize>> = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        if line.starts_with("## ") {
            section = line.chars().take(80).collect();
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("- ") {
            seen.entry((section.clone(), trimmed))
                .or_default()
                .push(idx + 1);
        }
    }
    let dups: Vec<String> = seen
        .iter()
        .filter(|(_, lines)| lines.len() > 1)
        .map(|((sec, bullet), lines)| {
            let head: String = bullet.chars().take(80).collect();
            format!("[{sec}] {head} (lines {lines:?})")
        })
        .collect();
    assert!(
        dups.is_empty(),
        "CHANGELOG.md has {} duplicated bullet(s) inside one release section, resolve by hand (#8583):\n{}",
        dups.len(),
        dups.join("\n")
    );
}
