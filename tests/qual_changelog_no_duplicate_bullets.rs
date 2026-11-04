// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8583 guard: no `CHANGELOG.md` bullet line may appear twice in the file.
//!
//! The `merge=union` attribute concatenates both sides of a conflicting hunk and
//! leaves duplicated bullets behind; this test fails on any such duplicate and
//! names each one.

use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn changelog_has_no_duplicate_bullets_8583() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CHANGELOG.md");
    let text = std::fs::read_to_string(&path).expect("read CHANGELOG.md");
    let mut seen: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("- ") {
            seen.entry(trimmed).or_default().push(idx + 1);
        }
    }
    let dups: Vec<String> = seen
        .iter()
        .filter(|(_, lines)| lines.len() > 1)
        .map(|(bullet, lines)| {
            let head: String = bullet.chars().take(80).collect();
            format!("{head} (lines {lines:?})")
        })
        .collect();
    assert!(
        dups.is_empty(),
        "CHANGELOG.md has {} duplicated bullet(s), resolve by hand (#8583):\n{}",
        dups.len(),
        dups.join("\n")
    );
}
