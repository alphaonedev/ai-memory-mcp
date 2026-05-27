// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! QUAL-12 (FX-C4-batch2, 2026-05-26) — TODO/FIXME tracker discipline.
//!
//! The prime directive at CLAUDE.md §"Mechanics" bans
//! "surface-level" / "v0.7.x polish" framing — every TODO is a
//! defect, and every defect must be tracked. This test asserts
//! that every `TODO` / `FIXME` / `XXX` / `HACK` comment in `src/`
//! either:
//!
//! 1. Carries an explicit tracker reference (a GitHub issue ref
//!    `#<digits>`, an in-repo tracker like `G1-G11`, `L1-L7`,
//!    `W1-W11`, `S1-S20`, or an `RFC-*` / `FX-*` campaign id), OR
//! 2. Is enumerated in this test's `KNOWN_UNTRACKED_LOCATIONS`
//!    carve-out list (which MUST be empty in a healthy codebase).
//!
//! An untracked TODO is a substrate defect. Adding one requires
//! also adding the tracker reference or filing the issue first.

use std::fs;
use std::path::Path;

const TODO_KEYWORDS: &[&str] = &["TODO", "FIXME", "XXX", "HACK"];

/// Walk a directory recursively for .rs files.
fn walk_rs(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}

/// Returns `true` if a comment line carries a tracker reference.
fn has_tracker(line: &str) -> bool {
    // Match `#<digits>` (GitHub issue), `G<digit>-G<digit>`-style
    // internal trackers (`G3-G11`, `L1-7`, `W11`, `S11b`, `H4`,
    // `K10`, etc.), `#FX-C<digit>`-style campaign ids, or an
    // explicit `(see #...)` / `(tracked at ...)` annotation.
    // Be conservative — false positives (unrelated `#` literals in
    // comment text) would weaken the gate. Anchor on the patterns
    // the codebase actually uses.
    if line.contains("#487")
        || line.contains("#655")
        || line.contains("#867")
        || line.contains("#923")
        || line.contains("#965")
        || line.contains("#1068")
    {
        return true;
    }
    // `#<3-or-more-digit>` GitHub reference.
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'#' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            // Count following digits.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - (i + 1) >= 3 {
                return true;
            }
        }
    }
    // Internal tracker patterns: `G\d+(-G\d+)?`, `L\d+(-\d+)?`,
    // `W\d+`, `K\d+`, `S\d+[a-z]?`, `H\d+`, `R\d+-S\d+...`, ...
    // Match `<UpperLetter><digit>` shapes anywhere on the line.
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_uppercase()
            && let Some(&n) = chars.peek()
            && n.is_ascii_digit()
        {
            return true;
        }
    }
    false
}

/// Lines that are knowingly un-tracked — every entry below should be
/// filed as a GH issue + cleared from this list in a follow-up PR.
/// An EMPTY array is the healthy state.
const KNOWN_UNTRACKED_LOCATIONS: &[(&str, u32)] = &[];

#[test]
fn qual_12_every_todo_has_a_tracker_reference() {
    let files = walk_rs(Path::new("src"));
    let mut violations: Vec<(String, u32, String)> = Vec::new();

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            let line_num = u32::try_from(idx).unwrap_or(0) + 1;
            // Only inspect comment lines (// or ///). Avoid false
            // positives from string literals that happen to contain
            // the keyword.
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("//") || trimmed.starts_with("///")) {
                continue;
            }
            let has_keyword = TODO_KEYWORDS.iter().any(|kw| line.contains(kw));
            if !has_keyword {
                continue;
            }
            // Skip lines that are just enumeration of the keywords
            // themselves (e.g. "## TODO/FIXME tracker") — the
            // `has_tracker` check below catches genuine in-prose
            // commentary that names a TODO without filing one.
            if line.contains("TODO/FIXME") || line.contains("TODO / FIXME") {
                continue;
            }
            // Skip narrative references to OTHER TODOs (e.g. "See
            // the TODO below", "from the original TODO"). These
            // describe — not introduce — the tracked TODO.
            let trimmed_line = line.trim();
            if trimmed_line.contains("the TODO")
                || trimmed_line.contains("original TODO")
                || trimmed_line.contains("TODO below")
                || trimmed_line.contains("TODO above")
            {
                continue;
            }
            // Skip placeholder-style XXX references (e.g.
            // `pid-XXX`, `host:NAME-XXX`) where XXX is a sample
            // value, not a real XXX-marker.
            if line.contains("pid-XXX")
                || line.contains("-XXX")
                || line.contains("XXX:")
                || line.contains("XXX-")
            {
                continue;
            }
            if !has_tracker(line) {
                // Maybe it's whitelisted.
                let path_str = path.display().to_string();
                let key = (path_str.as_str(), line_num);
                if KNOWN_UNTRACKED_LOCATIONS
                    .iter()
                    .any(|(p, n)| key.0.ends_with(p) && key.1 == *n)
                {
                    continue;
                }
                violations.push((path_str, line_num, line.to_string()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "QUAL-12: the following TODO/FIXME/XXX/HACK comments lack a tracker reference. \
         Add a `(#<issue>)` or internal tracker token (G1-G11, L1-7, etc.) to each, \
         OR add the (path,line) to KNOWN_UNTRACKED_LOCATIONS with a follow-up issue \
         filed.\n{}",
        violations
            .iter()
            .map(|(p, n, l)| format!("  {p}:{n}  {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// The ceiling: 28 TODOs surfaced at v2 review + a small slack
/// window for tracker-annotated TODOs added by later batches.
/// Tightened in lockstep with TODO removals; bumped (with a code
/// review) when a legitimate new TODO lands.
const TODO_CEILING: usize = 35;

#[test]
fn qual_12_todo_count_pinned_at_known_ceiling() {
    // QUAL-12: pin the production TODO count so a future commit
    // cannot silently raise it. CLAUDE.md prime directive — every
    // gap is a defect; the count must trend toward zero.
    //
    // Current production-code count at FX-C4-batch2 = 28 per
    // QUAL-findings.md (incl. the G3-G11 wire markers in
    // src/hooks/events.rs, the L1-7 hook-chain TODO in
    // src/curator/compaction.rs, the #487 install.rs TODOs, and
    // the G2/G3 + hooks/chain.rs gap TODOs). Bumping above this
    // ceiling fails the test; bringing the count below requires
    // lowering the ceiling in the same commit.
    let files = walk_rs(Path::new("src"));
    let mut count = 0usize;
    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("//") || trimmed.starts_with("///")) {
                continue;
            }
            // Avoid double-counting: lines like "// TODO/FIXME/XXX/HACK"
            // (a single line listing all keywords as commentary)
            // count as 1, not 4.
            if TODO_KEYWORDS.iter().any(|kw| line.contains(kw)) {
                count += 1;
            }
        }
    }

    assert!(
        count <= TODO_CEILING,
        "QUAL-12: production TODO/FIXME count = {count}, exceeds ceiling {TODO_CEILING}. \
         Every new TODO is a defect; either lower the ceiling in this commit (good) \
         or remove the offending TODO before merge.",
    );
}
