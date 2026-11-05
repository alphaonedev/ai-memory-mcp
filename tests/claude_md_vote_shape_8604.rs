// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #8604 pin: the tracked `CLAUDE.md` crossroads section must prescribe the
//! 1x3 vote (3-agent vote (6def5ab6)) with a threshold, never the superseded
//! 5-agent shape. The check is scoped to that one section and does not pin the
//! full heading text, so an operator edit elsewhere in `CLAUDE.md` (or a date
//! amendment in the heading) cannot break it.

use std::fs;
use std::path::PathBuf;

const SECTION_PREFIX: &str = "## Crossroads decision protocol";
const NEXT_SECTION_MARKER: &str = "\n## ";
const SHAPE_1X3: &str = "1x3";
const AUDIT_CITATION: &str = "3-agent vote (6def5ab6)";
const THRESHOLD_PHRASE: &str = "with a threshold";
/// Superseded 5-agent vote markers, matched against the normalised section
/// (see [`normalised_for_marker_scan`]): lowercase, no markup, single spaces.
const SUPERSEDED_MARKERS: [&str; 4] = [
    "5 concurrent",
    "five concurrent",
    "5-agent vote (4d3ea1c5)",
    "5-adversarial-agent",
];
/// Markup characters removed before the superseded-marker scan.
const MARKUP_CHARS: [char; 3] = ['*', '_', '`'];
/// Characters of normalised text shown on each side of a forbidden hit.
const CONTEXT_WINDOW_CHARS: usize = 60;
const CONDITIONS: [&str; 6] = ["T1", "T2", "T3", "T4", "T5", "T6"];

fn claude_md() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The crossroads section: from its heading line to the next `## ` heading.
fn crossroads_section(text: &str) -> &str {
    let start = text
        .find(SECTION_PREFIX)
        .unwrap_or_else(|| panic!("CLAUDE.md lacks the section prefix `{SECTION_PREFIX}`"));
    let rest = &text[start..];
    let end = rest.find(NEXT_SECTION_MARKER).unwrap_or(rest.len());
    &rest[..end]
}

/// The section as a human reads it: lowercased, markup characters removed,
/// every Unicode whitespace run (newlines and U+00A0 included) one ASCII space.
fn normalised_for_marker_scan(section: &str) -> String {
    let stripped: String = section
        .to_lowercase()
        .chars()
        .filter(|c| !MARKUP_CHARS.contains(c))
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Up to `CONTEXT_WINDOW_CHARS` characters either side of the hit at byte `at`.
fn context_around(text: &str, at: usize, marker_len: usize) -> String {
    let start = text[..at]
        .char_indices()
        .rev()
        .take(CONTEXT_WINDOW_CHARS)
        .last()
        .map_or(at, |(i, _)| i);
    let after = at + marker_len;
    let end = text[after..]
        .char_indices()
        .nth(CONTEXT_WINDOW_CHARS)
        .map_or(text.len(), |(i, _)| after + i);
    text[start..end].to_string()
}

#[test]
fn crossroads_section_prescribes_the_1x3_vote_8604() {
    let text = claude_md();
    let section = crossroads_section(&text);
    let heading = section.lines().next().unwrap_or_default();

    for marker in [SHAPE_1X3, AUDIT_CITATION] {
        assert!(
            section.contains(marker),
            "crossroads section must contain `{marker}`"
        );
    }
    assert!(
        heading.contains(THRESHOLD_PHRASE),
        "crossroads heading must contain `{THRESHOLD_PHRASE}`: {heading}"
    );
    for condition in CONDITIONS {
        assert!(
            section.contains(condition),
            "crossroads section must list trigger condition `{condition}`"
        );
    }
    let normalised = normalised_for_marker_scan(section);
    for marker in SUPERSEDED_MARKERS {
        if let Some(at) = normalised.find(marker) {
            panic!(
                "crossroads section prescribes superseded `{marker}`: ...{}...",
                context_around(&normalised, at, marker.len())
            );
        }
    }
}
