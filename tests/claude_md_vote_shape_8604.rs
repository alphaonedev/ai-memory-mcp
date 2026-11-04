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
const SUPERSEDED_SHAPES: [&str; 2] = ["5 concurrent", "5-agent vote (4d3ea1c5)"];
const HISTORY_LINE_PREFIX: &str = "Prior 5-agent votes";
const LEADING_MARKUP: [char; 3] = ['*', '_', '>'];
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

/// A history line is exempt only when it STARTS with the exact history
/// sentence prefix after leading whitespace and markdown emphasis are trimmed.
fn is_history_line(line: &str) -> bool {
    line.trim_start_matches(|c: char| c.is_whitespace() || LEADING_MARKUP.contains(&c))
        .starts_with(HISTORY_LINE_PREFIX)
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
    for line in section.lines() {
        let is_history = is_history_line(line);
        for shape in SUPERSEDED_SHAPES {
            assert!(
                is_history || !line.contains(shape),
                "crossroads section prescribes superseded `{shape}` outside a history line: {line}"
            );
        }
    }
}
