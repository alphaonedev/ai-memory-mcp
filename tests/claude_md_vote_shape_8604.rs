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
/// A line starting with this ends the section, unless it sits inside a fence.
const NEXT_HEADING_PREFIX: &str = "## ";
/// A line starting with this opens or closes a fenced code block.
const FENCE_PREFIX: &str = "```";
const SHAPE_1X3: &str = "1x3";
const AUDIT_CITATION: &str = "3-agent vote (6def5ab6)";
const THRESHOLD_PHRASE: &str = "with a threshold";
/// The live shape sentence ("exactly **3 concurrent read-only scout-tier
/// `Agent` calls**") pinned on the normalised section.
const SHAPE_SENTENCE: &str = "exactly 3 concurrent";
/// Superseded 5-agent vote markers, matched against the normalised section
/// (see [`normalised_for_marker_scan`]: lowercase, no markup, hyphens as
/// spaces, single spaces) and only at a token boundary ([`is_bounded_hit`]).
const SUPERSEDED_MARKERS: [&str; 9] = [
    // Rounds 1-6: the plain 5-concurrent shape and its word form (probes a-j).
    "5 concurrent",
    "five concurrent",
    // Round 6: the audit citation of the old rule (4d3ea1c5); the plural
    // history sentence `5 agent votes (4d3ea1c5)` is not a hit.
    "5 agent vote (4d3ea1c5)",
    // Round 6: the old section's own wording (probe h).
    "5 adversarial agent",
    // Round 6 code r13 / sec s12: word form of the citation.
    "five agent vote",
    // Round 6 code r9 / sec s10: synonym of "concurrent".
    "5 parallel",
    "five parallel",
    // Round 6 code r7 / sec s11: shape notation.
    "5x1",
    "1x5",
];
/// Non-ASCII characters the live section uses (census at chain tip 8382f308a,
/// CLAUDE.md:125-200): section sign, en dash, em dash, left-right arrow,
/// greater-than-or-equal. Any other non-ASCII character fails closed; extend
/// this constant deliberately to admit one.
const ALLOWED_NON_ASCII: [char; 5] = ['\u{00A7}', '\u{2013}', '\u{2014}', '\u{2194}', '\u{2265}'];
/// An HTML comment opener, forbidden in the section (invisible when rendered).
const HTML_COMMENT_OPEN: &str = "<!--";
/// Starts an HTML entity (`&#...;` or `&name;`), forbidden in the section.
const ENTITY_START: char = '&';
const NUMERIC_ENTITY_MARK: u8 = b'#';
const ENTITY_END: u8 = b';';
/// Markup characters removed before the superseded-marker scan.
const MARKUP_CHARS: [char; 3] = ['*', '_', '`'];
/// Hyphen, mapped to a space so hyphen joins and spaced forms meet.
const HYPHEN: char = '-';
/// Characters of text shown on each side of a forbidden hit.
const CONTEXT_WINDOW_CHARS: usize = 60;
const CONDITIONS: [&str; 6] = ["T1", "T2", "T3", "T4", "T5", "T6"];

fn claude_md() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The crossroads section: from its heading line to the first `## ` heading
/// outside a fenced code block. The heading prefix must occur exactly once.
fn crossroads_section(text: &str) -> &str {
    let count = text.matches(SECTION_PREFIX).count();
    assert!(
        count == 1,
        "CLAUDE.md must hold exactly one `{SECTION_PREFIX}` section, found {count}"
    );
    let start = text
        .find(SECTION_PREFIX)
        .unwrap_or_else(|| panic!("CLAUDE.md lacks the section prefix `{SECTION_PREFIX}`"));
    let rest = &text[start..];
    let mut in_fence = false;
    let mut offset = 0;
    for (index, line) in rest.split_inclusive('\n').enumerate() {
        if line.starts_with(FENCE_PREFIX) {
            in_fence = !in_fence;
        } else if index > 0 && !in_fence && line.starts_with(NEXT_HEADING_PREFIX) {
            return &rest[..offset];
        }
        offset += line.len();
    }
    rest
}

/// The section as a human reads it: lowercased, markup characters removed,
/// hyphens as spaces, every Unicode whitespace run (newlines and U+00A0
/// included) one ASCII space.
fn normalised_for_marker_scan(section: &str) -> String {
    let stripped: String = section
        .to_lowercase()
        .chars()
        .filter(|c| !MARKUP_CHARS.contains(c))
        .map(|c| if c == HYPHEN { ' ' } else { c })
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A hit at byte `at` counts only when the bytes before and after it are
/// absent or not ASCII alphanumeric (`15 concurrent` is not `5 concurrent`).
fn is_bounded_hit(text: &str, at: usize, marker_len: usize) -> bool {
    let bytes = text.as_bytes();
    let before_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
    let after_ok = bytes
        .get(at + marker_len)
        .is_none_or(|b| !b.is_ascii_alphanumeric());
    before_ok && after_ok
}

/// Byte offset of the first HTML entity (`&#` or `&letters;`) in `text`.
fn find_html_entity(text: &str) -> Option<usize> {
    text.match_indices(ENTITY_START).find_map(|(at, _)| {
        let tail = &text.as_bytes()[at + 1..];
        let letters = tail.iter().take_while(|b| b.is_ascii_alphabetic()).count();
        let numeric = tail.first() == Some(&NUMERIC_ENTITY_MARK);
        let named = letters > 0 && tail.get(letters) == Some(&ENTITY_END);
        (numeric || named).then_some(at)
    })
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

/// Fail closed on anything that can hide or disguise text in the rendered
/// section: non-allowlisted non-ASCII characters, HTML comments, entities.
fn assert_clean_characters(section: &str) {
    for (at, c) in section.char_indices() {
        assert!(
            c.is_ascii() || ALLOWED_NON_ASCII.contains(&c),
            "crossroads section holds non-allowlisted U+{:04X} at byte {at} \
             (extend ALLOWED_NON_ASCII to admit it): ...{}...",
            u32::from(c),
            context_around(section, at, c.len_utf8())
        );
    }
    if let Some(at) = section.find(HTML_COMMENT_OPEN) {
        panic!(
            "crossroads section holds an HTML comment: ...{}...",
            context_around(section, at, HTML_COMMENT_OPEN.len())
        );
    }
    if let Some(at) = find_html_entity(section) {
        panic!(
            "crossroads section holds an HTML entity: ...{}...",
            context_around(section, at, ENTITY_START.len_utf8())
        );
    }
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
    assert_clean_characters(section);
    let normalised = normalised_for_marker_scan(section);
    assert!(
        normalised.contains(SHAPE_SENTENCE),
        "crossroads section must state `{SHAPE_SENTENCE}`"
    );
    for marker in SUPERSEDED_MARKERS {
        for (at, _) in normalised.match_indices(marker) {
            assert!(
                !is_bounded_hit(&normalised, at, marker.len()),
                "crossroads section prescribes superseded `{marker}`: ...{}...",
                context_around(&normalised, at, marker.len())
            );
        }
    }
}
