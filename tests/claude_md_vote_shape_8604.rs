// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #8604 pin: the tracked `CLAUDE.md` crossroads section must prescribe the
//! 1x3 vote (3-agent vote (6def5ab6)) with a threshold, never the superseded
//! 5-agent shape. The section is pinned byte for byte against a fixture
//! (`tests/fixtures/claude_md/crossroads_section_8604.md`); the semantic checks
//! run on both the live section and the fixture, so a fixture edit that brings
//! the old shape back fails too. The check is scoped to that one section, so an
//! operator edit elsewhere in `CLAUDE.md` cannot break it.

use std::fs;
use std::path::PathBuf;

const SECTION_PREFIX: &str = "## Crossroads decision protocol";
/// A line starting with this ends the section, unless it sits inside a fence.
const NEXT_HEADING_PREFIX: &str = "## ";
/// The fixture path relative to this file, named in the panic message. It
/// repeats the literal in [`FIXTURE`]: `include_str!` takes a literal, and the
/// CI impact scanner (`scripts/ci/impact/build_index.py`) resolves only a
/// string literal there.
const FIXTURE_PATH: &str = "fixtures/claude_md/crossroads_section_8604.md";
/// The exact bytes of the crossroads section the operator approved.
const FIXTURE: &str = include_str!("fixtures/claude_md/crossroads_section_8604.md");
const LABEL_LIVE: &str = "live CLAUDE.md section";
const LABEL_FIXTURE: &str = "fixture";
const CHANGED_SENTENCE: &str = "the CLAUDE.md crossroads section changed; a crossroads rule change \
needs the Rule-Change-Approved-By trailer and the updated fixture in the same commit";
/// Bytes of excerpt shown on each side of the first differing byte.
const DIFF_EXCERPT_WIDTH: usize = 80;
/// A fence line: up to this many leading spaces, then a fence run.
const FENCE_MAX_INDENT: usize = 3;
/// Shortest run of fence characters that opens or closes a fence.
const FENCE_MIN_RUN: usize = 3;
/// The two characters a fence run is made of (`CommonMark`).
const FENCE_CHARS: &[u8] = b"`~";
const SHAPE_1X3: &str = "1x3";
const AUDIT_CITATION: &str = "3-agent vote (6def5ab6)";
const THRESHOLD_PHRASE: &str = "with a threshold";
/// The live shape sentence ("exactly **3 concurrent read-only scout-tier
/// `Agent` calls**") pinned on the normalised section.
const SHAPE_SENTENCE: &str = "exactly 3 concurrent";
/// Superseded 5-agent vote markers, matched against the normalised section
/// (see [`normalised_for_marker_scan`]: lowercase, no markup, dashes as
/// spaces, single spaces) and only at a token boundary ([`is_bounded_hit`]).
/// There is deliberately NO bare `5 agent vote` marker: the live history
/// sentence "Prior 5-agent votes (4d3ea1c5) stand." normalises to
/// `5 agent votes (4d3ea1c5)` and would false-hit; that form is covered by the
/// byte pin against the fixture instead.
const SUPERSEDED_MARKERS: [&str; 11] = [
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
    // Round 8 code r7 F3 / sec F4: the shape notation across a dash (`5-x1`
    // normalises to `5 x1`).
    "5 x1",
    "1 x5",
];
/// Non-ASCII characters the live section uses (census at chain tip 8382f308a,
/// CLAUDE.md:125-200): section sign, en dash, em dash, left-right arrow,
/// greater-than-or-equal. Any other non-ASCII character fails closed; extend
/// this constant deliberately to admit one.
const ALLOWED_NON_ASCII: [char; 5] = ['\u{00A7}', '\u{2013}', '\u{2014}', '\u{2194}', '\u{2265}'];
/// An HTML comment opener, forbidden in the section (invisible when rendered).
const HTML_COMMENT_OPEN: &str = "<!--";
/// An HTML comment closer, used to track an HTML comment opened before the
/// crossroads heading.
const HTML_COMMENT_CLOSE: &str = "-->";
const PANIC_OPEN_FENCE: &str = "crossroads heading sits inside an open fenced code block";
const PANIC_OPEN_COMMENT: &str = "crossroads heading sits inside an open HTML comment";
/// Starts an HTML entity (`&#...;` or `&name;`), forbidden in the section.
const ENTITY_START: u8 = b'&';
const NUMERIC_ENTITY_MARK: u8 = b'#';
const ENTITY_END: u8 = b';';
/// Opens an HTML tag, comment, closing tag or processing instruction when
/// followed by a letter or one of [`TAG_FOLLOWERS`]; the live section's only
/// `<` is the `<=` of "(<=120 words)".
const TAG_START: u8 = b'<';
/// Bytes after `<` that open raw HTML: `/` closing tag, `!` comment or
/// declaration, `?` processing instruction (`CommonMark` 6.6 counts `<?...?>`
/// as inline raw HTML, which renders hidden).
const TAG_FOLLOWERS: &[u8] = b"/!?";
/// Context length shown for a tag hit: the `<` byte plus one follower byte.
const TAG_CONTEXT_LEN: usize = std::mem::size_of_val(&TAG_START) + std::mem::size_of::<u8>();
/// Context length shown for an entity hit: the entity start byte.
const ENTITY_CONTEXT_LEN: usize = std::mem::size_of_val(&ENTITY_START);
/// Characters forbidden outright in the section (census at 8382f308a: the
/// live section holds none of them). Backslash escapes and link text render
/// differently from the raw bytes (`5\-concurrent`, `[5](#x) concurrent`).
const FORBIDDEN_ASCII: [char; 3] = ['\\', '[', ']'];
/// Markup characters removed before the superseded-marker scan.
const MARKUP_CHARS: [char; 3] = ['*', '_', '`'];
/// Characters mapped to a space before the scan: hyphen, en dash, em dash, so
/// dash joins and spaced forms meet.
const DASH_CHARS: [char; 3] = ['-', '\u{2013}', '\u{2014}'];
/// Characters of text shown on each side of a forbidden hit.
const CONTEXT_WINDOW_CHARS: usize = 60;
const CONDITIONS: [&str; 6] = ["T1", "T2", "T3", "T4", "T5", "T6"];

fn claude_md() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Fence run on `line`: up to [`FENCE_MAX_INDENT`] leading spaces, then
/// [`FENCE_MIN_RUN`] or more identical fence characters. Returns the
/// character, the run length and the text after the run.
fn fence_run(line: &str) -> Option<(u8, usize, &str)> {
    let indent = line.bytes().take_while(|&b| b == b' ').count();
    if indent > FENCE_MAX_INDENT {
        return None;
    }
    let body = &line[indent..];
    let first = *body.as_bytes().first()?;
    if !FENCE_CHARS.contains(&first) {
        return None;
    }
    let run = body.bytes().take_while(|&b| b == first).count();
    (run >= FENCE_MIN_RUN).then(|| (first, run, &body[run..]))
}

/// True when `line` leaves an HTML comment open, given whether one was open
/// at its start. Scans `<!--` and `-->` in order across the line.
fn comment_open_after(line: &str, mut in_comment: bool) -> bool {
    let mut rest = line;
    loop {
        let marker = if in_comment {
            HTML_COMMENT_CLOSE
        } else {
            HTML_COMMENT_OPEN
        };
        let Some(at) = rest.find(marker) else {
            return in_comment;
        };
        in_comment = !in_comment;
        rest = &rest[at + marker.len()..];
    }
}

/// Panics when the text before the heading leaves a fenced code block or an
/// HTML comment open at the heading. Fences follow the same `CommonMark` rule
/// as the section end (backtick or tilde runs, closed only by the same
/// character and at least as long a run); a fence line inside an open comment
/// and a comment marker inside an open fence are plain text.
fn assert_heading_not_wrapped(before: &str) {
    let mut open_fence: Option<(u8, usize)> = None;
    let mut in_comment = false;
    for line in before.split_inclusive('\n') {
        if in_comment {
            in_comment = comment_open_after(line, true);
            continue;
        }
        match (open_fence, fence_run(line)) {
            (None, Some((ch, run, _))) => open_fence = Some((ch, run)),
            (Some((open_ch, open_run)), Some((ch, run, tail)))
                if ch == open_ch && run >= open_run && tail.trim().is_empty() =>
            {
                open_fence = None;
            }
            (None, None) => in_comment = comment_open_after(line, false),
            _ => {}
        }
    }
    assert!(open_fence.is_none(), "{PANIC_OPEN_FENCE}");
    assert!(!in_comment, "{PANIC_OPEN_COMMENT}");
}

/// The crossroads section: from its heading line to the byte before the
/// first `\n## ` outside a fenced code block (`CommonMark` fences: backtick or
/// tilde runs, closed only by the same character and at least as long a run).
/// The heading prefix must occur exactly once, case-insensitively, anywhere in
/// the text; that one occurrence must sit at a line start (byte offset 0 or
/// right after a newline; a CRLF before it and a BOM at file start do not
/// change this test, and `scripts/check-claude-md-size.py` rejects the BOM).
/// The text before the heading is scanned from byte 0: the test panics when a
/// fenced code block or an HTML comment opened on an earlier line is still
/// open at the heading ([`assert_heading_not_wrapped`]). A heading on a
/// blockquote line or with an extra `#` is not found at a line start and also
/// panics. `CommonMark` allows up to three spaces before `#`; this pin
/// deliberately requires column 0 because the live file has it there.
fn crossroads_section(text: &str) -> &str {
    let lowered = text.to_ascii_lowercase();
    let prefix = SECTION_PREFIX.to_ascii_lowercase();
    let count = lowered.matches(&prefix).count();
    assert!(
        count == 1,
        "CLAUDE.md must hold exactly one `{SECTION_PREFIX}` section (case-insensitive), found {count}"
    );
    let start = lowered
        .match_indices(&prefix)
        .map(|(at, _)| at)
        .find(|&at| at == 0 || lowered.as_bytes()[at - 1] == b'\n')
        .unwrap_or_else(|| {
            panic!("crossroads heading not found at a line start: `{SECTION_PREFIX}`")
        });
    assert_heading_not_wrapped(&text[..start]);
    let rest = &text[start..];
    let mut open_fence: Option<(u8, usize)> = None;
    let mut offset = 0;
    for (index, line) in rest.split_inclusive('\n').enumerate() {
        match (open_fence, fence_run(line)) {
            (None, Some((ch, run, _))) => open_fence = Some((ch, run)),
            (Some((open_ch, open_run)), Some((ch, run, tail)))
                if ch == open_ch && run >= open_run && tail.trim().is_empty() =>
            {
                open_fence = None;
            }
            (None, None) if index > 0 && line.starts_with(NEXT_HEADING_PREFIX) => {
                // Exclude the newline that precedes the terminating `## `.
                return &rest[..offset - 1];
            }
            _ => {}
        }
        offset += line.len();
    }
    rest
}

/// The section as a human reads it: lowercased, markup characters removed,
/// dashes as spaces, every Unicode whitespace run (newlines and U+00A0
/// included) one ASCII space.
fn normalised_for_marker_scan(section: &str) -> String {
    let stripped: String = section
        .to_lowercase()
        .chars()
        .filter(|c| !MARKUP_CHARS.contains(c))
        .map(|c| if DASH_CHARS.contains(&c) { ' ' } else { c })
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A hit at byte `at` must have an absent or non-alphanumeric byte before it
/// (`15 concurrent` is not `5 concurrent`). The byte after it is checked only
/// when the marker ends in an ASCII digit ([`ends_in_digit`]): `5x1` must not
/// hit inside `5x10`, while `5 concurrently` and `5 adversarial agents` must
/// still hit the word-final markers.
fn is_bounded_hit(text: &str, at: usize, marker: &str) -> bool {
    let bytes = text.as_bytes();
    let before_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
    let after_ok = !ends_in_digit(marker)
        || bytes
            .get(at + marker.len())
            .is_none_or(|b| !b.is_ascii_alphanumeric());
    before_ok && after_ok
}

/// True when the last byte of `marker` is an ASCII digit.
fn ends_in_digit(marker: &str) -> bool {
    marker.as_bytes().last().is_some_and(u8::is_ascii_digit)
}

/// Byte offset of the first HTML entity in `text`: `&`, then `#` or an ASCII
/// letter, then an alphanumeric run, then `;` (`&nbsp;`, `&emsp13;`, `&#53;`,
/// `&#x35;`).
fn find_html_entity(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().find_map(|(at, &b)| {
        if b != ENTITY_START {
            return None;
        }
        let tail = &bytes[at + 1..];
        let head = *tail.first()?;
        if head != NUMERIC_ENTITY_MARK && !head.is_ascii_alphabetic() {
            return None;
        }
        let run = tail[1..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        let numeric_ok = head != NUMERIC_ENTITY_MARK || run > 0;
        (numeric_ok && tail.get(1 + run) == Some(&ENTITY_END)).then_some(at)
    })
}

/// Byte offset of the first `<` that opens an HTML tag, closing tag or
/// comment or processing instruction: `<` followed by an ASCII letter or one
/// of [`TAG_FOLLOWERS`] (`/`, `!`, `?`).
fn find_html_tag(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().find_map(|(at, &b)| {
        let next = *bytes.get(at + 1)?;
        (b == TAG_START && (next.is_ascii_alphabetic() || TAG_FOLLOWERS.contains(&next)))
            .then_some(at)
    })
}

/// Nearest char boundary at or below `index`.
fn floor_boundary(text: &str, index: usize) -> usize {
    let mut at = index.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// Nearest char boundary at or above `index`.
fn ceil_boundary(text: &str, index: usize) -> usize {
    let mut at = index.min(text.len());
    while !text.is_char_boundary(at) {
        at += 1;
    }
    at
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
/// section; every panic names the byte offset into the section.
fn assert_clean_characters(label: &str, section: &str) {
    for (at, c) in section.char_indices() {
        let window = || context_around(section, at, c.len_utf8());
        assert!(
            c.is_ascii() || ALLOWED_NON_ASCII.contains(&c),
            "{label}: non-allowlisted U+{:04X} at byte {at} \
             (extend ALLOWED_NON_ASCII to admit it): ...{}...",
            u32::from(c),
            window()
        );
        assert!(
            !(c.is_ascii_control() && c != '\n'),
            "{label}: ASCII control U+{:04X} at byte {at}: ...{}...",
            u32::from(c),
            window()
        );
        assert!(
            !FORBIDDEN_ASCII.contains(&c),
            "{label}: forbidden character {c:?} at byte {at}: ...{}...",
            window()
        );
    }
    if let Some(at) = section.find(HTML_COMMENT_OPEN) {
        panic!(
            "{label}: HTML comment at byte {at}: ...{}...",
            context_around(section, at, HTML_COMMENT_OPEN.len())
        );
    }
    if let Some(at) = find_html_tag(section) {
        panic!(
            "{label}: HTML tag at byte {at}: ...{}...",
            context_around(section, at, TAG_CONTEXT_LEN)
        );
    }
    if let Some(at) = find_html_entity(section) {
        panic!(
            "{label}: HTML entity at byte {at}: ...{}...",
            context_around(section, at, ENTITY_CONTEXT_LEN)
        );
    }
}

/// Every semantic check on one copy of the section; `label` names which copy
/// (the live `CLAUDE.md` section or the fixture) in each panic.
fn check_section(label: &str, section: &str) {
    let heading = section.lines().next().unwrap_or_default();
    for marker in [SHAPE_1X3, AUDIT_CITATION] {
        assert!(
            section.contains(marker),
            "{label}: crossroads section must contain `{marker}`"
        );
    }
    assert!(
        heading.contains(THRESHOLD_PHRASE),
        "{label}: crossroads heading must contain `{THRESHOLD_PHRASE}`: {heading}"
    );
    for condition in CONDITIONS {
        assert!(
            section.contains(condition),
            "{label}: crossroads section must list trigger condition `{condition}`"
        );
    }
    assert_clean_characters(label, section);
    let normalised = normalised_for_marker_scan(section);
    assert!(
        normalised.contains(SHAPE_SENTENCE),
        "{label}: crossroads section must state `{SHAPE_SENTENCE}`"
    );
    for marker in SUPERSEDED_MARKERS {
        for (at, _) in normalised.match_indices(marker) {
            assert!(
                !is_bounded_hit(&normalised, at, marker),
                "{label}: crossroads section prescribes superseded `{marker}`: ...{}...",
                context_around(&normalised, at, marker.len())
            );
        }
    }
}

/// Byte offset of the first difference between `actual` and `expected`.
fn first_difference(actual: &str, expected: &str) -> Option<usize> {
    let shared = actual
        .bytes()
        .zip(expected.bytes())
        .position(|(a, e)| a != e);
    shared.or_else(|| (actual.len() != expected.len()).then(|| actual.len().min(expected.len())))
}

/// Bounded, char-boundary-clamped excerpt of `text` around byte `at`.
fn diff_excerpt(text: &str, at: usize) -> &str {
    let start = floor_boundary(text, at.saturating_sub(DIFF_EXCERPT_WIDTH));
    let end = ceil_boundary(text, at.saturating_add(DIFF_EXCERPT_WIDTH));
    &text[start..end]
}

/// Panics with offset, line and excerpts when the live section differs from
/// the fixture.
fn assert_matches_fixture(actual: &str, expected: &str) {
    let Some(at) = first_difference(actual, expected) else {
        return;
    };
    let line = 1 + actual[..floor_boundary(actual, at)].matches('\n').count();
    panic!(
        "first differing byte {at} (line {line} of the section) against {FIXTURE_PATH}:\n\
         live    : {:?}\nfixture : {:?}\n{CHANGED_SENTENCE}",
        diff_excerpt(actual, at),
        diff_excerpt(expected, at)
    );
}

#[test]
fn crossroads_section_prescribes_the_1x3_vote_8604() {
    let text = claude_md();
    let section = crossroads_section(&text);
    assert_matches_fixture(section, FIXTURE);
    check_section(LABEL_FIXTURE, FIXTURE);
    check_section(LABEL_LIVE, section);
}

/// Text with `prefix` placed before the fixture section (which starts at its
/// heading) and `suffix` after it.
fn wrapped_fixture(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{FIXTURE}{suffix}")
}

const FENCE_LINE: &str = "```\n";
const NEXT_SECTION_LINE: &str = "\n## Next section\n";

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn heading_after_unclosed_fence_fails_closed_8604() {
    let text = wrapped_fixture(&format!("intro\n{FENCE_LINE}"), "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn heading_in_fence_closed_after_next_heading_fails_closed_8604() {
    let text = wrapped_fixture(
        &format!("intro\n{FENCE_LINE}"),
        &format!("{NEXT_SECTION_LINE}{FENCE_LINE}"),
    );
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn heading_after_unclosed_tilde_fence_fails_closed_8604() {
    let text = wrapped_fixture("intro\n~~~~\n", "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open HTML comment")]
fn heading_in_html_comment_opened_on_previous_line_fails_closed_8604() {
    let text = wrapped_fixture("intro\n<!-- hidden\n", &format!("{NEXT_SECTION_LINE}-->\n"));
    let _ = crossroads_section(&text);
}

#[test]
fn closed_fence_and_closed_comment_before_heading_still_pass_8604() {
    let prefix = format!("intro\n{FENCE_LINE}code\n{FENCE_LINE}<!-- note -->\n<!-- a\nb -->\n");
    let text = wrapped_fixture(&prefix, "");
    assert_eq!(crossroads_section(&text), FIXTURE);
}

#[test]
fn comment_marker_inside_earlier_fence_does_not_count_8604() {
    let prefix = format!("{FENCE_LINE}<!-- literal\n{FENCE_LINE}");
    let text = wrapped_fixture(&prefix, "");
    assert_eq!(crossroads_section(&text), FIXTURE);
}

#[test]
fn crlf_before_heading_still_passes_8604() {
    let text = wrapped_fixture("intro\r\n", "");
    assert_eq!(crossroads_section(&text), FIXTURE);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn backtick_info_string_with_backtick_is_not_a_fence_opener_8604() {
    // CommonMark 4.5: "``` a`b" is paragraph text, so the next bare fence
    // line opens a real fence that holds the heading.
    let text = wrapped_fixture("intro\n``` a`b\n```\n", "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn closer_followed_by_no_break_space_does_not_close_8604() {
    let text = wrapped_fixture("```\ncode\n```\u{00A0}\n", "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn closer_followed_by_ideographic_space_does_not_close_8604() {
    let text = wrapped_fixture("```\ncode\n```\u{3000}\n", "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn closer_followed_by_form_feed_does_not_close_8604() {
    let text = wrapped_fixture("```\ncode\n```\u{000C}\n", "");
    let _ = crossroads_section(&text);
}

#[test]
#[should_panic(expected = "inside an open fenced code block")]
fn fence_opener_line_interrupts_an_open_inline_comment_8604() {
    // "<!--" mid-line, then a fence opener line, then "-->": the fence
    // interrupts the paragraph, so the heading sits inside the fence.
    let text = wrapped_fixture(
        &format!("intro <!-- x\n{FENCE_LINE}-->\n"),
        &format!("{NEXT_SECTION_LINE}{FENCE_LINE}"),
    );
    let _ = crossroads_section(&text);
}

#[test]
fn inline_code_span_line_does_not_open_a_fence_8604() {
    let text = wrapped_fixture("intro\n```code```\n", "");
    assert_eq!(crossroads_section(&text), FIXTURE);
}

#[test]
fn closer_followed_by_tab_still_closes_8604() {
    let text = wrapped_fixture("```\ncode\n```\t\n", "");
    assert_eq!(crossroads_section(&text), FIXTURE);
}
