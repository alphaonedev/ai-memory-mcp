// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #6127 — the amendment ledger of the enterprise-federation certification is
//! append-only (#6423). The 2026-10-08 record (#6116) calls both #4507
//! citation retargets doc-comment edits, which misstates one of them. The
//! record stays byte-for-byte as written, and a NEW dated correction record
//! (2026-10-10, #6127) names each edit by the comment kind its line actually
//! carries: the `src/federation/mod.rs` retarget is a `///` doc comment, the
//! `src/handlers/federation_receive.rs` retarget is a plain `//` comment.
//!
//! Every input is read by path at runtime. A missing file, line or heading
//! fails an assertion (fail closed): a read error yields an empty string, and
//! every lookup on an empty string asserts.

use std::fs;
use std::path::Path;

const CERT_DOC: &str = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md";
const FEDERATION_MOD_RS: &str = "src/federation/mod.rs";
const RECEIVE_RS: &str = "src/handlers/federation_receive.rs";
/// Heading of the 2026-10-08 (#6116) record, which must not change.
const OLD_HEAD: &str = "**Amendment (2026-10-08, #6116";
/// Heading of the 2026-10-10 correction record this fix appends.
const NEW_HEAD: &str = "**Amendment (2026-10-10, #6127";
/// The 2026-10-08 record exactly as it stood at `6025dd3cd` (before #6127), `> ` prefixes included.
const OLD_RECORD: &str = r"> **Amendment (2026-10-08, #6116 - second §7 record for the #4507 doc-comment retargets).**
> Two §7-watched federation-wire files changed again after the 2026-10-07
> expiry record above, through the #4507 citation-retarget chain
> (`6c6634d66`, `015b44777`, `2a18bffe2`, merged at `cd3cb6140`):
> `src/federation/mod.rs` and `src/handlers/federation_receive.rs`, +1/-1
> lines each. Both edits are Rust doc-comment path retargets only; no code,
> no `AI_MEMORY_FED_*` identifier and no wire behaviour changed. This record
> does **not** re-measure anything and does **not** re-bind. The certification
> stays EXPIRED, and the re-measurement and re-issue stay under WP-B1
> ([#6063](https://github.com/alphaonedev/ai-memory-mcp/issues/6063)); re-binding
> without that re-measurement is forbidden (#3899).";
/// The #4507 retarget (`015b44777`) rewrote this line in `RECEIVE_RS`.
const RETARGETED_LINE: &str = "Reject anything that fails the agent_id shape per";
/// The #4507 retarget (`6c6634d66`, `2a18bffe2`) rewrote this line in `FEDERATION_MOD_RS`.
const MOD_RETARGETED_LINE: &str =
    "The contract is documented in `docs/reference/ARCHITECTURE_REFERENCE.md`";
/// The per-file phrases the correction must state, exactly as the doc words them.
const MOD_PHRASE: &str = "a `///` doc comment in `src/federation/mod.rs`";
const RECEIVE_PHRASE: &str = "a plain `//` comment in `src/handlers/federation_receive.rs`";

/// File text, or an empty string when unreadable; every consumer asserts on content.
fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(path).unwrap_or_default()
}

/// The paragraph that opens at `head`: its heading line to the next bare `>` line,
/// quote markers removed and lines joined by one space. `None` when `head` is absent.
fn paragraph(doc: &str, head: &str) -> Option<String> {
    let start = doc.find(head)?;
    Some(
        doc[start..]
            .lines()
            .take_while(|line| line.trim() != ">")
            .map(|line| line.strip_prefix("> ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// The correction record's text, asserting that the record exists exactly once.
fn correction(doc: &str) -> String {
    assert_eq!(
        doc.matches(NEW_HEAD).count(),
        1,
        "#6127: exactly one 2026-10-10 correction record is present in {CERT_DOC}"
    );
    paragraph(doc, NEW_HEAD).unwrap_or_default()
}

/// Lower-cased text with every Unicode dash read as `-` and whitespace folded around
/// each hyphen, so "doc-" ending a line, a U+2010 hyphen or a no-break space cannot
/// hide a spelling.
fn folded(text: &str) -> String {
    let dashed: String = text
        .chars()
        .map(|c| match c {
            '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE58}' | '\u{FE63}' | '\u{FF0D}' => '-',
            other => other,
        })
        .collect();
    dashed
        .to_lowercase()
        .split('-')
        .map(|part| part.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("-")
}

#[test]
fn the_receive_rs_retarget_is_a_plain_comment_6127() {
    let source = read(RECEIVE_RS);
    let line = source
        .lines()
        .find(|line| line.contains(RETARGETED_LINE))
        .unwrap_or("");
    let trimmed = line.trim_start();
    assert!(
        !trimmed.is_empty(),
        "#6127: the #4507 retargeted line is present in {RECEIVE_RS}"
    );
    assert!(
        trimmed.starts_with("// ") && !trimmed.starts_with("///") && !trimmed.starts_with("//!"),
        "#6127: the premise holds — the retargeted line is a plain `//` comment: {trimmed}"
    );
}

#[test]
fn the_mod_rs_retarget_is_a_doc_comment_6127() {
    let source = read(FEDERATION_MOD_RS);
    let line = source
        .lines()
        .find(|line| line.contains(MOD_RETARGETED_LINE))
        .unwrap_or("");
    assert!(
        !line.is_empty(),
        "#6127: the #4507 retargeted line is present in {FEDERATION_MOD_RS}"
    );
    // `////` is a plain comment in Rust, so a doc comment starts with exactly three slashes.
    let trimmed = line.trim_start();
    assert!(
        trimmed.starts_with("///") && !trimmed.starts_with("////"),
        "#6127: the premise holds — the retargeted line is a `///` doc comment: {line}"
    );
}

#[test]
fn the_2026_10_08_record_is_byte_identical_6127() {
    let doc = read(CERT_DOC);
    assert_eq!(
        doc.matches(OLD_HEAD).count(),
        1,
        "#6127: the 2026-10-08 (#6116) record is present once in {CERT_DOC}"
    );
    assert!(
        doc.contains(OLD_RECORD),
        "#6127: the amendment ledger is append-only (#6423): the 2026-10-08 (#6116) record \
         must stay byte-for-byte as it was at 6025dd3cd; fix a mistake with a new dated record"
    );
}

#[test]
fn the_correction_record_follows_the_2026_10_08_record_6127() {
    let doc = read(CERT_DOC);
    let text = correction(&doc);
    let old_end = doc
        .find(OLD_RECORD)
        .map_or(usize::MAX, |at| at + OLD_RECORD.len());
    let new_at = doc.find(NEW_HEAD).unwrap_or(0);
    assert!(
        new_at >= old_end,
        "#6127: the correction record is appended after the 2026-10-08 record, not merged into it"
    );
    for cite in ["#6127", "#6116", "2026-10-08"] {
        assert!(
            text.contains(cite),
            "#6127: the correction record cites `{cite}`: {text}"
        );
    }
}

#[test]
fn the_correction_names_each_files_comment_kind_6127() {
    let text = correction(&read(CERT_DOC));
    for phrase in [MOD_PHRASE, RECEIVE_PHRASE] {
        assert!(
            text.contains(phrase),
            "#6127: the correction states `{phrase}`: {text}"
        );
    }
    assert!(
        text.contains("comment-only"),
        "#6127: the correction records the edits as comment-only: {text}"
    );
}

#[test]
fn the_correction_does_not_call_both_retargets_doc_comments_6127() {
    let text = folded(&correction(&read(CERT_DOC)));
    for wrong in ["doc-comment retargets", "doc-comment path retargets"] {
        assert!(
            !text.contains(wrong),
            "#6127: the correction calls both #4507 edits `{wrong}`: {text}"
        );
    }
}

#[test]
fn doc_comment_appears_only_for_the_mod_rs_retarget_6127() {
    let text = correction(&read(CERT_DOC));
    let rest = text.replace(MOD_PHRASE, "");
    // Every Rust doc-comment sigil: only the mod.rs phrase may carry `///`.
    for sigil in ["///", "//!", "/**", "/*!"] {
        assert!(
            !rest.contains(sigil),
            "#6127: the `{sigil}` sigil appears outside the {FEDERATION_MOD_RS} phrase: {text}"
        );
    }
    let rest = folded(&rest);
    for spelling in [
        "doc-comment",
        "doc comment",
        "documentation comment",
        "documentation-comment",
        "inner doc",
    ] {
        assert!(
            !rest.contains(spelling),
            "#6127: `{spelling}` appears outside the {FEDERATION_MOD_RS} phrase: {text}"
        );
    }
}

#[test]
fn the_correction_record_stays_in_the_ledger_grammar_6127() {
    let text = correction(&read(CERT_DOC));
    // No zero-width, bidi or lookalike character; nothing that opens a fence, HTML or a comment.
    assert!(
        text.is_ascii(),
        "#6127: the correction record is plain ASCII: {text}"
    );
    for banned in ["```", "~~~", "<", "-->", "\r"] {
        assert!(
            !text.contains(banned),
            "#6127: the correction record carries no `{banned}`: {text}"
        );
    }
}
