// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #6127 — the 2026-10-08 certification amendment (#6116) records the two
//! #4507 citation retargets of §7-watched files. It must describe each edit
//! by the comment kind the edited line actually carries: the
//! `src/federation/mod.rs` retarget is a `///` doc comment, but the
//! `src/handlers/federation_receive.rs` retarget is a plain `//` comment, so
//! calling both "doc-comment" retargets misstates the record.

use std::fs;
use std::path::Path;

const CERT_DOC: &str = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md";
const RECEIVE_RS: &str = "src/handlers/federation_receive.rs";
const AMENDMENT_HEAD: &str = "**Amendment (2026-10-08, #6116";
/// The #4507 retarget (`015b44777`) rewrote this line in `RECEIVE_RS`.
const RETARGETED_LINE: &str = "Reject anything that fails the agent_id shape per";

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The amendment paragraph: from its heading to the next blank quote line.
fn amendment(doc: &str) -> String {
    let start = doc
        .find(AMENDMENT_HEAD)
        .unwrap_or_else(|| panic!("#6127: the #6116 amendment is present in {CERT_DOC}"));
    doc[start..]
        .lines()
        .take_while(|line| line.trim() != ">")
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_receive_rs_retarget_is_a_plain_comment_6127() {
    let source = read(RECEIVE_RS);
    let line = source
        .lines()
        .find(|line| line.contains(RETARGETED_LINE))
        .unwrap_or_else(|| panic!("#6127: the #4507 retargeted line is present in {RECEIVE_RS}"));
    let trimmed = line.trim_start();
    assert!(
        trimmed.starts_with("// ") && !trimmed.starts_with("///"),
        "#6127: the premise holds — the retargeted line is a plain `//` comment: {trimmed}"
    );
}

#[test]
fn the_amendment_does_not_call_both_retargets_doc_comments_6127() {
    let text = amendment(&read(CERT_DOC));
    for wrong in ["doc-comment retargets", "Rust doc-comment path retargets"] {
        assert!(
            !text.contains(wrong),
            "#6127: the amendment calls both #4507 edits `{wrong}`, but the \
             {RECEIVE_RS} edit is a plain `//` comment: {text}"
        );
    }
    assert!(
        text.contains("comment-only"),
        "#6127: the amendment records the edits as comment-only: {text}"
    );
}
