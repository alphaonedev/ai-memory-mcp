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
const FEDERATION_MOD_RS: &str = "src/federation/mod.rs";
const RECEIVE_RS: &str = "src/handlers/federation_receive.rs";
const AMENDMENT_HEAD: &str = "**Amendment (2026-10-08, #6116";
/// The #4507 retarget (`015b44777`) rewrote this line in `RECEIVE_RS`.
const RETARGETED_LINE: &str = "Reject anything that fails the agent_id shape per";
/// The #4507 retarget (`6c6634d66`, `2a18bffe2`) rewrote this line in `FEDERATION_MOD_RS`.
const MOD_RETARGETED_LINE: &str =
    "The contract is documented in `docs/reference/ARCHITECTURE_REFERENCE.md`";
/// The per-file phrases the amendment must state, exactly as the doc words them.
const MOD_PHRASE: &str = "a `///` doc comment in `src/federation/mod.rs`";
const RECEIVE_PHRASE: &str = "a plain `//` comment in `src/handlers/federation_receive.rs`";

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
        .map(|line| line.strip_prefix("> ").unwrap_or(line))
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
fn the_mod_rs_retarget_is_a_doc_comment_6127() {
    let source = read(FEDERATION_MOD_RS);
    let line = source
        .lines()
        .find(|line| line.contains(MOD_RETARGETED_LINE))
        .unwrap_or_else(|| {
            panic!("#6127: the #4507 retargeted line is present in {FEDERATION_MOD_RS}")
        });
    assert!(
        line.trim_start().starts_with("///"),
        "#6127: the premise holds — the retargeted line is a `///` doc comment: {line}"
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

#[test]
fn the_amendment_names_each_files_comment_kind_6127() {
    let text = amendment(&read(CERT_DOC));
    for phrase in [MOD_PHRASE, RECEIVE_PHRASE] {
        assert!(
            text.contains(phrase),
            "#6127: the amendment states `{phrase}`: {text}"
        );
    }
}

#[test]
fn doc_comment_appears_only_for_the_mod_rs_retarget_6127() {
    let text = amendment(&read(CERT_DOC));
    let rest = text.replace(MOD_PHRASE, "");
    for spelling in ["doc-comment", "doc comment"] {
        assert!(
            !rest.to_lowercase().contains(spelling),
            "#6127: `{spelling}` appears outside the {FEDERATION_MOD_RS} phrase: {text}"
        );
    }
}
