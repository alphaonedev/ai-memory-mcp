// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G7 (#1824) — the contradiction-CONSERVE STATIC GUARD.
//!
//! G7 replaces the hard-delete of the losing contradiction memory with a
//! non-destructive CONSERVE branch. This source-static test pins the two
//! load-bearing invariants of that change so a later edit cannot silently
//! regress it:
//!
//!   * P1 — NEITHER `autonomy::forget_if_superseded` NOR
//!     `storage::conserve_contradiction` may contain a `delete(` /
//!     `db::delete(` call (a physical delete of a memory row). CONSERVE
//!     retains BOTH memories; a delete anywhere in those bodies would
//!     falsify the design.
//!   * P2 — every `RecordKind::` the conserve path emits stays within the
//!     shipped 7-kind vocabulary (G7 introduces NO new `RecordKind`), and
//!     the conserve leaf is a `Supersede`.
//!
//! This guard is a sibling of `append_only_spine_guard_g6.rs`, which is
//! left untouched.

use std::path::{Path, PathBuf};

/// The shipped 7-kind revision vocabulary (mirrors
/// `revisions::RecordKind::ALL`). G7 adds none.
const SHIPPED_RECORD_KINDS: [&str; 7] = [
    "Supersede",
    "Tombstone",
    "Forget",
    "Archive",
    "Expire",
    "Evict",
    "Consolidate",
];

/// Repository root — the crate manifest dir at test-compile time.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip Rust line comments (`//...`) and single-line block comments
/// (`/* ... */`), preserving line structure. Copied from the G6 guard so
/// the two guards stay independent (an integration test links the crate as
/// an external library and cannot reach `#[cfg(test)]`-private helpers).
fn strip_rust_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let line_no_line_comment = match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        };
        let mut buf = String::from(line_no_line_comment);
        while let (Some(start), Some(end_rel)) = (buf.find("/*"), buf.find("*/").map(|i| i + 2)) {
            if end_rel <= start {
                break;
            }
            buf.replace_range(start..end_rel, "");
        }
        out.push_str(&buf);
        out.push('\n');
    }
    out
}

/// Does the line look like a Rust `fn NAME(` declaration for `name`?
fn is_fn_decl_for(line: &str, name: &str) -> bool {
    let needle = format!("fn {name}(");
    let Some(idx) = line.find(&needle) else {
        return false;
    };
    // Word boundary before `fn`.
    idx == 0 || line.as_bytes()[idx - 1].is_ascii_whitespace()
}

/// Return the comment-stripped body span of the first `fn NAME` in
/// `stripped`, brace-counted from its declaration to the matching close.
/// Panics if the function is not found — the guard's whole point is that
/// these two functions exist and behave.
fn fn_body(stripped: &str, name: &str) -> String {
    let lines: Vec<&str> = stripped.lines().collect();
    let start = lines
        .iter()
        .position(|l| is_fn_decl_for(l, name))
        .unwrap_or_else(|| panic!("guard could not locate `fn {name}`"));

    let mut depth: i32 = 0;
    let mut opened = false;
    let mut end = lines.len() - 1;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                opened = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            end = i;
            break;
        }
    }
    lines[start..=end].join("\n")
}

/// Every `RecordKind::<Ident>` identifier referenced in `body`.
fn record_kinds_in(body: &str) -> Vec<String> {
    const MARKER: &str = "RecordKind::";
    let mut kinds = Vec::new();
    let mut from = 0;
    while let Some(rel) = body[from..].find(MARKER) {
        let idx = from + rel + MARKER.len();
        from = idx;
        let ident: String = body[idx..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            kinds.push(ident);
        }
    }
    kinds
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("guard could not read {}: {e}", path.display()))
}

#[test]
fn conserve_path_never_deletes_a_memory() {
    let root = repo_root();
    let autonomy = strip_rust_comments(&read(&root.join("src/autonomy.rs")));
    let storage = strip_rust_comments(&read(&root.join("src/storage/mod.rs")));

    let forget_body = fn_body(&autonomy, "forget_if_superseded");
    let conserve_body = fn_body(&storage, "conserve_contradiction");

    // P1 — no physical memory delete in either body.
    for (name, body) in [
        ("forget_if_superseded", &forget_body),
        ("conserve_contradiction", &conserve_body),
    ] {
        assert!(
            !body.contains("db::delete("),
            "G7 invariant violated: `{name}` contains a `db::delete(` call — CONSERVE must retain both memories"
        );
        assert!(
            !body.contains("delete("),
            "G7 invariant violated: `{name}` contains a `delete(` call — CONSERVE must retain both memories"
        );
    }
}

#[test]
fn conserve_leaf_kind_stays_within_shipped_vocab() {
    let root = repo_root();
    let storage = strip_rust_comments(&read(&root.join("src/storage/mod.rs")));
    let conserve_body = fn_body(&storage, "conserve_contradiction");

    // P2 — every RecordKind referenced is one of the shipped seven, and the
    // conserve leaf is a Supersede.
    let kinds = record_kinds_in(&conserve_body);
    assert!(
        !kinds.is_empty(),
        "guard expected `conserve_contradiction` to emit a RecordKind leaf"
    );
    for kind in &kinds {
        assert!(
            SHIPPED_RECORD_KINDS.contains(&kind.as_str()),
            "G7 invariant violated: `conserve_contradiction` references RecordKind::{kind} \
             outside the shipped 7-kind vocabulary {SHIPPED_RECORD_KINDS:?}"
        );
    }
    assert!(
        kinds.iter().any(|k| k == "Supersede"),
        "G7 invariant violated: `conserve_contradiction` must emit a SUPERSEDE leaf"
    );
}
