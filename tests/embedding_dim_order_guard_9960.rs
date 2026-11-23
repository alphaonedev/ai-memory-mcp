// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9960 source guard: the destructive embedding-dim conversion has exactly
//! the callers, order builders and intent constructors written out below,
//! over the WHOLE tracked tree.
//!
//! The conversion needs a `ForceReembedOrder` (#9952), which only the argv
//! parser builds. This guard pins every site that names the order type, its
//! constructor, the argv accessor, the conversion, the intent enum or its
//! module, and every `Explicit` variant use in a file that names the enum or
//! its module. A new caller in another file, another call form
//! (`.map(EmbeddingDimIntent::Explicit)`), an alias
//! (`use ...::EmbeddingDimIntent as E; E::Explicit`) or a constant built from
//! the order constructor changes a count and turns this test red.
//!
//! Scope: every path `git ls-files` prints. Comments and string literals are
//! blanked first (`common/token_scan.rs`), so only code counts. Left out, with
//! the reason each time:
//! - every tracked path that does not end in `.rs`: rustc compiles only `.rs`
//!   files in this crate, and [`every_include_target_is_rust_source`] proves
//!   no `include!` pulls in a file of another kind;
//! - `Explicit` in a file that names neither the enum nor its module: such a
//!   file cannot reach the variant without one of those two names, unless an
//!   alias of the enum is made in another file, and that alias adds an enum
//!   count to the file that makes it.
//!
//! A tracked path that is a symlink, not a regular file or not UTF-8 fails the
//! guard; a failed `git ls-files` fails it too (never an empty scan).

#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "common/token_scan.rs"]
mod token_scan;
use token_scan::{ident_offsets, mask};

/// The guarded identifiers, in table column order.
const GUARDED: [&str; 6] = [
    "EmbeddingDimIntent",
    "embedding_dim_policy",
    "ForceReembedOrder",
    "from_argv",
    "force_reembed_order",
    "migrate_embedding_dim_for",
];
/// The variant counted only in files that name the enum or its module.
const VARIANT: &str = "Explicit";
/// The columns of [`GUARDED`] that make a file's `Explicit` uses count.
const ENUM_COLUMNS: [usize; 2] = [0, 1];
/// The only kind of tracked file rustc compiles here.
const RUST_EXT: &str = ".rs";
/// The `include!` marker in raw source.
const INCLUDE_IDENT: &str = "include";
/// What follows the macro name of an invocation.
const MACRO_OPEN: &str = "!(";
/// The end of a literal `include!("...")` argument.
const LITERAL_CLOSE: &str = "\")";

/// One allowlist row: a tracked path and its code counts of
/// `[EmbeddingDimIntent, embedding_dim_policy, ForceReembedOrder, from_argv,
///   force_reembed_order, migrate_embedding_dim_for, Explicit]`.
struct Row(&'static str, [usize; 7]);

/// Every file with a non-zero count, written out by hand. A file not listed
/// here must count zero in every column.
const ALLOWED: &[Row] = &[
    // The argv parser: the only production builder of the order (from both
    // flags) and of the Explicit intent; one conversion call in `run`, two in
    // its lib tests.
    Row("src/cli/schema_init.rs", [14, 2, 5, 3, 2, 3, 5]),
    // Boot: Configured/Defaulted intents only, no order, no conversion call.
    Row("src/daemon_runtime.rs", [3, 4, 0, 0, 0, 0, 0]),
    Row("src/daemon_runtime_1579_tests.rs", [1, 1, 0, 0, 0, 0, 0]),
    // The policy: defines the enum, the order and its argv-only constructor.
    Row("src/store/embedding_dim_policy.rs", [17, 0, 5, 1, 0, 0, 5]),
    Row(
        "src/store/embedding_dim_policy_tests.rs",
        [6, 0, 5, 2, 0, 0, 32],
    ),
    // Declares the policy module.
    Row("src/store/mod.rs", [0, 1, 0, 0, 0, 0, 0]),
    // The conversion's definition and the boot funnel's order-less call.
    Row("src/store/postgres.rs", [3, 2, 2, 0, 0, 2, 0]),
    // Integration tests that drive the conversion through the argv order.
    Row("tests/embedding_dim_migration.rs", [12, 1, 1, 0, 1, 3, 3]),
    Row("tests/embedding_dim_no_null_9933.rs", [5, 0, 0, 0, 0, 0, 0]),
    Row("tests/embedding_dim_no_null_9952.rs", [8, 0, 0, 0, 0, 0, 0]),
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked path, from `git ls-files -z`; panics (fails the guard) when
/// git fails or prints nothing.
fn tracked_paths(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .expect("#9960 guard: git ls-files must run");
    assert!(
        out.status.success(),
        "#9960 guard: git ls-files exited {:?}",
        out.status.code()
    );
    let paths: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8(p.to_vec()).expect("#9960 guard: a tracked path is not UTF-8"))
        .collect();
    assert!(
        !paths.is_empty(),
        "#9960 guard: git ls-files printed no path"
    );
    paths
}

/// The source of a tracked `.rs` path; a symlink or non-regular file fails.
fn read_rust(root: &Path, rel: &str) -> String {
    let p = root.join(rel);
    let meta = std::fs::symlink_metadata(&p)
        .unwrap_or_else(|e| panic!("#9960 guard: cannot stat {rel}: {e}"));
    assert!(
        meta.file_type().is_file(),
        "#9960 guard: {rel} is not a regular file"
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("#9960 guard: cannot read {rel}: {e}"))
}

/// The seven counts of one file's masked code.
fn counts(src: &str) -> [usize; 7] {
    let masked = mask(src);
    let mut c = [0usize; 7];
    for (i, ident) in GUARDED.iter().enumerate() {
        c[i] = ident_offsets(&masked, ident).len();
    }
    if ENUM_COLUMNS.iter().any(|&i| c[i] > 0) {
        c[6] = ident_offsets(&masked, VARIANT).len();
    }
    c
}

fn rust_paths(root: &Path) -> Vec<String> {
    tracked_paths(root)
        .into_iter()
        .filter(|p| {
            Path::new(p)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(&RUST_EXT[1..]))
        })
        .collect()
}

#[test]
fn conversion_order_and_intent_sites_match_the_allowlist_9960() {
    let root = manifest_dir();
    let paths = rust_paths(&root);
    assert!(
        paths.len() > 100,
        "#9960 guard: only {} tracked .rs files",
        paths.len()
    );
    let mut actual: BTreeMap<String, [usize; 7]> = BTreeMap::new();
    for rel in &paths {
        let src = read_rust(&root, rel);
        let c = counts(&src);
        if c.iter().any(|&n| n > 0) {
            actual.insert(rel.clone(), c);
        }
    }
    let expected: BTreeMap<String, [usize; 7]> = ALLOWED
        .iter()
        .map(|Row(p, c)| ((*p).to_string(), *c))
        .collect();
    assert_eq!(
        expected.len(),
        ALLOWED.len(),
        "#9960 guard: a path is listed twice in ALLOWED"
    );
    if actual != expected {
        let mut lines: Vec<String> = Vec::new();
        for (p, c) in &actual {
            if expected.get(p) != Some(c) {
                lines.push(format!(
                    "  found    {p} {c:?} allowed {:?}",
                    expected.get(p)
                ));
            }
        }
        for (p, c) in &expected {
            if !actual.contains_key(p) {
                lines.push(format!("  missing  {p} allowed {c:?} found none"));
            }
        }
        let report = lines.join("\n");
        panic!(
            "#9960 guard: the embedding-dim conversion, order or intent sites differ from \
             the allowlist (columns {GUARDED:?} + {VARIANT}):\n{report}"
        );
    }
}

/// The target of every `include!` in CODE (comments and strings masked):
/// `Some(path)` for a literal `include!("path")`, `None` for any other
/// argument form (`concat!`, `env!`, a macro), which the guard refuses.
fn include_targets(src: &str) -> Vec<Option<String>> {
    let masked = mask(src);
    assert_eq!(
        masked.chars().count(),
        src.chars().count(),
        "#9960 guard: the masker must keep one char per source char"
    );
    let raw_at: Vec<usize> = src.char_indices().map(|(b, _)| b).collect();
    let mut out = Vec::new();
    for off in ident_offsets(&masked, INCLUDE_IDENT) {
        let after = &masked[off + INCLUDE_IDENT.len()..];
        if !after.starts_with(MACRO_OPEN) {
            continue;
        }
        let char_idx = masked[..off].chars().count();
        let raw = &src[raw_at[char_idx] + INCLUDE_IDENT.len() + MACRO_OPEN.len()..];
        out.push(
            raw.strip_prefix('"')
                .and_then(|r| r.split_once(LITERAL_CLOSE))
                .map(|(target, _)| target.to_string()),
        );
    }
    out
}

#[test]
fn every_include_target_is_rust_source() {
    let root = manifest_dir();
    let mut bad = Vec::new();
    for rel in rust_paths(&root) {
        let src = read_rust(&root, &rel);
        bad.extend(include_targets(&src).into_iter().filter_map(|t| match t {
            Some(target) if target.ends_with(RUST_EXT) => None,
            Some(target) => Some(format!("{rel}: include!(\"{target}\")")),
            None => Some(format!("{rel}: include! of a non-literal path")),
        }));
    }
    assert!(
        bad.is_empty(),
        "#9960 guard: an include! pulls a non-.rs file into the crate, so the \
         .rs-only scan would miss it: {bad:?}"
    );
}

#[test]
fn counts_see_code_not_comments_or_strings_9960() {
    let src = "// EmbeddingDimIntent::Explicit\nconst S: &str = \"ForceReembedOrder::from_argv\";\n\
               use crate::store::embedding_dim_policy::EmbeddingDimIntent as E;\nfn f() { E::Explicit(1); }\n";
    assert_eq!(counts(src), [1, 1, 0, 0, 0, 0, 1]);
    // An Explicit in a file that names neither the enum nor its module is not counted.
    assert_eq!(counts("enum M { Explicit }\n"), [0; 7]);
}

#[test]
fn include_targets_read_code_only_and_refuse_non_literals_9960() {
    let src = "include!(\"a.rs\");\n// include!(\"b.txt\")\nconst S: &str = \"include!(\\\"c.in\\\")\";\n\
               include!(\"d.in\");\ninclude!(concat!(env!(\"OUT_DIR\"), \"/e.rs\"));\nlet include = 1;\n";
    assert_eq!(
        include_targets(src),
        vec![Some("a.rs".to_string()), Some("d.in".to_string()), None]
    );
}
