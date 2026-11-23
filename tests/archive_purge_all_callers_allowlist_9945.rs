// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9945 / #10009 — source ratchet: the store-wide purge-all primitive is
//! named only at the sites listed here, over the whole source tree.
//!
//! # Why
//!
//! `MemoryStore::archive_purge_all` deletes every archived row. Issue #9945
//! was an unset retention bound reaching that behaviour from the maintenance
//! loop; #10009 was that nothing turned red when the loop called the purge-all
//! primitive directly. The behaviour cells (`tests/archive_purge_unset_bound_9945.rs`)
//! pin the two loop ticks; this ratchet pins every OTHER site in the tree, so a
//! new caller anywhere (a second loop, a handler, a CLI verb, an example) fails
//! here before it can run.
//!
//! # The rule
//!
//! Every file under the repository root is read as bytes, whatever its
//! extension (an `include!` target need not end in `.rs`), and the identifier
//! is counted at identifier boundaries. Every form that reaches the method
//! names it: a method call, a UFCS call, a `use ... as` alias, a fn-pointer
//! binding, a raw identifier. The per-file counts must equal [`ALLOWED`]
//! exactly; every other file must count 0. A moved, added or removed site
//! changes a count and fails until the table is edited in the same commit.
//!
//! An identifier can also be synthesised by a macro that concatenates
//! fragments. In this tree the only proc-macro crate is the vendored `paste`
//! ([`PROC_MACRO_CRATES`]) and nothing outside its own directory invokes it
//! ([`paste_is_invoked_nowhere_outside_its_vendor_dir_9945`]); a new
//! proc-macro crate or a first `paste` invocation fails here and must be
//! reviewed against this rule. `macro_rules!` cannot join identifiers on
//! stable Rust.
//!
//! Left out, each with its reason, in [`SKIPPED_ROOT_ENTRIES`] and
//! [`SELF_PATH`].

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The guarded identifier.
const NAME: &str = "archive_purge_all";

/// This file: it names the identifier in its own tables and fixtures.
const SELF_PATH: &str = "tests/archive_purge_all_callers_allowlist_9945.rs";

/// Root entries that are not source, with the reason each is left out.
const SKIPPED_ROOT_ENTRIES: &[(&str, &str)] = &[
    (
        ".git",
        "git metadata (a worktree link file or the object store)",
    ),
    (
        ".local-runs",
        "gitignored local scratch (repository hard rule)",
    ),
    (".codegraph", "gitignored per-developer CodeGraph index"),
    ("target", "cargo build output"),
];

/// The floor of files scanned: the tree holds more than 4000 files and 1809
/// tracked `.rs` files, so a walk that drifted (a wrong root, a skip that
/// swallowed `src/`) fails instead of passing on an empty tree.
const MIN_FILES_SCANNED: usize = 1500;

/// Every permitted site: (path, exact token count, reason).
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "src/handlers/archive.rs",
        1,
        "the ONLY production caller: the admin HTTP purge with an explicit AllRows bound",
    ),
    (
        "src/store/mod.rs",
        4,
        "the trait method, its default body, two doc links and its refusal test",
    ),
    ("src/store/postgres.rs", 1, "the PostgresStore trait impl"),
    (
        "src/store/postgres/archive_purge_9945.rs",
        2,
        "module docs of the gated pg helper",
    ),
    (
        "src/store/sqlite.rs",
        4,
        "the SqliteStore trait impl, a doc link and its unit test",
    ),
    (
        "tests/archive_purge_unset_bound_9945.rs",
        2,
        "the explicit purge-all behaviour cell and its module doc",
    ),
    (
        "changelog.d/9945.fixed.md",
        1,
        "the changelog entry of #9945",
    ),
];

/// Every proc-macro crate in the tree: (Cargo.toml path, reason).
const PROC_MACRO_CRATES: &[(&str, &str)] = &[
    (
        "vendor/paste/Cargo.toml",
        "the vendored paste crate (#2050)",
    ),
    (
        "vendor/paste/tests/macros/Cargo.toml",
        "the vendored paste crate's own test fixture",
    ),
];

/// The vendored paste crate's directory: the only place it is invoked.
const PASTE_HOME: &str = "vendor/paste/";

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Count `needle` in `hay` at identifier boundaries. Linear in `hay`.
fn count_ident(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_ident_byte(hay[i - 1]);
            let end = i + needle.len();
            let after_ok = end == hay.len() || !is_ident_byte(hay[end]);
            if before_ok && after_ok {
                n += 1;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    n
}

/// A `paste` macro invocation or path: `paste!`, `paste ::`, `crate paste`.
fn invokes_paste(hay: &[u8]) -> bool {
    let needle = b"paste";
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle
            && (i == 0 || !is_ident_byte(hay[i - 1]))
            && hay.get(i + needle.len()).is_none_or(|b| !is_ident_byte(*b))
        {
            let rest = &hay[i + needle.len()..];
            let next = rest.iter().find(|b| !b.is_ascii_whitespace());
            if matches!(next, Some(b'!')) || rest.trim_ascii_start().starts_with(b"::") {
                return true;
            }
            let head = hay[..i].trim_ascii_end();
            if head.ends_with(b"crate") {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every regular file under the root (minus the skipped root entries), as
/// `/`-separated relative paths. A symlink fails the walk: following it could
/// loop or leave the tree, and skipping it could hide a site.
fn walk() -> Vec<(String, PathBuf)> {
    let base = root();
    let mut out = Vec::new();
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("dir entry in {}: {e}", dir.display()));
            let path = entry.path();
            let rel = path
                .strip_prefix(&base)
                .expect("walk stays under the root")
                .to_string_lossy()
                .replace('\\', "/");
            if dir == base && SKIPPED_ROOT_ENTRIES.iter().any(|(name, _)| *name == rel) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path)
                .unwrap_or_else(|e| panic!("lstat {}: {e}", path.display()));
            let kind = meta.file_type();
            assert!(
                !kind.is_symlink(),
                "{rel}: a symlink in the source tree; list it with a reason or remove it"
            );
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                out.push((rel, path));
            }
        }
    }
    out.sort();
    out
}

/// `relative path -> token count` for every file that names [`NAME`].
fn census() -> (BTreeMap<String, usize>, usize) {
    let files = walk();
    let mut hits = BTreeMap::new();
    for (rel, path) in &files {
        if rel == SELF_PATH {
            continue;
        }
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let n = count_ident(&bytes, NAME.as_bytes());
        if n > 0 {
            hits.insert(rel.clone(), n);
        }
    }
    (hits, files.len())
}

#[test]
fn purge_all_is_named_only_at_allowlisted_sites_9945() {
    let (hits, scanned) = census();
    assert!(
        scanned >= MIN_FILES_SCANNED,
        "scanned {scanned} files, floor {MIN_FILES_SCANNED}: the walk drifted"
    );
    let allowed: BTreeMap<String, usize> = ALLOWED
        .iter()
        .map(|(path, n, _)| ((*path).to_string(), *n))
        .collect();
    let mut problems = Vec::new();
    for (path, n) in &hits {
        match allowed.get(path) {
            None => problems.push(format!(
                "{path}: names `{NAME}` {n} time(s) and is not an allowlisted site"
            )),
            Some(want) if want != n => problems.push(format!(
                "{path}: names `{NAME}` {n} time(s), allowlisted {want}"
            )),
            Some(_) => {}
        }
    }
    for (path, want) in &allowed {
        if !hits.contains_key(path) {
            problems.push(format!(
                "{path}: allowlisted {want} site(s), found 0 (stale row: remove it)"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "#10009: the store-wide archive purge-all is reachable from a site \
         nobody reviewed:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn paste_is_invoked_nowhere_outside_its_vendor_dir_9945() {
    let mut proc_macro = Vec::new();
    let mut paste_users = Vec::new();
    for (rel, path) in walk() {
        if rel == SELF_PATH {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        if rel.ends_with("Cargo.toml") {
            let text = String::from_utf8_lossy(&bytes);
            if text
                .lines()
                .any(|l| l.split('#').next().unwrap_or("").replace(' ', "") == "proc-macro=true")
            {
                proc_macro.push(rel.clone());
            }
        }
        // Any case: a `#[path]` attribute can name a `.RS` file as a module.
        let is_rust = Path::new(&rel)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if is_rust && !rel.starts_with(PASTE_HOME) && invokes_paste(&bytes) {
            paste_users.push(rel);
        }
    }
    proc_macro.sort();
    let want: Vec<String> = PROC_MACRO_CRATES
        .iter()
        .map(|(p, _)| (*p).to_string())
        .collect();
    assert_eq!(
        proc_macro, want,
        "#10009: the proc-macro crates of the tree changed; a macro can join \
         identifier fragments into `{NAME}`, so review it against this ratchet"
    );
    assert!(
        paste_users.is_empty(),
        "#10009: `paste` is invoked outside {PASTE_HOME}; it can join \
         identifier fragments into `{NAME}`: {paste_users:?}"
    );
}

/// The matcher counts every call form and no longer or shorter identifier.
#[test]
fn matcher_counts_every_form_and_only_the_identifier_9945() {
    let table: &[(&str, usize)] = &[
        ("app.store.archive_purge_all(&admin).await", 1),
        (
            "crate::store::MemoryStore::archive_purge_all(&*app.store, admin)",
            1,
        ),
        ("<dyn MemoryStore>::archive_purge_all", 1),
        ("let wipe = MemoryStore::archive_purge_all;", 1),
        (
            "use crate::store::MemoryStore::archive_purge_all as wipe;",
            1,
        ),
        ("s.r#archive_purge_all(&c)", 1),
        ("store\n    .archive_purge_all(\n&c)", 1),
        ("archive_purge_all", 1),
        ("archive_purge_all archive_purge_all", 2),
        ("\"archive_purge_all\"", 1),
        ("archive_purge_allowed(&c)", 0),
        ("my_archive_purge_all(&c)", 0),
        ("archive_purge_al(&c)", 0),
        ("archive_purge(&c, days)", 0),
        ("ARCHIVE_PURGE_ALL", 0),
        ("", 0),
    ];
    for (src, want) in table {
        assert_eq!(
            count_ident(src.as_bytes(), NAME.as_bytes()),
            *want,
            "{src:?}"
        );
    }
    let paste_table: &[(&str, bool)] = &[
        ("paste::paste! { [<archive_purge _all>] }", true),
        ("paste ! { x }", true),
        ("use paste::paste as p;", true),
        ("extern crate paste as p;", true),
        ("// copy/paste from docs", false),
        ("a paste error", false),
        ("copypaste!()", false),
    ];
    for (src, want) in paste_table {
        assert_eq!(invokes_paste(src.as_bytes()), *want, "{src:?}");
    }
}

/// The scan is linear: a 4 MiB input near-miss on every byte finishes fast.
#[test]
fn matcher_is_linear_on_a_large_input_9945() {
    const SIZE: usize = 4 * 1024 * 1024;
    const CEILING: std::time::Duration = std::time::Duration::from_secs(5);
    let mut hay = b"archive_purge_al".repeat(SIZE / 16);
    hay.extend_from_slice(b" archive_purge_all");
    let started = std::time::Instant::now();
    assert_eq!(count_ident(&hay, NAME.as_bytes()), 1);
    assert!(!invokes_paste(&hay));
    assert!(
        started.elapsed() < CEILING,
        "scan of {SIZE} bytes took {:?}",
        started.elapsed()
    );
}

#[test]
fn every_skip_and_allow_row_has_a_reason_9945() {
    for (name, why) in SKIPPED_ROOT_ENTRIES {
        assert!(!why.trim().is_empty(), "{name}: no reason");
        assert!(!name.contains('/'), "{name}: skips are root entries only");
    }
    for (path, n, why) in ALLOWED {
        assert!(*n > 0, "{path}: a zero row is a stale row");
        assert!(!why.trim().is_empty(), "{path}: no reason");
        assert!(
            Path::new(&root().join(path)).is_file(),
            "{path}: not a file"
        );
    }
}
