// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #9178 D (umbrella #8169, lane #9218) — the postgres `archived_memories`
//! snapshot statement has ONE shared helper, and the inline copies that are
//! left may only fall.
//!
//! # The defect class this pins
//!
//! A live `memories` row is snapshotted into `archived_memories` by a column
//! list. Every inline copy of that list is a place where the next schema
//! column can be missed, so an archive -> restore round trip silently loses it.
//! PR #9178 added `pg_replace_archive_snapshot_in_tx` (`src/store/postgres.rs`),
//! the one DELETE + INSERT pair on the shared `SQL_ARCHIVE_SNAPSHOT_LIVE_ROW`,
//! and moved its own new site (`consolidate_archive_9018.rs`) onto it. The
//! older inline sites move in #9218. Until then this test pins, per file and
//! in both directions:
//!
//! * [`INLINE_CONST_CALLS`]: production `sqlx::query(SQL_ARCHIVE_SNAPSHOT_LIVE_ROW)`
//!   calls outside the helper (inline DELETE + INSERT pairs);
//! * [`INLINE_LITERAL_COPIES`]: `INSERT INTO archived_memories` string literals
//!   in the postgres store outside the shared const (hand-copied column lists).
//!
//! A new copy is red. A removed copy is red too until its pin is lowered, so
//! the ceiling can only go down.

use std::path::Path;

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

#[path = "common/token_scan.rs"]
mod token_scan;
use token_scan::mask;

/// The shared helper every new snapshot site calls.
const HELPER_FN: &str = "fn pg_replace_archive_snapshot_in_tx(";
/// The file that defines the helper and the shared const.
const HELPER_FILE: &str = "src/store/postgres.rs";
/// The #9018 consolidate site that must use the helper.
const CONSOLIDATE_FILE: &str = "src/store/postgres/consolidate_archive_9018.rs";
/// The inline call of the shared statement (rustfmt keeps it on one line).
const CONST_CALL: &str = "sqlx::query(SQL_ARCHIVE_SNAPSHOT_LIVE_ROW)";
/// The hand-copied snapshot SQL.
const LITERAL: &str = "INSERT INTO archived_memories";
/// The shared const definition, the one literal that is not a copy.
const CONST_DEF: &str =
    "const SQL_ARCHIVE_SNAPSHOT_LIVE_ROW: &str = \"INSERT INTO archived_memories";
/// Every postgres store source starts with this path.
const PG_PREFIX: &str = "src/store/postgres";

/// `(file, pinned inline const calls)`; total 4 at PR #9178 (#9218 takes it to 0).
const INLINE_CONST_CALLS: &[(&str, usize)] = &[
    ("src/store/postgres.rs", 3),
    ("src/store/postgres/merge_inbound_4023.rs", 1),
];

/// `(file, pinned literal copies)`; total 5 at PR #9178 (#9218 takes it to 0).
const INLINE_LITERAL_COPIES: &[(&str, usize)] = &[
    ("src/store/postgres.rs", 4),
    ("src/store/postgres/federation_by_id_4447.rs", 1),
];

/// The helper body (from its `fn` line to the first column-0 `}`), or "".
fn helper_span(text: &str) -> (usize, usize) {
    let Some(start) = text.find(HELPER_FN) else {
        return (0, 0);
    };
    let end = text[start..]
        .find("\n}\n")
        .map_or(text.len(), |e| start + e);
    (start, end)
}

fn count_outside(haystack: &str, needle: &str, span: (usize, usize)) -> usize {
    haystack
        .match_indices(needle)
        .filter(|(at, _)| *at < span.0 || *at >= span.1)
        .count()
}

type Observed = Vec<(String, usize)>;

/// Inline const calls (masked code, helper body excluded) and literal copies
/// (raw text, the const definition excluded), per postgres store file.
fn scan(sources: &[(String, String)]) -> (Observed, Observed) {
    let (mut calls, mut literals) = (Vec::new(), Vec::new());
    for (rel, text) in sources.iter().filter(|(r, _)| r.starts_with(PG_PREFIX)) {
        let span = if rel == HELPER_FILE {
            helper_span(text)
        } else {
            (0, 0)
        };
        let n = count_outside(&mask(text), CONST_CALL, span);
        if n > 0 {
            calls.push((rel.clone(), n));
        }
        let n = text.matches(LITERAL).count() - text.matches(CONST_DEF).count();
        if n > 0 {
            literals.push((rel.clone(), n));
        }
    }
    (calls, literals)
}

fn diff(label: &str, observed: &Observed, pinned: &[(&str, usize)], out: &mut Vec<String>) {
    for (file, n) in observed {
        match pinned.iter().find(|(f, _)| f == file) {
            Some((_, p)) if p == n => {}
            Some((_, p)) if n < p => out.push(format!(
                "{label}: {file} has {n}, pinned {p}: lower the pin (it may only go down)"
            )),
            Some((_, p)) => out.push(format!(
                "{label}: {file} has {n}, pinned {p}: a NEW inline archive snapshot; call \
                 `pg_replace_archive_snapshot_in_tx` instead (#8169, #9218)"
            )),
            None => out.push(format!(
                "{label}: {file} has {n} UNPINNED inline archive snapshot(s); call \
                 `pg_replace_archive_snapshot_in_tx` instead (#8169, #9218)"
            )),
        }
    }
    for (file, _) in pinned {
        if !observed.iter().any(|(f, _)| f == file) {
            out.push(format!(
                "{label}: {file} is pinned but has no site; remove the entry"
            ));
        }
    }
}

#[test]
fn pg_archive_snapshot_inline_copies_only_fall_9178() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = cfg_test_modules::production_sources(root);
    let (calls, literals) = scan(&sources);
    let mut violations = Vec::new();
    diff(
        "inline SQL_ARCHIVE_SNAPSHOT_LIVE_ROW call",
        &calls,
        INLINE_CONST_CALLS,
        &mut violations,
    );
    diff(
        "inline archived_memories INSERT literal",
        &literals,
        INLINE_LITERAL_COPIES,
        &mut violations,
    );
    assert_eq!(violations, Vec::<String>::new(), "#9178 D snapshot ratchet");
}

#[test]
fn consolidate_source_uses_the_shared_snapshot_helper_9178() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).expect("read source");
    let helper = mask(&read(HELPER_FILE));
    assert_eq!(
        helper.matches(HELPER_FN).count(),
        1,
        "exactly one definition of the shared snapshot helper"
    );
    let (start, end) = helper_span(&helper);
    assert_eq!(
        helper[start..end].matches(CONST_CALL).count(),
        1,
        "the helper runs the shared SQL_ARCHIVE_SNAPSHOT_LIVE_ROW once"
    );
    let consolidate = mask(&read(CONSOLIDATE_FILE));
    let uses: Vec<&str> = [
        "pg_replace_archive_snapshot_in_tx(",
        "SQL_ARCHIVE_SNAPSHOT_LIVE_ROW",
        "SQL_DELETE_ARCHIVED_MEMORY_BY_ID",
    ]
    .into_iter()
    .filter(|tok| consolidate.contains(tok))
    .collect();
    assert_eq!(
        uses,
        vec!["pg_replace_archive_snapshot_in_tx("],
        "the #9018 consolidate site calls the helper and holds no inline snapshot"
    );
}
