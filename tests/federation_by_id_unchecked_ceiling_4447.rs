// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #4447 — the UNCHECKED by-id writer ceiling (sibling of
//! `tests/merge_inbound_unchecked_ceiling_4023.rs`).
//!
//! # The defect class this pins
//!
//! The federation `/sync/push` by-id lanes (`deletions[]`, `archives[]`,
//! `restores[]`, `links[]`) re-authorize the pushing peer's namespace scope
//! against the row they lock, through the `apply_remote_*_authorized` store
//! methods (and the sqlite `db::{delete,archive_memory,restore_archived,
//! create_link_inbound}_authorized` free functions). The unchecked writers
//! (`apply_remote_deletion` / `_archive` / `_restore` / `_link`, and
//! `db::create_link_inbound`) stay for tests, operator tooling and the adapters'
//! own delegation, and the price of keeping them is that a NEW production
//! caller could silently bypass the in-transaction re-check and reopen #4447.
//! So the allowed sites are MECHANICAL: production `src/` (outside `cfg(test)`,
//! resolved by the shared `tests/common/cfg_test_modules.rs` production view)
//! may name each unchecked token only at the pinned sites below. Counts are
//! pinned in BOTH directions so the ledger cannot rot. The authorized names
//! are different identifiers and are never counted; comments, doc lines and
//! string literals are not code.

use std::path::Path;

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;
#[path = "common/token_scan.rs"]
mod token_scan;
use token_scan::{ident_offsets, mask};

/// `(token, &[(file, pinned count, disposition)])`.
type Ledger = &'static [(&'static str, &'static [(&'static str, usize, &'static str)])];

const LEDGER: Ledger = &[
    (
        "apply_remote_deletion",
        &[
            (
                "src/store/mod.rs",
                1,
                "the `MemoryStore::apply_remote_deletion` trait default",
            ),
            ("src/store/sqlite.rs", 1, "the sqlite adapter impl"),
            (
                "src/store/postgres.rs",
                1,
                "the postgres adapter impl (forwards to the inner body with None)",
            ),
        ],
    ),
    (
        "apply_remote_archive",
        &[
            (
                "src/store/mod.rs",
                1,
                "the `MemoryStore::apply_remote_archive` trait default",
            ),
            ("src/store/sqlite.rs", 1, "the sqlite adapter impl"),
            ("src/store/postgres.rs", 1, "the postgres adapter impl"),
        ],
    ),
    (
        "apply_remote_restore",
        &[
            (
                "src/store/mod.rs",
                1,
                "the `MemoryStore::apply_remote_restore` trait default",
            ),
            ("src/store/sqlite.rs", 1, "the sqlite adapter impl"),
            ("src/store/postgres.rs", 1, "the postgres adapter impl"),
        ],
    ),
    (
        "apply_remote_link",
        &[
            (
                "src/store/mod.rs",
                1,
                "the `MemoryStore::apply_remote_link` trait default",
            ),
            ("src/store/sqlite.rs", 1, "the sqlite adapter impl"),
            ("src/store/postgres.rs", 1, "the postgres adapter impl"),
            (
                "src/migrate.rs",
                1,
                "the OPERATOR store-to-store migration (not a peer push)",
            ),
        ],
    ),
    (
        "create_link_inbound",
        &[
            (
                "src/storage/mod.rs",
                1,
                "the unchecked `db::create_link_inbound` definition",
            ),
            (
                "src/storage/federation_by_id_4447.rs",
                1,
                "`create_link_inbound_authorized` delegates after its in-tx re-check",
            ),
            (
                "src/store/sqlite.rs",
                1,
                "the sqlite adapter's unchecked `apply_remote_link` delegation",
            ),
            (
                "src/cli/sync.rs",
                1,
                "the OPERATOR `sync` CLI (not a peer push)",
            ),
        ],
    ),
];

type Observed = Vec<(String, usize)>;

fn scan_token(sources: &[(String, String)], token: &str) -> Observed {
    let mut out = Vec::new();
    for (rel, text) in sources {
        let n = ident_offsets(&mask(text), token).len();
        if n > 0 {
            out.push((rel.clone(), n));
        }
    }
    out
}

fn diff(token: &str, observed: &Observed, allowed: &[(&str, usize, &str)], out: &mut Vec<String>) {
    for (file, n) in observed {
        match allowed.iter().find(|(f, _, _)| f == file) {
            Some((_, pinned, _)) if pinned == n => {}
            Some((_, pinned, why)) => out.push(format!(
                "`{token}`: {file} has {n} site(s), pinned {pinned} ({why})"
            )),
            None => out.push(format!(
                "`{token}`: {file} has {n} UNRECORDED site(s). A production caller of the \
                 unchecked by-id writer bypasses the #4447 in-transaction peer-scope \
                 re-check. Route it through the `*_authorized` method with a real verdict."
            )),
        }
    }
    for (file, _, _) in allowed {
        if !observed.iter().any(|(f, _)| f == file) {
            out.push(format!(
                "`{token}`: {file} is allowlisted but has no site — remove the stale entry"
            ));
        }
    }
}

/// `(file, tokens)`: the sqlite `/sync/push` receive funnel must name NONE of
/// these in production. `delete`, `archive_memory` and `restore_archived` have
/// many legitimate callers elsewhere (local operator paths), so a crate-wide
/// pin is impossible, but THIS file is the peer-driven funnel: reverting it to
/// the unchecked free functions silently reopens #4447 on sqlite, and the
/// ledger above (which pins the store-method names) cannot see that.
const FILE_ZERO: &[(&str, &[&str])] = &[(
    "src/handlers/federation_receive.rs",
    &["delete", "archive_memory", "restore_archived"],
)];

fn zero_violations(sources: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (file, tokens) in FILE_ZERO {
        for token in *tokens {
            for (rel, n) in scan_token(sources, token) {
                if rel == *file {
                    out.push(format!(
                        "`{token}`: {file} names the unchecked sqlite writer {n} time(s); the \
                         receive funnel must call the `*_authorized` free function (#4447)"
                    ));
                }
            }
        }
    }
    out
}

#[test]
fn production_never_reaches_the_unchecked_by_id_writers_4447() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = cfg_test_modules::production_sources(root);
    let mut violations = Vec::new();
    for (token, allowed) in LEDGER {
        diff(
            token,
            &scan_token(&sources, token),
            allowed,
            &mut violations,
        );
    }
    violations.extend(zero_violations(&sources));
    assert!(
        violations.is_empty(),
        "#4447 unchecked by-id writer ceiling:\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn the_scanner_is_load_bearing_4447() {
    let planted = |body: &str| vec![("src/planted.rs".to_string(), body.to_string())];
    for (token, body) in [
        (
            "apply_remote_deletion",
            "fn f(s: &S) { s.apply_remote_deletion(ctx, id); }",
        ),
        (
            "apply_remote_archive",
            "fn f(s: &S) { s.apply_remote_archive(ctx, id); }",
        ),
        (
            "apply_remote_restore",
            "fn f(s: &S) { s.apply_remote_restore(ctx, id); }",
        ),
        (
            "apply_remote_link",
            "fn f(s: &S) { s.apply_remote_link(ctx, l, a); }",
        ),
        (
            "create_link_inbound",
            "fn f() { db::create_link_inbound(&c, &l, a); }",
        ),
        // A fn REFERENCE is seen too, not only a call.
        (
            "apply_remote_deletion",
            "fn f() { let g = Store::apply_remote_deletion; }",
        ),
    ] {
        assert_eq!(
            scan_token(&planted(body), token).len(),
            1,
            "must see `{token}` in: {body}"
        );
    }
    // The authorized names are different identifiers; comments, doc lines and
    // string literals are not code.
    for (token, body) in [
        (
            "apply_remote_deletion",
            "fn f(s: &S) { s.apply_remote_deletion_authorized(ctx, id, &v); }",
        ),
        (
            "create_link_inbound",
            "fn f() { db::create_link_inbound_authorized(&c, &l, a, &v); }",
        ),
        (
            "apply_remote_archive",
            "/// see apply_remote_archive\n// apply_remote_archive(\nfn f() { let s = \"apply_remote_archive x\"; }",
        ),
    ] {
        assert!(
            scan_token(&planted(body), token).is_empty(),
            "must NOT count `{token}` in: {body}"
        );
    }
    // The sqlite receive funnel reverting to an unchecked free function is red.
    for body in [
        "fn f() { db::delete(&c, id); }",
        "fn f() { db::archive_memory(&c, id, None); }",
        "fn f() { db::restore_archived(&c, id); }",
    ] {
        let funnel = vec![(
            "src/handlers/federation_receive.rs".to_string(),
            body.to_string(),
        )];
        assert_eq!(zero_violations(&funnel).len(), 1, "must flag: {body}");
        // The same call in another file is out of this pin's scope.
        let other = vec![("src/cli/local.rs".to_string(), body.to_string())];
        assert!(
            zero_violations(&other).is_empty(),
            "scoped to the funnel: {body}"
        );
    }
    let ok = vec![(
        "src/handlers/federation_receive.rs".to_string(),
        "fn f() { db::delete_authorized(&c, id, &v); let m = \"db::delete(\"; }".to_string(),
    )];
    assert!(
        zero_violations(&ok).is_empty(),
        "authorized names and strings are fine"
    );
    // A stale or unrecorded site is a violation, in both directions.
    let mut v = Vec::new();
    diff(
        "t",
        &vec![("a.rs".to_string(), 2)],
        &[("a.rs", 1, "x")],
        &mut v,
    );
    diff("t", &vec![("b.rs".to_string(), 1)], &[], &mut v);
    diff("t", &Vec::new(), &[("c.rs", 1, "x")], &mut v);
    assert_eq!(v.len(), 3, "{v:?}");
}
