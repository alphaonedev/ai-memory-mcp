// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #4023 — the UNCHECKED-merge ceiling (5-agent vote (4d3ea1c5),
//! memory 179cf088; precedent `tests/db_open_funnel_ceiling_2445.rs`).
//!
//! # The defect class this pins
//!
//! `merge_inbound` (the `MemoryStore` method and the `db::` free fn) merges a
//! same-`id` row WITHOUT re-authorizing the pushing peer's namespace scope
//! against the row the merge locks. #4023 added `merge_inbound_authorized`,
//! which takes the verdict as a closure and evaluates it inside the merge
//! transaction. The vote kept the unchecked `merge_inbound` (tests + adapter
//! delegation only, `#[doc(hidden)]`), and the price of keeping it is that a
//! NEW production caller could silently bypass the in-transaction re-check and
//! reopen #4023. So the allowed sites are MECHANICAL:
//!
//! * production `src/` (outside `cfg(test)`, resolved by the shared
//!   `tests/common/cfg_test_modules.rs` production view) may name the token
//!   `merge_inbound` only at the pinned sites in [`ALLOWED`] — the trait
//!   declaration, the unchecked `db::` wrapper, and the two adapter
//!   delegations. That covers `.merge_inbound(`, `db::merge_inbound(` AND a
//!   method/function REFERENCE (`Store::merge_inbound` passed as a fn value),
//!   which a textual `(`-suffixed match would miss;
//! * no production call of `merge_inbound_authorized` may pass a literal `None`
//!   authorizer (that IS the unchecked path under a checked name), except the
//!   one inside the `db::merge_inbound` wrapper;
//! * `pg_merge_inbound` may be handed a literal `None` only by the postgres
//!   adapter's `merge_inbound` delegation.
//!
//! Counts are pinned in BOTH directions so the ledger cannot rot.

use std::path::Path;

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

// The comment/string mask and the whole-identifier scan are shared with the
// #4447 by-id ceiling (`tests/federation_by_id_unchecked_ceiling_4447.rs`).
#[path = "common/token_scan.rs"]
mod token_scan;
use token_scan::{ident_offsets, mask};

/// `(file, pinned count of the bare token `merge_inbound`, disposition)`.
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "src/store/mod.rs",
        1,
        "the `MemoryStore::merge_inbound` trait declaration",
    ),
    (
        "src/store/sqlite.rs",
        2,
        "the sqlite adapter's `merge_inbound` impl + its `db::merge_inbound` delegation",
    ),
    (
        "src/store/postgres.rs",
        1,
        "the postgres adapter's `merge_inbound` impl (delegates to pg_merge_inbound with None)",
    ),
    (
        "src/storage/mod.rs",
        1,
        "the unchecked `db::merge_inbound` wrapper definition",
    ),
];

/// `(file, pinned count of literal-`None` calls, disposition)` for
/// `merge_inbound_authorized`.
const ALLOWED_NONE_AUTHORIZED: &[(&str, usize, &str)] = &[(
    "src/storage/mod.rs",
    1,
    "the unchecked `db::merge_inbound` wrapper forwards None",
)];

/// `(file, pinned count of literal-`None` calls, disposition)` for
/// `pg_merge_inbound`.
const ALLOWED_NONE_PG: &[(&str, usize, &str)] = &[(
    "src/store/postgres.rs",
    1,
    "the postgres adapter's `merge_inbound` delegation",
)];

/// The last NON-EMPTY top-level argument of the call whose `(` follows `ident`
/// at `at`, trimmed (rustfmt's vertical form leaves an empty segment after the
/// trailing comma; that must not be mistaken for "no argument"). `None` when
/// the ident is not directly called.
fn last_call_arg(masked: &str, at: usize, ident: &str) -> Option<String> {
    let rest = &masked[at + ident.len()..];
    let rest_trim = rest.trim_start();
    if !rest_trim.starts_with('(') {
        return None;
    }
    let open = masked.len() - rest_trim.len();
    let mut depth = 0i32;
    let mut arg_start = open + 1;
    let mut last = String::new();
    for (off, ch) in masked[open..].char_indices() {
        let pos = open + off;
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    let tail = masked[arg_start..pos].trim();
                    if !tail.is_empty() {
                        last = tail.to_string();
                    }
                    break;
                }
            }
            ',' if depth == 1 => {
                let seg = masked[arg_start..pos].trim();
                if !seg.is_empty() {
                    last = seg.to_string();
                }
                arg_start = pos + 1;
            }
            _ => {}
        }
    }
    Some(last)
}

type Observed = Vec<(String, usize)>;

fn scan(sources: &[(String, String)]) -> (Observed, Observed, Observed) {
    let (mut token, mut none_auth, mut none_pg) = (Vec::new(), Vec::new(), Vec::new());
    for (rel, text) in sources {
        let masked = mask(text);
        let n = ident_offsets(&masked, "merge_inbound").len();
        if n > 0 {
            token.push((rel.clone(), n));
        }
        let n = ident_offsets(&masked, "merge_inbound_authorized")
            .into_iter()
            .filter(|&at| {
                last_call_arg(&masked, at, "merge_inbound_authorized").is_some_and(|a| a == "None")
            })
            .count();
        if n > 0 {
            none_auth.push((rel.clone(), n));
        }
        let n = ident_offsets(&masked, "pg_merge_inbound")
            .into_iter()
            .filter(|&at| {
                last_call_arg(&masked, at, "pg_merge_inbound").is_some_and(|a| a == "None")
            })
            .count();
        if n > 0 {
            none_pg.push((rel.clone(), n));
        }
    }
    (token, none_auth, none_pg)
}

fn diff(label: &str, observed: &Observed, allowed: &[(&str, usize, &str)], out: &mut Vec<String>) {
    for (file, n) in observed {
        match allowed.iter().find(|(f, _, _)| f == file) {
            Some((_, pinned, _)) if pinned == n => {}
            Some((_, pinned, why)) => out.push(format!(
                "{label}: {file} has {n} site(s), pinned {pinned} ({why})"
            )),
            None => out.push(format!(
                "{label}: {file} has {n} UNRECORDED site(s). A production caller of the \
                 unchecked merge bypasses the #4023 in-transaction peer-scope re-check. \
                 Route it through `merge_inbound_authorized` with a real authorizer."
            )),
        }
    }
    for (file, _, _) in allowed {
        if !observed.iter().any(|(f, _)| f == file) {
            out.push(format!(
                "{label}: {file} is allowlisted but has no site — remove the stale entry"
            ));
        }
    }
}

#[test]
fn production_never_reaches_the_unchecked_merge_4023() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = cfg_test_modules::production_sources(root);
    let (token, none_auth, none_pg) = scan(&sources);
    let mut violations = Vec::new();
    diff("merge_inbound token", &token, ALLOWED, &mut violations);
    diff(
        "merge_inbound_authorized(.., None)",
        &none_auth,
        ALLOWED_NONE_AUTHORIZED,
        &mut violations,
    );
    diff(
        "pg_merge_inbound(.., None)",
        &none_pg,
        ALLOWED_NONE_PG,
        &mut violations,
    );
    assert!(
        violations.is_empty(),
        "#4023 unchecked-merge ceiling:\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn the_scanner_is_load_bearing_4023() {
    let planted = |body: &str| vec![("src/planted.rs".to_string(), body.to_string())];
    // A `.merge_inbound(` method call, a `db::merge_inbound(` call, and a fn
    // REFERENCE are all seen.
    for body in [
        "fn f(s: &S) { s.merge_inbound(ctx, m, false); }",
        "fn f() { db::merge_inbound(&c, &m, false); }",
        "fn f() { let g = Store::merge_inbound; }",
        "fn f() { call(SqliteStore::merge_inbound) }",
    ] {
        let (token, _, _) = scan(&planted(body));
        assert_eq!(token.len(), 1, "must see: {body}");
    }
    // A literal None authorizer is seen, a real one is not.
    let (_, none_auth, _) = scan(&planted(
        "fn f() { db::merge_inbound_authorized(&c, &m, true, None); }",
    ));
    assert_eq!(none_auth.len(), 1);
    let (_, none_auth, _) = scan(&planted(
        "fn f() { db::merge_inbound_authorized(&c, &m, true, Some(&auth)); }",
    ));
    assert!(none_auth.is_empty());
    // rustfmt's vertical call form: a trailing comma after the last argument
    // must not hide a literal `None` (the last NON-EMPTY argument counts).
    let (_, none_auth, _) = scan(&planted(
        "fn f() {\n    db::merge_inbound_authorized(\n        &c,\n        &m,\n        true,\n        None,\n    );\n}",
    ));
    assert_eq!(
        none_auth.len(),
        1,
        "multi-line trailing-comma None must be seen"
    );
    let (_, none_auth, _) = scan(&planted(
        "fn f() {\n    db::merge_inbound_authorized(\n        &c,\n        &m,\n        true,\n        Some(&auth),\n    );\n}",
    ));
    assert!(none_auth.is_empty(), "multi-line Some(..) is not a None");
    let (_, _, none_pg) = scan(&planted(
        "fn f() {\n    self.pg_merge_inbound(\n        ctx,\n        m,\n        false,\n        None,\n    )\n}",
    ));
    assert_eq!(
        none_pg.len(),
        1,
        "multi-line pg_merge_inbound None must be seen"
    );
    // The authorized name is NOT the unchecked token; comments, doc lines and
    // string literals are not code.
    let (token, _, _) = scan(&planted(
        "/// see merge_inbound\n// merge_inbound(\nfn f() { let s = \"merge_inbound x\"; \
         db::merge_inbound_authorized(&c, &m, true, Some(&a)); let p = pg_merge_inbound; }",
    ));
    assert!(token.is_empty(), "{token:?}");
    // pg_merge_inbound with a literal None is seen.
    let (_, _, none_pg) = scan(&planted(
        "fn f() { self.pg_merge_inbound(c, m, v, None).await }",
    ));
    assert_eq!(none_pg.len(), 1);
}
