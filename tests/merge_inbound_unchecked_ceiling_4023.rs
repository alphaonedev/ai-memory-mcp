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

/// Blank every comment and string/char literal body with spaces (newlines
/// kept) so a token inside a doc line or an error-context string is never
/// counted as code.
fn mask(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            continue;
        }
        let prev_ident = i > 0 && is_ident(c[i - 1]);
        // Raw string r"..", r#".."#, br#".."#.
        let raw_at = if ch == 'r' && !prev_ident {
            Some(i + 1)
        } else if ch == 'b' && next == Some('r') && !prev_ident {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_at {
            let mut hashes = 0usize;
            while c.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if c.get(j) == Some(&'"') {
                while i <= j {
                    out.push(' ');
                    i += 1;
                }
                loop {
                    if i >= c.len() {
                        break;
                    }
                    if c[i] == '"' && (0..hashes).all(|k| c.get(i + 1 + k) == Some(&'#')) {
                        for _ in 0..=hashes {
                            out.push(' ');
                        }
                        i += 1 + hashes;
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
                continue;
            }
        }
        if ch == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    i += 1;
                    if i < c.len() {
                        blank(&mut out, c[i]);
                        i += 1;
                    }
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                blank(&mut out, c[i]);
                i += 1;
            }
            continue;
        }
        // Char literal (not a lifetime): `'x'`, `'\n'`, `'"'`.
        if ch == '\'' && !prev_ident {
            let close = if next == Some('\\') {
                c[i + 2..]
                    .iter()
                    .position(|&x| x == '\'')
                    .map(|p| i + 2 + p)
            } else if c.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                while i <= end {
                    blank(&mut out, c[i]);
                    i += 1;
                }
                continue;
            }
        }
        out.push(ch);
        i += 1;
    }
    out
}

/// Byte offsets of every whole-identifier occurrence of `ident` in `masked`.
fn ident_offsets(masked: &str, ident: &str) -> Vec<usize> {
    let b = masked.as_bytes();
    let is_ident = |x: u8| x.is_ascii_alphanumeric() || x == b'_';
    masked
        .match_indices(ident)
        .filter(|(at, _)| {
            let before_ok = *at == 0 || !is_ident(b[*at - 1]);
            let end = *at + ident.len();
            let after_ok = end >= b.len() || !is_ident(b[end]);
            before_ok && after_ok
        })
        .map(|(at, _)| at)
        .collect()
}

/// The last top-level argument of the call whose `(` follows `ident` at
/// `at`, trimmed. `None` when the ident is not directly called.
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
                    last = masked[arg_start..pos].trim().to_string();
                    break;
                }
            }
            ',' if depth == 1 => arg_start = pos + 1,
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
