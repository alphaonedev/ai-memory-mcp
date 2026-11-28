// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10287: macro indirection, deny by default.
//!
//! A macro can carry a watched name in from its call site, so the token
//! census sees the name at the call and not at the place the macro uses it.
//! Every form below is red, over the whole walked tree, unless its file has
//! a [`MACRO_ROWS`] row with the exact count of that form and a reason:
//!
//! * `$m!`: a metavariable in macro-invocation position;
//! * `<$t`, `$t::`, `$(..)::`: a metavariable in type or path position;
//! * `$t{`: a metavariable naming a struct in a literal (a `Config { fork:
//!   .. }` written through a macro);
//! * `proc-macro`: a procedural macro (its expansion is code the census
//!   never reads);
//! * `decl-macro`: a `macro NAME` (macros 2.0) definition;
//! * `hot-arg`: a macro invocation whose arguments name a watched, proptest,
//!   environment or fork name, unless the macro is one of [`ALLOWED`];
//! * `allow-redefined`, `allow-renamed`: a definition or an `as` rename that
//!   takes a name of [`ALLOWED`], which would hide a new macro behind it.
//!
//! [`ALLOWED`] holds the std, log and test macros whose expansion only
//! evaluates their arguments as expressions or formats them; a watched name
//! in their arguments stays pinned by its `T` site. Each scan is one pass
//! with prefix counts, so the cost is linear in the tokens.

use std::collections::{BTreeMap, BTreeSet};

use crate::census_pins::Prep;
use crate::rust_lex::{Lexed, Tok};

/// The macros whose arguments are expressions or format arguments only.
pub(crate) const ALLOWED: &[&str] = &[
    "anyhow",
    "assert",
    "assert_eq",
    "assert_matches",
    "assert_ne",
    "bail",
    "cfg",
    "column",
    "compile_error",
    "concat",
    "dbg",
    "debug",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "ensure",
    "env",
    "eprint",
    "eprintln",
    "error",
    "file",
    "format",
    "format_args",
    "include_bytes",
    "include_str",
    "info",
    "json",
    "line",
    "macro_rules",
    "matches",
    "module_path",
    "option_env",
    "panic",
    "print",
    "println",
    "proptest",
    "stringify",
    "thread_local",
    "todo",
    "trace",
    "unimplemented",
    "unreachable",
    "vec",
    "warn",
    "write",
    "writeln",
];

/// Names of the fork switches, hot in a macro argument as well.
pub(crate) const FORK_NAMES: &[&str] = &["with_fork", "with_timeout"];

/// What each form is, for the finding.
pub(crate) const FORMS: &[(&str, &str)] = &[
    ("$(..)::", "a repeated metavariable group in path position"),
    ("$m!", "a macro metavariable in invocation position"),
    ("$t::", "a macro metavariable in path position"),
    ("$t{", "a macro metavariable naming the struct of a literal"),
    ("<$t", "a macro metavariable in type position"),
    (
        "allow-redefined",
        "a macro definition that takes an allowed std macro name",
    ),
    ("allow-renamed", "an as rename to an allowed std macro name"),
    ("decl-macro", "a macro NAME definition (macros 2.0)"),
    (
        "hot-arg",
        "a macro invocation whose arguments name a watched, proptest, env or fork name",
    ),
    (
        "proc-macro",
        "a procedural macro, whose expansion the census never reads",
    ),
];

/// Files allowed to hold a form: (file, form, exact count, reason).
/// Hand-written; sorted by file, then form.
pub(crate) const MACRO_ROWS: &[(&str, &str, usize, &str)] = &[
    (
        "tests/corrupt_governance_escape_4285.rs",
        "$t{",
        1,
        "a test macro builds a governance struct literal named by its caller; no proptest Config",
    ),
    (
        "tests/cov3_handlers_postgres.rs",
        "hot-arg",
        2,
        "pg_test! wraps a test body that names process ids; the macro only runs the body under a pool",
    ),
    (
        "tests/cov_ga2_pg_handlers_2.rs",
        "hot-arg",
        3,
        "pg_test! wraps a test body that names process ids; the macro only runs the body under a pool",
    ),
    (
        "tests/issue_4357_reflect_approval_gate_parity.rs",
        "$t{",
        1,
        "a test macro builds a request struct literal named by its caller; no proptest Config",
    ),
    (
        "tests/record_stop_r45_1955.rs",
        "$t{",
        2,
        "a test macro builds record structs named by its caller; no proptest Config",
    ),
    (
        "vendor/paste/src/attr.rs",
        "proc-macro",
        1,
        "the vendored paste crate's proc-macro source; it pastes identifiers and starts nothing",
    ),
    (
        "vendor/paste/src/error.rs",
        "proc-macro",
        1,
        "the vendored paste crate's proc-macro source; it pastes identifiers and starts nothing",
    ),
    (
        "vendor/paste/src/lib.rs",
        "proc-macro",
        6,
        "the vendored paste crate's proc-macro entry points; they paste identifiers and start nothing",
    ),
    (
        "vendor/paste/src/segment.rs",
        "proc-macro",
        1,
        "the vendored paste crate's proc-macro source; it pastes identifiers and starts nothing",
    ),
    (
        "vendor/paste/tests/macros/lib.rs",
        "proc-macro",
        3,
        "the vendored paste crate's own test proc-macros; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_attr.rs",
        "$t{",
        1,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_doc.rs",
        "$t{",
        1,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_expr.rs",
        "hot-arg",
        6,
        "the vendored paste crate's own tests of env! pasting; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_item.rs",
        "$t::",
        1,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_item.rs",
        "$t{",
        1,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_item.rs",
        "<$t",
        11,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/test_item.rs",
        "allow-redefined",
        1,
        "the vendored paste crate's own tests; the workspace never builds them",
    ),
    (
        "vendor/paste/tests/ui/env-empty.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
    (
        "vendor/paste/tests/ui/env-non-string.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
    (
        "vendor/paste/tests/ui/env-suffix.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
    (
        "vendor/paste/tests/ui/env-unexpected.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
    (
        "vendor/paste/tests/ui/missing-paren-on-env.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
    (
        "vendor/paste/tests/ui/no-env-var.rs",
        "hot-arg",
        1,
        "a vendored paste compile-fail fixture of env! pasting; the workspace never builds it",
    ),
];

fn tok_at(t: &[Lexed], k: usize) -> Option<&Tok> {
    t.get(k).map(|x| &x.tok)
}

fn is_p(t: &[Lexed], k: usize, c: char) -> bool {
    matches!(tok_at(t, k), Some(Tok::Punct(p)) if *p == c)
}

fn ident_at(t: &[Lexed], k: usize) -> Option<&str> {
    match tok_at(t, k) {
        Some(Tok::Ident(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn is_sep(t: &[Lexed], k: usize) -> bool {
    matches!(tok_at(t, k), Some(Tok::PathSep))
}

/// Every macro form of one file, `(form, line)`, in token order.
#[expect(
    clippy::many_single_char_names,
    reason = "token-walk indices (p, t, n, k, e) follow the lexer convention of every census scan"
)]
pub(crate) fn macro_forms(p: &Prep<'_>, hot: &BTreeSet<String>) -> Vec<(&'static str, usize)> {
    let t = p.toks;
    let n = t.len();
    let allowed = |s: Option<&str>| s.is_some_and(|s| ALLOWED.contains(&s));
    let mut hot_count = vec![0usize; n + 1];
    for (k, x) in t.iter().enumerate() {
        hot_count[k + 1] =
            hot_count[k] + usize::from(matches!(&x.tok, Tok::Ident(s) if hot.contains(s)));
    }
    let mut out = Vec::new();
    for (k, x) in t.iter().enumerate() {
        let line = x.line;
        let v = ident_at(t, k);
        let meta = is_p(t, k, '$') && ident_at(t, k + 1).is_some_and(|s| s != "crate");
        if meta {
            if is_p(t, k + 2, '!') && !is_p(t, k + 3, '=') {
                out.push(("$m!", line));
            }
            if k.checked_sub(1).is_some_and(|j| is_p(t, j, '<')) {
                out.push(("<$t", line));
            }
            if is_sep(t, k + 2) {
                out.push(("$t::", line));
            }
            if is_p(t, k + 2, '{') {
                out.push(("$t{", line));
            }
        }
        if is_p(t, k, '$') && is_p(t, k + 1, '(') {
            let e = p.close.get(k + 1).copied().flatten().unwrap_or(n);
            if is_sep(t, e + 1) {
                out.push(("$(..)::", line));
            }
        }
        if matches!(
            v,
            Some("proc_macro" | "proc_macro_derive" | "proc_macro_attribute")
        ) {
            out.push(("proc-macro", line));
        }
        if v == Some("macro") && ident_at(t, k + 1).is_some() {
            out.push(("decl-macro", line));
        }
        if v.is_some()
            && is_p(t, k + 1, '!')
            && matches!(tok_at(t, k + 2), Some(Tok::Punct('(' | '[' | '{')))
            && !allowed(v)
        {
            let e = p.close.get(k + 2).copied().flatten().unwrap_or(n).min(n);
            let lo = (k + 3).min(e);
            if hot_count[e] > hot_count[lo] {
                out.push(("hot-arg", line));
            }
        }
        let redefined =
            (v == Some("macro_rules") && is_p(t, k + 1, '!') && allowed(ident_at(t, k + 2)))
                || (v == Some("macro") && allowed(ident_at(t, k + 1)));
        if redefined {
            out.push(("allow-redefined", line));
        }
        if v == Some("as") && allowed(ident_at(t, k + 1)) {
            out.push(("allow-renamed", line));
        }
    }
    out
}

fn what(form: &str) -> &'static str {
    FORMS
        .iter()
        .find(|(f, _)| *f == form)
        .map_or("an unknown macro form", |(_, w)| w)
}

/// The macro findings of the tree: every form of a file with no row for it,
/// every count that differs from its row, and the table's own defects.
pub(crate) fn macro_findings(
    have: &BTreeMap<(String, &'static str), Vec<usize>>,
    rows: &[(&str, &str, usize, &str)],
) -> Vec<String> {
    let mut out = Vec::new();
    let want: BTreeMap<(&str, &str), usize> =
        rows.iter().map(|(r, f, n, _)| ((*r, *f), *n)).collect();
    for ((rel, form), lines) in have {
        match want.get(&(rel.as_str(), *form)) {
            None => out.extend(lines.iter().map(|line| {
                format!(
                    "{rel}:{line}: {form}: {}; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)",
                    what(form)
                )
            })),
            Some(w) if *w != lines.len() => out.push(format!(
                "{rel}: {} {form} forms, MACRO_ROWS has {w}; a new or removed macro form needs its row (#10287)",
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for (rel, form, n, why) in rows {
        if !have.contains_key(&((*rel).to_string(), *form)) && !form.is_empty() {
            let known = FORMS.iter().any(|(f, _)| f == form);
            if known {
                out.push(format!(
                    "{rel}: 0 {form} forms, MACRO_ROWS has {n}; a stale row is red (#10287)"
                ));
            }
        }
        if !FORMS.iter().any(|(f, _)| f == form) {
            out.push(format!(
                "{rel}: MACRO_ROWS names the unknown form {form:?} (#10287)"
            ));
        }
        if why.trim().len() < 20 {
            out.push(format!(
                "{rel}: the MACRO_ROWS row for {form} has no reason of at least 20 bytes (#10287)"
            ));
        }
    }
    for w in rows.windows(2) {
        if (w[0].0, w[0].1) >= (w[1].0, w[1].1) {
            out.push(format!(
                "{}: MACRO_ROWS is not sorted or holds the file and form twice (#10287)",
                w[1].0
            ));
        }
    }
    out
}
