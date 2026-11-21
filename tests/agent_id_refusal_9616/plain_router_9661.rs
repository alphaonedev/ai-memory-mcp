// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9661 source ratchet: no plain (non-test) `fn` registers a production
//! handler on a router.
//!
//! Why: `CodeQL`'s `rust/unsafe-deserialization` query treats the extractor
//! parameters of a handler as remote sources once the handler is registered
//! with `.route(...)` in a plain helper `fn` of a test file. The typed and
//! bounded `from_slice` / `from_value` lines inside the handlers, unchanged
//! by the PR, then become critical alerts (941, 953, 954, 955 on PR 9661).
//! Registration inside a `#[test]` / `#[tokio::test]` body raises nothing, and
//! a `macro_rules!` expanded in such a body is the same form.
//!
//! The scan is an allowlist over every tracked `.rs` file under `tests/`: a plain `fn`
//! whose body holds a `.route(` call and names the handlers module (directly,
//! through a `use ... handlers as <alias>` alias, through a name imported
//! from `handlers`, or through a macro defined here that does so) is an
//! offender unless [`ALLOW`] names its file and fn with a reason. A stale
//! allow row is an offender too.

use super::ratchet::{Tok, lex};
use std::collections::BTreeSet;
use std::path::Path;

/// The exact reason a finding carries.
const PLAIN_FN_REGISTERS_HANDLER: &str = "plain fn registers a production handler with .route(; \
     register it inside a #[test] or #[tokio::test] body (a macro_rules! expanded there is fine)";
/// A file the lexer refused.
const LEX_REFUSED: &str = "cannot be lexed";
/// The module whose handlers are production handlers.
const HANDLERS: &str = "handlers";
/// The route-constant submodule of `handlers`: a name taken from it is a path
/// string, never a handler.
const ROUTES_MODULE: &str = "routes";
/// Upper bound on a file the scan reads.
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

/// Plain helper fns that already registered production handlers at the merge
/// base of PR 9661. They are tracked as checklist items on issue 9616 and
/// stay allowed here only until moved; the ratchet stops a new one.
const ALLOW: &[(&str, &str, &str)] = &[];

fn is_ident(tok: &Tok, name: &str) -> bool {
    matches!(tok, Tok::Ident(i) if i == name)
}

fn is_punct(tok: &Tok, c: char) -> bool {
    matches!(tok, Tok::Punct(p) if *p == c)
}

/// The index of the bracket that closes the one opened at `open`.
fn matching(toks: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, tok) in toks.iter().enumerate().skip(open) {
        if let Tok::Punct(c) = tok {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Names a handler can be reached by in this file: `handlers` itself and
/// every identifier a `use` statement brings in after `handlers` (an alias
/// such as `h`, or an imported handler).
fn handler_names(toks: &[Tok]) -> BTreeSet<String> {
    let mut names = BTreeSet::from([HANDLERS.to_owned()]);
    let mut i = 0;
    while i < toks.len() {
        if is_ident(&toks[i], "use") {
            let end = toks[i..]
                .iter()
                .position(|t| is_punct(t, ';'))
                .map_or(toks.len(), |p| i + p);
            let stmt = &toks[i + 1..end];
            if let Some(at) = stmt.iter().position(|t| is_ident(t, HANDLERS)) {
                for tok in &stmt[at + 1..] {
                    if let Tok::Ident(n) = tok
                        && !matches!(n.as_str(), "as" | "self" | "super" | "crate")
                        && n != ROUTES_MODULE
                    {
                        names.insert(n.clone());
                    }
                }
            }
            i = end;
        }
        i += 1;
    }
    names
}

/// Whether `body` holds a `.route(` call whose arguments name a handler (see
/// [`handler_names`]).
fn registers_handler(body: &[Tok], names: &BTreeSet<String>) -> bool {
    body.windows(3).enumerate().any(|(i, w)| {
        if !(is_punct(&w[0], '.') && is_ident(&w[1], "route") && is_punct(&w[2], '(')) {
            return false;
        }
        matching(body, i + 2).is_some_and(|close| {
            body[i + 3..close]
                .iter()
                .any(|t| matches!(t, Tok::Ident(n) if names.contains(n)))
        })
    })
}

/// `macro_rules!` macros of the file whose definition registers a handler.
fn route_macros(toks: &[Tok], names: &BTreeSet<String>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (i, w) in toks.windows(4).enumerate() {
        if is_ident(&w[0], "macro_rules")
            && is_punct(&w[1], '!')
            && let Tok::Ident(name) = &w[2]
            && let Some(close) = matching(toks, i + 3)
        {
            let body = &toks[i + 4..close];
            if registers_handler(body, names) {
                found.insert(name.clone());
            }
        }
    }
    found
}

/// Whether the item whose `fn` keyword is at `at` carries a test attribute
/// (`#[test]`, `#[tokio::test]`, `#[tokio::test(...)]`): the last path
/// segment of an attribute is `test`. `#[cfg(test)]` is not one.
fn is_test_fn(toks: &[Tok], at: usize) -> bool {
    let mut start = at;
    while start > 0
        && !is_punct(&toks[start - 1], ';')
        && !is_punct(&toks[start - 1], '}')
        && !is_punct(&toks[start - 1], '{')
    {
        start -= 1;
    }
    let span = &toks[start..at];
    span.windows(2).enumerate().any(|(i, w)| {
        if !(is_punct(&w[0], '#') && is_punct(&w[1], '[')) {
            return false;
        }
        let last = span[i + 2..]
            .iter()
            .take_while(|t| matches!(t, Tok::Ident(_)) || is_punct(t, ':'))
            .filter_map(|t| match t {
                Tok::Ident(n) => Some(n.as_str()),
                _ => None,
            })
            .last();
        last == Some("test")
    })
}

/// The findings of one file: one line per plain `fn` that registers a
/// production handler, as `<path>: fn <name>: <reason>`.
fn plain_fn_findings(path: &str, src: &str) -> Vec<String> {
    let Ok(toks) = lex(src) else {
        return vec![format!("{path}: {LEX_REFUSED}")];
    };
    let names = handler_names(&toks);
    let macros = route_macros(&toks, &names);
    let mut found = Vec::new();
    for (i, w) in toks.windows(2).enumerate() {
        let (true, Tok::Ident(name)) = (is_ident(&w[0], "fn"), &w[1]) else {
            continue;
        };
        // The body opens at the first `{` outside parentheses and brackets; a
        // `;` first means a declaration without a body.
        let mut depth = 0usize;
        let mut open = None;
        for (j, tok) in toks.iter().enumerate().skip(i + 2) {
            if let Tok::Punct(c) = tok {
                match c {
                    '(' | '[' => depth += 1,
                    ')' | ']' => depth = depth.saturating_sub(1),
                    ';' if depth == 0 => break,
                    '{' if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    _ => {}
                }
            }
        }
        let Some(open) = open else { continue };
        let Some(close) = matching(&toks, open) else {
            continue;
        };
        let body = &toks[open + 1..close];
        let via_macro = body
            .windows(2)
            .any(|m| matches!(&m[0], Tok::Ident(n) if macros.contains(n)) && is_punct(&m[1], '!'));
        let direct = registers_handler(body, &names);
        if (direct || via_macro) && !is_test_fn(&toks, i) {
            found.push(format!("{path}: fn {name}: {PLAIN_FN_REGISTERS_HANDLER}"));
        }
    }
    found
}

/// Whether `path` is a file the ratchet reads.
fn scanned(path: &str) -> bool {
    let rust = Path::new(path).extension().is_some_and(|e| e == "rs");
    rust && path.starts_with("tests/")
}

fn read_source(root: &Path, rel: &str) -> Result<String, String> {
    use std::io::Read as _;
    let file =
        std::fs::File::open(root.join(rel)).map_err(|e| format!("{rel}: unreadable ({e})"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{rel}: unreadable ({e})"))?;
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_SOURCE_BYTES) {
        return Err(format!("{rel}: larger than the source size cap"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{rel}: not UTF-8"))
}

/// The offenders over `files` (path, source): findings not granted by
/// `allow`, plus every allow row that matched nothing.
fn offenders(files: &[(String, String)], allow: &[(&str, &str, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut used = BTreeSet::new();
    for (path, src) in files {
        for line in plain_fn_findings(path, src) {
            let granted = allow.iter().position(|(file, name, _)| {
                line == format!("{file}: fn {name}: {PLAIN_FN_REGISTERS_HANDLER}")
            });
            match granted {
                Some(row) => {
                    used.insert(row);
                }
                None => out.push(line),
            }
        }
    }
    for (row, (file, name, reason)) in allow.iter().enumerate() {
        if !used.contains(&row) {
            out.push(format!("{file}: stale allow row for fn {name} ({reason})"));
        }
    }
    out.sort();
    out
}

/// The real tree: no plain fn under `tests/` registers a production handler, except the rows of [`ALLOW`].
#[test]
fn no_plain_fn_registers_a_production_handler_9661() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.rs"])
        .output()
        .expect("run git ls-files");
    assert!(out.status.success(), "git ls-files failed: {out:?}");
    let tracked = String::from_utf8(out.stdout).expect("tracked paths are UTF-8");
    let mut files = Vec::new();
    let mut problems = Vec::new();
    for path in tracked.split('\0').filter(|p| !p.is_empty() && scanned(p)) {
        match read_source(root, path) {
            Ok(src) => files.push((path.to_owned(), src)),
            Err(why) => problems.push(why),
        }
    }
    assert!(
        files
            .iter()
            .any(|(p, _)| p == "tests/agent_id_refusal_9616.rs"),
        "the scan must reach tests/agent_id_refusal_9616.rs"
    );
    problems.extend(offenders(&files, ALLOW));
    assert_eq!(problems, Vec::<String>::new());
}

// ---- break-it rows for the scan itself ----

/// The plain-fn form this PR had: registration through an alias.
const PLAIN_ALIAS: &str = "fn handler_router(app: AppState) -> axum::Router {\n    \
    use ai_memory::handlers as h;\n    axum::Router::new().route(\"/x\", get(h::get_memory)).with_state(app)\n}\n";
/// Same, through the full path.
const PLAIN_FULL_PATH: &str =
    "pub fn r() -> Router { Router::new().route(\"/x\", get(ai_memory::handlers::get_memory)) }";
/// Same, through a name imported from `handlers`.
const PLAIN_IMPORTED: &str = "use ai_memory::handlers::{delete_link};\n\
    async fn r() -> Router { Router::new().route(\"/x\", delete(delete_link)) }";
/// Same, through an alias inside a group import.
const PLAIN_GROUP_ALIAS: &str = "use ai_memory::{handlers as hh, other};\n\
    fn r() -> Router { Router::new().route(\"/x\", get(hh::get_memory)) }";
/// A `#[cfg(test)]` helper is still a plain fn.
const PLAIN_CFG_TEST: &str =
    "#[cfg(test)]\nfn r() -> Router { Router::new().route(\"/x\", get(handlers::get_memory)) }";
/// A plain fn that expands the registering macro.
const PLAIN_VIA_MACRO: &str = "macro_rules! reg { ($a:expr) => { Router::new().route(\"/x\", get(handlers::get_memory)).with_state($a) }; }\n\
    fn r(app: AppState) -> Router { reg!(app) }";
/// A plain fn nested in a test body is still plain.
const NESTED_PLAIN: &str = "#[tokio::test]\nasync fn t() {\n    fn inner() -> Router { Router::new().route(\"/x\", get(handlers::get_memory)) }\n}";
/// The in-test form: registration inside the test body.
const IN_TEST: &str = "use ai_memory::handlers as h;\n#[tokio::test]\nasync fn t() {\n    let r = Router::new().route(\"/x\", get(h::get_memory));\n}";
/// The in-test form with attribute arguments and a second attribute.
const IN_TEST_ARGS: &str = "use ai_memory::handlers as h;\n#[cfg(feature = \"x\")]\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn t() {\n    let r = Router::new().route(\"/x\", get(h::get_memory));\n}";
/// The plain `#[test]` form.
const IN_PLAIN_TEST: &str = "use ai_memory::handlers as h;\n#[test]\nfn t() { let r = Router::new().route(\"/x\", get(h::get_memory)); }";
/// The macro form expanded in a test.
const MACRO_IN_TEST: &str = "macro_rules! reg { ($a:expr) => { Router::new().route(\"/x\", get(handlers::get_memory)).with_state($a) }; }\n\
    #[tokio::test]\nasync fn t() { let r = reg!(app); }";
/// A plain fn that registers a dummy, not a production handler.
const PLAIN_DUMMY: &str =
    "async fn dummy() {}\nfn r() -> Router { Router::new().route(\"/x\", get(dummy)) }";
/// A plain fn that names a handler and builds no route.
const PLAIN_NO_ROUTE: &str = "fn r() { let _ = ai_memory::handlers::get_memory; }";
/// A string that only says `.route(`.
const ONLY_IN_STRING: &str =
    "use ai_memory::handlers as h;\nfn r() -> &'static str { \".route(h::x)\" }";
/// A comment that says it.
const ONLY_IN_COMMENT: &str =
    "use ai_memory::handlers as h;\nfn r() { // .route(\"/x\", get(h::get_memory))\n}";

const PATH: &str = "tests/probe.rs";

fn expect_reason(name: &str, src: &str, fn_name: &str) {
    assert_eq!(
        plain_fn_findings(PATH, src),
        vec![format!(
            "{PATH}: fn {fn_name}: {PLAIN_FN_REGISTERS_HANDLER}"
        )],
        "{name}"
    );
}

#[test]
fn plain_fn_forms_are_findings_with_the_exact_reason_9661() {
    expect_reason("alias", PLAIN_ALIAS, "handler_router");
    expect_reason("full path", PLAIN_FULL_PATH, "r");
    expect_reason("imported name", PLAIN_IMPORTED, "r");
    expect_reason("group alias", PLAIN_GROUP_ALIAS, "r");
    expect_reason("cfg(test) is not a test attribute", PLAIN_CFG_TEST, "r");
    expect_reason("via macro", PLAIN_VIA_MACRO, "r");
    expect_reason("nested plain fn in a test", NESTED_PLAIN, "inner");
}

#[test]
fn test_body_macro_and_non_handler_forms_are_not_findings_9661() {
    for (name, src) in [
        ("in tokio test", IN_TEST),
        ("in tokio test with args", IN_TEST_ARGS),
        ("in plain test", IN_PLAIN_TEST),
        ("macro in test", MACRO_IN_TEST),
        ("dummy handler", PLAIN_DUMMY),
        ("no route call", PLAIN_NO_ROUTE),
        ("route only in a string", ONLY_IN_STRING),
        ("route only in a comment", ONLY_IN_COMMENT),
    ] {
        assert_eq!(plain_fn_findings(PATH, src), Vec::<String>::new(), "{name}");
    }
}

#[test]
fn allow_rows_grant_exactly_one_fn_and_stale_rows_are_findings_9661() {
    let files = vec![(PATH.to_owned(), PLAIN_ALIAS.to_owned())];
    assert_eq!(
        offenders(&files, &[(PATH, "handler_router", "checklist item")]),
        Vec::<String>::new()
    );
    assert_eq!(
        offenders(&files, &[(PATH, "other", "checklist item")]),
        vec![
            format!("{PATH}: fn handler_router: {PLAIN_FN_REGISTERS_HANDLER}"),
            format!("{PATH}: stale allow row for fn other (checklist item)"),
        ]
    );
}

#[test]
fn scan_reaches_tests_only_9661() {
    assert!(scanned("tests/a.rs"));
    assert!(scanned("tests/sub/a.rs"));
    assert!(!scanned("src/handlers/tests.rs"));
    assert!(!scanned("src/handlers/links.rs"));
    assert!(!scanned("tests/a.txt"));
}

/// A lexer refusal is a finding, not a pass.
#[test]
fn unlexable_source_is_a_finding_9661() {
    assert_eq!(
        plain_fn_findings(PATH, "fn r() { \"unterminated"),
        vec![format!("{PATH}: {LEX_REFUSED}")]
    );
}

/// Linear time: a 100K+ token file is scanned inside a wall-clock ceiling.
#[test]
fn scan_is_linear_on_a_large_file_9661() {
    let mut src = String::from("use ai_memory::handlers as h;\n");
    let unit = "fn f() { let x = 1; }\n";
    while src.len() < 400_000 {
        src.push_str(unit);
    }
    src.push_str(PLAIN_ALIAS);
    let started = std::time::Instant::now();
    let found = plain_fn_findings(PATH, &src);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "scan took {:?}",
        started.elapsed()
    );
}
