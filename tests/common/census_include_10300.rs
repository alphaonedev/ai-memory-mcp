// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10300: every `include!` and `#[path]` of a walked file is a site of the
//! census (`include_str!` and `include_bytes!` name data that is never
//! compiled as Rust, so they are not sites). Each fixture below is a small
//! tree written on disk under `CARGO_TARGET_TMPDIR` (never `/tmp`), read with
//! [`read_tree`] and run through [`census`]; every expected line is written
//! out here by hand, never built by the census.

use super::*;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, Instant};

/// The include macro whose target is Rust code, and the form its sites are
/// written as in a finding. `include_str!` and `include_bytes!` name data
/// that is never compiled as Rust, so they are not sites (#10300).
const INCLUDE_MACRO: &str = "include";
const INCLUDE_FORM: &str = "include!";
/// The form of a `path = ..` of a `#[path]` or `#[cfg_attr(.., path = ..)]`.
const PATH_FORM: &str = "#[path]";
/// The largest include target the census reads or accepts, in bytes.
const INCLUDE_CAP: u64 = 4 * 1024 * 1024;
/// The longest include argument the census resolves, in bytes (`PATH_MAX`);
/// it bounds the lookups of one site.
const INCLUDE_PATH_CAP: usize = 4096;
/// One include site: its token index, form, line and its argument when the
/// argument is one string literal.
pub(super) struct IncludeSite {
    pub idx: usize,
    pub form: &'static str,
    pub line: usize,
    pub arg: Option<String>,
}

/// `s` with `\` and `"` escaped and every character outside printable ASCII
/// written `\u{hex}`; the Python scanner writes the same text.
pub(super) fn shown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
        }
    }
    out
}

/// For each opening bracket its closing index (or the end), with the same
/// stack rule as the Python `brackets`; the end elsewhere.
fn closers(toks: &[Lexed]) -> Vec<usize> {
    let mut close = vec![toks.len(); toks.len()];
    let mut stack = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        match t.tok {
            Tok::Punct('(' | '[' | '{') => stack.push(k),
            Tok::Punct(')' | ']' | '}') => {
                if let Some(o) = stack.pop() {
                    close[o] = k;
                }
            }
            _ => {}
        }
    }
    close
}

fn is_open(toks: &[Lexed], k: usize) -> bool {
    matches!(tok(toks, k), Some(Tok::Punct('(' | '[' | '{')))
}

/// The comma-separated items of `toks[lo..hi]`, each (first, end), nested
/// groups jumped.
fn top_items(toks: &[Lexed], close: &[usize], lo: usize, hi: usize) -> Vec<(usize, usize)> {
    let mut items = Vec::new();
    let (mut start, mut k) = (lo, lo);
    while k < hi {
        if is_open(toks, k) {
            k = close[k].saturating_add(1);
            continue;
        }
        if is_p(toks, k, ',') {
            items.push((start, k));
            start = k + 1;
        }
        k += 1;
    }
    if start < hi {
        items.push((start, hi));
    }
    items
}

fn one_literal(toks: &[Lexed], lo: usize, hi: usize) -> Option<String> {
    match tok(toks, lo) {
        Some(Tok::Str(s)) if hi == lo + 1 => Some(s.clone()),
        _ => None,
    }
}

/// Every `include!` call and every `path = ..` of a `#[path]` or `#[cfg_attr(.., path = ..)]` attribute, in
/// token order. Each attribute is walked once with a worklist, so the cost is
/// linear in the tokens.
pub(super) fn include_sites(toks: &[Lexed]) -> Vec<IncludeSite> {
    let close = closers(toks);
    let mut out = Vec::new();
    let mut done = 0usize;
    for k in 0..toks.len() {
        if ident(toks, k) == Some(INCLUDE_MACRO) && is_p(toks, k + 1, '!') && is_open(toks, k + 2) {
            out.push(IncludeSite {
                idx: k,
                form: INCLUDE_FORM,
                line: toks[k].line,
                arg: one_literal(toks, k + 3, close[k + 2]),
            });
            continue;
        }
        if k < done || !is_p(toks, k, '#') {
            continue;
        }
        let b = if is_p(toks, k + 1, '!') { k + 2 } else { k + 1 };
        if !is_p(toks, b, '[') || !matches!(ident(toks, b + 1), Some("path" | "cfg_attr")) {
            continue;
        }
        let end = close[b];
        done = end.saturating_add(1);
        let mut work = vec![(b + 1, end)];
        while let Some((lo, hi)) = work.pop() {
            match ident(toks, lo) {
                Some("path") if is_p(toks, lo + 1, '=') => out.push(IncludeSite {
                    idx: lo,
                    form: PATH_FORM,
                    line: toks[lo].line,
                    arg: one_literal(toks, lo + 2, hi),
                }),
                Some("cfg_attr") if is_p(toks, lo + 1, '(') => {
                    let inner = close[lo + 1].min(hi);
                    work.extend(top_items(toks, &close, lo + 2, inner).into_iter().skip(1));
                }
                _ => {}
            }
        }
    }
    out.sort_by_key(|s| s.idx);
    out
}

/// Every tree path a lookup of `path` from the directory of `rel` passes, in
/// order, the target last (`.` and `..` folded, so a component later undone
/// by `..` is still listed); `None` when it leaves the tree, is absolute or
/// holds a backslash.
pub(super) fn include_steps(rel: &str, path: &str) -> Option<Vec<String>> {
    if path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = rel.split('/').collect();
    parts.pop();
    let mut steps = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => {
                parts.push(p);
                steps.push(parts.join("/"));
            }
        }
    }
    steps.push(parts.join("/"));
    Some(steps)
}

/// The outcome of a site before any lookup: `Ok(steps)` or the finding.
pub(super) fn lexical_outcome(rel: &str, site: &IncludeSite) -> Result<Vec<String>, String> {
    let at = format!("{rel}:{}: {}", site.line, site.form);
    let Some(arg) = &site.arg else {
        return Err(format!(
            "{at} with an argument that is not one string literal; the census cannot resolve it (#10300)"
        ));
    };
    if arg.len() > INCLUDE_PATH_CAP {
        return Err(format!(
            "{at} with an argument over {INCLUDE_PATH_CAP} bytes; the census cannot resolve it (#10300)"
        ));
    }
    include_steps(rel, arg).ok_or_else(|| {
        format!(
            "{at} \"{}\" leaves the repository root (#10300)",
            shown(arg)
        )
    })
}

/// What one lookup step found.
enum Step {
    Missing,
    Link,
    Other,
    File { size: u64, dev: u64, ino: u64 },
}

/// One step on disk under `root` (never followed) or, for a tree built in
/// memory, in the tree.
fn look(tree: &Tree, step: &str) -> Result<Step, String> {
    if let Some(root) = &tree.root {
        return match std::fs::symlink_metadata(root.join(step)) {
            Ok(m) if m.file_type().is_symlink() => Ok(Step::Link),
            Ok(m) if m.file_type().is_file() => Ok(Step::File {
                size: m.len(),
                dev: m.dev(),
                ino: m.ino(),
            }),
            Ok(_) => Ok(Step::Other),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Step::Missing),
            Err(e) => Err(format!("errno {}", e.raw_os_error().unwrap_or(-1))),
        };
    }
    if tree.links.iter().any(|l| l == step) {
        return Ok(Step::Link);
    }
    Ok(tree
        .files
        .iter()
        .find(|(r, _)| r == step)
        .map_or(Step::Other, |(_, b)| Step::File {
            size: b.len() as u64,
            dev: 0,
            ino: 0,
        }))
}

/// The target of a site: a regular file of at most [`INCLUDE_CAP`] bytes
/// reached with no symbolic link on any step; else the finding.
fn include_target(tree: &Tree, rel: &str, site: &IncludeSite) -> Result<(String, Step), String> {
    let steps = lexical_outcome(rel, site)?;
    let arg = site.arg.as_deref().unwrap_or_default();
    let target = steps.last().cloned().unwrap_or_default();
    let named = format!(
        "{rel}:{}: {} \"{}\" names {}",
        site.line,
        site.form,
        shown(arg),
        shown(&target)
    );
    let mut last = Step::Other;
    for step in &steps {
        last = if step.is_empty() {
            Step::Other
        } else {
            look(tree, step).map_err(|e| format!("{named}, which cannot be read ({e}) (#10300)"))?
        };
        match last {
            Step::Link => {
                return Err(format!(
                    "{named}, a symbolic link or a path through one; the census never follows links (#10300)"
                ));
            }
            Step::Missing => return Err(format!("{named}, which is not a regular file (#10300)")),
            _ => {}
        }
    }
    match last {
        Step::File { size, .. } if size > INCLUDE_CAP => Err(format!(
            "{named}, a file over {INCLUDE_CAP} bytes; the census does not read it (#10300)"
        )),
        Step::File { .. } => Ok((target, last)),
        _ => Err(format!("{named}, which is not a regular file (#10300)")),
    }
}

/// The bytes of a code target found by [`include_target`]: read at most
/// [`INCLUDE_CAP`] bytes, and refused when the file read is not the file
/// looked up.
fn read_target(tree: &Tree, target: &str, found: &Step) -> Result<Vec<u8>, String> {
    let Some(root) = &tree.root else {
        return tree
            .files
            .iter()
            .find(|(r, _)| r == target)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| format!("{target}: not in the tree (#10300)"));
    };
    let fail = |e: std::io::Error| {
        format!(
            "{target}: cannot be read (errno {}) (#10300)",
            e.raw_os_error().unwrap_or(-1)
        )
    };
    let file = std::fs::File::open(root.join(target)).map_err(fail)?;
    let m = file.metadata().map_err(fail)?;
    if !matches!(found, Step::File { dev, ino, .. } if *dev == m.dev() && *ino == m.ino()) {
        return Err(format!(
            "{target}: changed while the census read it; the census never follows links (#10300)"
        ));
    }
    let mut bytes = Vec::new();
    file.take(INCLUDE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() as u64 > INCLUDE_CAP {
        return Err(format!(
            "{target}: grew over {INCLUDE_CAP} bytes while the census read it (#10300)"
        ));
    }
    Ok(bytes)
}

/// Follow every include site of `lexed`: each target not yet lexed is lexed
/// as Rust and appended, so its own sites follow the same rule (a visited set
/// bounds cycles and the cost), and each site that cannot be resolved is a
/// finding.
pub(super) fn join_includes(
    tree: &Tree,
    lexed: &mut Vec<(String, Vec<Lexed>)>,
    errors: &mut Vec<String>,
) {
    let mut seen: BTreeSet<String> = lexed.iter().map(|(r, _)| r.clone()).collect();
    let mut i = 0;
    while i < lexed.len() {
        let rel = lexed[i].0.clone();
        let sites = include_sites(&lexed[i].1);
        i += 1;
        for site in &sites {
            let (target, found) = match include_target(tree, &rel, site) {
                Ok(t) => t,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            if !seen.insert(target.clone()) {
                continue;
            }
            match read_target(tree, &target, &found).map(String::from_utf8) {
                Ok(Ok(text)) => {
                    let toks = lex(&text);
                    lexed.push((target, toks));
                }
                Ok(Err(e)) => errors.push(format!(
                    "{target}: not UTF-8 ({}); the census cannot read it (#10176)",
                    e.utf8_error()
                )),
                Err(e) => errors.push(e),
            }
        }
    }
}

/// The directory that holds the fixture trees of this file.
fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("census_include_10300")
        .join(name)
}

/// Write a fresh fixture tree: `files` are (relative path, text) and `links`
/// are (relative path, link target); returns the census of the tree.
fn include_case(name: &str, files: &[(&str, &str)], links: &[(&str, &str)]) -> Vec<String> {
    let root = fixture_dir(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("#10300: clear the old fixture tree");
    }
    for (rel, text) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a fixture file has a parent"))
            .expect("#10300: create a fixture dir");
        std::fs::write(&p, text).expect("#10300: write a fixture file");
    }
    for (rel, to) in links {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a fixture link has a parent"))
            .expect("#10300: create a fixture dir");
        std::os::unix::fs::symlink(to, &p).expect("#10300: create a fixture link");
    }
    census(&read_tree(&root))
}

fn has(got: &[String], want: &str) {
    assert!(
        got.iter().any(|l| l == want),
        "missing line:\n  {want}\ncensus gave:\n  {}",
        got.join("\n  ")
    );
}

const START: &str = "fn f() { std::process::Command::new(\"x\"); }\n";

#[test]
fn an_include_of_a_non_rs_file_is_lexed_10300() {
    let got = include_case(
        "include_txt",
        &[
            ("src/a.rs", "include!(\"gen.txt\");\n"),
            ("src/gen.txt", START),
        ],
        &[],
    );
    has(
        &got,
        "src/gen.txt:1: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)",
    );
}

#[test]
fn a_path_module_in_a_skipped_dir_is_lexed_10300() {
    let got = include_case(
        "path_skipped",
        &[
            ("src/a.rs", "#[path = \"../target/m.rs\"]\nmod m;\n"),
            ("target/m.rs", START),
        ],
        &[],
    );
    has(
        &got,
        "target/m.rs:1: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)",
    );
}

#[test]
fn a_non_literal_include_argument_is_red_10300() {
    let got = include_case(
        "non_literal",
        &[("src/a.rs", "include!(concat!(\"b\", \".rs\"));\n")],
        &[],
    );
    has(
        &got,
        "src/a.rs:1: include! with an argument that is not one string literal; the census cannot resolve it (#10300)",
    );
}

#[test]
fn an_include_outside_the_root_is_red_10300() {
    let got = include_case(
        "outside_root",
        &[("src/a.rs", "include!(\"../../x\");\n")],
        &[],
    );
    has(
        &got,
        "src/a.rs:1: include! \"../../x\" leaves the repository root (#10300)",
    );
}

#[test]
fn an_include_of_a_link_is_red_10300() {
    let got = include_case(
        "link_target",
        &[
            ("src/a.rs", "include!(\"l.rs\");\n"),
            ("src/real.txt", START),
        ],
        &[("src/l.rs", "real.txt")],
    );
    has(
        &got,
        "src/a.rs:1: include! \"l.rs\" names src/l.rs, a symbolic link or a path through one; the census never follows links (#10300)",
    );
}

/// The site table both scanners read (`scripts/ci/tests/test_census_rows_10286.py`
/// `IncludeSites10300`): (source, [(line, form, literal or null)]), written by
/// hand.
const INCLUDE_PARITY_10300: &str = include_str!("census_include_parity_10300.json");
/// The number of rows of [`INCLUDE_PARITY_10300`].
const INCLUDE_PARITY_ROWS: usize = 22;
/// The size of the generated inputs of the bound tests, in bytes.
const INCLUDE_BOUND_BYTES: usize = 100_000;
/// The wall-clock ceiling of one bound test.
const INCLUDE_BOUND_SECONDS: u64 = 5;

type ParityRow = (String, Vec<(usize, String, Option<String>)>);

#[test]
fn include_sites_match_the_parity_table_10300() {
    let rows: Vec<ParityRow> =
        serde_json::from_str(INCLUDE_PARITY_10300).expect("the #10300 site table is a JSON list");
    assert_eq!(rows.len(), INCLUDE_PARITY_ROWS, "#10300 parity rows");
    let mut bad = Vec::new();
    for (i, (text, want)) in rows.iter().enumerate() {
        let got: Vec<(usize, String, Option<String>)> = include_sites(&lex(text))
            .into_iter()
            .map(|s| (s.line, s.form.to_string(), s.arg))
            .collect();
        if &got != want {
            bad.push(format!("row {i}: {text:?} gave {got:?}"));
        }
    }
    assert!(bad.is_empty(), "#10300 site table:\n{}", bad.join("\n"));
}

#[test]
fn include_sites_are_linear_on_large_inputs_10300() {
    let flat = "include!(\"a.rs\");\n".repeat(INCLUDE_BOUND_BYTES / 18 + 1);
    let depth = INCLUDE_BOUND_BYTES / 12;
    let nested = format!(
        "#[{}path = \"p.rs\"{}]\nmod m;\n",
        "cfg_attr(a, ".repeat(depth),
        ")".repeat(depth)
    );
    for (text, want) in [(&flat, INCLUDE_BOUND_BYTES / 18 + 1), (&nested, 1)] {
        assert!(text.len() >= INCLUDE_BOUND_BYTES, "#10300 bound input size");
        let t0 = Instant::now();
        let got = include_sites(&lex(text));
        assert!(
            t0.elapsed() < Duration::from_secs(INCLUDE_BOUND_SECONDS),
            "#10300: {} bytes took {:?}",
            text.len(),
            t0.elapsed()
        );
        assert_eq!(got.len(), want, "#10300 sites of a bound input");
    }
}

#[test]
fn an_include_str_target_is_not_lexed_10300() {
    let got = include_case(
        "include_str_data",
        &[
            ("src/a.rs", "const X: &str = include_str!(\"d.txt\");\n"),
            ("src/d.txt", START),
        ],
        &[],
    );
    assert!(
        got.iter().all(|l| !l.starts_with("src/d.txt")),
        "#10300: a data include was lexed:\n  {}",
        got.join("\n  ")
    );
}
