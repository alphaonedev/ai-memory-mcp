// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4200 — ONE resolver for "which `src/` files are test-only", shared by
//! every Rust structural gate that scans `src/`: B7 (#4149) and the #2445
//! raw-open funnel ceiling. Each gate once read files standalone and
//! trusted only an in-file `#[cfg(test)]`. So an out-of-line module declared
//! test-only by its PARENT (`#[cfg(test)] mod owner_gate_txn_3957;`) was
//! scanned as production, first by B7 (#4149) and then by #2445 (#4200). Two
//! copies of this rule could disagree, which is how the second gate stayed
//! red after the first was fixed. Included with `#[path]`, never copied.

#![allow(dead_code)]

use std::collections::HashSet;

/// Whether a `#[cfg(...)]` attribute makes its item TEST-ONLY: `cfg(test)`,
/// or `cfg(all(..))` with `test` as a top-level member. `any(test, ..)` and
/// `not(test)` are production. Erring here scans more, which can only
/// false-red a gate, never hide production code.
pub fn cfg_requires_test(attr: &str) -> bool {
    let Some(pred) = attr
        .strip_prefix("#[cfg(")
        .and_then(|r| r.strip_suffix(")]"))
    else {
        return false;
    };
    let pred = pred.trim();
    if pred == "test" {
        return true;
    }
    let Some(inner) = pred.strip_prefix("all(").and_then(|r| r.strip_suffix(')')) else {
        return false;
    };
    let (mut depth, mut member, mut members) = (0i32, String::new(), Vec::new());
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                members.push(std::mem::take(&mut member));
                continue;
            }
            _ => {}
        }
        member.push(c);
    }
    members.push(member);
    members.iter().any(|m| m.trim() == "test")
}

/// Strip a leading visibility modifier from a trimmed declaration line.
fn strip_visibility(t: &str) -> &str {
    if t.starts_with("pub(") {
        return t.find(')').map_or(t, |close| t[close + 1..].trim_start());
    }
    t.strip_prefix("pub ").map_or(t, str::trim_start)
}

/// #4149 — the files that are compiled ONLY under `cfg(test)` because their
/// MODULE DECLARATION says so: `#[cfg(test)]` immediately followed by an
/// out-of-line `mod NAME;` (any visibility) in a parent file. Test-ness is
/// decided by the DECLARATION, never by a test-looking file name (the #4054
/// rule: a name proves nothing, and an undeclared file is production). A
/// declared test-only module's own children are test-only too.
///
/// `files` are `(rel path under the crate root, source)` pairs; the result
/// holds rel paths such as `src/store/sqlite/owner_gate_txn_3957.rs`.
pub fn cfg_test_declared_files(files: &[(String, String)]) -> HashSet<String> {
    let known: HashSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let mut out: HashSet<String> = HashSet::new();
    for (rel, src) in files {
        // The directory a child module of `rel` lives in.
        let dir =
            if rel.ends_with("/mod.rs") || rel.ends_with("/lib.rs") || rel.ends_with("/main.rs") {
                rel.rsplit_once('/')
                    .map_or_else(String::new, |(d, _)| d.to_string())
            } else {
                rel.trim_end_matches(".rs").to_string()
            };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !cfg_requires_test(line.trim()) {
                continue;
            }
            let Some(next) = lines
                .iter()
                .skip(i + 1)
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
            else {
                continue;
            };
            let decl = strip_visibility(next);
            let Some(rest) = decl.strip_prefix("mod ") else {
                continue;
            };
            let Some(name) = rest.strip_suffix(';') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            for cand in [format!("{dir}/{name}.rs"), format!("{dir}/{name}/mod.rs")] {
                if known.contains(cand.as_str()) {
                    out.insert(cand);
                }
            }
        }
    }
    // Children of a test-only module are test-only: a file under the
    // module's directory (`src/a/x.rs` declared -> `src/a/x/**`).
    let roots: Vec<String> = out
        .iter()
        .map(|p| {
            p.trim_end_matches("/mod.rs")
                .trim_end_matches(".rs")
                .to_string()
                + "/"
        })
        .collect();
    for (rel, _) in files {
        if roots.iter().any(|r| rel.starts_with(r.as_str())) {
            out.insert(rel.clone());
        }
    }
    out
}

/// #4179 — the offset (in lines, from `lines[0]`, the `mod NAME {` line) of
/// the line holding the brace that CLOSES that module. One lexer pass carries
/// its state across lines: normal strings with escapes, raw strings
/// (`r"…"`, `r#"…"#`, `br…`), nested block comments, line comments, and char
/// literals vs lifetimes. A `{` or `}` inside any of them cannot move the
/// match.
///
/// FAILS CLOSED (f2r, #4179 review). A module whose closing brace is never
/// found panics instead of being stripped to end-of-file, because a strip to
/// EOF would hide every production caller after it.
pub fn cfg_test_mod_close_offset(lines: &[&str], decl_line: usize) -> usize {
    let text = lines.join("\n");
    let c: Vec<char> = text.chars().collect();
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let (mut i, mut line, mut depth) = (0usize, 0usize, 0i64);
    let mut opened = false;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let mut comment_depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    comment_depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    comment_depth -= 1;
                    i += 2;
                    if comment_depth == 0 {
                        break;
                    }
                } else {
                    if c[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            continue;
        }
        let prev_ident = i > 0 && is_ident(c[i - 1]);
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
                i = j + 1;
                while i < c.len() {
                    if c[i] == '"' && (1..=hashes).all(|h| c.get(i + h) == Some(&'#')) {
                        i += 1 + hashes;
                        break;
                    }
                    if c[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
                continue;
            }
        }
        if ch == '"' {
            i += 1;
            while i < c.len() {
                match c[i] {
                    '\\' => {
                        if c.get(i + 1) == Some(&'\n') {
                            line += 1;
                        }
                        i += 2;
                    }
                    '"' => {
                        i += 1;
                        break;
                    }
                    '\n' => {
                        line += 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }
        if ch == '\'' && (next == Some('\\') || c.get(i + 2) == Some(&'\'')) {
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    i += 2;
                    continue;
                }
                i += 1;
                if c[i - 1] == '\'' {
                    break;
                }
            }
            continue;
        }
        if ch == '{' {
            depth += 1;
            opened = true;
        } else if ch == '}' {
            depth -= 1;
            if opened && depth == 0 {
                return line;
            }
        }
        i += 1;
    }
    panic!(
        "#4179 census strip: the cfg(test) module declared at src line {} never closes \
         (depth {depth} at end of file); refusing to strip to EOF, which would hide \
         every later production caller",
        decl_line + 1
    );
}

/// #4198 — `text` with every INLINE test-only module body removed (a
/// `cfg(test)` / `cfg(all(.., test, ..))` attribute, optionally followed by
/// further attributes, then `mod NAME {`). Everything else is kept.
/// FAILS CLOSED: an unclosed module panics ([`cfg_test_mod_close_offset`]).
pub fn strip_cfg_test_inline_mods(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        if cfg_requires_test(lines[i].trim()) {
            let mut d_at = i + 1;
            while lines.get(d_at).is_some_and(|l| l.trim().starts_with("#[")) {
                d_at += 1;
            }
            let opens_inline_mod = lines.get(d_at).is_some_and(|d| {
                let d = strip_visibility(d.trim());
                d.starts_with("mod ") && d.ends_with('{')
            });
            if opens_inline_mod {
                i = d_at + cfg_test_mod_close_offset(&lines[d_at..], d_at) + 1;
                continue;
            }
        }
        out.push_str(lines[i]);
        out.push('\n');
        i += 1;
    }
    out
}

/// #4198 — THE production view of `src/` for every structural scanner:
/// `(path relative to root, production text)` for each `src/**/*.rs`, sorted,
/// EXCLUDING files a parent declares test-only ([`cfg_test_declared_files`])
/// and with every inline test-only module body removed
/// ([`strip_cfg_test_inline_mods`]). A test-looking file NAME is never a
/// reason to skip (#4054). A scanner that decides test-ness on its own can
/// disagree with this one; that is the #4149/#4200 failure, three times.
///
/// # Panics
/// On an unreadable file, an empty tree (anti-vacuity), or an unclosed
/// test-only module.
pub fn production_sources(root: &std::path::Path) -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(&root.join("src"), &mut paths);
    paths.sort();
    assert!(
        paths.len() > 100,
        "production_sources must see the whole src tree"
    );
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            (rel, text)
        })
        .collect();
    let test_only = cfg_test_declared_files(&files);
    files
        .into_iter()
        .filter(|(rel, _)| !test_only.contains(rel))
        .map(|(rel, text)| {
            let prod = strip_cfg_test_inline_mods(&text);
            (rel, prod)
        })
        .collect()
}
