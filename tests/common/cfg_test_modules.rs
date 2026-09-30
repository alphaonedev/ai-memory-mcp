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

/// #4198 — the reachability of every `src/` file through the module graph,
/// walked from the crate roots the way rustc resolves it.
#[derive(Debug, Default)]
pub struct ModuleGraph {
    /// Files compiled in a production (non-test) build.
    pub production: HashSet<String>,
    /// Files reachable ONLY through a test-only declaration.
    pub test_only: HashSet<String>,
    /// Files no declaration reaches from the crate roots (strict mode only).
    pub orphans: Vec<String>,
}

/// A walk item: (file, reached test-only, the (path dir, module dir) an
/// included file inherits from its includer).
type WorkItem = (String, bool, Option<(String, String)>);

/// One module-graph edge found in a source file.
enum Edge {
    /// `mod NAME;` (optionally `#[path = ".."]`), inside `inline` inline modules.
    Mod {
        name: String,
        path: Option<String>,
        test: bool,
        inline: Vec<String>,
    },
    /// `include!("..")`: the file's text is part of the including module.
    Include {
        path: String,
        test: bool,
        inline: Vec<String>,
    },
}

/// A copy of `text` with every comment and every string/char literal body
/// blanked to spaces; newlines are kept so line numbers line up.
fn mask_code(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                blank(&mut out, c[i]);
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
                for &k in &c[i..=j] {
                    out.push(k);
                }
                i = j + 1;
                while i < c.len() {
                    if c[i] == '"' && (1..=hashes).all(|h| c.get(i + h) == Some(&'#')) {
                        out.push('"');
                        out.extend(std::iter::repeat_n('#', hashes));
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
            out.push('"');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    blank(&mut out, c[i]);
                    if let Some(&e) = c.get(i + 1) {
                        blank(&mut out, e);
                    }
                    i += 2;
                    continue;
                }
                if c[i] == '"' {
                    out.push('"');
                    i += 1;
                    break;
                }
                blank(&mut out, c[i]);
                i += 1;
            }
            continue;
        }
        if ch == '\'' && (next == Some('\\') || c.get(i + 2) == Some(&'\'')) {
            out.push('\'');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c[i] == '\'' {
                    out.push('\'');
                    i += 1;
                    break;
                }
                blank(&mut out, c[i]);
                i += 1;
            }
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

/// The quoted value of `#[path = "..."]` or `include!("...")` on `line`.
fn quoted(line: &str) -> Option<String> {
    let a = line.find('"')?;
    let b = line[a + 1..].find('"')?;
    Some(line[a + 1..a + 1 + b].to_string())
}

/// Every module-graph edge in `src`, with its test-ness and the inline
/// modules enclosing it.
fn scan_edges(src: &str) -> Vec<Edge> {
    let masked = mask_code(src);
    let orig: Vec<&str> = src.lines().collect();
    let mlines: Vec<&str> = masked.lines().collect();
    // (inline module name, test-only, brace depth outside it)
    let mut stack: Vec<(String, bool, i64)> = Vec::new();
    let mut depth: i64 = 0;
    let mut edges = Vec::new();
    for (i, mline) in mlines.iter().enumerate() {
        let m = strip_visibility(mline.trim());
        let enclosing_test = stack.iter().any(|f| f.1);
        let inline: Vec<String> = stack.iter().map(|f| f.0.clone()).collect();
        if let Some(rest) = m.strip_prefix("mod ") {
            let name: String = rest
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
                .collect();
            let tail = rest[name.len()..].trim_start();
            // Attributes directly above the declaration (doc comments skipped).
            let (mut test, mut path) = (false, None);
            let mut j = i;
            while j > 0 {
                j -= 1;
                let t = orig[j].trim();
                // Rust allows doc comments and blank lines between an
                // attribute and its item.
                if t.is_empty() || t.starts_with("///") || t.starts_with("//!") {
                    continue;
                }
                if !t.starts_with("#[") {
                    break;
                }
                test |= cfg_requires_test(t);
                if t.starts_with("#[path") {
                    path = quoted(t);
                }
            }
            let test = test || enclosing_test;
            if !name.is_empty() && tail.starts_with(';') {
                edges.push(Edge::Mod {
                    name,
                    path,
                    test,
                    inline: inline.clone(),
                });
            } else if !name.is_empty() && tail.starts_with('{') {
                stack.push((name, test, depth));
            }
        }
        if mline.contains("include!(")
            && !mline.contains("include_str!(")
            && let Some(p) = orig.get(i).and_then(|l| quoted(l))
        {
            {
                edges.push(Edge::Include {
                    path: p,
                    test: enclosing_test,
                    inline: inline.clone(),
                });
            }
        }
        for ch in mline.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                while stack.last().is_some_and(|f| f.2 == depth) {
                    stack.pop();
                }
            }
        }
    }
    edges
}

/// Join and normalise a relative path (`..` and `.` segments).
fn join(base: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// Walk the module graph of `files` (`(rel path, source)`).
///
/// Roots are `src/lib.rs` and `src/main.rs`. STRICT: every file must be
/// reached, or it is reported in `orphans`. LENIENT (a synthetic fixture
/// without crate roots): any file nothing reaches becomes a production root,
/// which errs toward scanning more.
///
/// # Panics
/// A `mod NAME;`, `#[path]` or `include!` that resolves to no file in
/// `files`: an unresolved declaration must never silently hide a module.
#[must_use]
pub fn module_graph(files: &[(String, String)], strict: bool) -> ModuleGraph {
    let by_path: std::collections::HashMap<&str, &str> = files
        .iter()
        .map(|(p, s)| (p.as_str(), s.as_str()))
        .collect();
    // file -> reached test-only (false = production)
    let mut state: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    // (file, test, override (file_dir, mod_dir) for included text)
    let mut work: Vec<WorkItem> = Vec::new();
    for root in ["src/lib.rs", "src/main.rs"] {
        if by_path.contains_key(root) {
            work.push((root.to_string(), false, None));
        }
    }
    let drain = |work: &mut Vec<WorkItem>, state: &mut std::collections::HashMap<String, bool>| {
        while let Some((file, test, ctx)) = work.pop() {
            // Production reachability wins; skip an already-covered visit.
            match state.get(&file) {
                Some(&prev) if prev == test || !prev => continue,
                _ => {}
            }
            state.insert(file.clone(), test);
            let src = by_path
                .get(file.as_str())
                .unwrap_or_else(|| panic!("#4198 module graph: {file} is not a src file"));
            let file_dir = file.rsplit_once('/').map_or("", |(d, _)| d).to_string();
            let base_name = file.rsplit('/').next().unwrap_or("");
            let own_mod_dir = if matches!(base_name, "mod.rs" | "lib.rs" | "main.rs") {
                file_dir.clone()
            } else {
                join(&file_dir, base_name.trim_end_matches(".rs"))
            };
            let (path_dir, mod_dir) = ctx.clone().unwrap_or((file_dir.clone(), own_mod_dir));
            for edge in scan_edges(src) {
                match edge {
                    Edge::Mod {
                        name,
                        path,
                        test: t,
                        inline,
                    } => {
                        let in_dir = join(&mod_dir, &inline.join("/"));
                        let target = match path {
                            Some(p) if inline.is_empty() => join(&path_dir, &p),
                            Some(p) => join(&in_dir, &p),
                            None => {
                                let a = join(&in_dir, &format!("{name}.rs"));
                                if by_path.contains_key(a.as_str()) {
                                    a
                                } else {
                                    join(&in_dir, &format!("{name}/mod.rs"))
                                }
                            }
                        };
                        let child_test = test || t;
                        if !by_path.contains_key(target.as_str()) {
                            // A TEST-ONLY module may live outside src/ (e.g. a
                            // `#[path = "../../../tests/unit/x.rs"]` cell file);
                            // it is not src code, so no src scanner reads it.
                            assert!(
                                child_test && !target.starts_with("src/"),
                                "#4198 module graph: `mod {name};` in {file} resolves to {target}, \
                                 which is not a src file (an unresolved declaration must not hide a module)"
                            );
                            continue;
                        }
                        work.push((target, child_test, None));
                    }
                    Edge::Include {
                        path,
                        test: t,
                        inline,
                    } => {
                        let target = join(&file_dir, &path);
                        assert!(
                            by_path.contains_key(target.as_str()),
                            "#4198 module graph: include!(\"{path}\") in {file} resolves to {target}, \
                             which is not a src file"
                        );
                        let in_dir = join(&mod_dir, &inline.join("/"));
                        work.push((target, test || t, Some((path_dir.clone(), in_dir))));
                    }
                }
            }
        }
    };
    drain(&mut work, &mut state);
    let mut orphans = Vec::new();
    let mut sorted: Vec<&String> = files.iter().map(|(p, _)| p).collect();
    sorted.sort();
    for p in sorted {
        let is_rs = std::path::Path::new(p.as_str())
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if !is_rs || state.contains_key(p.as_str()) {
            continue;
        }
        if strict {
            orphans.push(p.clone());
        } else {
            work.push((p.clone(), false, None));
            drain(&mut work, &mut state);
        }
    }
    let mut g = ModuleGraph {
        orphans,
        ..ModuleGraph::default()
    };
    for (p, t) in state {
        if t {
            g.test_only.insert(p);
        } else {
            g.production.insert(p);
        }
    }
    g
}

/// #4149/#4200 — the files compiled ONLY under `cfg(test)`, by DECLARATION
/// (never by a test-looking file name, #4054). Lenient [`module_graph`]
/// walk: a file nothing declares is production. `#[path]`, attributes
/// between the cfg and the `mod`, and children declared inside inline test
/// modules are followed (#4198).
#[must_use]
pub fn cfg_test_declared_files(files: &[(String, String)]) -> HashSet<String> {
    module_graph(files, false).test_only
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
    let graph = module_graph(&files, true);
    assert!(
        graph.orphans.is_empty(),
        "#4198 production_sources: src files no declaration reaches from src/lib.rs or \
         src/main.rs (unaccounted code is never silently skipped): {:?}",
        graph.orphans
    );
    files
        .into_iter()
        .filter(|(rel, _)| graph.production.contains(rel))
        .map(|(rel, text)| {
            let prod = strip_cfg_test_inline_mods(&text);
            (rel, prod)
        })
        .collect()
}
