// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10257 (GA standard 1) — whole-`src/` production allowlist ratchet
//! forbidding untracked truncating file writes (`std::fs::write`, `fs::write`,
//! `File::create`, `OpenOptions::truncate(true)`, and their `use`/`type` aliases).
//!
//! Uses the repository's shared `#4198` compiler-accurate production view
//! (`tests/common/cfg_test_modules.rs::production_sources`), which walks the
//! full module graph from `src/lib.rs` and `src/main.rs`, rejects orphan `.rs`
//! files, excludes only modules declared under `#[cfg(test)]`, and strips
//! inline `#[cfg(test)]` modules fail-closed.
//!
//! `src/cli/governance_migrate.rs` is NOT on `ALLOWLIST`: every config write
//! there routes through `snapshot_file::write_replacing` with a prior
//! `snapshot_file::write_new_private_unique` backup.
//!
//! The allowlist is exact in both directions: adding a new truncating write,
//! increasing a file's count, or retiring a site without shrinking the table
//! fails the ratchet.

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Non-`src/` top-level directories excluded from this production-code ratchet,
/// each with its reason (per whole-source-tree ratchet discipline).
const EXCLUDED_NON_PRODUCTION_DIRS: &[(&str, &str)] = &[
    (
        "tests",
        "integration test binaries; seed/tamper sandbox fixtures, never shipped",
    ),
    ("benches", "criterion benchmark harnesses, never shipped"),
    ("examples", "standalone example binaries, never shipped"),
    ("target", "cargo build output, generated, never tracked"),
    (".git", "git object store, not source"),
    (
        ".local-runs",
        "gitignored agent scratch (project no-tmp rule)",
    ),
    (".codegraph", "gitignored navigation index"),
    (
        "node_modules",
        "gitignored JavaScript dependencies of site tooling",
    ),
    (
        "vendor",
        "vendored third-party crates, not first-party ai-memory source",
    ),
];

/// Exact allowlist of permitted production truncating-write sites under `src/`:
/// `(relative_path, exact_site_count, reason_with_issue_where_applicable)`.
///
/// `src/cli/governance_migrate.rs` is deliberately absent (#10257).
const ALLOWLIST: &[(&str, usize, &str)] = &[
    (
        "src/audit.rs",
        1,
        "temp-then-rename high-water mark write to .tmp followed by sync_all + rename (src/audit.rs:705-712)",
    ),
    (
        "src/background/fts_integrity.rs",
        1,
        "tracked sibling lane #10256: FTS integrity verdict sidecar write (src/background/fts_integrity.rs:439)",
    ),
    (
        "src/cli/commands/config.rs",
        2,
        "tracked sibling lanes #10282 / #10334: config migrate and clean_claude_json writes (src/cli/commands/config.rs:674,928)",
    ),
    (
        "src/cli/install.rs",
        1,
        "tracked sibling lane (install config rewrite, src/cli/install.rs:501)",
    ),
    (
        "src/cli/logs.rs",
        1,
        "operator CLI `logs compress` writing new .zst output archive beside rotated log (src/cli/logs.rs:1022; reported to conductor)",
    ),
    (
        "src/cli/offload.rs",
        1,
        "operator CLI `deref --out PATH` writing dereferenced content to operator-chosen output path (src/cli/offload.rs:129)",
    ),
    (
        "src/cli/rules.rs",
        2,
        "tracked sibling lane #10258: #[cfg(not(unix))] operator keypair writes (src/cli/rules.rs:754,784)",
    ),
    (
        "src/config.rs",
        1,
        "tracked sibling lane #10259: write_default_if_missing default config creation (src/config.rs:10541)",
    ),
    (
        "src/erasure/store.rs",
        2,
        "temp-dir-then-rename erasure bundle publish: writes shard and manifest inside unique tmp_dir, fsyncs both + tmp_dir, then renames dir (src/erasure/store.rs:420,431)",
    ),
    (
        "src/federation/erasure_outbox.rs",
        1,
        "erasure-outbox drainability marker sidecar write (src/federation/erasure_outbox.rs:246; reported to conductor)",
    ),
    (
        "src/forensic/bundle.rs",
        1,
        "operator CLI `export-forensic-bundle` writing ustar tarball to operator-chosen output path (src/forensic/bundle.rs:1448)",
    ),
    (
        "src/mcp/shutdown.rs",
        1,
        "#[cfg(any(test, debug_assertions))] test-hold synchronization marker `entered`, compiled to no-op in release builds (src/mcp/shutdown.rs:557)",
    ),
    (
        "src/mcp/tools/skill_export.rs",
        2,
        "operator/caller-requested skill export writing SKILL.md and resource files inside jailed export directory (src/mcp/tools/skill_export.rs:650,754)",
    ),
];

/// Strip Rust line comments, nested block comments, string / byte-string /
/// C-string / raw-string literals, and char / byte literals while preserving
/// newlines and lifetimes (`'a`).
fn strip_comments_and_literals(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut out = String::with_capacity(src.len());
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
                    out.push(if c[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            continue;
        }
        let prev_ident = i > 0 && is_ident(c[i - 1]);
        let raw_at = if ch == 'r' && !prev_ident {
            Some(i + 1)
        } else if matches!(ch, 'b' | 'c') && next == Some('r') && !prev_ident {
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
                for _ in i..=j {
                    out.push(' ');
                }
                i = j + 1;
                while i < c.len() {
                    if c[i] == '"' && (1..=hashes).all(|h| c.get(i + h) == Some(&'#')) {
                        for _ in 0..=hashes {
                            out.push(' ');
                        }
                        i += 1 + hashes;
                        break;
                    }
                    out.push(if c[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                continue;
            }
        }
        if matches!(ch, 'b' | 'c') && next == Some('"') && !prev_ident {
            out.push_str("  ");
            i += 2;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    if let Some(&e) = c.get(i + 1) {
                        out.push(if e == '\n' { '\n' } else { ' ' });
                    }
                    i += 2;
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if c[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        if ch == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    if let Some(&e) = c.get(i + 1) {
                        out.push(if e == '\n' { '\n' } else { ' ' });
                    }
                    i += 2;
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if c[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        // Byte/char literal: `'x'`, `'\n'`, `b'x'`, `b'\x00'`; keep lifetimes like `'a`.
        let char_start = if ch == 'b' && next == Some('\'') && !prev_ident {
            Some(i + 1)
        } else if ch == '\'' {
            Some(i)
        } else {
            None
        };
        if let Some(q) = char_start {
            let after_q = c.get(q + 1).copied();
            let is_char_lit = after_q == Some('\\') || c.get(q + 2) == Some(&'\'');
            if is_char_lit {
                for _ in i..=q {
                    out.push(' ');
                }
                i = q + 1;
                while i < c.len() {
                    if c[i] == '\\' {
                        out.push_str("  ");
                        i += 2;
                        continue;
                    }
                    if c[i] == '\'' {
                        out.push(' ');
                        i += 1;
                        break;
                    }
                    out.push(if c[i] == '\n' { '\n' } else { ' ' });
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    ColonColon,
    Dot,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LAngle,
    RAngle,
    Semi,
    Comma,
    Eq,
    Other(char),
}

fn tokenize(stripped: &str) -> Vec<(Tok, usize)> {
    let bytes = stripped.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            toks.push((Tok::Ident(stripped[start..i].to_string()), line));
            continue;
        }
        if b == b':' && bytes.get(i + 1) == Some(&b':') {
            toks.push((Tok::ColonColon, line));
            i += 2;
            continue;
        }
        let tok = match b {
            b'.' => Tok::Dot,
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'{' => Tok::LBrace,
            b'}' => Tok::RBrace,
            b'<' => Tok::LAngle,
            b'>' => Tok::RAngle,
            b';' => Tok::Semi,
            b',' => Tok::Comma,
            b'=' => Tok::Eq,
            other => Tok::Other(other as char),
        };
        toks.push((tok, line));
        i += 1;
    }
    toks
}

#[derive(Default)]
struct Aliases {
    fs_mods: BTreeSet<String>,
    file_types: BTreeSet<String>,
    write_fns: BTreeSet<String>,
}

/// Recursively parse a `use` tree (after the `use` keyword up to `;`) to
/// capture `fs`, `File`, and `fs::write` imports and aliases.
fn parse_use_tree(toks: &[(Tok, usize)], pos: &mut usize, prefix: &[String], out: &mut Aliases) {
    let mut segs: Vec<String> = prefix.to_vec();
    while *pos < toks.len() {
        match &toks[*pos].0 {
            Tok::ColonColon => {
                *pos += 1;
            }
            Tok::Ident(name) => {
                let name = name.clone();
                *pos += 1;
                if *pos < toks.len() && toks[*pos].0 == Tok::ColonColon {
                    segs.push(name);
                    *pos += 1;
                    if *pos < toks.len() && toks[*pos].0 == Tok::LBrace {
                        *pos += 1;
                        while *pos < toks.len() && toks[*pos].0 != Tok::RBrace {
                            parse_use_tree(toks, pos, &segs, out);
                            if *pos < toks.len() && toks[*pos].0 == Tok::Comma {
                                *pos += 1;
                            }
                        }
                        if *pos < toks.len() && toks[*pos].0 == Tok::RBrace {
                            *pos += 1;
                        }
                        return;
                    }
                    continue;
                }
                let mut leaf = segs.clone();
                if name != "self" {
                    leaf.push(name);
                }
                let alias = if *pos + 1 < toks.len()
                    && matches!(&toks[*pos].0, Tok::Ident(kw) if kw == "as")
                {
                    *pos += 1;
                    if let Tok::Ident(a) = &toks[*pos].0 {
                        let a = a.clone();
                        *pos += 1;
                        Some(a)
                    } else {
                        None
                    }
                } else {
                    None
                };
                record_use_leaf(&leaf, alias.as_deref(), out);
                return;
            }
            Tok::LBrace => {
                *pos += 1;
                while *pos < toks.len() && toks[*pos].0 != Tok::RBrace {
                    parse_use_tree(toks, pos, &segs, out);
                    if *pos < toks.len() && toks[*pos].0 == Tok::Comma {
                        *pos += 1;
                    }
                }
                if *pos < toks.len() && toks[*pos].0 == Tok::RBrace {
                    *pos += 1;
                }
                return;
            }
            Tok::Semi | Tok::Comma | Tok::RBrace => return,
            _ => {
                *pos += 1;
            }
        }
    }
}

fn record_use_leaf(path: &[String], alias: Option<&str>, out: &mut Aliases) {
    let Some(last) = path.last().map(String::as_str) else {
        return;
    };
    let prev = path
        .len()
        .checked_sub(2)
        .and_then(|idx| path.get(idx))
        .map(String::as_str);
    let bound = alias.unwrap_or(last);
    if bound == "_" {
        return;
    }
    if last == "fs" {
        out.fs_mods.insert(bound.to_string());
    } else if last == "File" && matches!(prev, Some("fs") | None) {
        out.file_types.insert(bound.to_string());
    } else if last == "write" && prev == Some("fs") {
        out.write_fns.insert(bound.to_string());
    }
}

fn collect_aliases(toks: &[(Tok, usize)]) -> Aliases {
    let mut out = Aliases::default();
    out.fs_mods.insert("fs".to_string());
    out.file_types.insert("File".to_string());

    let mut i = 0;
    while i < toks.len() {
        match &toks[i].0 {
            Tok::Ident(kw) if kw == "use" => {
                i += 1;
                parse_use_tree(toks, &mut i, &[], &mut out);
                while i < toks.len() && toks[i].0 != Tok::Semi {
                    i += 1;
                }
                if i < toks.len() {
                    i += 1;
                }
            }
            Tok::Ident(kw) if kw == "type" => {
                // `type Alias = ...::File;`
                if let Some((Tok::Ident(alias), _)) = toks.get(i + 1)
                    && toks.get(i + 2).is_some_and(|(t, _)| *t == Tok::Eq)
                {
                    let mut j = i + 3;
                    let mut last_ident: Option<&str> = None;
                    while j < toks.len() && toks[j].0 != Tok::Semi {
                        if let Tok::Ident(id) = &toks[j].0 {
                            last_ident = Some(id.as_str());
                        }
                        j += 1;
                    }
                    if last_ident.is_some_and(|id| out.file_types.contains(id)) {
                        out.file_types.insert(alias.clone());
                    }
                    i = j + usize::from(j < toks.len());
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Return line numbers of every truncating file write in `src` (outside `use`
/// declarations):
/// - `<fs_or_alias>::write` (call, fn pointer, table entry, match arm)
/// - directly imported `std::fs::write` (or alias)
/// - `<File_or_alias>::create` or `<...::File>::create`
/// - `.truncate(true)` (OpenOptions truncating open, single-line or multi-line)
fn find_truncating_write_lines(src: &str) -> Vec<usize> {
    let stripped = strip_comments_and_literals(src);
    let toks = tokenize(&stripped);
    let aliases = collect_aliases(&toks);

    let mut hits = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        // Skip `use ...;` statements so `use std::fs::write;` itself is not
        // counted as a write site.
        if matches!(&toks[i].0, Tok::Ident(kw) if kw == "use") {
            while i < toks.len() && toks[i].0 != Tok::Semi {
                i += 1;
            }
            if i < toks.len() {
                i += 1;
            }
            continue;
        }

        // Pattern A: `<fs_alias>::write` or `<File_alias>::create`
        if let Tok::Ident(qual) = &toks[i].0
            && toks.get(i + 1).is_some_and(|(t, _)| *t == Tok::ColonColon)
            && let Some((Tok::Ident(member), line)) = toks.get(i + 2)
        {
            if member == "write" && aliases.fs_mods.contains(qual) {
                hits.push(*line);
                i += 3;
                continue;
            }
            if member == "create" && aliases.file_types.contains(qual) {
                hits.push(*line);
                i += 3;
                continue;
            }
        }

        // Pattern B: UFCS `<File>::create` or `<std::fs::File>::create`
        if toks[i].0 == Tok::RAngle
            && i > 0
            && let Tok::Ident(qual) = &toks[i - 1].0
            && aliases.file_types.contains(qual)
            && toks.get(i + 1).is_some_and(|(t, _)| *t == Tok::ColonColon)
            && matches!(toks.get(i + 2), Some((Tok::Ident(m), _)) if m == "create")
        {
            hits.push(toks[i + 2].1);
            i += 3;
            continue;
        }

        // Pattern C: `.truncate(true)`
        if toks[i].0 == Tok::Dot
            && matches!(toks.get(i + 1), Some((Tok::Ident(m), _)) if m == "truncate")
            && toks.get(i + 2).is_some_and(|(t, _)| *t == Tok::LParen)
            && matches!(toks.get(i + 3), Some((Tok::Ident(v), _)) if v == "true")
            && toks.get(i + 4).is_some_and(|(t, _)| *t == Tok::RParen)
        {
            hits.push(toks[i + 1].1);
            i += 5;
            continue;
        }

        // Pattern D: bare imported `write` (or alias of `std::fs::write`),
        // not preceded by `.` or `::` and not a `fn write` declaration.
        if let Tok::Ident(name) = &toks[i].0
            && aliases.write_fns.contains(name)
        {
            let prev = i.checked_sub(1).and_then(|p| toks.get(p)).map(|(t, _)| t);
            let is_member_or_decl = matches!(prev, Some(Tok::Dot | Tok::ColonColon))
                || matches!(prev, Some(Tok::Ident(kw)) if kw == "fn");
            if !is_member_or_decl {
                hits.push(toks[i].1);
                i += 1;
                continue;
            }
        }

        i += 1;
    }
    hits
}

/// Strip standalone `#[cfg(test)]` / `#[cfg(all(..., test, ...))]` or `#[test]`
/// functions/modules (e.g. `#[cfg(test)] fn recovery_test_barrier` or a
/// top-level `#[test] fn`) that `cfg_test_modules::strip_cfg_test_inline_mods`
/// leaves in place. Only `fn` and `mod` declarations are stripped (never struct
/// fields or statements), using `cfg_test_modules::cfg_test_mod_close_offset`
/// (fail-closed brace scan) so production code after the item is always scanned.
fn strip_test_only_items(src: &str) -> String {
    let masked = strip_comments_and_literals(src);
    let orig_lines: Vec<&str> = src.lines().collect();
    let masked_lines: Vec<&str> = masked.lines().collect();
    let mut kept = vec![true; orig_lines.len()];
    let mut i = 0;
    while i < orig_lines.len() {
        let trimmed = masked_lines[i].trim();
        let is_test_attr = cfg_test_modules::cfg_requires_test(trimmed)
            || trimmed == "#[test]"
            || trimmed == "#[tokio::test]"
            || trimmed.starts_with("#[tokio::test(");
        if is_test_attr {
            let mut d_at = i + 1;
            while masked_lines.get(d_at).is_some_and(|l| {
                let t = l.trim();
                t.is_empty() || t.starts_with("#[")
            }) {
                d_at += 1;
            }
            if let Some(decl_line) = masked_lines.get(d_at) {
                let mut rest = decl_line.trim();
                if let Some(after_pub) = rest.strip_prefix("pub(") {
                    if let Some(close) = after_pub.find(')') {
                        rest = after_pub[close + 1..].trim_start();
                    }
                } else if let Some(after_pub) = rest.strip_prefix("pub ") {
                    rest = after_pub.trim_start();
                }
                for kw in ["async ", "const ", "unsafe "] {
                    if let Some(after) = rest.strip_prefix(kw) {
                        rest = after.trim_start();
                    }
                }
                if rest.starts_with("fn ") || rest.starts_with("mod ") {
                    let mut sig_end = d_at;
                    while sig_end < masked_lines.len()
                        && !masked_lines[sig_end].contains('{')
                        && !masked_lines[sig_end].trim_end().ends_with(';')
                    {
                        sig_end += 1;
                    }
                    if let Some(line) = masked_lines.get(sig_end) {
                        if line.contains('{') {
                            let end = sig_end
                                + cfg_test_modules::cfg_test_mod_close_offset(
                                    &orig_lines[sig_end..],
                                    sig_end,
                                )
                                + 1;
                            kept[i..end].fill(false);
                            i = end;
                            continue;
                        }
                        if line.trim_end().ends_with(';') {
                            kept[i..=sig_end].fill(false);
                            i = sig_end + 1;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    let mut out = String::with_capacity(src.len());
    for (line, keep) in orig_lines.iter().zip(kept) {
        if keep {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn check_sources(
    sources: &[(String, String)],
    allowlist: &[(&str, usize, &str)],
) -> Result<(), Vec<String>> {
    let mut expected: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
    for &(path, count, reason) in allowlist {
        assert!(
            !reason.trim().is_empty(),
            "allowlist entry {path} lacks a reason"
        );
        assert!(
            expected.insert(path, (count, reason)).is_none(),
            "duplicate allowlist entry for {path}"
        );
    }

    let mut actual: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (rel, text) in sources {
        let prod_only = strip_test_only_items(text);
        let lines = find_truncating_write_lines(&prod_only);
        if !lines.is_empty() {
            actual.insert(rel.as_str(), lines);
        }
    }

    let mut violations = Vec::new();
    for (&path, lines) in &actual {
        match expected.get(path) {
            None => violations.push(format!(
                "{path}: {} truncating write site(s) at lines {lines:?} not in ALLOWLIST \
                 (route through snapshot_file::write_replacing)",
                lines.len()
            )),
            Some(&(ceiling, _)) if lines.len() != ceiling => violations.push(format!(
                "{path}: found {} truncating write site(s) at lines {lines:?}, allowlist pins {ceiling}",
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for &path in expected.keys() {
        if !actual.contains_key(path) {
            violations.push(format!(
                "{path}: pinned in ALLOWLIST but has 0 production truncating write sites (remove stale entry)"
            ));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[test]
fn no_truncating_write_outside_allowlist_10257() {
    assert!(
        !ALLOWLIST
            .iter()
            .any(|(path, _, _)| *path == "src/cli/governance_migrate.rs"),
        "src/cli/governance_migrate.rs must never be on the truncating-write allowlist"
    );
    for &(dir, reason) in EXCLUDED_NON_PRODUCTION_DIRS {
        assert_ne!(
            dir, "src",
            "src/ must never be in EXCLUDED_NON_PRODUCTION_DIRS"
        );
        assert!(
            !reason.trim().is_empty(),
            "excluded dir {dir} lacks a reason"
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = cfg_test_modules::production_sources(root);
    if let Err(violations) = check_sources(&sources, ALLOWLIST) {
        panic!(
            "#10257 truncating-write ratchet failed:\n{}",
            violations.join("\n")
        );
    }
}

/// Mutant matrix proving every required spelling, alias, container form, and
/// out-of-directory file trips the ratchet, while non-truncating controls pass.
#[test]
fn ratchet_catches_every_truncating_write_spelling_and_container_10257() {
    let empty_allowlist: &[(&str, usize, &str)] = &[];
    let mutants: &[(&str, &str, &str)] = &[
        (
            "std::fs::write direct",
            "src/cli/governance_migrate.rs",
            "pub fn f(p: &std::path::Path) { let _ = std::fs::write(p, b\"x\"); }",
        ),
        (
            "fs::write via use std::fs",
            "src/cli/governance_migrate.rs",
            "use std::fs;\npub fn f(p: &std::path::Path) { let _ = fs::write(p, b\"x\"); }",
        ),
        (
            "direct use std::fs::write",
            "src/cli/governance_migrate.rs",
            "use std::fs::write;\npub fn f(p: &std::path::Path) { let _ = write(p, b\"x\"); }",
        ),
        (
            "File::create via use std::fs::File",
            "src/cli/governance_migrate.rs",
            "use std::fs::File;\npub fn f(p: &std::path::Path) { let _ = File::create(p); }",
        ),
        (
            "OpenOptions::new().write(true).truncate(true)",
            "src/cli/governance_migrate.rs",
            "use std::fs::OpenOptions;\npub fn f(p: &std::path::Path) {\n    let _ = OpenOptions::new()\n        .write(true)\n        .truncate(true)\n        .open(p);\n}",
        ),
        (
            "alias use std::fs as f; f::write",
            "src/cli/governance_migrate.rs",
            "use std::fs as f;\npub fn g(p: &std::path::Path) { let _ = f::write(p, b\"x\"); }",
        ),
        (
            "alias use std::fs::write as w; w(...)",
            "src/cli/governance_migrate.rs",
            "use std::fs::{self, write as w};\npub fn g(p: &std::path::Path) { let _ = w(p, b\"x\"); }",
        ),
        (
            "File alias + type alias",
            "src/cli/governance_migrate.rs",
            "use std::fs::File as F;\npub fn g(p: &std::path::Path) { let _ = F::create(p); }",
        ),
        (
            "const/array/match container form",
            "src/cli/governance_migrate.rs",
            "pub fn g(k: bool) {\n    let tbl = [std::fs::File::create];\n    let _ = match k { true => tbl[0], false => std::fs::File::create };\n}",
        ),
        (
            "site in another directory outside src/cli/",
            "src/storage/other_dir/writer.rs",
            "pub fn g(p: &std::path::Path) { let _ = std::fs::write(p, b\"x\"); }",
        ),
    ];

    for &(label, path, body) in mutants {
        let sources = vec![(path.to_string(), body.to_string())];
        let err = check_sources(&sources, empty_allowlist)
            .expect_err(&format!("mutant `{label}` must fail the ratchet"));
        assert!(
            err.iter().any(|msg| msg.starts_with(path)),
            "mutant `{label}` must name `{path}`, got {err:?}"
        );
    }

    // Non-truncating controls + #[test] / #[cfg(test)] items must report 0 sites,
    // while a production write directly after a #[test] fn must still be caught.
    let clean = vec![(
        "src/cli/governance_migrate.rs".to_string(),
        r#"
// std::fs::write(p, b"comment")
/* File::create(p) */
const DOC: &str = "std::fs::write OpenOptions::new().truncate(true)";
#[cfg(test)]
fn test_helper(p: &std::path::Path) {
    let _ = std::fs::write(p, b"test-only");
}
#[test]
fn unit_test_fn() {
    let _ = std::fs::write("x", b"test-only");
}
pub fn safe(p: &std::path::Path, v: &mut Vec<u8>) {
    v.truncate(10);
    let _ = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(p);
}
"#
        .to_string(),
    )];
    check_sources(&clean, empty_allowlist).expect("non-truncating controls must pass");

    let after_test_mutant = vec![(
        "src/cli/governance_migrate.rs".to_string(),
        r#"
#[test]
fn unit_test_fn() {
    let _ = std::fs::write("x", b"test-only");
}
pub fn leaked_prod(p: &std::path::Path) {
    let _ = std::fs::write(p, b"prod-leak");
}
"#
        .to_string(),
    )];
    let err = check_sources(&after_test_mutant, empty_allowlist)
        .expect_err("production write after #[test] fn must still fail the ratchet");
    assert!(
        err.iter()
            .any(|msg| msg.starts_with("src/cli/governance_migrate.rs: 1 truncating write")),
        "expected exactly 1 prod site after #[test] fn, got {err:?}"
    );

    // Table-swap mutant: pinning a different path or wrong count must fail.
    let swapped_allowlist: &[(&str, usize, &str)] = &[("src/other/file.rs", 1, "swapped member")];
    let err = check_sources(&after_test_mutant, swapped_allowlist)
        .expect_err("swapped allowlist member must fail the ratchet");
    assert_eq!(
        err.len(),
        2,
        "expected unallowlisted + stale entry, got {err:?}"
    );
}
