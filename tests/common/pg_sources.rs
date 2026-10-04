// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared source loader for the Postgres-adapter structural scanners (#4023).
//!
//! The Postgres adapter is `src/store/postgres.rs` PLUS every child module
//! under `src/store/postgres/`. Moving a method body into a child module (as
//! #4023 did for `pg_merge_inbound`) must not hide it from a text scanner:
//! the #3175 record-stop parity scan, the B9 write-gate scan and the
//! #2393/#2397 write-funnel scan all read their source through THIS ONE
//! loader (#4198 lesson: one helper, not three hand-rolled `read_to_string`
//! calls that each silently go stale when code moves).
//!
//! Fail closed (ERRORS-09): the loader panics rather than return a short
//! set. It asserts that
//!   - `postgres.rs` itself is present and non-empty,
//!   - the child set is non-empty and contains the pinned children in
//!     [`EXPECTED_CHILDREN`] (so a scanner can never silently scan nothing),
//!   - every `mod <name>;` that `postgres.rs` declares at column 0 has a
//!     loaded file, and every loaded child is declared (no orphan, no
//!     undiscovered module).
//!
//! Leaf module, `std` only; take it with the `#[path]` idiom:
//!
//! ```ignore
//! #[path = "common/pg_sources.rs"]
//! mod pg_sources;
//! ```

#![allow(dead_code, clippy::missing_panics_doc)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The adapter root file, relative to the crate root.
pub const PG_ROOT_REL: &str = "src/store/postgres.rs";
/// The adapter child-module directory, relative to the crate root.
pub const PG_CHILD_DIR_REL: &str = "src/store/postgres";

/// Child modules that MUST be discovered. Pins the discovery itself: if the
/// directory walk ever returned a subset, the scanners would silently stop
/// seeing these bodies. `merge_inbound_4023.rs` is the module the #4023 move
/// created; the rest are long-standing children that hold write paths.
pub const EXPECTED_CHILDREN: &[&str] = &[
    "src/store/postgres/merge_inbound_4023.rs",
    "src/store/postgres/reown_3124.rs",
    "src/store/postgres/federation_3075.rs",
    "src/store/postgres/lifecycle_tx_3152.rs",
    "src/store/postgres/swarm_rewind.rs",
];

/// One adapter source file: crate-relative path (forward slashes) + LF text.
#[derive(Debug, Clone)]
pub struct PgSource {
    pub rel: String,
    pub text: String,
}

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_lf(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("pg_sources: read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let rd = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("pg_sources: read_dir {}: {e}", dir.display()));
    for entry in rd {
        let entry = entry.unwrap_or_else(|e| panic!("pg_sources: dir entry: {e}"));
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn rel_of(path: &Path) -> String {
    path.strip_prefix(crate_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// A `mod <name>;` declaration in `postgres.rs`: the module name and, when a
/// `#[path = "..."]` attribute precedes it, that path (relative to the
/// directory holding `postgres.rs`).
struct DeclaredMod {
    name: String,
    path_attr: Option<String>,
}

/// Modules declared as `mod <name>;` / `pub mod <name>;` at column 0.
fn declared_children(root_text: &str) -> Vec<DeclaredMod> {
    let mut out = Vec::new();
    let mut pending_path: Option<String> = None;
    for line in root_text.lines() {
        if let Some(rest) = line.strip_prefix("#[path = \"") {
            if let Some(p) = rest.strip_suffix("\"]") {
                pending_path = Some(p.to_string());
            }
            continue;
        }
        let rest = line
            .strip_prefix("pub(crate) mod ")
            .or_else(|| line.strip_prefix("pub(super) mod "))
            .or_else(|| line.strip_prefix("pub mod "))
            .or_else(|| line.strip_prefix("mod "));
        let Some(rest) = rest else {
            if !line.starts_with("#[") && !line.trim().is_empty() && !line.starts_with("//") {
                pending_path = None;
            }
            continue;
        };
        // 2026-10-03 (GOD ai:god-zsg): drop a trailing LINE COMMENT before looking for the `;`.
        // `rest.strip_suffix(';')` alone returned None for `mod governance_chain_4477; // #4477 …`,
        // so three modules the unit and #4478 declared read as UNDECLARED and the batch-7 census
        // failed 5/5 in 3175 and 4/6 in 2397 — while those scanners, being red, asserted nothing
        // about the parity they exist to check. A `mod x;` line may carry a comment; a scanner that
        // breaks on one depends on the textual shape of valid Rust beside the declaration it reads,
        // which is the defect, not the declaration (rule k). A `mod` line cannot contain a string
        // literal, so splitting on the first `//` is safe here.
        let rest = rest.split("//").next().unwrap_or(rest).trim_end();
        if let Some(name) = rest.strip_suffix(';') {
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                out.push(DeclaredMod {
                    name: name.to_string(),
                    path_attr: pending_path.take(),
                });
            }
        }
        pending_path = None;
    }
    out
}

/// #4504-adjacent instrument pin (2026-10-03, GOD): a trailing line comment on a `mod x;`
/// declaration must not hide the module from the parser. `declared_children` took
/// `rest.strip_suffix(';')`, so `mod governance_chain_4477; // #4477 ...` yielded None and the
/// module read as UNDECLARED — which made the batch-7 census fail 5/5 in 3175 and 4/6 in 2397 with
/// "`governance_chain_4477.rs` is not declared", while the scanners those binaries exist to run
/// asserted nothing at all. A scanner must not depend on the textual shape of valid Rust beside the
/// declaration it reads (rule k). This cell lives next to the parser because the parser is private,
/// and it is compiled into every binary that uses the helper, so a regression reds all of them.
#[test]
fn declaration_with_a_trailing_comment_is_still_declared() {
    let root = "mod plain;\nmod commented; // a reason a human wrote here\npub mod pub_commented; // and here\n#[path = \"sub/renamed.rs\"]\nmod renamed; // with a path attribute too\n";
    let got: Vec<String> = declared_children(root)
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(
        got.contains(&"plain".to_string()),
        "plain declaration lost: {got:?}"
    );
    assert!(
        got.contains(&"commented".to_string()),
        "a trailing `// comment` hid the declaration from the parser: {got:?}"
    );
    assert!(
        got.contains(&"pub_commented".to_string()),
        "a trailing comment on a `pub mod` hid the declaration: {got:?}"
    );
    assert!(
        got.contains(&"renamed".to_string()),
        "a trailing comment hid a #[path]-attributed declaration: {got:?}"
    );
    let renamed = declared_children(root)
        .into_iter()
        .find(|d| d.name == "renamed")
        .unwrap();
    assert_eq!(
        renamed.path_attr.as_deref(),
        Some("sub/renamed.rs"),
        "the #[path] attribute must survive the comment strip"
    );
}

/// Every adapter source file: `postgres.rs` first, then each child module in
/// sorted path order. Panics (fail closed) on any non-vacuity violation.
#[must_use]
pub fn pg_adapter_sources() -> Vec<PgSource> {
    let root_path = crate_root().join(PG_ROOT_REL);
    let root_text = read_lf(&root_path);
    assert!(
        root_text.contains("impl PostgresStore") || root_text.contains("PostgresStore"),
        "pg_sources: {PG_ROOT_REL} does not look like the adapter root"
    );

    let mut paths = Vec::new();
    collect_rs(&crate_root().join(PG_CHILD_DIR_REL), &mut paths);
    paths.sort();
    assert!(
        !paths.is_empty(),
        "pg_sources: no child modules found under {PG_CHILD_DIR_REL} — a scanner \
         built on this loader would silently scan only {PG_ROOT_REL}"
    );

    let mut out = vec![PgSource {
        rel: PG_ROOT_REL.to_string(),
        text: root_text.clone(),
    }];
    for p in &paths {
        let text = read_lf(p);
        assert!(
            !text.trim().is_empty(),
            "pg_sources: {} is empty",
            rel_of(p)
        );
        out.push(PgSource {
            rel: rel_of(p),
            text,
        });
    }

    let have: BTreeSet<&str> = out.iter().map(|s| s.rel.as_str()).collect();
    for want in EXPECTED_CHILDREN {
        assert!(
            have.contains(want),
            "pg_sources: expected child module {want} was not discovered \
             (loaded: {have:?})"
        );
    }

    // Declared <-> loaded must agree, so a child wired in with a `#[path]`
    // rename or an undeclared file cannot hide from the scanners. A module
    // with a `#[path]` attribute (the `hub` module) is loaded from that path
    // and added to the set.
    let declared = declared_children(&root_text);
    let mut dir_declared: BTreeSet<String> = BTreeSet::new();
    for d in &declared {
        if let Some(rel_attr) = &d.path_attr {
            let rel = format!("src/store/{rel_attr}");
            let text = read_lf(&crate_root().join(&rel));
            assert!(!text.trim().is_empty(), "pg_sources: {rel} is empty");
            out.push(PgSource { rel, text });
        } else {
            dir_declared.insert(d.name.clone());
        }
    }
    let loaded: BTreeSet<String> = paths
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    for name in &dir_declared {
        assert!(
            loaded.contains(name),
            "pg_sources: {PG_ROOT_REL} declares `mod {name};` but no \
             {PG_CHILD_DIR_REL}/{name}.rs was loaded"
        );
    }
    for name in &loaded {
        assert!(
            dir_declared.contains(name),
            "pg_sources: {PG_CHILD_DIR_REL}/{name}.rs is not declared by \
             {PG_ROOT_REL} (undeclared or #[path]-renamed module)"
        );
    }
    out
}

/// All adapter sources joined into one LF string, `postgres.rs` first.
/// Each file is terminated by a newline so no span can bleed across files.
#[must_use]
pub fn pg_adapter_concat() -> String {
    let mut s = String::new();
    for f in pg_adapter_sources() {
        s.push_str(&f.text);
        if !s.ends_with('\n') {
            s.push('\n');
        }
    }
    s
}

/// An unterminated literal or comment found by [`try_mask_rust`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskError {
    /// Byte offset where the still-open token started.
    pub offset: usize,
    /// What was left open.
    pub what: &'static str,
}

impl std::fmt::Display for MaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unterminated {} starting at byte offset {}",
            self.what, self.offset
        )
    }
}

impl std::error::Error for MaskError {}

/// A copy of `src` with the CONTENT of every comment, string literal and
/// char/byte literal replaced by spaces (#4023). Newlines are kept and every
/// replaced byte becomes exactly one space, so byte offsets and line numbers
/// match the original. Structural detection (fn spans, `impl`/item
/// boundaries, `const`/`static` items) must run on this copy, so text inside a
/// literal or comment can never re-segment a scan; SQL is then searched in the
/// ORIGINAL text over the spans found here, because the SQL lives in strings.
///
/// Handles: `"..."` with escapes; raw strings with any number of `#`
/// (`r".."`, `r#".."#`, `r##".."##`); byte (`b".."`, `br#".."#`) and C
/// (`c".."`, `cr#".."#`) strings; char / byte literals (a lifetime such as
/// `'a` is NOT a char literal); `//` line comments; nested `/* */` comments.
///
/// Delimiters (the quotes, `#`s and the `r`/`b`/`c` prefix) are kept; only
/// the content between them is blanked.
///
/// FAIL CLOSED (#4023, K3): a string, raw string (any `#` count), byte/C
/// string or block comment (at any nesting depth) still open at end of input
/// is an `Err` naming the byte offset where the open token started. It is
/// never blanked "best effort" to the end of the file, which would fold every
/// later fn header into the opening method. (A lone `'` that does not close
/// as a char literal is a lifetime or label by construction, so a char
/// literal cannot be left open.)
///
/// # Errors
///
/// [`MaskError`] when a literal or comment is unterminated.
///
/// # Scope
///
/// The guarantee holds for source that compiles under `sal-postgres`. The
/// required "Postgres feature gate" CI check is the backstop for non-compiling
/// source, which these lexer heuristics cannot fully resolve. The desync checks
/// (`//` after a plain string newline, column-0 brace depth) assume
/// rustfmt-formatted source. Known false red FR6: a plain (non-raw) string
/// containing a newline followed by `//` fails closed with a file and offset
/// message; use a raw string instead.
pub fn try_mask_rust(src: &str) -> Result<String, MaskError> {
    let b = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let blank = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        // Line comment.
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Block comment (nested).
        if c == b'/' && next == Some(b'*') {
            let started = i;
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
            if depth != 0 {
                return Err(MaskError {
                    offset: started,
                    what: "block comment",
                });
            }
            continue;
        }
        // Raw string: r"..", r#".."#, with an optional b/c prefix. The `r`
        // must start a token (not be the tail of an identifier).
        if c == b'r' {
            let prefixed = i > 0 && (b[i - 1] == b'b' || b[i - 1] == b'c');
            let before = if prefixed {
                i.checked_sub(2).map(|k| b[k])
            } else {
                i.checked_sub(1).map(|k| b[k])
            };
            if !before.is_some_and(is_ident) {
                let mut j = i + 1;
                let mut hashes = 0usize;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let started = i;
                    out.extend_from_slice(&b[i..=j]);
                    j += 1;
                    let mut closed = false;
                    loop {
                        if j >= b.len() {
                            break;
                        }
                        if b[j] == b'"'
                            && b[j + 1..].iter().take(hashes).all(|&h| h == b'#')
                            && b.len() - (j + 1) >= hashes
                        {
                            out.extend_from_slice(&b[j..=j + hashes]);
                            j += hashes + 1;
                            closed = true;
                            break;
                        }
                        blank(&mut out, b[j]);
                        j += 1;
                    }
                    if !closed {
                        return Err(MaskError {
                            offset: started,
                            what: "raw string",
                        });
                    }
                    i = j;
                    continue;
                }
            }
        }
        // Ordinary string (the b/c prefix, if any, was already copied).
        if c == b'"' {
            let started = i;
            let mut closed = false;
            out.push(b'"');
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    out.push(b' ');
                    i += 1;
                    if i < b.len() {
                        blank(&mut out, b[i]);
                        i += 1;
                    }
                    continue;
                }
                if b[i] == b'"' {
                    out.push(b'"');
                    i += 1;
                    closed = true;
                    break;
                }
                // A plain (non-raw) string that runs onto a line starting with
                // `//` is, in rustfmt-formatted source, a lexer desync (an odd
                // quote earlier flipped string state) far more often than a
                // real literal: fail closed rather than mask a comment as a
                // string and re-segment everything after it.
                if b[i] == b'\n' {
                    let rest = &b[i + 1..];
                    let ws = rest
                        .iter()
                        .take_while(|&&x| x == b' ' || x == b'\t')
                        .count();
                    if rest[ws..].starts_with(b"//") {
                        return Err(MaskError {
                            offset: started,
                            what: "plain string running onto a `//` comment line (lexer desync)",
                        });
                    }
                }
                blank(&mut out, b[i]);
                i += 1;
            }
            if !closed {
                return Err(MaskError {
                    offset: started,
                    what: "string literal",
                });
            }
            continue;
        }
        // Char / byte literal vs lifetime.
        if c == b'\'' {
            let mut end: Option<usize> = None;
            if next == Some(b'\\') {
                // Escaped char: scan to the closing quote.
                let mut j = i + 2;
                if j < b.len() {
                    j += 1; // the escaped char itself (e.g. the `'` of `'\''`)
                }
                while j < b.len() && b[j] != b'\'' && b[j] != b'\n' {
                    j += 1;
                }
                if b.get(j) == Some(&b'\'') {
                    end = Some(j);
                }
            } else if let Some(n) = next {
                // One UTF-8 scalar then a closing quote => char literal.
                let width = match n {
                    0x00..=0x7F => 1,
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    _ => 4,
                };
                if n != b'\n' && b.get(i + 1 + width) == Some(&b'\'') {
                    end = Some(i + 1 + width);
                }
            }
            if let Some(e) = end {
                out.push(b'\'');
                for &x in &b[i + 1..e] {
                    blank(&mut out, x);
                }
                out.push(b'\'');
                i = e + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    // Only whole literal / comment contents were blanked byte-for-byte with
    // ASCII spaces; everything else was copied verbatim, so this is valid UTF-8.
    let masked = String::from_utf8(out).map_err(|_| MaskError {
        offset: 0,
        what: "masked output (invalid UTF-8)",
    })?;
    check_item_depth(&masked)?;
    Ok(masked)
}

/// Column-0 tokens that start a top-level item in rustfmt-formatted source.
const ITEM_STARTS: &[&str] = &[
    "impl",
    "pub",
    "fn",
    "async",
    "const",
    "static",
    "mod",
    "use",
    "struct",
    "enum",
    "trait",
    "type",
    "macro_rules",
    "extern",
    "unsafe",
    "#[",
    "#![",
];

/// Second, independent fail-closed check on the MASKED text (#4023, K3): a
/// lexer desync that happens to re-balance before end of input (an odd quote
/// that a later stray quote closes) is invisible to the end-of-input check,
/// but it flips which braces count as code, so a top-level item no longer
/// starts at brace depth 0. In rustfmt-formatted source every column-0 line
/// starting with an item keyword begins at depth 0, a column-0 `}` returns to
/// depth 0, and the file ends at depth 0; a violation is reported as an
/// error naming the offending byte offset.
fn check_item_depth(masked: &str) -> Result<(), MaskError> {
    let mut depth: i64 = 0;
    let mut offset = 0usize;
    for line in masked.split_inclusive('\n') {
        let t = line.trim_end_matches('\n');
        let starts_item = ITEM_STARTS.iter().any(|k| {
            t.strip_prefix(k)
                .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
        });
        if starts_item && depth != 0 {
            return Err(MaskError {
                offset,
                what: "item start at nonzero brace depth (lexer desync)",
            });
        }
        for c in t.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
        if depth < 0 || (t.starts_with('}') && depth != 0) {
            return Err(MaskError {
                offset,
                what: "unbalanced closing brace (lexer desync)",
            });
        }
        offset += line.len();
    }
    if depth != 0 {
        return Err(MaskError {
            offset: masked.len(),
            what: "unbalanced braces at end of input (lexer desync)",
        });
    }
    Ok(())
}

/// [`try_mask_rust`] for callers with no file name to report: panics (a test
/// failure) on an unterminated literal or comment.
///
/// # Panics
///
/// On an unterminated literal or comment.
#[must_use]
pub fn mask_rust(src: &str) -> String {
    try_mask_rust(src).unwrap_or_else(|e| panic!("mask_rust: {e}"))
}
