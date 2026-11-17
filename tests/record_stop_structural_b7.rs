// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B7 — STRUCTURAL record-stop completeness.
//!
//! Scans `src/**/*.rs` for write-SQL (`INSERT INTO` / `INSERT OR … INTO` /
//! `UPDATE … SET` / `DELETE FROM`) in the enclosing function and asserts
//! that function calls a record-stop gate, or is on the reviewed
//! exception allowlist. A new write-SQL function that is neither gated
//! nor allowlisted fails this test — that is the durable round-N
//! guarantee (LESSON-5). `append_signed_event` stays ungated so resume
//! can persist the attestation.
//!
//! #3942 — a Rust string literal may escape a newline with a trailing
//! `\`, and the write verb and its companion keyword then sit on
//! different physical lines. [`join_string_continuations`] collapses
//! that escape before [`write_sql_line`], so a split `UPDATE` / `SET`
//! (and the same split of `INSERT` / `INTO` or `DELETE` / `FROM`) is
//! classified. The predicate itself stays single-line; the pre-#3942
//! scanner is the frozen leg of `b7_scanner_sees_backslash_continued_write_sql_3942`.
//!
//! #4149 — a file is skipped as test-only ONLY when a parent module
//! DECLARES it `#[cfg(test)] mod NAME;` ([`cfg_test_declared_files`]),
//! plus that module's descendants. A test-looking file NAME proves
//! nothing (#4054); an undeclared file is scanned as production.
//!
//! # Known limits (#4182)
//!
//! This is a TEXTUAL scanner, so it proves less than a reader may assume:
//!
//! - **Reachability is lexical (#9414).** A gate call is credited only in a
//!   statement with no closure, attribute, short circuit, `else` or
//!   macro-argument prefix, after no early exit in its block or an enclosing
//!   one, and only when it DOMINATES every own write-SQL line: its block
//!   encloses the write's block and it comes first ([`span_gate_credit`]).
//!   A gate-only wrapper needs that gate at brace depth 1 of the body.
//!   Every other gate is a "conditional gate" and needs a reviewed fix or
//!   ALLOWLIST row. Values are not evaluated: a callee that never returns or
//!   a gate whose result is discarded still reads as gated.
//! - **Every byte is classified (#9414).** Comments and literals are read by
//!   the one tokenizer in `tests/common/rust_tokens.rs`; a form it cannot
//!   classify fails the scan naming file:line.
//! - **Macro-generated code is invisible.** Write SQL or a gate call
//!   produced by a macro expansion is never seen.
//! - **Enclosing function is lexical.** Write SQL is attributed to the
//!   nearest preceding `fn` in the text, not to the function that
//!   executes it (a SQL const used from another function is attributed
//!   to wherever it is declared).
//! - **`#[path = ...]` is not resolved** by the #4149 declaration walk,
//!   so such a cfg(test) module stays scanned (fail-closed direction).
//!
//! A green B7 therefore means "every write-SQL function NAMES a gate or is
//! allowlisted", not "every write is gated at run time". The run-time
//! proof is the record-stop behavioural cells.

use std::collections::{HashMap, HashSet};

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;
use cfg_test_modules::cfg_test_declared_files;
#[path = "common/rust_tokens.rs"]
mod rust_tokens;
use std::fs;
use std::path::{Path, PathBuf};

const GATE_MARKERS: &[&str] = &[
    "gate_storage_conn",
    "gate_storage_conn_rusqlite",
    "gate_record_stop",
    "refuse_if_record_stopped",
    "record_stop_status",
    // R4-G2: the SAL record-stop primitive (`store::record_stop::gate_flag`)
    // that pg `gate_record_stop` wraps. Pre-R4-G2 the in-transaction wrapper
    // `gate_record_stop_in_transaction` "counted" only because its name
    // CONTAINS `gate_record_stop`; it is now proven by its own call to this.
    "gate_flag",
];

/// Functions that MUST be gated (the B7 enumerated siblings). If any of
/// these appear ungated the test fails even if they were accidentally
/// added to the allowlist.
const MUST_BE_GATED: &[&str] = &[
    "queue_pending_action",
    "entity_register",
    "ensure_row",
    "enforce_governance_action",
    "quota_status",
    "quota_status_ns",
    "pending_decide",
    "governance_approve_with_consensus",
    "reflect_with_hooks",
    "update_embedding",
    "fold_recall_accesses",
];

/// Sqlite SSOT fn → postgres SAL method. If the sqlite twin's body
/// contains a record-stop gate, the pg method must too (B7' parity —
/// an allowlist exemption cannot mask a gated-sqlite / ungated-pg split).
const SQLITE_PG_TWINS: &[(&str, &str)] = &[
    ("decide_pending_action", "pending_decide"),
    (
        "approve_with_approver_type",
        "governance_approve_with_consensus",
    ),
    ("set_namespace_standard", "set_namespace_standard"),
    ("clear_namespace_standard", "clear_namespace_standard"),
    ("bind_agent_api_key", "bind_agent_api_key"),
    ("set_embeddings_batch", "set_embeddings_batch"),
    ("queue_pending_action", "enforce_governance_action"),
    ("set_embedding", "update_embedding"),
    ("fold_recall_accesses", "fold_recall_accesses"),
];

fn write_sql_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    let upper = line.to_ascii_uppercase();
    (upper.contains("INSERT INTO") || upper.contains("INSERT OR"))
        && (upper.contains(" INTO ") || upper.contains("INTO\n") || upper.contains("INTO "))
        || upper.contains("DELETE FROM")
        || (upper.contains("UPDATE ") && upper.contains(" SET"))
}

/// #3942 — the pre-fix predicate, frozen verbatim. It is [`write_sql_line`]
/// as it stood when both tokens had to share one physical line. The
/// sensitivity test calls this on the UNJOINED source so a split
/// `UPDATE \` / `SET` stays invisible, which is the bug.
fn write_sql_line_single_line_frozen(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    let upper = line.to_ascii_uppercase();
    (upper.contains("INSERT INTO") || upper.contains("INSERT OR"))
        && (upper.contains(" INTO ") || upper.contains("INTO\n") || upper.contains("INTO "))
        || upper.contains("DELETE FROM")
        || (upper.contains("UPDATE ") && upper.contains(" SET"))
}

/// A line ends by escaping the newline when it has an odd run of
/// trailing backslashes (Rust string-literal rule). An even run is a
/// literal backslash and does not continue.
fn escapes_newline(line: &str) -> bool {
    let n = line.chars().rev().take_while(|c| *c == '\\').count();
    n % 2 == 1
}

/// #4148 — the 0-based indices of the physical lines whose trailing
/// backslash escapes the newline INSIDE a non-raw string literal, the only
/// place Rust gives `\`+newline that meaning. One lexer pass over the whole
/// source, so a string opened on an earlier line is still tracked. A
/// backslash at the end of a `//` or `/* */` comment, in code, or inside a
/// raw string is NOT a continuation. Before #4148 every odd trailing
/// backslash run joined, so a doc comment ending in `\` (a shell example)
/// swallowed the `fn` signature below it, and that fn's write SQL was
/// credited to the gated function above.
fn string_continuation_lines(src: &str) -> HashSet<usize> {
    let c: Vec<char> = src.chars().collect();
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut found = HashSet::new();
    let mut line = 0usize;
    let mut i = 0;
    // Advance over c[i], counting a newline.
    let step = |i: &mut usize, line: &mut usize| {
        if c[*i] == '\n' {
            *line += 1;
        }
        *i += 1;
    };
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    step(&mut i, &mut line);
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
                    step(&mut i, &mut line);
                }
                continue;
            }
        }
        if ch == '"' {
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    if c.get(i + 1) == Some(&'\n') {
                        found.insert(line);
                    }
                    i += 1;
                    if i < c.len() {
                        step(&mut i, &mut line);
                    }
                    continue;
                }
                if c[i] == '"' {
                    i += 1;
                    break;
                }
                step(&mut i, &mut line);
            }
            continue;
        }
        if ch == '\'' && (next == Some('\\') || c.get(i + 2) == Some(&'\'')) {
            // A char literal ('x', '\n', '\u{..}'); a lifetime ('a) is left.
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    i += 2;
                    continue;
                }
                if c[i] == '\'' {
                    i += 1;
                    break;
                }
                step(&mut i, &mut line);
            }
            continue;
        }
        step(&mut i, &mut line);
    }
    found
}

/// Collapse a `\`-escaped newline inside a string literal into one
/// logical line, then drop the leading whitespace of the continued
/// line (the string-literal rule). When that would glue two word
/// characters (`UPDATE\` + `SET`), keep a single space so the keyword
/// boundary the predicate looks for still exists. #4148: only a line whose
/// backslash sits inside a string literal joins
/// ([`string_continuation_lines`]).
fn join_string_continuations(src: &str) -> String {
    let string_lines = string_continuation_lines(src);
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let mut acc = lines[i].to_string();
        while escapes_newline(&acc) && string_lines.contains(&i) {
            let Some(next) = lines.get(i + 1) else {
                break;
            };
            let _ = acc.pop();
            i += 1;
            let continued = next.trim_start();
            let glue = matches!(
                (acc.chars().last(), continued.chars().next()),
                (Some(a), Some(b)) if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric()
            );
            if glue {
                acc.push(' ');
            }
            acc.push_str(continued);
        }
        out.push(acc);
        i += 1;
    }
    out.join("\n")
}

/// #3934 — strip a leading visibility modifier (`pub`, `pub(crate)`,
/// `pub(super)`, `pub(self)`, `pub(in a::b)`) from an already-`trim_start`ed
/// line, returning the remainder. Restriction parens are non-nested (the
/// first `)` closes them); a malformed unterminated `pub(` is left as-is.
/// Shared by [`is_fn_start`] and the #3484 [`is_item_boundary_line`]
/// const/static/mod probe so BOTH recognise restricted visibilities — before
/// #3934 an ungated `pub(restricted)` item "passed" on a neighbour's gate.
fn strip_visibility(t: &str) -> &str {
    if t.starts_with("pub(") {
        return match t.find(')') {
            Some(close) => t[close + 1..].trim_start(),
            None => t,
        };
    }
    if let Some(rest) = t.strip_prefix("pub ") {
        return rest.trim_start();
    }
    if let Some(rest) = t.strip_prefix("pub\t") {
        return rest.trim_start();
    }
    t
}

/// #3934 (addendum) — is `line` a module/impl-level `const`/`static`/`mod`
/// item at or shallower than `fn_indent` (the #3484 boundary that ends the
/// preceding fn's attributed body)? Recognises restricted visibilities via
/// [`strip_visibility`], so a `pub(super) const` holding write SQL counts as a
/// boundary exactly like a bare `const`; the pre-addendum two-case strip
/// (`pub(crate)`/`pub` only) missed it and mis-attributed the const's write
/// SQL to the preceding fn.
fn is_item_boundary_line(line: &str, fn_indent: usize) -> bool {
    let indent = line.len() - line.trim_start().len();
    if indent > fn_indent {
        return false;
    }
    let t = strip_visibility(line.trim_start());
    t.starts_with("const ") || t.starts_with("static ") || t.starts_with("mod ")
}

/// R4-G2 — strip an `extern` qualifier with or without an ABI string
/// (`extern "C" `, `extern "system" `, bare `extern `). Before this an
/// `extern "C" fn` was not a function start at all, so the preceding
/// function's slice ran into it and borrowed its gate.
fn strip_extern_abi(t: &str) -> Option<&str> {
    let rest = t.strip_prefix("extern")?;
    if let Some(r) = rest.strip_prefix(' ') {
        let r = r.trim_start();
        if let Some(q) = r.strip_prefix('"') {
            let close = q.find('"')?;
            return Some(q[close + 1..].trim_start());
        }
        return Some(r);
    }
    None
}

fn is_fn_start(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    // #3934 — recognise ANY visibility (incl. `pub(super)`/`pub(self)`/
    // `pub(in a::b)`) via `strip_visibility`, then any `const`/`unsafe`/`async`
    // qualifier, before requiring `fn `. A restricted-visibility fn was NOT a
    // function start under the old two-case strip, so its body merged into the
    // PRECEDING recognised fn and B7 read gate presence from the merged text.
    let mut t = strip_visibility(line.trim_start());
    loop {
        let next = t
            .strip_prefix("const ")
            .or_else(|| t.strip_prefix("unsafe "))
            .or_else(|| t.strip_prefix("async "))
            .or_else(|| strip_extern_abi(t));
        match next {
            Some(rest) => t = rest.trim_start(),
            None => break,
        }
    }
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        return Some((indent, name));
    }
    None
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn strip_test_mod(src: &str) -> &str {
    // Only drop a trailing `#[cfg(test)] mod tests { … }` so in-file
    // `#[cfg(test)]` helpers earlier in a large module are not mistaken
    // for the end of production code (storage/mod.rs, postgres.rs).
    let needle = "\n#[cfg(test)]\nmod tests {";
    if let Some(idx) = src.rfind(needle) {
        return &src[..idx];
    }
    src
}

fn skip_path(rel: &str) -> bool {
    // Trees whose writes are not record-plane content, or already sit
    // behind an entry gate (MCP dispatch / federation chokepoint /
    // schema). A new write-SQL fn in a NON-skipped path still fails.
    rel.contains("/mcp/tools/")
        || rel.ends_with("tests.rs")
        || rel.ends_with("/migrations.rs")
        || rel.contains("/cli/")
        || rel.starts_with("src/federation/")
        || rel.starts_with("src/background/")
        || rel.starts_with("src/confidence/")
        || rel.starts_with("src/atomisation/")
        || rel.starts_with("src/offload/")
        || rel.starts_with("src/observations/")
        || rel.starts_with("src/portability/")
        || rel.starts_with("src/erasure/")
        || rel.starts_with("src/governance/")
        || rel.starts_with("src/handlers/")
        || rel.starts_with("src/transcripts/")
        || rel.starts_with("src/subscriptions.rs")
        || rel.starts_with("src/vectorlite.rs")
        || rel.starts_with("src/revisions.rs")
}

fn is_test_fn(lines: &[&str], start: usize) -> bool {
    for j in (0..start).rev().take(12) {
        let t = lines[j].trim();
        if t.starts_with("#[test") || t.starts_with("#[tokio::test") {
            return true;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        break;
    }
    false
}

fn rel_src(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// #9414 — a copy of `text` in which every comment and every literal body is
/// blanked to spaces, line structure preserved, built on the ONE tokenizer
/// in `tests/common/rust_tokens.rs` (replacing the R4-G2 hand masker, which
/// did not know `c` / `cr` strings: in `cr"\"` it read `\"` as an escape and
/// masked real code up to the next quote). A form the tokenizer cannot
/// classify is an `Err("line N: <reason>")`, a scan FINDING, never code.
fn code_mask(text: &str) -> Result<String, String> {
    rust_tokens::code_mask(text).map_err(|e| e.to_string())
}

/// R4-G2 — same-file gate WRAPPERS: a fn named `<marker>_<suffix>` (e.g.
/// `gate_record_stop_actions`, `gate_record_stop_in_transaction`) counts as
/// a gate only when its OWN span calls a gate (a marker or an already
/// proven wrapper). Pre-R4-G2 any identifier merely CONTAINING a marker
/// counted, proven or not.
fn gate_wrappers(lines: &[&str], masked: &[&str], spans: &[(usize, usize, String)]) -> Vec<String> {
    let mut wrappers: Vec<String> = Vec::new();
    loop {
        let before = wrappers.len();
        for (s, e, name) in spans {
            let named = GATE_MARKERS
                .iter()
                .any(|g| name.strip_prefix(g).is_some_and(|r| r.starts_with('_')));
            if named
                && !wrappers.contains(name)
                && span_has_gate(lines, masked, spans, *s, *e, &wrappers)
            {
                wrappers.push(name.clone());
            }
        }
        if wrappers.len() == before {
            return wrappers;
        }
    }
}

/// #4052 + R4-G2 — the ONE function-boundary routine every B7 slicer uses.
/// Returns `(start, end, name)` for each function start `start_of`
/// recognises on the MASKED lines, where `end` is one past the line holding
/// the function's REAL closing brace (brace-matched on the mask, so braces
/// in comments/strings are ignored), or one past the `;` of a body-less
/// declaration. Before R4-G2 a body ran to the NEXT recognised start, so an
/// unrecognised following item (an `extern "C" fn`, a `const`) was absorbed
/// and its gate credited to the ungated function before it. An unterminated
/// body runs to the end of the text.
fn fn_spans(
    masked: &[&str],
    start_of: impl Fn(&str) -> Option<(usize, String)>,
) -> Vec<(usize, usize, String)> {
    let mut spans = Vec::new();
    for (s, line) in masked.iter().enumerate() {
        let Some((_, name)) = start_of(line) else {
            continue;
        };
        let mut paren = 0i64;
        let mut brace = 0i64;
        let mut opened = false;
        let mut end = masked.len();
        'scan: for (j, l) in masked.iter().enumerate().skip(s) {
            for ch in l.chars() {
                if opened {
                    match ch {
                        '{' => brace += 1,
                        '}' => {
                            brace -= 1;
                            if brace == 0 {
                                end = j + 1;
                                break 'scan;
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                match ch {
                    '(' | '[' => paren += 1,
                    ')' | ']' => paren -= 1,
                    '{' if paren == 0 => {
                        opened = true;
                        brace = 1;
                    }
                    ';' if paren == 0 => {
                        end = j + 1;
                        break 'scan;
                    }
                    _ => {}
                }
            }
        }
        spans.push((s, end, name));
    }
    spans
}

/// The INNERMOST span containing line `idx` (a write inside a nested fn is
/// that nested fn's), or `None` when `idx` is outside every function.
fn enclosing_span(spans: &[(usize, usize, String)], idx: usize) -> Option<&(usize, usize, String)> {
    spans
        .iter()
        .filter(|(s, e, _)| *s <= idx && idx < *e)
        .max_by_key(|(s, _, _)| *s)
}

/// #9414 — why span `(s, e)` is or is not credited with a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateCredit {
    /// A gate call that provably runs before the span's first write.
    Credited,
    /// Gate calls exist, but none provably runs first (0-based line of the
    /// first one): nested block, closure, attribute, short circuit, macro
    /// argument, after a depth-1 exit, or after the first write.
    Conditional(usize),
    /// No gate call at all.
    Absent,
}

/// #9414 — words that leave the fn body at brace depth 1 (and the macros
/// that diverge when invoked with `!`).
const EARLY_EXIT_WORDS: &[&str] = &["return", "break", "continue"];
const DIVERGING_MACROS: &[&str] = &["panic", "unreachable", "todo", "unimplemented", "bail"];
/// #9414 — a gate whose statement prefix (depth-1 code since the statement
/// began) holds one of these may not run: `else`, an `async` / `move` block
/// or closure.
const CONDITIONAL_PREFIX_WORDS: &[&str] = &["else", "async", "move"];
/// #9414 — the same for punctuation: closure params and `||` (`|`), an
/// attribute such as `#[cfg(test)]` (`#`), `&&`, a match arm (`=>`) and a
/// macro argument (`!(` / `![`).
const CONDITIONAL_PREFIX_PUNCT: &[&str] = &["|", "#", "&&", "=>", "!(", "!["];

fn prefix_is_unconditional(prefix: &str) -> bool {
    !CONDITIONAL_PREFIX_PUNCT.iter().any(|p| prefix.contains(p))
        && !prefix
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|w| CONDITIONAL_PREFIX_WORDS.contains(&w))
}

/// #9414 — 0-based lines of the write-SQL lines that belong to span
/// `(s, e)` itself (not to a nested fn).
fn own_writes(lines: &[&str], spans: &[(usize, usize, String)], s: usize, e: usize) -> Vec<usize> {
    (s..e)
        .filter(|&k| {
            lines.get(k).is_some_and(|l| write_sql_line(l))
                && enclosing_span(spans, k).is_some_and(|(ss, se, _)| *ss == s && *se == e)
        })
        .collect()
}

/// #9414 — the control-flow credit of span `(s, e)` (masked lines). A gate
/// CALL (a marker or proven wrapper followed by `(` or `::<`) is VALID when
/// its statement prefix in its own block is unconditional and no early exit
/// ran earlier in that block or an enclosing one. The span is credited when
/// every own write-SQL line is DOMINATED by a valid gate (the gate's block
/// encloses the write's block and the gate's line comes first) or, for a
/// span with no own write (a wrapper), when a valid gate sits at brace depth
/// 1 of the body. A gate in an `if false` block, a closure, after an early
/// return or after the write therefore never counts. Anything else with a
/// gate call is [`GateCredit::Conditional`].
fn span_gate_credit(
    lines: &[&str],
    masked: &[&str],
    spans: &[(usize, usize, String)],
    s: usize,
    e: usize,
    wrappers: &[String],
) -> GateCredit {
    struct Level {
        id: usize,
        prefix: String,
        stmt_exits: bool,
        exited: bool,
    }
    let writes = own_writes(lines, spans, s, e);
    let mut write_blocks: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut valid_gates: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut first_gate = None;
    let mut stack: Vec<Level> = Vec::new();
    let mut next_id = 0usize;
    let mut paren = 0i64;
    let mut opened = false;
    'lines: for k in s..e.min(masked.len()) {
        if opened && writes.contains(&k) {
            write_blocks.push((k, stack.iter().map(|l| l.id).collect()));
        }
        let chars: Vec<char> = masked[k].chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            if !opened {
                match ch {
                    '(' | '[' => paren += 1,
                    ')' | ']' => paren -= 1,
                    '{' if paren == 0 => {
                        opened = true;
                        stack.push(Level {
                            id: next_id,
                            prefix: String::new(),
                            stmt_exits: false,
                            exited: false,
                        });
                        next_id += 1;
                    }
                    ';' if paren == 0 => return GateCredit::Absent,
                    _ => {}
                }
                i += 1;
                continue;
            }
            let Some(top) = stack.last_mut() else {
                break 'lines;
            };
            if ch.is_alphabetic() || ch == '_' {
                let st = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[st..i].iter().collect();
                let next = chars.get(i).copied();
                let turbofish = next == Some(':')
                    && chars.get(i + 1) == Some(&':')
                    && chars.get(i + 2) == Some(&'<');
                if EARLY_EXIT_WORDS.contains(&word.as_str())
                    || (next == Some('!') && DIVERGING_MACROS.contains(&word.as_str()))
                {
                    top.stmt_exits = true;
                }
                let is_gate = (next == Some('(') || turbofish)
                    && (GATE_MARKERS.contains(&word.as_str()) || wrappers.contains(&word));
                if is_gate {
                    first_gate.get_or_insert(k);
                    let valid =
                        prefix_is_unconditional(&top.prefix) && !stack.iter().any(|l| l.exited);
                    if valid {
                        valid_gates.push((k, stack.iter().map(|l| l.id).collect()));
                    }
                }
                if let Some(top) = stack.last_mut() {
                    top.prefix.push_str(&word);
                    top.prefix.push(' ');
                }
                continue;
            }
            match ch {
                '{' => {
                    stack.push(Level {
                        id: next_id,
                        prefix: String::new(),
                        stmt_exits: false,
                        exited: false,
                    });
                    next_id += 1;
                }
                '}' => {
                    stack.pop();
                    let Some(top) = stack.last_mut() else {
                        break 'lines;
                    };
                    top.exited |= top.stmt_exits;
                    top.stmt_exits = false;
                    top.prefix.clear();
                }
                ';' => {
                    top.exited |= top.stmt_exits;
                    top.stmt_exits = false;
                    top.prefix.clear();
                }
                c if !c.is_whitespace() => top.prefix.push(c),
                _ => {}
            }
            i += 1;
        }
        if let Some(top) = stack.last_mut() {
            top.prefix.push(' ');
        }
    }
    let credited = if writes.is_empty() {
        valid_gates.iter().any(|(_, ids)| ids.len() == 1)
    } else {
        writes.len() == write_blocks.len()
            && write_blocks.iter().all(|(wk, wids)| {
                valid_gates
                    .iter()
                    .any(|(gk, gids)| gk < wk && wids.starts_with(gids))
            })
    };
    match (credited, first_gate) {
        (true, _) => GateCredit::Credited,
        (false, Some(at)) => GateCredit::Conditional(at),
        (false, None) => GateCredit::Absent,
    }
}

/// Is span `(s, e)` credited with a gate ([`span_gate_credit`])?
fn span_has_gate(
    lines: &[&str],
    masked: &[&str],
    spans: &[(usize, usize, String)],
    s: usize,
    e: usize,
    wrappers: &[String],
) -> bool {
    span_gate_credit(lines, masked, spans, s, e, wrappers) == GateCredit::Credited
}

/// #4052 — gate verdict of EVERY production function named exactly `fn_name`
/// in `src` (trailing `#[cfg(test)] mod tests` stripped, string
/// continuations joined — the same preprocessing as the main scanner), sliced
/// by the shared [`fn_spans`] boundary. Exact name match: `fn foo_v2` is not
/// `fn foo` (the pre-#4052 `find("fn foo")` matched it).
fn fn_gate_verdicts(
    src: &str,
    fn_name: &str,
    start_of: impl Fn(&str) -> Option<(usize, String)>,
) -> Vec<bool> {
    try_fn_gate_verdicts(src, fn_name, start_of).unwrap_or_else(|finding| {
        panic!("#9414 B7 tokenizer finding in the `{fn_name}` source: {finding}")
    })
}

/// #9414 — [`fn_gate_verdicts`] with the tokenizer finding as the error.
fn try_fn_gate_verdicts(
    src: &str,
    fn_name: &str,
    start_of: impl Fn(&str) -> Option<(usize, String)>,
) -> Result<Vec<bool>, String> {
    let text = join_string_continuations(strip_test_mod(src));
    let mask = code_mask(&text)?;
    let lines: Vec<&str> = text.lines().collect();
    let masked: Vec<&str> = mask.lines().collect();
    let spans = fn_spans(&masked, start_of);
    let wrappers = gate_wrappers(&lines, &masked, &spans);
    Ok(spans
        .iter()
        .filter(|(_, _, n)| n == fn_name)
        .map(|(s, e, _)| span_has_gate(&lines, &masked, &spans, *s, *e, &wrappers))
        .collect())
}

/// Parity-side read: is `fn_name` gated in `src`? Fails CLOSED — every
/// same-named definition must carry a gate, and an absent function is
/// ungated.
fn fn_body_has_gate(src: &str, fn_name: &str) -> bool {
    let v = fn_gate_verdicts(src, fn_name, is_fn_start);
    !v.is_empty() && v.iter().all(|g| *g)
}

/// Twin-side read: does ANY definition of `fn_name` gate? Used to decide
/// whether the parity obligation applies — `any` so a gated twin can never
/// be skipped because a same-named sibling is ungated.
fn fn_any_body_has_gate(src: &str, fn_name: &str) -> bool {
    fn_gate_verdicts(src, fn_name, is_fn_start)
        .iter()
        .any(|g| *g)
}

/// #4052 R-203 — the EXACT pre-#4052 parity slicer, frozen so the self-test
/// proves the blind spot: it credits a FOLLOWING function's gate.
fn fn_body_has_gate_frozen_4052(src: &str, fn_name: &str) -> bool {
    let needle = format!("fn {fn_name}");
    let Some(idx) = src.find(&needle) else {
        return false;
    };
    let rest = &src[idx..];
    let end = rest
        .find("\n    async fn ")
        .or_else(|| rest.find("\npub fn "))
        .unwrap_or(rest.len().min(8000));
    let body = &rest[..end];
    GATE_MARKERS.iter().any(|g| body.contains(g))
}

/// #3934 — the boundary+gate core B7 uses, factored so the self-test can
/// drive it with EITHER the shipped `is_fn_start` or a frozen pre-fix copy.
/// Returns the write-SQL functions whose attributed body (nearest preceding
/// fn start .. next fn start) carries no [`GATE_MARKERS`] marker. This is the
/// exact detection the #3934 widening affects; the main test layers the
/// skip/test/migrate/allowlist/const-boundary filters on top of the same
/// core.
fn ungated_write_fns_for(
    text: &str,
    start_of: impl Fn(&str) -> Option<(usize, String)>,
    classify: impl Fn(&str) -> bool,
) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mask =
        code_mask(text).unwrap_or_else(|finding| panic!("#9414 B7 tokenizer finding: {finding}"));
    let masked: Vec<&str> = mask.lines().collect();
    let spans = fn_spans(&masked, start_of);
    let wrappers = gate_wrappers(&lines, &masked, &spans);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        if !classify(line) {
            continue;
        }
        // R4-G2: a write outside every recognised fn is reported, never
        // silently dropped (fail closed).
        let Some((start, end, name)) = enclosing_span(&spans, idx) else {
            out.push(format!("<no enclosing fn @{}>", idx + 1));
            continue;
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        if !span_has_gate(&lines, &masked, &spans, *start, *end, &wrappers) {
            out.push(name.clone());
        }
    }
    out
}

/// #3934 R-203 — the EXACT pre-fix `is_fn_start` (strips only `pub(crate) `
/// / `pub ` then `async `), frozen so the self-test can prove the blind spot
/// the widening closes: this predicate ACCEPTS (fails to flag) a planted
/// ungated `pub(super)` write fn, while the shipped [`is_fn_start`] REDs it.
fn is_fn_start_prefix_frozen(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        return Some((indent, name));
    }
    None
}

/// #3934 — sensitivity + R-203 specificity for the `is_fn_start` widening.
/// A gated fn is followed by an ungated `pub(super)` write fn (and, for good
/// measure, an ungated `pub(in crate::x)` write fn). The SHIPPED scanner must
/// flag both (RED = the blind spot is closed); the FROZEN pre-fix scanner
/// must NOT flag either (it merges each into the preceding gated fn — the bug
/// this reproduces). A gated `pub(self)` write fn must NOT be flagged by the
/// shipped scanner (no false positive).
#[test]
fn b7_scanner_sees_pub_restricted_write_fns_3934() {
    let planted = r#"
    pub(crate) async fn gated_before(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute("UPDATE memories SET x = 1", [])?;
        Ok(())
    }

    pub(super) async fn plant_pub_super_ungated(conn: &Connection) -> Result<()> {
        conn.execute("UPDATE memories SET y = 2", [])?;
        Ok(())
    }

    pub(in crate::store) fn plant_pub_in_ungated(conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM memories WHERE z = 3", [])?;
        Ok(())
    }

    pub(self) async fn plant_pub_self_gated(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute("UPDATE memories SET w = 4", [])?;
        Ok(())
    }
"#;

    let shipped = ungated_write_fns_for(planted, is_fn_start, write_sql_line);
    assert!(
        shipped.contains(&"plant_pub_super_ungated".to_string()),
        "sensitivity: the widened scanner must FLAG an ungated pub(super) write fn (got {shipped:?})"
    );
    assert!(
        shipped.contains(&"plant_pub_in_ungated".to_string()),
        "sensitivity: the widened scanner must FLAG an ungated pub(in ..) write fn (got {shipped:?})"
    );
    assert!(
        !shipped.contains(&"plant_pub_self_gated".to_string()),
        "specificity: a GATED pub(self) write fn must NOT be flagged (got {shipped:?})"
    );

    // R-203 — the frozen pre-fix predicate reproduces the blind spot: it does
    // NOT recognise the pub(super)/pub(in ..) fn starts, so it can never flag
    // them BY NAME. (Pre-R4-G2 their writes merged into the preceding gated
    // fn and read as gated; with brace-matched spans they now surface only
    // as `<no enclosing fn>` — still not the named function.)
    let frozen = ungated_write_fns_for(planted, is_fn_start_prefix_frozen, write_sql_line);
    assert!(
        !frozen.contains(&"plant_pub_super_ungated".to_string())
            && !frozen.contains(&"plant_pub_in_ungated".to_string()),
        "R-203: the frozen pre-fix scanner must be BLIND to pub(restricted) write fns (that is the #3934 bug); got {frozen:?}"
    );
}

/// #3934 (addendum) — the #3484 item-boundary probe must recognise a
/// RESTRICTED-visibility item, the same widening `is_fn_start` got. A
/// `pub(super) const` holding write SQL is a module-level item, NOT the body
/// of the preceding fn, so it must register as a boundary. (25
/// restricted-visibility consts exist in `src/` today; 0 hold write SQL — this
/// pins the scanner before one does.) The pre-addendum two-case strip returned
/// false here, mis-attributing the const's write SQL to the fn above.
#[test]
fn item_boundary_recognises_restricted_visibility_const_3934() {
    // At or shallower than the fn indent → a boundary (the fix).
    assert!(
        is_item_boundary_line(
            "    pub(super) const SQL_X: &str = \"INSERT INTO x VALUES (1)\";",
            4
        ),
        "a pub(super) const at fn-indent must register as a #3484 item boundary"
    );
    assert!(
        is_item_boundary_line(
            "pub(in crate::store) static SQL_Y: &str = \"DELETE FROM y\";",
            0
        ),
        "a pub(in ..) static must register as a boundary"
    );
    // A bare (private) const is a boundary — unchanged by the widening.
    assert!(is_item_boundary_line(
        "const SQL_Z: &str = \"UPDATE z SET a = 1\";",
        0
    ));
    // Specificity: DEEPER than the fn indent → inside the fn body, NOT a boundary.
    assert!(
        !is_item_boundary_line(
            "        pub(super) const INNER: &str = \"INSERT INTO w VALUES (2)\";",
            4
        ),
        "a const deeper than the fn indent is inside the fn body, not a boundary"
    );
    // Specificity: a restricted-visibility FN is a fn start (is_fn_start's job),
    // NOT a const/static/mod item boundary.
    assert!(
        !is_item_boundary_line("    pub(super) fn helper() {", 4),
        "a pub(super) fn is a fn start, not a const/static/mod item boundary"
    );
}

/// #3942 — a split `UPDATE \` / `SET` in an ungated fn must be flagged.
/// The shipped scanner joins the continuation first. The frozen
/// single-line predicate, run on the physical lines, stays blind to it
/// (that is the gap). A gated split is not flagged, and a single-line
/// `DELETE FROM` is still flagged.
#[test]
fn b7_scanner_sees_backslash_continued_write_sql_3942() {
    let planted = r#"
    pub fn plant_split_update_ungated(conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE x \
             SET y = 1",
            [],
        )?;
        Ok(())
    }

    pub fn plant_split_insert_ungated(conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT \
             INTO memories (id) VALUES (1)",
            [],
        )?;
        Ok(())
    }

    pub fn plant_split_delete_ungated(conn: &Connection) -> Result<()> {
        conn.execute(
            "DELETE \
             FROM memories WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    pub fn plant_split_update_gated(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute(
            "UPDATE x \
             SET y = 2",
            [],
        )?;
        Ok(())
    }

    pub fn plant_single_line_still_seen(conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM memories WHERE id = 3", [])?;
        Ok(())
    }
"#;

    let shipped = ungated_write_fns_for(
        &join_string_continuations(planted),
        is_fn_start,
        write_sql_line,
    );
    for name in [
        "plant_split_update_ungated",
        "plant_split_insert_ungated",
        "plant_split_delete_ungated",
        "plant_single_line_still_seen",
    ] {
        assert!(
            shipped.iter().any(|n| n == name),
            "sensitivity: joined scanner must FLAG ungated `{name}` (got {shipped:?})"
        );
    }
    assert!(
        !shipped.iter().any(|n| n == "plant_split_update_gated"),
        "specificity: a GATED split UPDATE must NOT be flagged (got {shipped:?})"
    );

    let frozen = ungated_write_fns_for(planted, is_fn_start, write_sql_line_single_line_frozen);
    assert!(
        !frozen.iter().any(|n| n == "plant_split_update_ungated")
            && !frozen.iter().any(|n| n == "plant_split_insert_ungated")
            && !frozen.iter().any(|n| n == "plant_split_delete_ungated"),
        "R-203: the frozen single-line predicate must be BLIND to a \\-continued write (that is the #3942 gap); got {frozen:?}"
    );
    assert!(
        frozen.iter().any(|n| n == "plant_single_line_still_seen"),
        "R-203 control: the frozen predicate must still FLAG a single-line DELETE (got {frozen:?})"
    );
}

/// #4052 — sensitivity + R-203 specificity for the PARITY slicer. An
/// ungated indented `async fn set_embeddings_batch` is followed by a gated
/// private sync `pub(self) fn` (the exact plant from the issue), and a gated
/// `fn set_embeddings_batch_v2` precedes it (a prefix-name trap). The shipped
/// [`fn_body_has_gate`] must report the target UNGATED; the frozen pre-#4052
/// slicer credits the neighbour's gate (the bug). Control: a GATED target
/// followed by an ungated neighbour is credited by the shipped slicer.
#[test]
fn b7_parity_slicer_does_not_borrow_a_following_gate_4052() {
    let plant = r#"
impl SqliteStore {
    async fn set_embeddings_batch_v2(&self) -> Result<()> {
        gate_record_stop(&self.conn)?;
        Ok(())
    }

    async fn set_embeddings_batch(&self) -> Result<()> {
        self.conn.execute("UPDATE memories SET embedding = ?1", [])?;
        Ok(())
    }

    pub(self) fn private_gated_helper(&self) -> Result<()> {
        gate_record_stop(&self.conn)?;
        Ok(())
    }

    fn sync_gated_helper(&self) -> Result<()> {
        gate_record_stop(&self.conn)?;
        Ok(())
    }
}
"#;
    assert!(
        !fn_body_has_gate(plant, "set_embeddings_batch"),
        "sensitivity: an ungated parity target followed by a gated pub(self)/sync fn must read UNGATED"
    );
    assert!(
        !fn_any_body_has_gate(plant, "set_embeddings_batch"),
        "sensitivity: the twin-side read must not borrow a neighbour's gate either"
    );
    assert!(
        fn_body_has_gate_frozen_4052(plant, "set_embeddings_batch"),
        "R-203: the frozen pre-#4052 slicer must credit the borrowed gate (that is the #4052 bug)"
    );

    let control = r#"
impl PostgresStore {
    async fn set_embeddings_batch(&self) -> Result<()> {
        gate_record_stop(&self.pool)?;
        sqlx::query("UPDATE memories SET embedding = $1");
        Ok(())
    }

    pub(super) fn ungated_neighbour(&self) -> Result<()> {
        sqlx::query("DELETE FROM memories");
        Ok(())
    }
}
"#;
    assert!(
        fn_body_has_gate(control, "set_embeddings_batch"),
        "specificity: a GATED parity target must be credited"
    );
    assert!(
        !fn_body_has_gate(control, "no_such_fn"),
        "fail-closed: an absent parity target is not gated"
    );
}

/// R4-G2 — a gate counts only when the TARGET function itself CALLS it.
/// Sensitivity (each must read UNGATED, on the parity read, the twin read
/// and the main-scanner core): an ungated write fn followed by a gated
/// `extern "C" fn`; followed by a `const` whose string mentions a gate;
/// with the gate only in a `//` comment, a `/* */` comment or a string
/// literal; and with the gate only inside a NESTED helper fn. Specificity
/// (each must read GATED): a real call after a nested helper, a real call
/// on a line that also carries a brace-bearing string, and a `::<T>`
/// turbofish call. Fail-closed: a write outside every fn is reported.
#[test]
fn b7_gate_must_be_called_by_the_target_itself_r4_g2() {
    let ungated_plants = [
        (
            "following extern fn",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        execute(\"UPDATE memories SET x = 1\");\n    }\n    extern \"C\" fn helper() { gate_record_stop(); }\n}",
        ),
        (
            "following const mention",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        execute(\"UPDATE memories SET x = 1\");\n    }\n    const EXPLANATION: &str = \"gate_record_stop is required here\";\n}",
        ),
        (
            "line comment",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        // TODO: gate_record_stop();\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "block comment",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        /* gate_record_stop(); { */\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "string literal",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        log(\"call gate_record_stop() first }\");\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "nested helper only",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        fn inner() { gate_record_stop(); }\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "raw string mention",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        let _s = r#\"gate_record_stop(); \"}\"#;\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
    ];
    for (label, plant) in ungated_plants {
        assert!(
            !fn_body_has_gate(plant, "set_embeddings_batch"),
            "sensitivity ({label}): parity read credited a gate the target never calls"
        );
        assert!(
            !fn_any_body_has_gate(plant, "set_embeddings_batch"),
            "sensitivity ({label}): twin read credited a gate the target never calls"
        );
        let core = ungated_write_fns_for(plant, is_fn_start, write_sql_line);
        assert!(
            core.iter().any(|n| n == "set_embeddings_batch"),
            "sensitivity ({label}): the main-scanner core must flag the target (got {core:?})"
        );
    }

    let gated_plants = [
        (
            "call after a nested helper",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        fn inner() -> u8 { 1 }\n        self.gate_record_stop().await?;\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "call beside a brace-bearing string",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        let _t = \"{\"; gate_storage_conn(&c)?;\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "turbofish call",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        record_stop_status::<Db>(&c)?;\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
        (
            "call split from its await",
            "impl Store {\n    async fn set_embeddings_batch(&self) {\n        self.gate_record_stop()\n            .await?;\n        execute(\"UPDATE memories SET x = 1\");\n    }\n}",
        ),
    ];
    for (label, plant) in gated_plants {
        assert!(
            fn_body_has_gate(plant, "set_embeddings_batch"),
            "specificity ({label}): a real gate call must be credited"
        );
        let core = ungated_write_fns_for(plant, is_fn_start, write_sql_line);
        assert!(
            !core.iter().any(|n| n == "set_embeddings_batch"),
            "specificity ({label}): the core must not flag a gated target (got {core:?})"
        );
    }

    // Wrappers: a proven same-file wrapper is a gate; an UNPROVEN one (its
    // own body never calls a gate) is not.
    let proven = "fn gate_record_stop_actions(c: &C) -> R { gate_storage_conn_rusqlite(c) }\nfn create(c: &C) -> R {\n    gate_record_stop_actions(c)?;\n    c.execute(\"INSERT INTO actions VALUES (1)\")\n}\n";
    assert!(
        fn_body_has_gate(proven, "create"),
        "specificity: a proven gate wrapper must be credited"
    );
    let unproven = "fn gate_record_stop_actions(c: &C) -> R { Ok(()) }\nfn create(c: &C) -> R {\n    gate_record_stop_actions(c)?;\n    c.execute(\"INSERT INTO actions VALUES (1)\")\n}\n";
    assert!(
        !fn_body_has_gate(unproven, "create"),
        "sensitivity: a wrapper whose body never calls a gate must NOT be credited"
    );

    let outside = "static Q: &[&str] = &[];\nmacro_rules! m { () => { execute(\"DELETE FROM memories\") } }\n";
    let core = ungated_write_fns_for(outside, is_fn_start, write_sql_line);
    assert!(
        core.iter().any(|n| n.starts_with("<no enclosing fn")),
        "fail-closed: a write outside every fn must be reported, not dropped (got {core:?})"
    );
}

#[test]
fn record_stop_write_sql_fns_are_gated_or_allowlisted_b7() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = root.join("src");
    let mut files = Vec::new();
    walk_rs(&src_root, &mut files);
    let sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|p| Some((rel_src(p, root), fs::read_to_string(p).ok()?)))
        .collect();
    let test_only = cfg_test_declared_files(&sources);

    let allow: HashSet<(String, String)> = include_str!("record_stop_b7_allowlist.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.split('\t');
            (
                parts.next().expect("allowlist file").to_string(),
                parts.next().expect("allowlist fn").to_string(),
            )
        })
        .collect();

    let mut ungated: Vec<(String, String, usize)> = Vec::new();
    let mut findings: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;
    let mut gated_fns = 0usize;
    let mut gated_hits: HashMap<String, bool> = MUST_BE_GATED
        .iter()
        .map(|n| ((*n).to_string(), false))
        .collect();

    for path in files {
        let rel = rel_src(&path, root);
        if skip_path(&rel) || test_only.contains(&rel) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let text = join_string_continuations(strip_test_mod(&raw));
        let lines: Vec<&str> = text.lines().collect();

        // Pair every write-SQL line with the nearest preceding `fn`
        // (impl methods sit at indent 4; do not swallow them as nested
        // inside an earlier indent-0 helper).
        // #9414: a form the tokenizer cannot classify is a finding naming
        // file:line; the file is never skipped and never read as code.
        let mask = match code_mask(&text) {
            Ok(m) => m,
            Err(finding) => {
                findings.push(format!("{rel}: {finding}"));
                continue;
            }
        };
        scanned_files += 1;
        let masked: Vec<&str> = mask.lines().collect();
        let spans = fn_spans(&masked, is_fn_start);
        let wrappers = gate_wrappers(&lines, &masked, &spans);
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for (idx, line) in lines.iter().enumerate() {
            if !write_sql_line(line) {
                continue;
            }
            let Some(&(start, end, ref name)) = enclosing_span(&spans, idx) else {
                // R4-G2: outside every fn. Write SQL held in a module/impl
                // `const`/`static` item is the #3484 case (the executor is
                // #3485); anything else is reported, never dropped.
                let prev_end = spans
                    .iter()
                    .filter(|(_, e, _)| *e <= idx)
                    .map(|(_, e, _)| *e)
                    .max()
                    .unwrap_or(0);
                let in_item = lines[prev_end..=idx]
                    .iter()
                    .any(|&l| is_item_boundary_line(l, usize::MAX));
                if !in_item {
                    ungated.push((rel.clone(), "<no enclosing fn>".to_string(), idx + 1));
                }
                continue;
            };
            // #3484 — write SQL held in a module/impl-level `const`/`static`
            // item is not inside the preceding fn; attributing it there
            // flagged `embed_skip::from_stored` for `SQL_INSERT_IGNORE`.
            // (Const-reference tracking, so the fn that EXECUTES the const
            // is scanned instead, is #3485.)
            let fn_indent = lines[start].len() - lines[start].trim_start().len();
            let item_boundary_between = lines[start + 1..=idx]
                .iter()
                .any(|&l| is_item_boundary_line(l, fn_indent));
            if item_boundary_between {
                continue;
            }
            let key = (rel.clone(), name.clone());
            if !seen.insert(key.clone()) {
                continue;
            }
            if is_test_fn(&lines, start)
                || name.starts_with("migrate_v")
                || name.starts_with("test_")
            {
                continue;
            }
            let credit = span_gate_credit(&lines, &masked, &spans, start, end, &wrappers);
            if credit == GateCredit::Credited {
                gated_fns += 1;
                if let Some(flag) = gated_hits.get_mut(name) {
                    *flag = true;
                }
                continue;
            }
            if allow.contains(&key) {
                continue;
            }
            let why = match credit {
                GateCredit::Conditional(at) => format!("conditional gate at line {}", at + 1),
                _ => "no gate".to_string(),
            };
            ungated.push((rel.clone(), format!("{name} ({why})"), start + 1));
        }
    }

    assert!(
        findings.is_empty(),
        "#9414 B7 tokenizer findings (unclassifiable forms):\n  {}",
        findings.join("\n  ")
    );
    // #9414 fail closed: an empty scan or zero credited gates is a failure.
    assert!(scanned_files > 0, "#9414 B7 scanned no source file");
    assert!(gated_fns > 0, "#9414 B7 credited no gated fn");

    let mut missing_required = Vec::new();
    for (name, hit) in &gated_hits {
        if !hit {
            missing_required.push(name.clone());
        }
    }
    missing_required.sort();

    let mut extra: Vec<String> = ungated
        .iter()
        .map(|(f, n, line)| format!("{f}:{line} {n}"))
        .collect();
    extra.sort();

    assert!(
        missing_required.is_empty(),
        "B7 required functions are not gated: {}",
        missing_required.join(", ")
    );
    assert!(
        extra.is_empty(),
        "B7 structural completeness: write-SQL functions are neither gated nor allowlisted:\n  {}\n(add a gate or a reviewed ALLOWLIST row)",
        extra.join("\n  ")
    );

    let sqlite_src = fs::read_to_string(root.join("src/storage/mod.rs")).expect("storage/mod.rs");
    let pg_src = fs::read_to_string(root.join("src/store/postgres.rs")).expect("postgres.rs");
    let allow_txt = include_str!("record_stop_b7_allowlist.txt");
    let mut parity_fail = Vec::new();
    for (sqlite_fn, pg_fn) in SQLITE_PG_TWINS {
        if !fn_any_body_has_gate(&sqlite_src, sqlite_fn) {
            continue;
        }
        if !fn_body_has_gate(&pg_src, pg_fn) {
            parity_fail.push(format!("sqlite {sqlite_fn} is gated but pg {pg_fn} is not"));
        }
        let exempt = allow_txt.lines().any(|l| {
            l.starts_with("src/store/postgres.rs\t") && l.ends_with(&format!("\t{pg_fn}"))
        });
        if exempt {
            parity_fail.push(format!(
                "pg {pg_fn} is allowlisted while sqlite twin {sqlite_fn} gates — remove from allowlist"
            ));
        }
    }
    assert!(
        parity_fail.is_empty(),
        "B7 pg/sqlite gate parity failures:\n  {}",
        parity_fail.join("\n  ")
    );
}

/// #4149 — test-ness comes from the module DECLARATION, never from the name.
#[test]
fn cfg_test_declared_modules_are_skipped_and_nothing_else_4149() {
    let f = |p: &str, s: &str| (p.to_string(), s.to_string());
    let files = vec![
        // Declared test-only (the #3957 shape, incl. visibility + blank line).
        f(
            "src/store/sqlite.rs",
            "fn a() {}\n#[cfg(test)]\n\npub(crate) mod owner_gate_txn_3957;\n#[cfg(test)]\nmod dir_mod;\n",
        ),
        f(
            "src/store/sqlite/owner_gate_txn_3957.rs",
            "fn arm() { \"UPDATE memories SET x\"; }",
        ),
        f("src/store/sqlite/dir_mod/mod.rs", "mod inner;"),
        f("src/store/sqlite/dir_mod/inner.rs", "fn i() {}"),
        // NOT declared test-only: a test-looking NAME must not be skipped.
        f("src/store/sqlite.rs.bak", ""),
        f("src/store/sqlite/looks_like_test_hook.rs", "fn prod() {}"),
        // A `cfg(test)` attribute on something that is NOT an out-of-line mod.
        f("src/lib.rs", "#[cfg(test)]\nfn helper() {}\nmod store;\n"),
        f("src/store.rs", ""),
    ];
    let got = cfg_test_declared_files(&files);
    assert!(
        got.contains("src/store/sqlite/owner_gate_txn_3957.rs"),
        "{got:?}"
    );
    assert!(got.contains("src/store/sqlite/dir_mod/mod.rs"), "{got:?}");
    assert!(
        got.contains("src/store/sqlite/dir_mod/inner.rs"),
        "children of a test-only module: {got:?}"
    );
    assert!(
        !got.contains("src/store/sqlite/looks_like_test_hook.rs"),
        "a NAME proves nothing: {got:?}"
    );
    assert!(
        !got.contains("src/store.rs"),
        "an ungated `mod store;` is production: {got:?}"
    );
    assert_eq!(got.len(), 3, "exactly the declared set: {got:?}");
}

/// #4148 — a comment ending in a backslash is not a string continuation.
/// A doc comment carrying a shell example that ends in `\` sits directly
/// above an UNGATED writer, which follows a GATED function. Before #4148
/// the join swallowed the `fn` signature into the comment line, so the
/// ungated writer's SQL was credited to the gated function above it. The
/// same shape with a trailing `\` on a code-line comment is covered too.
/// Control: a `\`-continued UPDATE/SET inside a string still joins and is
/// still flagged when ungated (the #3942 guarantee).
#[test]
fn a_comment_ending_in_a_backslash_never_hides_a_writer_4148() {
    let planted = r#"
    pub fn plant_gated_before(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute("DELETE FROM memories WHERE id = 1", [])?;
        Ok(())
    }

    /// Example:
    ///     ai-memory store --title x \
    pub fn plant_ungated_after_doc_backslash(conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM memories WHERE id = 2", [])?;
        Ok(())
    }

    pub fn plant_gated_before_two(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        let _ = 1; // trailing code comment \
        Ok(())
    }
    pub fn plant_ungated_after_code_comment(conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM memories WHERE id = 3", [])?;
        Ok(())
    }

    pub fn plant_split_update_ungated_control(conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE x \
             SET y = 2",
            [],
        )?;
        Ok(())
    }
"#;
    let flagged = ungated_write_fns_for(
        &join_string_continuations(planted),
        is_fn_start,
        write_sql_line,
    );
    for name in [
        "plant_ungated_after_doc_backslash",
        "plant_ungated_after_code_comment",
        "plant_split_update_ungated_control",
    ] {
        assert!(
            flagged.iter().any(|n| n == name),
            "sensitivity: `{name}` must be flagged as an ungated writer (got {flagged:?})"
        );
    }
    for name in ["plant_gated_before", "plant_gated_before_two"] {
        assert!(
            !flagged.iter().any(|n| n == name),
            "specificity: gated `{name}` must not be flagged (got {flagged:?})"
        );
    }
    // Only the string-literal line is a continuation.
    let lines = string_continuation_lines(planted);
    let at = |needle: &str| planted.lines().position(|l| l.contains(needle)).unwrap();
    assert!(lines.contains(&at("\"UPDATE x \\")));
    assert!(!lines.contains(&at("--title x \\")));
    assert!(!lines.contains(&at("trailing code comment \\")));
}

/// #4324 — an allowlisted migrate-only repair must not be `pub`: the B7
/// exemption holds only because the sole callers are the open-time/ladder
/// repair sites inside `crate::storage`, so a crate-visible-or-wider fn lets
/// a future outside caller inherit the record-stop exemption unreviewed.
#[test]
fn migrate_only_repair_is_not_public_4324() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = fs::read_to_string(root.join("src/storage/embed_skip.rs")).expect("embed_skip.rs");
    let decl = src
        .lines()
        .find(|l| l.contains("fn repair_sqlite_after_trigger_gap"))
        .expect("repair_sqlite_after_trigger_gap must exist");
    assert!(
        decl.trim_start().starts_with("pub(super) fn "),
        "#4324: allowlisted migrate-only repair must be `pub(super)`, found `{decl}`"
    );
}

/// #4324 — does `line` mention `name` as a whole identifier (the chars on both
/// sides are not `[A-Za-z0-9_]`)? Matches calls, fn-pointer takes, `use .. as`
/// aliases and `name (` with a space, not just `name(`.
fn mentions_bare_ident(line: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(name).any(|(i, m)| {
        let before = line[..i].chars().next_back();
        let after = line[i + m.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// #4324 — `pub(super)` alone does not pin "migrate callers only": any
/// wrapper inside `crate::storage` could re-expose the record-stop-exempt
/// repair, and B7 cannot see it (no write SQL in the wrapper). So pin the
/// call sites: every non-declaration, non-comment mention must be in
/// `src/storage/migrations.rs`, and there are exactly two today (open-time
/// repair + ladder tail); a new site must be reviewed here.
#[test]
fn repair_call_sites_are_migrate_only_4324() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    let mut sites: Vec<String> = Vec::new();
    for f in &files {
        let Ok(text) = fs::read_to_string(f) else {
            continue;
        };
        let rel = rel_src(f, root);
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//")
                || !mentions_bare_ident(line, "repair_sqlite_after_trigger_gap")
                || line.contains("fn repair_sqlite_after_trigger_gap")
            {
                continue;
            }
            sites.push(format!("{rel}:{}", i + 1));
        }
    }
    let outside: Vec<&String> = sites
        .iter()
        .filter(|s| !s.starts_with("src/storage/migrations.rs:"))
        .collect();
    assert!(
        outside.is_empty(),
        "#4324: repair call sites outside src/storage/migrations.rs: {outside:?}"
    );
    assert_eq!(
        sites.len(),
        2,
        "#4324: expected exactly 2 migrate call sites (open-time repair + ladder tail), got {sites:?}"
    );
}

// ---------------------------------------------------------------------------
// #9414 — the gate is credited only where it provably runs before the write,
// and every literal form of the edition is classified (never guessed).
// ---------------------------------------------------------------------------

/// #9414 — the verdict a unit cell asserts: `Ok(gated)` for the one fn named
/// `fn_name` in `src`, or the tokenizer finding (`line N: <reason>`).
fn b7_try_verdict(src: &str, fn_name: &str) -> Result<bool, String> {
    let v = try_fn_gate_verdicts(src, fn_name, is_fn_start)?;
    Ok(!v.is_empty() && v.iter().all(|g| *g))
}

/// #9414 — a write fn named `w` whose body is `body` (one statement per line).
fn b7_plant(body: &str) -> String {
    format!(
        "pub fn w(conn: &Connection, id: &str) -> Result<(bool, bool)> {{\n{body}\n    \
         conn.execute(\"UPDATE t SET a = 1 WHERE id = ?1\", [id])?;\n    Ok((true, true))\n}}\n"
    )
}

/// #9414 control-flow table: `(label, body, credited)`. m7a / m7b / m2 are
/// the issue's mutants; every `false` row is a gate the scanner cannot prove
/// runs before the write.
const B7_CONTROL_FLOW_ROWS_9414: &[(&str, &str, bool)] = &[
    ("plain gate first", "    gate_storage_conn(conn)?;", true),
    (
        "gate in an if condition",
        "    if record_stop_status(conn)? {\n        return Ok((false, false));\n    }",
        true,
    ),
    (
        "conditional early return before the gate",
        "    if id.is_empty() {\n        return Ok((false, false));\n    }\n    gate_storage_conn(conn)?;",
        true,
    ),
    (
        "? before the gate",
        "    let _n = id.parse::<i64>()?;\n    gate_storage_conn(conn)?;",
        true,
    ),
    (
        "m7a gate inside if false",
        "    if false {\n        gate_storage_conn(conn)?;\n    }",
        false,
    ),
    (
        "m7b gate after an early return in the same block",
        "    if id.is_empty() {\n        return Ok((false, false));\n        gate_storage_conn(conn)?;\n    }",
        false,
    ),
    (
        "m2 gate after the write transaction",
        "    let out = in_write_txn(conn, || {\n        conn.execute(\"UPDATE t SET b = 2\", [])?;\n        Ok(())\n    });\n    gate_storage_conn(conn)?;\n    out?;",
        false,
    ),
    (
        "gate only in a nested fn",
        "    fn inner(conn: &Connection) -> Result<()> {\n        gate_storage_conn(conn)\n    }",
        false,
    ),
    (
        "gate in an uncalled closure",
        "    let _later = || gate_storage_conn(conn);",
        false,
    ),
    (
        "gate in a braced closure",
        "    let _later = move || {\n        gate_storage_conn(conn)\n    };",
        false,
    ),
    (
        "gate under a cfg attribute",
        "    #[cfg(test)]\n    gate_storage_conn(conn)?;",
        false,
    ),
    (
        "gate behind a short circuit",
        "    let _ = id.is_empty() && gate_storage_conn(conn).is_ok();",
        false,
    ),
    (
        "gate in an else branch",
        "    if id.is_empty() {\n        let _ = 1;\n    } else {\n        gate_storage_conn(conn)?;\n    }",
        false,
    ),
    (
        "gate after a depth-1 return",
        "    return Ok((false, false));\n    gate_storage_conn(conn)?;",
        false,
    ),
    (
        "gate inside a macro argument",
        "    debug_assert!(gate_storage_conn(conn).is_ok());",
        false,
    ),
];

#[test]
fn b7_gate_is_credited_only_where_it_runs_before_the_write_9414() {
    let mut wrong = Vec::new();
    for (label, body, credited) in B7_CONTROL_FLOW_ROWS_9414 {
        let got = b7_try_verdict(&b7_plant(body), "w");
        if got != Ok(*credited) {
            wrong.push(format!("{label}: expected Ok({credited}), got {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "#9414 control-flow rows misjudged:\n  {}",
        wrong.join("\n  ")
    );
}

/// #9414 literal-form table: `(label, statement hiding a gate-looking text,
/// statement with the same form and no gate text)`. The first must never be
/// credited; the second, followed by a real gate, must be. `None` = the form
/// cannot carry the gate text.
const B7_LITERAL_FORM_ROWS_9414: &[(&str, Option<&str>, &str)] = &[
    (
        "string with escapes",
        Some(r#"    let _ = "gate_storage_conn(conn)?; } \" {";"#),
        r#"    let _ = "} \" {";"#,
    ),
    (
        "raw string",
        Some(r#"    let _ = r"gate_storage_conn(conn)?; }\";"#),
        r#"    let _ = r"\";"#,
    ),
    (
        "raw string with two #",
        Some(r###"    let _ = r##"gate_storage_conn(conn)?; "# }"##;"###),
        r###"    let _ = r##"" "# }"##;"###,
    ),
    (
        "byte string",
        Some(r#"    let _ = b"gate_storage_conn(conn)?; } \"";"#),
        r#"    let _ = b"}\"";"#,
    ),
    (
        "raw byte string",
        Some(r##"    let _ = br#"gate_storage_conn(conn)?; }"#;"##),
        r#"    let _ = br"\";"#,
    ),
    (
        "C string",
        Some(r#"    let _ = c"gate_storage_conn(conn)?; } \"";"#),
        r#"    let _ = c"}\"";"#,
    ),
    (
        "raw C string with #",
        Some(r##"    let _ = cr#"gate_storage_conn(conn)?; }"#;"##),
        r##"    let _ = cr#"\"#;"##,
    ),
    (
        "raw C string ending in a backslash (9414 comment 6948153318)",
        Some(r#"    let _ = cr"gate_storage_conn(conn)?; }\";"#),
        r#"    let _ = cr"\";"#,
    ),
    ("char brace", None, "    let _ = '{';"),
    ("char quote", None, "    let _ = '\"';"),
    ("char escaped quote", None, r"    let _ = '\'';"),
    ("byte char", None, "    let _ = b'\"';"),
    ("lifetime", None, "    let _: &'static str = \"}\";"),
    ("raw identifier", None, "    let r#match = \"}\";"),
    (
        "numbers",
        None,
        "    let _ = (1_000_u32, 0x1F, 1.5e-3, 2..3);",
    ),
    (
        "line comment",
        Some("    // gate_storage_conn(conn)?; }"),
        "    // }",
    ),
    (
        "nested block comment",
        Some("    /* /* gate_storage_conn(conn)?; */ } */"),
        "    /* /* } */ { */",
    ),
    (
        "doc comment",
        Some("    /// gate_storage_conn(conn)?; }"),
        "    /// }",
    ),
];

#[test]
fn b7_literal_forms_never_hide_or_fake_a_gate_9414() {
    let mut wrong = Vec::new();
    for (label, hiding, plain) in B7_LITERAL_FORM_ROWS_9414 {
        if let Some(h) = hiding {
            let got = b7_try_verdict(&b7_plant(h), "w");
            if got != Ok(false) {
                wrong.push(format!("{label} (gate text in the form): got {got:?}"));
            }
        }
        let real = format!("{plain}\n    gate_storage_conn(conn)?;");
        let got = b7_try_verdict(&b7_plant(&real), "w");
        if got != Ok(true) {
            wrong.push(format!("{label} (real gate after the form): got {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "#9414 literal-form rows misjudged:\n  {}",
        wrong.join("\n  ")
    );
}

/// #9414 — forms the tokenizer cannot classify: `(label, statement, exact
/// finding)`. Each is a finding naming the line (the plant's body starts on
/// line 2), never skipped and never read as code.
const B7_UNCLASSIFIABLE_ROWS_9414: &[(&str, &str, &str)] = &[
    (
        "reserved string prefix",
        "    let _ = f\"gate_storage_conn(conn)\";",
        "line 2: reserved literal prefix",
    ),
    (
        "reserved guarded string",
        "    let _ = #\"gate_storage_conn(conn)\"#;",
        "line 2: reserved guarded string literal",
    ),
    (
        "unterminated block comment",
        "    /* gate_storage_conn(conn)?;",
        "line 2: unterminated block comment",
    ),
    (
        "char literal with two characters",
        "    let _ = 'ab';",
        "line 2: char literal with more than one character",
    ),
    (
        "character outside the grammar",
        "    let _ = `gate_storage_conn(conn)`;",
        "line 2: unclassifiable character",
    ),
];

#[test]
fn b7_unclassifiable_form_is_a_finding_9414() {
    let mut wrong = Vec::new();
    for (label, stmt, finding) in B7_UNCLASSIFIABLE_ROWS_9414 {
        let got = b7_try_verdict(&b7_plant(stmt), "w");
        if got != Err((*finding).to_string()) {
            wrong.push(format!("{label}: expected Err({finding:?}), got {got:?}"));
        }
    }
    let hashes = "#".repeat(B7_RAW_HASH_OVER_LIMIT_9414);
    let over = format!("    let _ = r{hashes}\"x\"{hashes};");
    let got = b7_try_verdict(&b7_plant(&over), "w");
    let want = "line 2: raw string delimiter has more than 255 #";
    if got != Err(want.to_string()) {
        wrong.push(format!(
            "256 # raw string: expected Err({want:?}), got {got:?}"
        ));
    }
    assert!(
        wrong.is_empty(),
        "#9414 unclassifiable rows misjudged:\n  {}",
        wrong.join("\n  ")
    );
}

/// #9414 — one more `#` than a raw string delimiter may carry (rustc: 255).
const B7_RAW_HASH_OVER_LIMIT_9414: usize = 256;
/// #9414 — size of the generated input of the linear bound.
const B7_LINEAR_BOUND_BYTES_9414: usize = 100_000;
/// #9414 — wall-clock ceiling for scanning that input (debug build).
const B7_LINEAR_BOUND_CEILING_9414: std::time::Duration = std::time::Duration::from_secs(3);

#[test]
fn b7_scan_is_linear_on_a_100k_input_9414() {
    // Every literal form, a deep brace nest, and a long quote run inside a
    // raw string with many `#` (the shape that is quadratic in a naive
    // closing-delimiter search).
    let mut body = String::new();
    let quotes = format!(
        "    let _ = r{h}\"{q}\"{h};\n",
        h = "#".repeat(200),
        q = "\"#".repeat(400)
    );
    while body.len() < B7_LINEAR_BOUND_BYTES_9414 {
        for (_, hiding, plain) in B7_LITERAL_FORM_ROWS_9414 {
            body.push_str(hiding.unwrap_or(plain));
            body.push('\n');
        }
        body.push_str(&quotes);
        body.push_str("    { { { { let _ = '}'; } } } }\n");
    }
    body.push_str("    gate_storage_conn(conn)?;");
    let src = b7_plant(&body);
    assert!(
        src.len() >= B7_LINEAR_BOUND_BYTES_9414,
        "generated input too small"
    );
    let started = std::time::Instant::now();
    let got = b7_try_verdict(&src, "w");
    let took = started.elapsed();
    assert_eq!(
        got,
        Ok(true),
        "#9414 100K input: the trailing gate must be credited"
    );
    assert!(
        took <= B7_LINEAR_BOUND_CEILING_9414,
        "#9414 100K input took {took:?}, ceiling {B7_LINEAR_BOUND_CEILING_9414:?}"
    );
    // Op-count bound: one step per char plus at most RAW_HASH_LIMIT per
    // quote inside a raw string, so steps <= (RAW_HASH_LIMIT + 1) * bytes.
    let (tokens, steps) = rust_tokens::tokenize_steps(&src);
    assert!(tokens.is_ok(), "#9414 100K input must tokenize: {tokens:?}");
    let ceiling = u64::try_from((rust_tokens::RAW_HASH_LIMIT + 1) * src.len()).unwrap_or(u64::MAX);
    assert!(
        steps <= ceiling,
        "#9414 100K input took {steps} steps, ceiling {ceiling}"
    );
}

#[test]
fn b7_absent_fn_is_never_gated_9414() {
    // Fail closed: a fn the scanner cannot find is not gated.
    assert_eq!(
        b7_try_verdict(&b7_plant("    gate_storage_conn(conn)?;"), "no_such_fn"),
        Ok(false),
        "#9414 an absent fn must read as ungated"
    );
}
