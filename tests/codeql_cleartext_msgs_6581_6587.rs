// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Red guard for the `CodeQL` `rust/cleartext-logging` cluster
//! #6581 / #6583 / #6585 / #6586 / #6587 (Refs #9017 #8741 #6163 #6351).
//!
//! Re-cut on the chain tip from the lost commit 4830cdf0a328: the lost
//! per-issue anchor cells are kept (anchors moved with the code; no cell
//! was dropped) and the guard now locks the whole CLASS, not five sites.
//!
//! Class invariant: no assertion message interpolates a value that holds a
//! secret on the failing path. Concretely, for every `assert!` /
//! `debug_assert!` whose condition is a negative leak check
//! `!HAYSTACK.contains(NEEDLE)`, the message must not render the haystack
//! (it holds the secret exactly when the assertion fails) nor a
//! secret-bearing needle binding; and in the scanned files no assertion
//! message renders a secret-valued binding in any form, `Debug`-dumps a
//! binding that can carry one (a whole result, response, warning vector,
//! peer, cert or key path), or prints a cert-derived peer id. A size-only
//! rendering (`.len()`, `.is_empty()`, ...) is the one allowed form; every
//! other rendering of a guarded binding is a finding (fail closed).
//!
//! The scanner is a small lexer (string, raw-string, char-literal and
//! comment aware), linear in its input; it is exercised on a table of
//! leaky and clean forms and on a 100K+ synthetic input under a time bound.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Files whose assertion messages get the full secret-binding check.
const SCANNED_FILES: &[&str] = &[
    "src/cli/agents.rs",
    "src/cli/commands/config.rs",
    "src/config_redact.rs",
    "src/daemon_runtime.rs",
    "src/federation/mod.rs",
    "src/cli/boot.rs",
    "src/cli/install.rs",
    "src/cli/schema_init.rs",
    "src/federation/peer.rs",
    "src/federation/erasure_outbox.rs",
    "src/federation/receive_auth.rs",
    "src/handlers/errors.rs",
    "src/handlers/skills.rs",
    "src/handlers/agent_api_key.rs",
    "src/cli/capability.rs",
    "src/cli/rules.rs",
];

/// Roots (directories or files) over which the leak-echo rule holds.
const CLASS_ROOTS: &[&str] = &[
    "src/cli",
    "src/federation",
    "src/handlers",
    "src/daemon_runtime",
    "src/daemon_runtime.rs",
    "src/config_redact.rs",
];

/// Bindings whose VALUE is a secret (or the text that carries one): never
/// rendered in an assertion message, in any format.
const SECRET_VALUE_BINDINGS: &[&str] = &[
    "secret",
    "secrets",
    "token",
    "password",
    "passwd",
    "passphrase",
    "canary",
    "cred",
    "creds",
    "credential",
    "fixture",
    "leak",
    "leaked",
    "warning",
    "bearer",
    "api_key",
];

/// Bindings of a type that can hold a secret (a whole result / response /
/// warning vector / peer / cert or key path / config): never `Debug`-dumped.
const SECRET_BEARING_DEBUG_BINDINGS: &[&str] = &[
    "res", "resp", "response", "result", "w", "warnings", "peer", "cert", "key", "cfg", "config",
];

/// Expressions that render a certificate-derived peer identity.
const PEER_IDENTITY_EXPRS: &[&str] = &["peer.id"];

/// Renderings that expose only a size, never the content.
const SIZE_ONLY_SUFFIXES: &[&str] = &[
    ".len()",
    ".lines().count()",
    ".chars().count()",
    ".is_empty()",
];

/// Macros whose first argument is the condition.
const CONDITION_MACROS: &[&str] = &["assert", "debug_assert"];

/// Macros whose first two arguments are the compared operands.
const OPERAND_MACROS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// Synthetic size-bound input: lines, byte floor and wall-clock ceiling.
const SCAN_SIZE_LINES: usize = 20_000;
const SCAN_SIZE_FLOOR_BYTES: usize = 100_000;
const SCAN_TIME_CEILING: Duration = Duration::from_secs(5);
/// Longest char-literal escape (`'\u{10FFFF}'`) in bytes.
const CHAR_ESCAPE_MAX_BYTES: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Code,
    Literal,
    Comment,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn fill(kinds: &mut [Kind], from: usize, to: usize, kind: Kind) {
    let to = to.min(kinds.len());
    for k in &mut kinds[from..to] {
        *k = kind;
    }
}

fn string_end(b: &[u8], mut j: usize) -> usize {
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

fn raw_string_end(b: &[u8], i: usize) -> Option<usize> {
    let prefix_ok =
        i == 0 || !is_ident(b[i - 1]) || (b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2])));
    if !prefix_ok {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0usize;
    while b.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if b.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < b.len() {
        if b[j] == b'"'
            && b.get(j + 1..j + 1 + hashes)
                .is_some_and(|s| s.iter().all(|&c| c == b'#'))
        {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(b.len())
}

fn block_comment_end(b: &[u8], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    while j < b.len() {
        if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
            depth += 1;
            j += 2;
        } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
            depth = depth.saturating_sub(1);
            j += 2;
            if depth == 0 {
                return j;
            }
        } else {
            j += 1;
        }
    }
    b.len()
}

fn char_literal_end(src: &str, i: usize) -> Option<usize> {
    let b = src.as_bytes();
    if b.get(i + 1) == Some(&b'\\') {
        let window = b.get(i + 3..(i + CHAR_ESCAPE_MAX_BYTES).min(b.len()))?;
        return window
            .iter()
            .position(|&c| c == b'\'')
            .map(|o| i + 3 + o + 1);
    }
    let c = src.get(i + 1..)?.chars().next()?;
    let after = i + 1 + c.len_utf8();
    (b.get(after) == Some(&b'\'')).then_some(after + 1)
}

/// Classify every byte of `src` as code, literal or comment.
fn classify(src: &str) -> Vec<Kind> {
    let b = src.as_bytes();
    let mut kinds = vec![Kind::Code; b.len()];
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied();
        let (end, kind) = match b[i] {
            b'/' if next == Some(b'/') => (
                src[i..].find('\n').map_or(b.len(), |o| i + o),
                Kind::Comment,
            ),
            b'/' if next == Some(b'*') => (block_comment_end(b, i), Kind::Comment),
            b'"' => (string_end(b, i + 1), Kind::Literal),
            b'r' => raw_string_end(b, i).map_or((i + 1, Kind::Code), |e| (e, Kind::Literal)),
            b'\'' => char_literal_end(src, i).map_or((i + 1, Kind::Code), |e| (e, Kind::Literal)),
            _ => (i + 1, Kind::Code),
        };
        fill(&mut kinds, i, end, kind);
        i = end;
    }
    kinds
}

/// One macro invocation: its name, line and trimmed top-level arguments.
struct Invocation {
    name: String,
    line: usize,
    args: Vec<String>,
}

/// The matching close of every open bracket (one linear stack pass over
/// code bytes); `None` for an open bracket that is never closed.
fn bracket_pairs(b: &[u8], kinds: &[Kind]) -> Vec<Option<usize>> {
    let mut pairs = vec![None; b.len()];
    let mut stack = Vec::new();
    for (j, (&c, &k)) in b.iter().zip(kinds).enumerate() {
        if k != Kind::Code {
            continue;
        }
        match c {
            b'(' | b'[' | b'{' => stack.push(j),
            b')' | b']' | b'}' => {
                if let Some(open) = stack.pop() {
                    pairs[open] = Some(j);
                }
            }
            _ => {}
        }
    }
    pairs
}

fn split_args(src: &str, kinds: &[Kind], open: usize, close: usize) -> Vec<String> {
    let b = src.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    for (off, (&c, &k)) in b[open + 1..close]
        .iter()
        .zip(&kinds[open + 1..close])
        .enumerate()
    {
        if k != Kind::Code {
            continue;
        }
        let j = open + 1 + off;
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(src[start..j].trim().to_string());
                start = j + 1;
            }
            _ => {}
        }
    }
    let last = src[start..close].trim();
    if !last.is_empty() {
        args.push(last.to_string());
    }
    args
}

/// Every invocation of one of `names`; `Err((name, line))` when unterminated.
fn invocations(src: &str, names: &[&str]) -> Vec<Result<Invocation, (String, usize)>> {
    let b = src.as_bytes();
    let kinds = classify(src);
    let pairs = bracket_pairs(b, &kinds);
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(src.match_indices('\n').map(|(o, _)| o + 1))
        .collect();
    let mut out = Vec::new();
    for (bang, _) in src.match_indices('!') {
        if kinds[bang] != Kind::Code {
            continue;
        }
        let name_end = src[..bang].trim_end().len();
        let name_start = src[..name_end]
            .bytes()
            .rposition(|c| !is_ident(c))
            .map_or(0, |p| p + 1);
        let name = &src[name_start..name_end];
        if !names.contains(&name) {
            continue;
        }
        let open = bang + 1 + (src[bang + 1..].len() - src[bang + 1..].trim_start().len());
        if b.get(open) != Some(&b'(') {
            continue;
        }
        let line = line_starts.partition_point(|&s| s <= bang);
        match pairs[open] {
            Some(close) => out.push(Ok(Invocation {
                name: name.to_string(),
                line,
                args: split_args(src, &kinds, open, close),
            })),
            None => out.push(Err((name.to_string(), line))),
        }
    }
    out
}

/// The body of a string literal argument (plain or raw), if it is one.
fn literal_body(arg: &str) -> Option<&str> {
    if let Some(inner) = arg.strip_prefix('"') {
        return inner.strip_suffix('"');
    }
    let raw = arg.strip_prefix('r')?;
    let hashes = raw.len() - raw.trim_start_matches('#').len();
    let inner = raw.get(hashes..raw.len().checked_sub(hashes)?)?;
    inner.strip_prefix('"')?.strip_suffix('"')
}

/// `(argument, spec)` for every `{...}` placeholder of a format body.
fn placeholders(body: &str) -> Vec<(String, String)> {
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'{' {
            i += 1;
            continue;
        }
        if b.get(i + 1) == Some(&b'{') {
            i += 2;
            continue;
        }
        let Some(close) = body[i + 1..].find('}').map(|o| i + 1 + o) else {
            out.push(("<unterminated placeholder>".to_string(), "?".to_string()));
            break;
        };
        let inner = &body[i + 1..close];
        let (arg, spec) = inner.split_once(':').unwrap_or((inner, ""));
        out.push((arg.trim().to_string(), spec.to_string()));
        i = close + 1;
    }
    out
}

fn named_arg(arg: &str) -> Option<(String, String)> {
    let (name, value) = arg.split_once('=')?;
    let name = name.trim();
    let plain_ident = !name.is_empty() && name.bytes().all(is_ident);
    (plain_ident && !value.starts_with('=')).then(|| (name.to_string(), value.trim().to_string()))
}

/// `(rendered expression, spec)` for every value a message renders.
/// A message whose format argument is not a literal renders every argument
/// (fail closed: each is treated as a `Debug` rendering).
fn interpolations(msg_args: &[String]) -> Vec<(String, String)> {
    let Some((fmt, rest)) = msg_args.split_first() else {
        return Vec::new();
    };
    let Some(body) = literal_body(fmt) else {
        return msg_args
            .iter()
            .map(|a| (a.clone(), "?".to_string()))
            .collect();
    };
    let mut named = BTreeMap::new();
    let mut positional = Vec::new();
    for a in rest {
        match named_arg(a) {
            Some((k, v)) => {
                named.insert(k, v);
            }
            None => positional.push(a.clone()),
        }
    }
    let mut next = 0usize;
    let mut out = Vec::new();
    for (arg, spec) in placeholders(body) {
        let expr = if arg.is_empty() {
            next += 1;
            positional.get(next - 1).cloned()
        } else if let Ok(idx) = arg.parse::<usize>() {
            positional.get(idx).cloned()
        } else {
            Some(named.get(&arg).cloned().unwrap_or_else(|| arg.clone()))
        };
        out.push((
            expr.unwrap_or_else(|| "<missing argument>".to_string()),
            spec,
        ));
    }
    out
}

/// Binding-like identifiers of an expression: not a field / method / path
/// segment, not a call or macro name.
fn bindings(expr: &str) -> Vec<&str> {
    let b = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_ident(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        let before = expr[..start].trim_end();
        let after = expr[i..].trim_start();
        let member = before.ends_with('.') || before.ends_with("::");
        let callee = after.starts_with('(') || after.starts_with("::") || after.starts_with('!');
        if !b[start].is_ascii_digit() && !member && !callee {
            out.push(&expr[start..i]);
        }
    }
    out
}

fn size_only(expr: &str) -> bool {
    SIZE_ONLY_SUFFIXES
        .iter()
        .any(|s| expr.trim_end().ends_with(s))
}

fn normalized(expr: &str) -> String {
    expr.chars()
        .filter(|c| !c.is_whitespace() && *c != '&')
        .collect()
}

/// `(haystack, needle)` of a `!HAYSTACK.contains(NEEDLE)` condition.
fn negated_contains(cond: &str) -> Option<(&str, &str)> {
    let c = cond
        .trim()
        .strip_prefix('!')?
        .trim_start()
        .strip_suffix(')')?;
    let at = c.rfind(".contains(")?;
    Some((c[..at].trim(), c[at + ".contains(".len()..].trim()))
}

fn leak_echo_findings(rel: &str, inv: &Invocation, out: &mut Vec<String>) {
    let Some((hay, needle)) = inv.args.first().and_then(|c| negated_contains(c)) else {
        return;
    };
    let hay_ids = bindings(hay);
    let needle_ids: Vec<&str> = bindings(needle)
        .into_iter()
        .filter(|id| SECRET_VALUE_BINDINGS.contains(id))
        .collect();
    for (expr, _) in interpolations(&inv.args[1..]) {
        if size_only(&expr) {
            continue;
        }
        let ids = bindings(&expr);
        if ids.iter().any(|id| hay_ids.contains(id)) || normalized(&expr) == normalized(hay) {
            out.push(format!(
                "{rel}:{}: `{}!` leak check echoes its haystack via `{expr}`",
                inv.line, inv.name
            ));
        }
        if ids.iter().any(|id| needle_ids.contains(id)) {
            out.push(format!(
                "{rel}:{}: `{}!` leak check echoes its secret needle via `{expr}`",
                inv.line, inv.name
            ));
        }
    }
}

fn secret_binding_findings(rel: &str, inv: &Invocation, out: &mut Vec<String>) {
    let skip = if OPERAND_MACROS.contains(&inv.name.as_str()) {
        2
    } else {
        1
    };
    let Some(msg) = inv.args.get(skip..) else {
        return;
    };
    for (expr, spec) in interpolations(msg) {
        if size_only(&expr) {
            continue;
        }
        let ids = bindings(&expr);
        if let Some(id) = ids.iter().find(|id| SECRET_VALUE_BINDINGS.contains(id)) {
            out.push(format!(
                "{rel}:{}: `{}!` message renders secret-valued `{id}`",
                inv.line, inv.name
            ));
        }
        let debug = spec.contains('?');
        if let Some(id) = ids
            .iter()
            .find(|id| debug && SECRET_BEARING_DEBUG_BINDINGS.contains(id))
        {
            out.push(format!(
                "{rel}:{}: `{}!` message Debug-dumps secret-bearing `{id}`",
                inv.line, inv.name
            ));
        }
        if let Some(p) = PEER_IDENTITY_EXPRS.iter().find(|p| expr.contains(*p)) {
            out.push(format!(
                "{rel}:{}: `{}!` message renders the peer identity `{p}`",
                inv.line, inv.name
            ));
        }
    }
}

/// Scan `src` (named `rel` in findings). `secret_bindings` adds the full
/// secret-binding check on every assertion macro to the leak-echo rule.
fn scan_text(rel: &str, src: &str, secret_bindings: bool) -> Vec<String> {
    let names: Vec<&str> = CONDITION_MACROS
        .iter()
        .chain(OPERAND_MACROS)
        .copied()
        .collect();
    let mut out = Vec::new();
    for found in invocations(src, &names) {
        match found {
            Ok(inv) => {
                if CONDITION_MACROS.contains(&inv.name.as_str()) {
                    leak_echo_findings(rel, &inv, &mut out);
                }
                if secret_bindings {
                    secret_binding_findings(rel, &inv, &mut out);
                }
            }
            Err((name, line)) => out.push(format!(
                "{rel}:{line}: `{name}!` is unterminated (fail closed)"
            )),
        }
    }
    out
}

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_src(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel))
        .unwrap_or_else(|e| panic!("guard could not read {rel}: {e}"))
}

fn rust_files_under(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("guard could not list {}: {e}", root.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("guard could not read a dir entry: {e}"))
            .path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn assert_no_findings(findings: &[String]) {
    assert!(
        findings.is_empty(),
        "cleartext assertion-message sites remain ({}):\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// One guarded anchor site (the lost cells' shape).
struct Site {
    anchor: &'static str,
    forbidden: &'static [&'static str],
    /// Minimum anchor occurrences, so a renamed anchor cannot turn the
    /// guard vacuously green.
    min_hits: usize,
}

/// The text of the file from its first `#[cfg(test)]` module onward.
fn test_module(rel: &str, src: &str) -> String {
    let mut search_from = 0;
    while let Some(off) = src[search_from..].find("#[cfg(test)]") {
        let at = search_from + off;
        let tail = &src[at..];
        let head: String = tail.lines().take(3).collect::<Vec<_>>().join("\n");
        if head.contains("mod ") {
            return tail.to_string();
        }
        search_from = at + "#[cfg(test)]".len();
    }
    panic!("guard found no #[cfg(test)] module in {rel}");
}

fn anchor_violations(rel: &str, text: &str, sites: &[Site]) -> Vec<String> {
    let mut out = Vec::new();
    for site in sites {
        let mut hits = 0usize;
        let mut from = 0usize;
        while let Some(off) = text[from..].find(site.anchor) {
            let start = from + off;
            let end = text[start..].find(");").map_or(text.len(), |e| start + e);
            let window = &text[start..end];
            hits += 1;
            for tok in site.forbidden {
                if window.contains(tok) {
                    out.push(format!(
                        "{rel}: site at anchor `{}` still interpolates `{tok}`",
                        site.anchor
                    ));
                }
            }
            from = start + site.anchor.len();
        }
        if hits < site.min_hits {
            out.push(format!(
                "{rel}: anchor `{}` found {hits} time(s), expected >= {}",
                site.anchor, site.min_hits
            ));
        }
    }
    out
}

fn assert_clean(rel: &str, sites: &[Site]) {
    let src = read_src(rel);
    assert_no_findings(&anchor_violations(rel, &test_module(rel, &src), sites));
}

/// #6581 — alert 167: `{res:?}` Debug dump of the quorum-approval result.
#[test]
fn cleartext_msgs_6581_cli_agents() {
    assert_clean(
        "src/cli/agents.rs",
        &[Site {
            anchor: "a met signed quorum must approve on the CLI",
            forbidden: &["{res:?}", "{res}", "{res:#?}"],
            min_hits: 1,
        }],
    );
}

/// #6583 — alerts 168/169/170: the migrate redaction loop. The loop
/// binding moved from `secret` to `fixture` on the tip; same conditions.
#[test]
fn cleartext_msgs_6583_cli_commands_config() {
    assert_clean(
        "src/cli/commands/config.rs",
        &[
            Site {
                anchor: "!stdout.contains(fixture),",
                forbidden: &["{fixture}", "{stdout}"],
                min_hits: 1,
            },
            Site {
                anchor: "!stderr.contains(fixture),",
                forbidden: &["{fixture}", "{stderr}"],
                min_hits: 1,
            },
            Site {
                anchor: " on_disk.contains(fixture),",
                forbidden: &["{fixture}", "{on_disk}"],
                min_hits: 1,
            },
        ],
    );
}

/// #6585 — alert 171: `"{secret} leaked: {rendered}"`, plus the sibling
/// loop of the identical shape (binding `fixture` on the tip).
#[test]
fn cleartext_msgs_6585_config_redact() {
    assert_clean(
        "src/config_redact.rs",
        &[
            Site {
                anchor: "!rendered.contains(secret),",
                forbidden: &["{secret}", "{rendered}"],
                min_hits: 1,
            },
            Site {
                anchor: "!rendered.contains(fixture),",
                forbidden: &["{fixture}", "{rendered}"],
                min_hits: 1,
            },
        ],
    );
}

/// #6586 — alerts 123..127: `api_key_bind_guard` warning text and the
/// `cert_peer_binding_boot_warnings` vectors.
#[test]
fn cleartext_msgs_6586_daemon_runtime() {
    assert_clean(
        "src/daemon_runtime.rs",
        &[
            Site {
                anchor: "warning.contains(\"reverse proxy\")",
                forbidden: &["{warning}", "{warning:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn mTLS-not-configured inert",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn no-binding-map inert",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn open window (mode",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "enforce must NOT warn open window",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
        ],
    );
}

/// #6587 — alerts 172..175: peer ids derived from certificate material
/// and the cert fixture paths.
#[test]
fn cleartext_msgs_6587_federation_mod() {
    assert_clean(
        "src/federation/mod.rs",
        &[
            Site {
                anchor: "stable-identity prefix",
                forbidden: &["peer.id", "{peer:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must never impersonate the legacy positional shape",
                forbidden: &["peer.id", "{peer:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "cert.exists(),",
                forbidden: &["{cert:?}", "{cert}", "cert.display()"],
                min_hits: 2,
            },
            Site {
                anchor: "key.exists(),",
                forbidden: &["{key:?}", "{key}", "key.display()"],
                min_hits: 1,
            },
        ],
    );
}

/// Sibling (production surface): `doctor --remote` error and note strings
/// rendered the operator-supplied URL verbatim, userinfo and query
/// included. They must render the credential-free origin and path only.
#[test]
fn cleartext_msgs_sibling_doctor_remote_url() {
    let rel = "src/cli/doctor.rs";
    let src = read_src(rel);
    assert_no_findings(&anchor_violations(
        rel,
        &src,
        &[
            Site {
                anchor: "anyhow::bail!(\"HTTP {status} from",
                forbidden: &["{url}", ", url)"],
                min_hits: 1,
            },
            Site {
                anchor: "format!(\"could not reach",
                forbidden: &["{url}", ", url)"],
                min_hits: 1,
            },
            Site {
                anchor: "(local db reference:",
                forbidden: &["{base} (", "\", base,"],
                min_hits: 1,
            },
        ],
    ));
}

/// Scan raw file bytes: the walk reads bytes, never a `String`, so a file
/// the guard cannot decode is reported, never skipped.
fn scan_bytes(rel: &str, bytes: &[u8], secret_bindings: bool) -> Vec<String> {
    match std::str::from_utf8(bytes) {
        Ok(src) => scan_text(rel, src, secret_bindings),
        Err(e) => panic!("guard could not read {rel}: {e}"),
    }
}

/// Every Rust file under the class roots, as `(repo-relative path, path)`.
fn class_files() -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    for root in CLASS_ROOTS {
        let path = repo_path(root);
        if path.exists() {
            rust_files_under(&path, &mut files);
        }
    }
    files.sort();
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    files
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&base)
                .unwrap_or(&path)
                .display()
                .to_string();
            (rel, path)
        })
        .collect()
}

/// Class cell: the leak-echo rule over every Rust file under the roots.
#[test]
fn cleartext_msgs_class_leak_echo_roots() {
    let files = class_files();
    assert!(
        files.len() > SCANNED_FILES.len(),
        "class roots resolved to {} files",
        files.len()
    );
    let mut findings = Vec::new();
    for (rel, path) in &files {
        let bytes =
            std::fs::read(path).unwrap_or_else(|e| panic!("guard could not read {rel}: {e}"));
        findings.extend(scan_bytes(rel, &bytes, false));
    }
    assert_no_findings(&findings);
}

/// Files the class roots must reach (#9307 review probe b3: `src/store`
/// was outside the five roots; `tests/` was never scanned).
const ROOT_PROBE_FILES: &[&str] = &[
    "src/store/mod.rs",
    "src/mcp/mod.rs",
    "src/main.rs",
    "tests/codeql_cleartext_msgs_6581_6587.rs",
];

#[test]
fn cleartext_msgs_class_roots_cover_src_and_tests() {
    let files = class_files();
    let missing: Vec<&str> = ROOT_PROBE_FILES
        .iter()
        .copied()
        .filter(|probe| {
            assert!(repo_path(probe).is_file(), "probe file {probe} is gone");
            !files.iter().any(|(rel, _)| rel == probe)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "class roots do not reach: {missing:?}"
    );
}

/// Table cell: the full secret-binding check over every scanned file, with
/// the binding lists named in `SECRET_VALUE_BINDINGS` and
/// `SECRET_BEARING_DEBUG_BINDINGS`.
#[test]
fn cleartext_msgs_class_secret_bindings_scanned_files() {
    let mut findings = Vec::new();
    for rel in SCANNED_FILES {
        findings.extend(scan_text(rel, &read_src(rel), true));
    }
    assert_no_findings(&findings);
}

macro_rules! sibling_cell {
    ($name:ident, $rel:literal) => {
        /// Per-file sibling cell: the full check on one scanned file, so a
        /// red names the file.
        #[test]
        fn $name() {
            assert!(
                SCANNED_FILES.contains(&$rel),
                "{} is not in SCANNED_FILES",
                $rel
            );
            assert_no_findings(&scan_text($rel, &read_src($rel), true));
        }
    };
}

sibling_cell!(cleartext_msgs_sibling_cli_agents, "src/cli/agents.rs");
sibling_cell!(
    cleartext_msgs_sibling_cli_commands_config,
    "src/cli/commands/config.rs"
);
sibling_cell!(cleartext_msgs_sibling_config_redact, "src/config_redact.rs");
sibling_cell!(
    cleartext_msgs_sibling_daemon_runtime,
    "src/daemon_runtime.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_federation_mod,
    "src/federation/mod.rs"
);
sibling_cell!(cleartext_msgs_sibling_cli_boot, "src/cli/boot.rs");
sibling_cell!(cleartext_msgs_sibling_cli_install, "src/cli/install.rs");
sibling_cell!(
    cleartext_msgs_sibling_cli_schema_init,
    "src/cli/schema_init.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_federation_peer,
    "src/federation/peer.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_federation_erasure_outbox,
    "src/federation/erasure_outbox.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_federation_receive_auth,
    "src/federation/receive_auth.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_handlers_errors,
    "src/handlers/errors.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_handlers_skills,
    "src/handlers/skills.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_handlers_agent_api_key,
    "src/handlers/agent_api_key.rs"
);
sibling_cell!(
    cleartext_msgs_sibling_cli_capability,
    "src/cli/capability.rs"
);
sibling_cell!(cleartext_msgs_sibling_cli_rules, "src/cli/rules.rs");

/// Leaky forms: each must yield at least one finding.
const LEAKY_FORMS: &[(&str, &str)] = &[
    (
        "inline haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {out}");"#,
    ),
    (
        "debug haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {out:?}");"#,
    ),
    (
        "pretty haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {out:#?}");"#,
    ),
    (
        "positional haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {}", out);"#,
    ),
    (
        "indexed haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {0}", out);"#,
    ),
    (
        "named haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {body}", body = out);"#,
    ),
    (
        "borrowed haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {}", &out);"#,
    ),
    (
        "trimmed haystack",
        r#"assert!(!out.contains(SECRET), "leaked: {}", out.trim());"#,
    ),
    (
        "lossy haystack",
        r#"assert!(!out.contains(SECRET), "{}", String::from_utf8_lossy(&out));"#,
    ),
    (
        "expression haystack",
        r#"assert!(!env.stderr_str().contains(SECRET), "{}", env.stderr_str());"#,
    ),
    (
        "needle echo",
        r#"assert!(!out.contains(secret), "{secret} leaked");"#,
    ),
    (
        "needle debug",
        r#"assert!(!out.contains(token), "{token:?} leaked");"#,
    ),
    (
        "raw literal",
        "assert!(!out.contains(SECRET), r#\"leaked \"{out}\"\"#);",
    ),
    (
        "debug_assert",
        r#"debug_assert!(!out.contains(SECRET), "{out}");"#,
    ),
    (
        "spaced macro",
        r#"assert ! ( !out.contains(SECRET) , "{out}" );"#,
    ),
    (
        "non-literal message",
        r"assert!(!out.contains(SECRET), describe(out));",
    ),
    (
        "multi-line",
        "assert!(\n    !out.contains(SECRET),\n    \"leak in\\n{out}\"\n);",
    ),
    ("result debug", r#"assert!(res.is_ok(), "{res:?}");"#),
    ("warning vector", r#"assert_eq!(w.len(), 1, "got {w:?}");"#),
    ("token display", r#"assert!(ok, "got: {}", token);"#),
    ("peer debug", r#"assert!(ok, "{peer:?}");"#),
    ("peer id", r#"assert!(ok, "got {}", peer.id);"#),
    ("secret in assert_ne", r#"assert_ne!(a, b, "{secret}");"#),
    ("cert path debug", r#"assert!(cert.exists(), "{cert:?}");"#),
    (
        "unterminated macro",
        r#"assert!(!out.contains(SECRET), "x""#,
    ),
];

/// Clean forms: each must yield no finding.
const CLEAN_FORMS: &[(&str, &str)] = &[
    (
        "fixed message",
        r#"assert!(!out.contains(SECRET), "the output must not contain the fixture");"#,
    ),
    (
        "size only",
        r#"assert!(!out.contains(SECRET), "output of {} bytes", out.len());"#,
    ),
    (
        "case index",
        r#"assert!(!out.contains(secret), "case {case_idx} leaked");"#,
    ),
    (
        "line comment",
        r#"// assert!(!out.contains(SECRET), "{out}");"#,
    ),
    (
        "block comment",
        r#"/* assert!(!out.contains(SECRET), "{out}"); */"#,
    ),
    (
        "inside a string",
        r#"let s = "assert!(!out.contains(SECRET), \"{out}\")";"#,
    ),
    (
        "escaped braces",
        r#"assert!(!out.contains(SECRET), "{{out}}");"#,
    ),
    (
        "positive contains",
        r#"assert!(out.contains(EXPECTED), "{out}");"#,
    ),
    (
        "char literal quote",
        r#"let c = '"'; assert!(!out.contains(c), "char case");"#,
    ),
    (
        "lifetime",
        r#"fn f<'a>(x: &'a str) { assert!(!x.contains('z'), "no z"); }"#,
    ),
    (
        "field of other",
        r#"assert!(!out.contains(SECRET), "status {}", status.code);"#,
    ),
    (
        "result display bool",
        r#"assert!(res.is_ok(), "ok={}", res.is_ok());"#,
    ),
    (
        "key name display",
        r#"assert!(ok, "key {key} must be masked");"#,
    ),
];

#[test]
fn cleartext_msgs_scanner_flags_every_leaky_form() {
    let missed: Vec<&str> = LEAKY_FORMS
        .iter()
        .filter(|(_, src)| scan_text("synthetic.rs", src, true).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(missed.is_empty(), "scanner missed leaky forms: {missed:?}");
}

#[test]
fn cleartext_msgs_scanner_passes_clean_forms() {
    let flagged: Vec<String> = CLEAN_FORMS
        .iter()
        .flat_map(|(name, src)| {
            scan_text("synthetic.rs", src, true)
                .into_iter()
                .map(move |f| format!("{name}: {f}"))
        })
        .collect();
    assert!(
        flagged.is_empty(),
        "scanner flagged clean forms:\n{}",
        flagged.join("\n")
    );
}

#[test]
fn cleartext_msgs_scanner_exact_finding_text() {
    let findings = scan_text(
        "x.rs",
        "\nassert!(!out.contains(SECRET), \"{out}\");",
        false,
    );
    assert_eq!(
        findings,
        vec!["x.rs:2: `assert!` leak check echoes its haystack via `out`".to_string()]
    );
}

/// Size and time bound: a 100K+ input of leaky lines is scanned in linear
/// time with exactly one finding per line, and adversarial unterminated
/// inputs finish under the same ceiling.
#[test]
fn cleartext_msgs_scanner_linear_on_large_input() {
    let line = "    assert!(!out.contains(SECRET), \"leaked: {out}\");\n";
    let big = line.repeat(SCAN_SIZE_LINES);
    assert!(
        big.len() >= SCAN_SIZE_FLOOR_BYTES,
        "synthetic input is {} bytes",
        big.len()
    );
    let started = Instant::now();
    let findings = scan_text("big.rs", &big, true);
    assert_eq!(findings.len(), SCAN_SIZE_LINES);
    let adversarial = [
        format!("assert!({}", "(".repeat(SCAN_SIZE_FLOOR_BYTES)),
        format!("assert!(x, \"{}", "a".repeat(SCAN_SIZE_FLOOR_BYTES)),
        "'\\".repeat(SCAN_SIZE_FLOOR_BYTES),
        "/*".repeat(SCAN_SIZE_FLOOR_BYTES),
        "assert!(".repeat(SCAN_SIZE_FLOOR_BYTES / 8),
    ];
    for input in &adversarial {
        let _ = scan_text("adversarial.rs", input, true);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < SCAN_TIME_CEILING,
        "scan took {elapsed:?}, ceiling {SCAN_TIME_CEILING:?}"
    );
}

/// One self-test row: the review probe or form it pins, the fixture file
/// name, the fixture source and the EXACT findings the class rule reports.
struct ProbeRow {
    id: &'static str,
    rel: &'static str,
    src: &'static str,
    want: &'static [&'static str],
}

/// #9307 review probes b1..b7 (REVIEW-9307-code-r1) and one row per
/// message-producing form the class rule classifies. A clean row has an
/// empty `want`.
const PROBE_ROWS: &[ProbeRow] = &[
    ProbeRow {
        id: "b1 format! of a credentialed url",
        rel: "src/handlers/a2a.rs",
        src: r#"let m = format!("dial {cred_url}");"#,
        want: &["src/handlers/a2a.rs:1: `format!` message renders secret-valued `cred_url`"],
    },
    ProbeRow {
        id: "b1 tracing::warn!",
        rel: "src/handlers/a2a.rs",
        src: r#"tracing::warn!("refused bearer {token}");"#,
        want: &["src/handlers/a2a.rs:1: `warn!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "b1 anyhow::bail!",
        rel: "src/handlers/a2a.rs",
        src: r#"anyhow::bail!("refused bearer {token}");"#,
        want: &["src/handlers/a2a.rs:1: `bail!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "b2 control: leak-echo assert",
        rel: "src/handlers/a2a.rs",
        src: r#"assert!(!out.contains(token), "leaked {out}");"#,
        want: &["src/handlers/a2a.rs:1: `assert!` leak check echoes its haystack via `out`"],
    },
    ProbeRow {
        id: "b3 leak-echo assert in src/store",
        rel: "src/store/mod.rs",
        src: r#"assert!(!out.contains(token), "leaked {out}");"#,
        want: &["src/store/mod.rs:1: `assert!` leak check echoes its haystack via `out`"],
    },
    ProbeRow {
        id: "b4 assert_eq! operand under the default message",
        rel: "src/cli/agents.rs",
        src: r#"assert_eq!(token, "y");"#,
        want: &["src/cli/agents.rs:1: `assert_eq!` operand renders secret-valued `token`"],
    },
    ProbeRow {
        id: "b5 member access cfg.api_key",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "key was {}", cfg.api_key);"#,
        want: &["src/cli/agents.rs:1: `assert!` message renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "b6 compound name api_token",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "key was {api_token}");"#,
        want: &["src/cli/agents.rs:1: `assert!` message renders secret-valued `api_token`"],
    },
    ProbeRow {
        id: "b7 find(..).is_none() leak check",
        rel: "src/handlers/a2a.rs",
        src: r#"assert!(out.find(token).is_none(), "leaked {out}");"#,
        want: &["src/handlers/a2a.rs:1: `assert!` leak check echoes its haystack via `out`"],
    },
    ProbeRow {
        id: "form write!",
        rel: "x.rs",
        src: r#"write!(f, "auth {}", self.password)?;"#,
        want: &["x.rs:1: `write!` message renders secret-valued `password`"],
    },
    ProbeRow {
        id: "form writeln!",
        rel: "x.rs",
        src: r#"writeln!(out, "{secret}")?;"#,
        want: &["x.rs:1: `writeln!` message renders secret-valued `secret`"],
    },
    ProbeRow {
        id: "form panic!",
        rel: "x.rs",
        src: r#"panic!("bad {token:?}");"#,
        want: &["x.rs:1: `panic!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "form expect(&format!)",
        rel: "x.rs",
        src: r#"x.expect(&format!("no {api_key}"));"#,
        want: &["x.rs:1: `format!` message renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "form anyhow!",
        rel: "x.rs",
        src: r#"let e = anyhow::anyhow!("bad {}", creds);"#,
        want: &["x.rs:1: `anyhow!` message renders secret-valued `creds`"],
    },
    ProbeRow {
        id: "form ensure! leak check",
        rel: "x.rs",
        src: r#"anyhow::ensure!(!body.contains(token), "leaked {body}");"#,
        want: &["x.rs:1: `ensure!` leak check echoes its haystack via `body`"],
    },
    ProbeRow {
        id: "form eprintln!",
        rel: "x.rs",
        src: r#"eprintln!("using {passphrase}");"#,
        want: &["x.rs:1: `eprintln!` message renders secret-valued `passphrase`"],
    },
    ProbeRow {
        id: "form println! compound",
        rel: "x.rs",
        src: r#"println!("{}", bearer_token);"#,
        want: &["x.rs:1: `println!` message renders secret-valued `bearer_token`"],
    },
    ProbeRow {
        id: "form tracing field value",
        rel: "x.rs",
        src: r#"tracing::info!(peer = %t.token, "rotated");"#,
        want: &["x.rs:1: `info!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "form tracing shorthand field",
        rel: "x.rs",
        src: r#"log::debug!(?password, "login");"#,
        want: &["x.rs:1: `debug!` message renders secret-valued `password`"],
    },
    ProbeRow {
        id: "form debug_assert_eq! operand",
        rel: "x.rs",
        src: "debug_assert_eq!(secret, other);",
        want: &["x.rs:1: `debug_assert_eq!` operand renders secret-valued `secret`"],
    },
    ProbeRow {
        id: "form unterminated format!",
        rel: "x.rs",
        src: r#"let m = format!("x {token}""#,
        want: &["x.rs:1: `format!` is unterminated (fail closed)"],
    },
    ProbeRow {
        id: "clean metadata suffix",
        rel: "x.rs",
        src: r#"let m = format!("used {token_count} of {max_tokens}");"#,
        want: &[],
    },
    ProbeRow {
        id: "clean tracing field key",
        rel: "x.rs",
        src: r#"tracing::warn!(token_id = %id, "rotated");"#,
        want: &[],
    },
    ProbeRow {
        id: "clean size-only operand",
        rel: "x.rs",
        src: "assert_eq!(token.len(), 32);",
        want: &[],
    },
    ProbeRow {
        id: "clean redacted rendering",
        rel: "x.rs",
        src: r#"let m = format!("bearer {}", redacted_token);"#,
        want: &[],
    },
    ProbeRow {
        id: "clean secret name inside a literal",
        rel: "x.rs",
        src: r#"assert_eq!(body["token"], expected, "the token field");"#,
        want: &[],
    },
];

/// Every probe row yields exactly its `want` findings under the class rule
/// (the rule every file under the class roots gets).
#[test]
fn cleartext_msgs_scanner_probe_rows_exact() {
    let mut wrong = Vec::new();
    for row in PROBE_ROWS {
        let got = scan_text(row.rel, row.src, false);
        if got != row.want {
            wrong.push(format!("[{}] got {got:?}", row.id));
        }
    }
    assert!(
        wrong.is_empty(),
        "probe rows with the wrong findings ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// 100K+ line bound: lines cycle through four message forms, one finding
/// each, under a wall-clock ceiling generous enough for a loaded host and
/// far below what a quadratic scan of this input takes.
const SCAN_100K_LINES: usize = 100_000;
const SCAN_100K_TIME_CEILING: Duration = Duration::from_secs(30);
const MIXED_FORM_LINES: &[&str] = &[
    "    let m = format!(\"dial {token}\");\n",
    "    tracing::warn!(peer = %token, \"x\");\n",
    "    assert_eq!(api_key, \"y\");\n",
    "    assert!(out.find(secret).is_none(), \"{out}\");\n",
];

#[test]
fn cleartext_msgs_scanner_linear_on_100k_mixed_forms() {
    let big: String = MIXED_FORM_LINES
        .iter()
        .cycle()
        .take(SCAN_100K_LINES)
        .copied()
        .collect();
    assert_eq!(big.lines().count(), SCAN_100K_LINES);
    let started = Instant::now();
    let findings = scan_text("big.rs", &big, false);
    let elapsed = started.elapsed();
    assert_eq!(findings.len(), SCAN_100K_LINES, "one finding per line");
    assert!(
        elapsed < SCAN_100K_TIME_CEILING,
        "scan took {elapsed:?}, ceiling {SCAN_100K_TIME_CEILING:?}"
    );
}

/// Bytes that are not UTF-8: a finding naming the line, never a panic and
/// never a skip.
const NON_UTF8_FIXTURE: &[u8] = b"// ok\nlet a = 1;\n\xff\xfe\n";

#[test]
fn cleartext_msgs_scanner_reports_non_utf8_input() {
    let got = std::panic::catch_unwind(|| scan_bytes("x.rs", NON_UTF8_FIXTURE, false));
    assert_eq!(
        got.ok(),
        Some(vec!["x.rs:3: file is not UTF-8 (fail closed)".to_string()])
    );
}
