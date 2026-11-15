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
//! leaky and clean forms and on 100K+ synthetic inputs under a time bound.
//!
//! Fail closed by construction (#9307 r2 class-fix design): a member chain
//! is matched against one closed [`Segment`] grammar with sticky secret
//! taint, so a Rust form the grammar does not know is a finding, never a
//! pass; name exemptions match whole identifiers, never a word part (the
//! last-word head noun of [`NON_SECRET_LAST_PARTS`] aside); and a missing
//! class root or root prefix fails the run instead of scanning nothing.

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

/// Roots (directories or files) over which the class rule holds. Widening
/// them to every file under `src/` and `tests/` (#9307 M1) is the #8741
/// lane: it needs a classification ruling on `token` / `credential` first.
const CLASS_ROOTS: &[&str] = &[
    "src/cli",
    "src/federation",
    "src/handlers",
    "src/daemon_runtime",
    "src/daemon_runtime.rs",
    "src/config_redact.rs",
];

/// Paths where ANY negative containment check that echoes its haystack is a
/// finding, whatever the needle (every class root is one). Elsewhere (a
/// probe row's synthetic path) a containment check is a leak check only
/// when its needle carries a secret-named value or a canary literal
/// ([`needle_is_secret`]); a needle such as `"retry"` makes it an ordinary
/// content assertion.
const STRICT_LEAK_ECHO_ROOTS: &[&str] = &[
    "src/cli/",
    "src/federation/",
    "src/handlers/",
    "src/daemon_runtime/",
    "src/daemon_runtime.rs",
    "src/config_redact.rs",
];

/// Lower-cased markers that make a literal or a constant needle a secret
/// canary (`"hunter2"`, `"sekrit-must-not-leak"`, `SECRET_CANARY`).
const LEAK_CANARY_MARKERS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "passphrase",
    "cred",
    "bearer",
    "api_key",
    "apikey",
    "private_key",
    "canary",
    "hunter2",
    "sekrit",
    "leak",
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
const CONDITION_MACROS: &[&str] = &["assert", "debug_assert", "ensure"];

/// Macros whose every argument is a format string and its arguments.
const FORMAT_MACROS: &[&str] = &[
    "format",
    "format_args",
    "print",
    "println",
    "eprint",
    "eprintln",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "anyhow",
    "bail",
];

/// Macros whose first argument is the writer, then a format string.
const WRITER_MACROS: &[&str] = &["write", "writeln"];

/// `tracing` / `log` macros: fields (or a target / parent / level) before
/// the first literal, then a format string.
const TRACING_MACROS: &[&str] = &["error", "warn", "info", "debug", "trace", "event"];

/// Tracing arguments that name where an event goes, never what it says.
const TRACING_META_PREFIXES: &[&str] = &["target:", "parent:", "name:"];

/// Word parts (of a `_`-split, lower-cased identifier) that make it a
/// secret-named value. `tokens` is absent on purpose: it counts LLM tokens.
const SECRET_WORD_PARTS: &[&str] = &[
    "secret",
    "secrets",
    "token",
    "password",
    "passwd",
    "passphrase",
    "cred",
    "creds",
    "credential",
    "credentials",
    "bearer",
    "apikey",
];

/// Adjacent word-part pairs that make an identifier secret-named (a lone
/// `key` is a map key or a config key name, never a secret by itself). Each
/// pair is written once, singular; [`secret_pair`] derives the plural
/// (`api_keys`, `private_keys`) with [`PLURAL_SUFFIX`].
const SECRET_WORD_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("private", "key"),
    ("signing", "key"),
    ("access", "key"),
];

/// The one plural rule for [`SECRET_WORD_PAIRS`]: the second word plus `s`.
const PLURAL_SUFFIX: char = 's';

/// A last word part that makes a secret-named identifier METADATA about
/// the secret (its count, length, name, location, hash or state), never
/// the secret itself. The last word of a `snake_case` compound is its head
/// noun (`token_count` is a count), so this is the one word-part exemption;
/// a first word only qualifies the head (`redacted_token` is a token) and
/// clears nothing.
const NON_SECRET_LAST_PARTS: &[&str] = &[
    "count",
    "len",
    "length",
    "budget",
    "limit",
    "max",
    "min",
    "name",
    "names",
    "path",
    "paths",
    "file",
    "dir",
    "env",
    "var",
    "vars",
    "kind",
    "type",
    "ty",
    "id",
    "ids",
    "hash",
    "digest",
    "ttl",
    "expiry",
    "expires",
    "header",
    "prefix",
    "label",
    "field",
    "scope",
    "scopes",
    "source",
    "status",
    "state",
    "mode",
    "policy",
    "ref",
    "fingerprint",
    "sha256",
    "hex",
    "guard",
    "required",
    "ok",
    "summary",
    "command",
    "seconds",
    "secs",
    "duration",
    "age",
];

/// Whole identifiers that are secret-named by word part but provably hold
/// no secret, each with its reason. An exemption matches the WHOLE name,
/// never a word part (#9307 R2-2: a first-part rule cleared
/// `created_token` along with the flag it was written for).
const NON_SECRET_WHOLE_NAMES: &[(&str, &str)] = &[(
    "created_root_secret",
    "bool: whether `cli capability init` created the root secret",
)];

/// Whole identifiers that provably hold no secret under one source root
/// only, each with its reason: `(root, name, reason)`. Scoped so the same
/// name elsewhere (a `cred` holding a password) stays secret-named; a
/// secret-named segment after it (`cred.private_key`) still taints.
const NON_SECRET_SCOPED_NAMES: &[(&str, &str, &str)] = &[
    (
        "src/federation/identity/",
        "cred",
        "FederationCredential: the public signed claim set (subject id, pubkey, issuer, validity)",
    ),
    (
        "src/federation/identity/",
        "credential",
        "SignedCredential::credential(): the public FederationCredential claim set",
    ),
    (
        "src/handlers/federation_signing_check.rs",
        "cred",
        "CertChain::verify output: the public FederationCredential claim set",
    ),
];

/// Renderings that expose only a boolean, never the content.
const BOOLEAN_ONLY_SUFFIXES: &[&str] = &[".is_some()", ".is_none()", ".is_ok()", ".is_err()"];

/// Member-chain rule: methods that return (a view of) the receiver's own
/// value. A chain through one is judged by its receiver, so
/// `password.clone()` and `secret.as_str()` render `password` / `secret`.
/// The repo's expose-style accessors are the `Zeroizing` deref, the key
/// `to_bytes()` and the `into_inner()` / `as_slice()` / `to_vec()` /
/// `as_deref()` / `unwrap()` / `expect(..)` unwrappers.
const TRANSPARENT_METHODS: &[&str] = &[
    "clone",
    "to_string",
    "to_owned",
    "as_str",
    "as_ref",
    "as_bytes",
    "deref",
    "borrow",
    "to_bytes",
    "into_inner",
    "as_slice",
    "to_vec",
    "as_deref",
    "unwrap",
    "expect",
];

/// Member-chain rule: methods that reveal nothing of a secret receiver.
/// Any other method called on a secret-named receiver is a finding.
const NON_REVEALING_METHODS: &[&str] = &["len", "is_empty", "is_some", "is_none"];

/// Methods whose negated result (or `.is_none()`) is a leak check: the
/// receiver is the haystack, the argument the needle.
const LEAK_CHECK_METHODS: &[&str] = &[".contains(", ".find(", ".rfind(", ".matches("];

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

/// `(haystack, needle)` of a negative leak check: `!HAYSTACK.contains(NEEDLE)`
/// or `HAYSTACK.find(NEEDLE).is_none()` (and the other [`LEAK_CHECK_METHODS`]),
/// #9307 review probe b7.
fn negated_contains(cond: &str) -> Option<(&str, &str)> {
    let cond = cond.trim();
    let c = match cond.strip_prefix('!') {
        Some(rest) => rest.trim_start(),
        None => cond.strip_suffix(".is_none()")?.trim_end(),
    }
    .strip_suffix(')')?;
    let (at, method) = LEAK_CHECK_METHODS
        .iter()
        .filter_map(|m| c.rfind(m).map(|at| (at, *m)))
        .max_by_key(|(at, _)| *at)?;
    Some((c[..at].trim(), c[at + method.len()..].trim()))
}

/// `true` when a leak-check needle carries a secret: a secret-named value,
/// or a literal or constant holding a [`LEAK_CANARY_MARKERS`] word.
fn needle_is_secret(rel: &str, needle: &str) -> bool {
    let lower = needle.to_ascii_lowercase();
    let marked = LEAK_CANARY_MARKERS.iter().any(|m| lower.contains(m));
    let kinds = classify(needle);
    let literal_or_const = kinds.contains(&Kind::Literal)
        || needle
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(is_constant_name);
    (marked && literal_or_const)
        || bindings(needle)
            .into_iter()
            .any(|id| SECRET_VALUE_BINDINGS.contains(&id) || is_secret_name(rel, id))
        || rendered_secret(rel, needle).is_some()
}

fn leak_echo_findings(rel: &str, inv: &Invocation, out: &mut Vec<String>) {
    let Some((hay, needle)) = inv.args.first().and_then(|c| negated_contains(c)) else {
        return;
    };
    let strict = STRICT_LEAK_ECHO_ROOTS.iter().any(|r| rel.starts_with(r));
    if !strict && !needle_is_secret(rel, needle) {
        return;
    }
    let hay_ids = bindings(hay);
    let needle_ids: Vec<&str> = bindings(needle)
        .into_iter()
        .filter(|id| SECRET_VALUE_BINDINGS.contains(id) || is_secret_name(rel, id))
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

/// `true` for a `SCREAMING_CASE` identifier: a constant, whose value is in
/// the source and so is never a runtime secret.
fn is_constant_name(id: &str) -> bool {
    id.bytes().any(|c| c.is_ascii_uppercase())
        && id
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// `true` when `(w0, w1)` is a [`SECRET_WORD_PAIRS`] pair, singular or
/// with the one [`PLURAL_SUFFIX`] rule on the second word (`api_keys`).
fn secret_pair(w0: &str, w1: &str) -> bool {
    SECRET_WORD_PAIRS
        .iter()
        .any(|(a, b)| *a == w0 && (w1 == *b || w1.strip_suffix(PLURAL_SUFFIX) == Some(*b)))
}

/// `true` when `id` names a secret value by word part (#9307 review probe
/// b6): `api_token`, `bearer_token`, `cred_url`, `cfg.api_key`'s `api_key`,
/// `redacted_token`, but not `token_count`, `max_tokens` or `TOKEN_PREFIX`.
/// The only exemptions are a [`NON_SECRET_LAST_PARTS`] head noun and a
/// [`NON_SECRET_WHOLE_NAMES`] whole identifier (anywhere, or under the
/// root of its [`NON_SECRET_SCOPED_NAMES`] row) in the file named `rel`.
fn is_secret_name(rel: &str, id: &str) -> bool {
    if is_constant_name(id)
        || NON_SECRET_WHOLE_NAMES.iter().any(|(name, _)| *name == id)
        || NON_SECRET_SCOPED_NAMES
            .iter()
            .any(|(root, name, _)| *name == id && rel.starts_with(root))
    {
        return false;
    }
    let lower = id.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('_').filter(|p| !p.is_empty()).collect();
    let Some(last) = parts.last() else {
        return false;
    };
    if NON_SECRET_LAST_PARTS.contains(last) {
        return false;
    }
    parts.iter().any(|p| SECRET_WORD_PARTS.contains(p))
        || parts.windows(2).any(|w| secret_pair(w[0], w[1]))
}

/// `expr` with string and char literals and comments blanked to spaces.
fn code_bytes(expr: &str) -> Vec<u8> {
    let kinds = classify(expr);
    expr.bytes()
        .zip(&kinds)
        .map(|(c, &k)| {
            if k == Kind::Code && c.is_ascii() {
                c
            } else {
                b' '
            }
        })
        .collect()
}

/// First index at or after `i` that is not ASCII whitespace.
fn skip_ws(code: &[u8], mut i: usize) -> usize {
    while code.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// For every opening bracket of `code`, the index just past its group (end
/// of input when it is unmatched; literals are already blanked); `0` at
/// every other index. One stack pass, so each lookup is O(1) and a chain
/// scan stays linear however many groups are left open (#9307 r2 E-d).
fn bracket_ends(code: &[u8]) -> Vec<usize> {
    let mut ends = vec![0; code.len()];
    let mut open = Vec::new();
    for (j, &c) in code.iter().enumerate() {
        match c {
            b'(' | b'[' | b'{' => open.push(j),
            b')' | b']' | b'}' => {
                if let Some(o) = open.pop() {
                    ends[o] = j + 1;
                }
            }
            _ => {}
        }
    }
    for o in open {
        ends[o] = code.len();
    }
    ends
}

/// End index of the identifier starting at `i`.
fn ident_end(code: &[u8], mut i: usize) -> usize {
    while code.get(i).copied().is_some_and(is_ident) {
        i += 1;
    }
    i
}

/// Longest `::<..>` turbofish group a method segment may carry; a longer
/// or unclosed one is an [`Segment::Unclassified`] segment (fail closed),
/// which also keeps the angle scan linear.
const TURBOFISH_MAX_BYTES: usize = 256;

/// One segment of a member chain (#9307 R2-1 class fix: a closed grammar).
/// Every byte sequence after a chain's root parses to exactly one variant,
/// and [`judge_chain`] matches the enum exhaustively, so a Rust form the
/// grammar does not know is [`Segment::Unclassified`], never clean.
#[derive(Debug)]
enum Segment {
    /// `.name` not followed by a call.
    Field(String),
    /// `.name(..)` or `.name::<..>(..)`; the turbofish is skipped.
    Method { name: String, zero_args: bool },
    /// `.0`: the tuple field of the value itself.
    TupleIndex,
    /// `.await`: the future's own output.
    Await,
    /// `?`: the `Ok` / `Some` value itself.
    Try,
    /// `[..]`: an element of the value itself.
    Index,
    /// A `.` followed by anything else; the text names the segment.
    Unclassified(String),
}

/// Index just past the turbofish group whose `<` is at `open`, if it closes
/// within [`TURBOFISH_MAX_BYTES`]. A `>` of `->` does not close a level.
fn turbofish_end(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let limit = code.len().min(open.saturating_add(TURBOFISH_MAX_BYTES));
    for j in open..limit {
        match code[j] {
            b'<' => depth += 1,
            b'>' if j > 0 && code[j - 1] == b'-' => {}
            b'>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(j + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The raw source text of an unclassified segment starting at the `.` at
/// `dot`: up to the next ASCII delimiter, bounded and lossy-decoded.
fn segment_text(src: &[u8], dot: usize) -> String {
    let tail = &src[dot..];
    let len = tail
        .iter()
        .skip(1)
        .position(|&c| c.is_ascii() && !is_ident(c))
        .map_or(tail.len(), |p| p + 1)
        .min(TURBOFISH_MAX_BYTES);
    String::from_utf8_lossy(&tail[..len]).trim_end().to_owned()
}

/// The chain segment at `i` (after whitespace), with the index past it;
/// `None` at the end of the chain (any byte that starts no segment: an
/// operator, a separator, a `..` range, the end of input). `code` is
/// [`code_bytes`] of `src`, index for index.
fn next_segment(code: &[u8], src: &[u8], ends: &[usize], i: usize) -> Option<(Segment, usize)> {
    let j = skip_ws(code, i);
    match code.get(j)? {
        b'?' => Some((Segment::Try, j + 1)),
        b'[' => Some((Segment::Index, ends[j])),
        b'.' if code.get(j + 1) == Some(&b'.') => None,
        b'.' => {
            let unclassified = || Some((Segment::Unclassified(segment_text(src, j)), j + 1));
            let s = skip_ws(code, j + 1);
            let e = ident_end(code, s);
            if s == e || !src[j + 1..e].is_ascii() || src.get(e).is_some_and(|c| !c.is_ascii()) {
                return unclassified();
            }
            let name = String::from_utf8_lossy(&code[s..e]).into_owned();
            if name.bytes().all(|c| c.is_ascii_digit()) {
                return Some((Segment::TupleIndex, e));
            }
            let mut after = skip_ws(code, e);
            if code[after..].starts_with(b"::") {
                let open = skip_ws(code, after + 2);
                if code.get(open) != Some(&b'<') {
                    return unclassified();
                }
                let Some(close) = turbofish_end(code, open) else {
                    return unclassified();
                };
                after = skip_ws(code, close);
                if code.get(after) != Some(&b'(') {
                    return unclassified();
                }
            }
            if code.get(after) == Some(&b'(') {
                let close = ends[after];
                let zero_args = code[after + 1..close.saturating_sub(1).max(after + 1)]
                    .trim_ascii()
                    .is_empty();
                return Some((Segment::Method { name, zero_args }, close));
            }
            if name == "await" {
                return Some((Segment::Await, e));
            }
            Some((Segment::Field(name), e))
        }
        _ => None,
    }
}

/// What a member chain renders: nothing secret, a secret-named value, or
/// a segment the grammar cannot classify (both of the last two are findings).
#[derive(Debug)]
enum ChainVerdict {
    Clean,
    Secret(String),
    Unclassified {
        taint: Option<String>,
        segment: String,
    },
}

/// The member-chain rule for the chain rooted at the identifier
/// `code[start..end]`: `(verdict, index past the chain)`. Sticky taint over
/// the closed [`Segment`] grammar (#9307 r2 class-fix design):
///
/// - The chain is tainted once its root or any segment is secret-named, and
///   stays tainted to its end: `cred.uid` renders `cred`, `cfg.api_key.0`
///   renders `api_key`. No later field renames it.
/// - Only a [`NON_REVEALING_METHODS`] segment clears the taint:
///   `token.len()`, `cfg.api_key.as_ref().is_some()` are clean.
/// - A [`TRANSPARENT_METHODS`] segment, a tuple index, `.await`, `?` and
///   `[..]` keep the taint. Any other method on a tainted chain is a finding.
/// - On a clean chain a secret-named field or zero-argument method taints
///   (`parsed.credential()`); a method with arguments renders its own
///   result (its arguments are scanned as chains of their own).
/// - An [`Segment::Unclassified`] segment is a finding on any chain.
/// - Not values: a path prefix (`a::`), a macro name (`m!`), a type,
///   variant or constant (upper-case first letter) and a free-function
///   callee (`agent_id_for_api_key(&k)` renders an agent id).
fn judge_chain(
    rel: &str,
    code: &[u8],
    src: &[u8],
    ends: &[usize],
    start: usize,
    end: usize,
) -> (ChainVerdict, usize) {
    let root = String::from_utf8_lossy(&code[start..end]).into_owned();
    let mut i = end;
    let next = skip_ws(code, i);
    if code[next..].starts_with(b"::") || code[next..].starts_with(b"!") {
        return (ChainVerdict::Clean, end);
    }
    let mut taint = if code.get(next) == Some(&b'(') {
        i = ends[next];
        None
    } else if code[start].is_ascii_uppercase() || !is_secret_name(rel, &root) {
        None
    } else {
        Some(root)
    };
    while let Some((segment, past)) = next_segment(code, src, ends, i) {
        i = past;
        match segment {
            Segment::TupleIndex | Segment::Await | Segment::Try | Segment::Index => {}
            Segment::Field(name) => {
                if taint.is_none() && is_secret_name(rel, &name) {
                    taint = Some(name);
                }
            }
            Segment::Method { name, zero_args } => {
                if NON_REVEALING_METHODS.contains(&name.as_str()) {
                    taint = None;
                } else if TRANSPARENT_METHODS.contains(&name.as_str()) {
                    // The receiver's own value: the taint stays.
                } else if let Some(id) = taint {
                    return (ChainVerdict::Secret(id), i);
                } else if zero_args && is_secret_name(rel, &name) {
                    taint = Some(name);
                }
            }
            Segment::Unclassified(segment) => {
                return (ChainVerdict::Unclassified { taint, segment }, i);
            }
        }
    }
    match taint {
        Some(id) => (ChainVerdict::Secret(id), i),
        None => (ChainVerdict::Clean, i),
    }
}

/// `true` for a rendering that exposes only a size or a boolean.
fn shape_only(expr: &str) -> bool {
    size_only(expr)
        || BOOLEAN_ONLY_SUFFIXES
            .iter()
            .any(|s| expr.trim_end().ends_with(s))
}

/// What the first finding of `expr` renders under the member-chain rule
/// ([`judge_chain`]), if any: "secret-valued `x`", or that plus the
/// unclassified segment it went through. A member segment is judged with
/// the chain it belongs to; one that follows a parenthesised expression
/// (`(a).token`) belongs to no identifier chain and is judged as a root
/// (fail closed).
fn rendered_secret(rel: &str, expr: &str) -> Option<String> {
    if shape_only(expr) {
        return None;
    }
    let code = code_bytes(expr);
    let src = expr.as_bytes();
    let ends = bracket_ends(&code);
    let mut chained_until = 0;
    let mut i = 0;
    while i < code.len() {
        if !is_ident(code[i]) {
            i += 1;
            continue;
        }
        let start = i;
        i = ident_end(&code, i);
        let before = code[..start].trim_ascii_end();
        let member = before.ends_with(b".") && !before.ends_with(b"..");
        if (member && start < chained_until) || code[start].is_ascii_digit() {
            continue;
        }
        let (verdict, chain_end) = judge_chain(rel, &code, src, &ends, start, i);
        match verdict {
            ChainVerdict::Clean => {}
            ChainVerdict::Secret(id) => return Some(format!("secret-valued `{id}`")),
            ChainVerdict::Unclassified {
                taint: Some(id),
                segment,
            } => {
                return Some(format!(
                    "secret-valued `{id}` through unclassified segment `{segment}` (fail closed)"
                ));
            }
            ChainVerdict::Unclassified {
                taint: None,
                segment,
            } => {
                let root = String::from_utf8_lossy(&code[start..i]).into_owned();
                return Some(format!(
                    "unclassified segment `{segment}` after `{root}` (fail closed)"
                ));
            }
        }
        chained_until = chained_until.max(chain_end);
    }
    None
}

/// The value a tracing field argument renders: `key = %v`, `key = ?v`,
/// `key = v`, or the shorthand `%v` / `?v` / `v`. `None` for a target,
/// parent or name argument.
fn tracing_field_value(arg: &str) -> Option<&str> {
    if TRACING_META_PREFIXES.iter().any(|p| arg.starts_with(p)) {
        return None;
    }
    let value = match arg.split_once('=') {
        Some((key, value))
            if !value.starts_with('=')
                && !key.trim().is_empty()
                && key
                    .trim()
                    .bytes()
                    .all(|c| is_ident(c) || c == b'.' || c == b'"') =>
        {
            value.trim()
        }
        _ => arg,
    };
    Some(value.trim_start_matches(['%', '?']).trim())
}

/// The class rule (#9307 M1/M2) on one invocation of any message-producing
/// form: no rendered value of the message (and no compared operand of an
/// `assert_eq!` family macro, which the default message prints) is
/// secret-named.
fn class_findings(rel: &str, inv: &Invocation, out: &mut Vec<String>) {
    let name = inv.name.as_str();
    let mut push = |what: &str, rendered: &str| {
        out.push(format!(
            "{rel}:{}: `{name}!` {what} renders {rendered}",
            inv.line
        ));
    };
    let msg: &[String] = if FORMAT_MACROS.contains(&name) {
        &inv.args
    } else if WRITER_MACROS.contains(&name) || CONDITION_MACROS.contains(&name) {
        inv.args.get(1..).unwrap_or_default()
    } else if OPERAND_MACROS.contains(&name) {
        for operand in inv.args.iter().take(2) {
            if let Some(id) = rendered_secret(rel, operand) {
                push("operand", &id);
            }
        }
        inv.args.get(2..).unwrap_or_default()
    } else {
        let first_literal = inv
            .args
            .iter()
            .position(|a| literal_body(a).is_some())
            .unwrap_or(inv.args.len());
        for field in &inv.args[..first_literal] {
            if let Some(id) = tracing_field_value(field).and_then(|v| rendered_secret(rel, v)) {
                push("message", &id);
            }
        }
        &inv.args[first_literal..]
    };
    for (expr, _) in interpolations(msg) {
        if let Some(id) = rendered_secret(rel, &expr) {
            push("message", &id);
        }
    }
}

/// Scan `src` (named `rel` in findings) with the class rule and the
/// leak-echo rule. `secret_bindings` adds the narrow whole-name checks
/// (`SECRET_VALUE_BINDINGS`, Debug dumps, peer ids) on every assertion
/// macro of a scanned file.
fn scan_text(rel: &str, src: &str, secret_bindings: bool) -> Vec<String> {
    let names: Vec<&str> = CONDITION_MACROS
        .iter()
        .chain(OPERAND_MACROS)
        .chain(FORMAT_MACROS)
        .chain(WRITER_MACROS)
        .chain(TRACING_MACROS)
        .copied()
        .collect();
    let mut out = Vec::new();
    for found in invocations(src, &names) {
        match found {
            Ok(inv) => {
                let name = inv.name.as_str();
                if CONDITION_MACROS.contains(&name) {
                    leak_echo_findings(rel, &inv, &mut out);
                }
                class_findings(rel, &inv, &mut out);
                if secret_bindings
                    && (CONDITION_MACROS.contains(&name) || OPERAND_MACROS.contains(&name))
                {
                    secret_binding_findings(rel, &inv, &mut out);
                }
            }
            Err((name, line)) => out.push(format!(
                "{rel}:{line}: `{name}!` is unterminated (fail closed)"
            )),
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|f| seen.insert(f.clone()));
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
        Err(e) => {
            // One more line than newlines before the bad byte.
            let line = bytes[..e.valid_up_to()].split(|&c| c == b'\n').count();
            vec![format!("{rel}:{line}: file is not UTF-8 (fail closed)")]
        }
    }
}

/// Every Rust file under the class roots, as `(repo-relative path, path)`.
fn class_files() -> Vec<(String, PathBuf)> {
    class_files_for(CLASS_ROOTS)
}

/// Every Rust file under `roots`, as `(repo-relative path, path)`.
fn class_files_for(roots: &[&str]) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    for root in roots {
        let path = repo_path(root);
        assert!(path.exists(), "class root {root} is missing (fail closed)");
        rust_files_under(&path, &mut files);
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
        id: "b3 leak-echo assert (form; reaching src/store is the #8741 lane)",
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
        id: "chain transparent method keeps the receiver",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "pw {}", password.clone());"#,
        want: &["src/cli/agents.rs:1: `assert!` message renders secret-valued `password`"],
    },
    ProbeRow {
        id: "sticky taint: a field does not rename a secret receiver",
        rel: "src/cli/agents.rs",
        src: r"assert_eq!(cred.uid, 7);",
        want: &["src/cli/agents.rs:1: `assert_eq!` operand renders secret-valued `cred`"],
    },
    ProbeRow {
        id: "chain non-revealing method",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "n {}", token.len());"#,
        want: &[],
    },
    ProbeRow {
        id: "chain transparent then non-revealing",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "n {}", token.clone().len() * 2);"#,
        want: &[],
    },
    ProbeRow {
        id: "sticky taint: transparent then a field",
        rel: "src/cli/agents.rs",
        src: "assert_eq!(cred.clone().uid, 7);",
        want: &["src/cli/agents.rs:1: `assert_eq!` operand renders secret-valued `cred`"],
    },
    ProbeRow {
        id: "chain unlisted method on a secret receiver",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "x {}", secret.frobnicate());"#,
        want: &["src/cli/agents.rs:1: `assert!` message renders secret-valued `secret`"],
    },
    ProbeRow {
        id: "chain secret field under a clean parent",
        rel: "src/cli/agents.rs",
        src: r#"assert_eq!(cfg.api_key, "y");"#,
        want: &["src/cli/agents.rs:1: `assert_eq!` operand renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "chain secret getter under a clean parent",
        rel: "src/cli/agents.rs",
        src: r"assert_eq!(parsed.credential(), other);",
        want: &["src/cli/agents.rs:1: `assert_eq!` operand renders secret-valued `credential`"],
    },
    ProbeRow {
        id: "chain member after a parenthesised receiver",
        rel: "src/cli/agents.rs",
        src: r#"assert!(ok, "x {}", (a).token);"#,
        want: &["src/cli/agents.rs:1: `assert!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "clean was-created flag",
        rel: "src/cli/capability.rs",
        src: r#"writeln!(out, "{}", outcome.created_root_secret)?;"#,
        want: &[],
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
        id: "Y-2 a first-word claim is no exemption: redacted_token",
        rel: "x.rs",
        src: r#"let m = format!("bearer {}", redacted_token);"#,
        want: &["x.rs:1: `format!` message renders secret-valued `redacted_token`"],
    },
    ProbeRow {
        id: "clean secret name inside a literal",
        rel: "x.rs",
        src: r#"assert_eq!(body["token"], expected, "the token field");"#,
        want: &[],
    },
    // #9307 delta r2 (REVIEW-9307-combined-r2 R2-1, R2-2, R2-4): every
    // segment shape after a secret-named receiver keeps the taint.
    ProbeRow {
        id: "Y-1 tuple index on a secret field",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", cfg.api_key.0);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "Y-1 tuple index on a secret root",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", token.0);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "Y-1 tuple index then a transparent method",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", creds.0.clone());"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `creds`"],
    },
    ProbeRow {
        id: "Y-1 tuple index as an assert_eq! operand",
        rel: "x.rs",
        src: r#"assert_eq!(cfg.api_key.0, "x");"#,
        want: &["x.rs:1: `assert_eq!` operand renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "Y-1 tuple index as a tracing field value",
        rel: "x.rs",
        src: r#"tracing::info!(key = %cfg.api_key.0, "x");"#,
        want: &["x.rs:1: `info!` message renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "Y-1 turbofish method on a secret receiver",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", api_key.parse::<String>().unwrap());"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `api_key`"],
    },
    ProbeRow {
        id: "Y-1 .await on a secret receiver",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", bearer.await);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `bearer`"],
    },
    ProbeRow {
        id: "Y-1 ? on a secret receiver",
        rel: "x.rs",
        src: r#"let m = format!("x {}", token?);"#,
        want: &["x.rs:1: `format!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "Y-1 unclassified segment on a secret receiver",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", token.é);"#,
        want: &[
            "x.rs:1: `assert!` message renders secret-valued `token` through unclassified segment `.é` (fail closed)",
        ],
    },
    ProbeRow {
        id: "Y-1 unclassified segment on a clean receiver",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", cfg.é);"#,
        want: &[
            "x.rs:1: `assert!` message renders unclassified segment `.é` after `cfg` (fail closed)",
        ],
    },
    ProbeRow {
        id: "Y-1 unclosed turbofish on a secret receiver",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", token.parse::<Vec<u8>);"#,
        want: &[
            "x.rs:1: `assert!` message renders secret-valued `token` through unclassified segment `.parse` (fail closed)",
        ],
    },
    ProbeRow {
        id: "Y-6 scoped whole name clears only its root",
        rel: "src/federation/identity/issuer.rs",
        src: r#"assert_eq!(cred.issuer_id, "root");"#,
        want: &[],
    },
    ProbeRow {
        id: "Y-6 scoped whole name outside its root",
        rel: "src/handlers/a2a.rs",
        src: r#"assert_eq!(cred.issuer_id, "root");"#,
        want: &["src/handlers/a2a.rs:1: `assert_eq!` operand renders secret-valued `cred`"],
    },
    ProbeRow {
        id: "Y-6 scoped whole name keeps a later secret segment",
        rel: "src/federation/identity/issuer.rs",
        src: "assert_eq!(cred.private_key, k);",
        want: &[
            "src/federation/identity/issuer.rs:1: `assert_eq!` operand renders secret-valued `private_key`",
        ],
    },
    ProbeRow {
        id: "Y-1 sticky taint through a field",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", cfg.token.value);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `token`"],
    },
    ProbeRow {
        id: "Y-1 clean: len() on a secret field",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", cfg.api_key.len());"#,
        want: &[],
    },
    ProbeRow {
        id: "Y-1 clean: is_empty() on a secret root",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", token.is_empty());"#,
        want: &[],
    },
    ProbeRow {
        id: "Y-1 clean: as_ref().is_some() on a secret field",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", cfg.api_key.as_ref().is_some());"#,
        want: &[],
    },
    ProbeRow {
        id: "Y-2 created_token placeholder",
        rel: "x.rs",
        src: r#"let m = format!("x {created_token}");"#,
        want: &["x.rs:1: `format!` message renders secret-valued `created_token`"],
    },
    ProbeRow {
        id: "Y-2 created_api_key argument",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", created_api_key);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `created_api_key`"],
    },
    ProbeRow {
        id: "Y-4 plural pair indexed: api_keys[0]",
        rel: "x.rs",
        src: r#"assert!(ok, "x {}", api_keys[0]);"#,
        want: &["x.rs:1: `assert!` message renders secret-valued `api_keys`"],
    },
    ProbeRow {
        id: "Y-4 plural pair: private_keys",
        rel: "x.rs",
        src: r#"let m = format!("x {private_keys:?}");"#,
        want: &["x.rs:1: `format!` message renders secret-valued `private_keys`"],
    },
    ProbeRow {
        id: "Y-4 plural pair: signing_keys",
        rel: "x.rs",
        src: r#"let m = format!("x {signing_keys:?}");"#,
        want: &["x.rs:1: `format!` message renders secret-valued `signing_keys`"],
    },
    ProbeRow {
        id: "Y-4 plural pair: access_keys",
        rel: "x.rs",
        src: r#"let m = format!("x {access_keys:?}");"#,
        want: &["x.rs:1: `format!` message renders secret-valued `access_keys`"],
    },
];

/// Secret-named receivers for the generative chain cells (#9307 delta r2):
/// one per word part family, the pairs and their plurals.
const SECRET_NAME_CORPUS: &[&str] = &[
    "token",
    "secret",
    "password",
    "bearer",
    "creds",
    "apikey",
    "api_key",
    "api_keys",
    "private_key",
    "private_keys",
    "signing_keys",
    "access_keys",
];

/// Segments that keep a secret receiver's taint, with the tail the finding
/// carries (an unclassified segment names itself).
const TAINT_KEEPING_SEGMENTS: &[(&str, &str)] = &[
    (".0", ""),
    (".0.clone()", ""),
    (".await", ""),
    ("?", ""),
    ("[0]", ""),
    (".inner", ""),
    (".inner.name", ""),
    (".clone()", ""),
    (".parse::<String>()", ""),
    (".parse::<Vec<u8>>().unwrap()", ""),
    (".frobnicate()", ""),
    (".é", " through unclassified segment `.é` (fail closed)"),
];

/// Renderings of a secret receiver that reveal nothing of it.
const TAINT_CLEARING_SEGMENTS: &[&str] = &[
    ".len()",
    ".is_empty()",
    ".as_ref().is_some()",
    ".clone().len() * 2",
];

/// Receiver prefixes the generative cells put before each corpus name.
const RECEIVER_PREFIXES: &[&str] = &["", "cfg.", "self.inner."];

/// The first words `NON_SECRET_FIRST_PARTS` used to clear (#9307 R2-2): no
/// first word part clears a secret-named identifier.
const FIRST_WORD_PROBES: &[&str] = &[
    "has",
    "is",
    "num",
    "max",
    "min",
    "redact",
    "redacted",
    "mask",
    "masked",
    "sanitize",
    "sanitized",
    "scrub",
    "scrubbed",
    "hash",
    "hashed",
    "fingerprint",
    "require",
    "requires",
    "created",
];

/// Secret tails the first-word probes are joined to.
const FIRST_WORD_TAILS: &[&str] = &["token", "api_key", "secret"];

/// Generative cell over the closed segment grammar: every corpus name, in
/// every receiver shape, followed by every taint-keeping segment, is EXACTLY
/// one finding naming the corpus name; every taint-clearing segment is clean.
#[test]
fn cleartext_msgs_scanner_chain_grammar_generative() {
    let mut wrong = Vec::new();
    for name in SECRET_NAME_CORPUS {
        for before in RECEIVER_PREFIXES {
            for (segment, tail) in TAINT_KEEPING_SEGMENTS {
                let src = format!("assert!(ok, \"x {{}}\", {before}{name}{segment});");
                let want = vec![format!(
                    "x.rs:1: `assert!` message renders secret-valued `{name}`{tail}"
                )];
                let got = scan_text("x.rs", &src, false);
                if got != want {
                    wrong.push(format!("{src} -> {got:?}"));
                }
            }
            for segment in TAINT_CLEARING_SEGMENTS {
                let src = format!("assert!(ok, \"x {{}}\", {before}{name}{segment});");
                let got = scan_text("x.rs", &src, false);
                if !got.is_empty() {
                    wrong.push(format!("{src} -> {got:?}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "chain grammar cases with the wrong findings ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Generative cell for design item 3: a first word part never clears a
/// secret-named identifier; only a whole-name row does.
#[test]
fn cleartext_msgs_scanner_first_word_never_exempts() {
    let mut wrong = Vec::new();
    for first in FIRST_WORD_PROBES {
        for tail in FIRST_WORD_TAILS {
            let id = format!("{first}_{tail}");
            let src = format!("let m = format!(\"x {{{id}}}\");");
            let want = vec![format!(
                "x.rs:1: `format!` message renders secret-valued `{id}`"
            )];
            let got = scan_text("x.rs", &src, false);
            if got != want {
                wrong.push(format!("{src} -> {got:?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "first-word exemptions still clear ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A class root that does not exist, for the fail-closed cell.
const MISSING_CLASS_ROOT: &str = "src/no_such_class_root_9307";

/// Design item 4: a missing class root is a panic naming it, never a
/// silent skip that leaves every class cell passing with nothing scanned.
#[test]
fn cleartext_msgs_class_missing_root_fails_closed() {
    let got = std::panic::catch_unwind(|| class_files_for(&[MISSING_CLASS_ROOT]));
    let message = got.err().and_then(|p| p.downcast_ref::<String>().cloned());
    assert_eq!(
        message.as_deref(),
        Some("class root src/no_such_class_root_9307 is missing (fail closed)")
    );
}

/// Design item 4: every class root yields at least one Rust file.
#[test]
fn cleartext_msgs_class_roots_each_yield_files() {
    for root in CLASS_ROOTS {
        let files = class_files_for(&[root]);
        assert!(!files.is_empty(), "class root {root} yields no Rust file");
    }
    // The prefix lists are judged by `starts_with`, so a stale entry would
    // silently match nothing: each one must name a real path.
    let prefixes = STRICT_LEAK_ECHO_ROOTS
        .iter()
        .copied()
        .chain(NON_SECRET_SCOPED_NAMES.iter().map(|(root, _, _)| *root));
    for prefix in prefixes {
        assert!(
            repo_path(prefix.trim_end_matches('/')).exists(),
            "root prefix {prefix} is missing (fail closed)"
        );
    }
}

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
    eprintln!("E-d 100k mixed forms: {elapsed:?} (ceiling {SCAN_100K_TIME_CEILING:?})");
    assert_eq!(findings.len(), SCAN_100K_LINES, "one finding per line");
    assert!(
        elapsed < SCAN_100K_TIME_CEILING,
        "scan took {elapsed:?}, ceiling {SCAN_100K_TIME_CEILING:?}"
    );
}

/// Adversarial chain shapes for the segment grammar: unclosed turbofish
/// groups and unclosed call groups, each repeated past 100K bytes. A scan
/// that rescans to the end per segment or per root is quadratic on these.
const ADVERSARIAL_CHAIN_UNITS: &[(&str, &str)] = &[
    ("a.b::<", "unclosed turbofish"),
    ("t.f(", "unclosed call"),
    ("token.f::<", "unclosed turbofish on a secret receiver"),
    ("x[", "unclosed index"),
];
const ADVERSARIAL_CHAIN_BYTES: usize = 120_000;

#[test]
fn cleartext_msgs_scanner_linear_on_adversarial_chains() {
    for (unit, what) in ADVERSARIAL_CHAIN_UNITS {
        let expr = unit.repeat(ADVERSARIAL_CHAIN_BYTES / unit.len() + 1);
        assert!(expr.len() >= ADVERSARIAL_CHAIN_BYTES, "{what}");
        let started = Instant::now();
        let got = rendered_secret("x.rs", &expr);
        let elapsed = started.elapsed();
        eprintln!(
            "E-d {what}: {} bytes {elapsed:?} (ceiling {SCAN_100K_TIME_CEILING:?})",
            expr.len()
        );
        assert!(
            elapsed < SCAN_100K_TIME_CEILING,
            "{what}: {} bytes took {elapsed:?}, ceiling {SCAN_100K_TIME_CEILING:?} (got {got:?})",
            expr.len()
        );
    }
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
