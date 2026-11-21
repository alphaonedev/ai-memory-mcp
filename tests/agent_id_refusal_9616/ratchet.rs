// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9616 source ratchet: an ALLOWLIST over every tracked `.rs` file of the
//! crate, refusing by default.
//!
//! Each scanned file is lexed (comments dropped, string literals decoded,
//! char literals and lifetimes told apart) and four counts are taken:
//!
//! * [`Class::HeaderName`]: the `HEADER_AGENT_ID` identifier, plus every
//!   string literal (plain, raw, byte, escaped, line-continued) whose
//!   decoded text holds `x-agent` in any case. An alias is counted at its
//!   `use` line, a name split into fragments at the `x-agent` fragment.
//! * [`Class::Resolver`]: the raw resolver `resolve_http_agent_id`.
//! * [`Class::Sentinel`]: the `ANONYMOUS_INVALID` identifier and every
//!   string literal holding `anonymous:invalid`.
//! * [`Class::Fold`]: a call of a funnel entry ([`FUNNEL_CALLS`]) whose
//!   method chain reaches a fold ([`FOLDS`]), which turns a refusal into a
//!   value.
//!
//! A count that is not exactly what [`ALLOW`] grants that file (no row
//! grants 0) is an offender. A tracked `.rs` file under a root that is
//! neither scanned nor in [`LEFT_OUT`] is an offender too, so a new crate
//! directory cannot hide a read. One run lists every offender.
//!
//! What a token scan cannot see is a header name built at run time from
//! fragments that never spell `x-agent` and a refusal discarded by a `match`
//! arm; the behaviour census in the parent module pins every route for
//! those.

use std::collections::BTreeMap;
use std::path::Path;

/// The counted construct classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    HeaderName,
    Resolver,
    Sentinel,
    Fold,
}

impl Class {
    const ALL: [Self; 4] = [Self::HeaderName, Self::Resolver, Self::Sentinel, Self::Fold];

    fn label(self) -> &'static str {
        match self {
            Self::HeaderName => "header-name",
            Self::Resolver => "raw-resolver",
            Self::Sentinel => "anonymous-invalid",
            Self::Fold => "refusal-folded",
        }
    }
}

/// How many mentions a row grants.
#[derive(Clone, Copy, Debug)]
enum Grant {
    Exactly(usize),
    /// Any number above zero: the file is the funnel itself, or is compiled
    /// only under `cfg(test)`.
    AnyNonZero,
}

struct Allow {
    file: &'static str,
    class: Class,
    grant: Grant,
    reason: &'static str,
}

const fn allow(file: &'static str, class: Class, grant: Grant, reason: &'static str) -> Allow {
    Allow {
        file,
        class,
        grant,
        reason,
    }
}

use Class::{Fold, HeaderName, Resolver, Sentinel};
use Grant::{AnyNonZero, Exactly};

/// Every permitted site. Anything not granted here is refused.
const ALLOW: &[Allow] = &[
    allow(
        "src/handlers/caller_identity.rs",
        HeaderName,
        AnyNonZero,
        "the funnel: the one read, its reason strings and its unit tables",
    ),
    allow(
        "src/handlers/caller_identity.rs",
        Resolver,
        Exactly(1),
        "the funnel calls the raw resolver once, in resolve_caller",
    ),
    allow(
        "src/handlers/caller_identity.rs",
        Sentinel,
        Exactly(2),
        "audit_actor's label on a path that is already refusing, and its test row",
    ),
    allow(
        "src/handlers/caller_identity.rs",
        Fold,
        Exactly(1),
        "audit_actor: a label for an audit row, never an authority decision",
    ),
    allow(
        "src/lib.rs",
        HeaderName,
        Exactly(2),
        "the HEADER_AGENT_ID definition and its value",
    ),
    allow(
        "src/identity/mod.rs",
        Resolver,
        Exactly(10),
        "the raw resolver's definition and nine calls in its own cfg(test) unit tests",
    ),
    allow(
        "src/identity/mod.rs",
        Sentinel,
        Exactly(2),
        "two cfg(test) rows asserting the CLI resolver's sentinel",
    ),
    allow(
        "src/identity/sentinels.rs",
        Sentinel,
        Exactly(2),
        "the ANONYMOUS_INVALID definition and its value",
    ),
    allow(
        "src/handlers/kg.rs",
        Fold,
        Exactly(1),
        "display-only subject in the agent_id_body_header_mismatch branch, reached only \
         after the header resolved; the request is already refused there",
    ),
    allow(
        "src/handlers/hook_subscribers.rs",
        Sentinel,
        Exactly(2),
        "comparisons that refuse a caller equal to the sentinel",
    ),
    allow(
        "src/handlers/identity_binding.rs",
        Sentinel,
        Exactly(1),
        "comparison that refuses a caller equal to the sentinel",
    ),
    allow(
        "src/confidence/calibrate.rs",
        Sentinel,
        Exactly(1),
        "comparison that excludes the sentinel from calibration",
    ),
    allow(
        "src/cli/backup.rs",
        Sentinel,
        Exactly(1),
        "CLI audit actor from the env/host resolver; no HTTP request, no header",
    ),
    allow(
        "src/mcp/tools/archive.rs",
        Sentinel,
        Exactly(1),
        "MCP audit actor on a refusal path; MCP has no HTTP header",
    ),
    allow(
        "src/mcp/tools/pending.rs",
        Sentinel,
        Exactly(2),
        "MCP audit actors on two refusal paths; MCP has no HTTP header",
    ),
    allow(
        "src/mcp/tools/namespace.rs",
        Sentinel,
        Exactly(4),
        "MCP wire-claim fallback refused by the ownership gate, and three cfg(test) rows",
    ),
    allow(
        "src/mcp/tools/namespace.rs",
        Resolver,
        Exactly(1),
        "cfg(test) row proving a wire daemon claim is not honoured",
    ),
    allow(
        "src/mcp/tools/skill_integrity.rs",
        Sentinel,
        Exactly(1),
        "cfg(test) row naming the sentinel among anonymous owners",
    ),
    allow(
        "loadtest/src/main.rs",
        HeaderName,
        Exactly(2),
        "HTTP client: writes the header on outbound requests, reads none",
    ),
    allow(
        "src/identity/mod.rs",
        HeaderName,
        Exactly(1),
        "the anonymous-default warn text",
    ),
    allow(
        "src/handlers/tests.rs",
        HeaderName,
        AnyNonZero,
        "cfg(test) request builders (declared #[cfg(test)] mod tests in src/handlers/mod.rs)",
    ),
    allow(
        "src/handlers/create.rs",
        HeaderName,
        Exactly(5),
        "cfg(test) header() request builders",
    ),
    allow(
        "src/handlers/transport.rs",
        HeaderName,
        Exactly(4),
        "three refusal texts and the insert that sets the resolved caller",
    ),
    allow(
        "src/mtls_agent_binding.rs",
        HeaderName,
        Exactly(4),
        "#9666: bind_request's claimed read (first value, lossy UTF-8) is client-visible \
         and waits for a decision; the other three are its insert and two refusal texts",
    ),
    allow(
        "src/daemon_runtime.rs",
        HeaderName,
        Exactly(4),
        "two outbound request header writes and two log texts",
    ),
    allow(
        "src/federation/receive.rs",
        HeaderName,
        Exactly(3),
        "outbound federation request header writes",
    ),
    allow(
        "src/mcp/tools/store/transport.rs",
        HeaderName,
        Exactly(5),
        "outbound header writes and their test",
    ),
    allow(
        "src/confidence/calibrate.rs",
        HeaderName,
        Exactly(1),
        "message text",
    ),
    allow("src/errors.rs", HeaderName, Exactly(1), "message text"),
    allow(
        "src/handlers/admin_role.rs",
        HeaderName,
        Exactly(1),
        "message text",
    ),
    allow(
        "src/handlers/approvals.rs",
        HeaderName,
        Exactly(2),
        "message text",
    ),
    allow(
        "src/handlers/hook_subscribers.rs",
        HeaderName,
        Exactly(1),
        "message text",
    ),
    allow(
        "src/handlers/identity_binding.rs",
        HeaderName,
        Exactly(3),
        "message text",
    ),
    allow(
        "src/handlers/memories.rs",
        HeaderName,
        Exactly(1),
        "message text",
    ),
    allow(
        "src/handlers/subscriptions.rs",
        HeaderName,
        Exactly(1),
        "message text",
    ),
];

/// Tracked top-level directories that hold `.rs` files and are scanned.
const SCANNED_ROOTS: &[&str] = &[
    "src",
    "benches",
    "benchmarks",
    "examples",
    "fuzz",
    "loadtest",
    "tools",
];

/// Tracked top-level directories that hold `.rs` files and are not scanned,
/// each with its reason.
const LEFT_OUT: &[(&str, &str)] = &[
    (
        "tests",
        "integration tests are HTTP clients of the daemon: they write the header on \
         requests, and no file there is compiled into the served binary",
    ),
    (
        "vendor",
        "third-party sources vendored as they were published; none of them names the header",
    ),
];

/// Funnel entries whose result is a caller or a refusal.
const FUNNEL_CALLS: &[&str] = &[
    "header_agent_id",
    "resolve_caller",
    "resolve_http_agent_id",
    "resolve_caller_agent_id",
    "http_caller",
    "http_caller_in",
    "http_caller_ctx",
];

/// Methods that turn a refusal into a value.
const FOLDS: &[&str] = &[
    "ok",
    "or",
    "or_else",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "map_or",
    "map_or_else",
];

/// The header name, lower case (ASCII).
const HEADER_NAME: &str = "x-agent-id";
const HEADER_NEEDLE: &str = "x-agent";
const SENTINEL_NEEDLE: &str = "anonymous:invalid";

// Reasons for a file that is refused whole (`<file>: <reason>`).
const UNTERMINATED_BLOCK_COMMENT: &str = "unterminated block comment";
const UNTERMINATED_RAW_STRING: &str = "unterminated raw string";
const UNTERMINATED_STRING: &str = "unterminated string literal";
const UNTERMINATED_CHAR: &str = "unterminated char literal";
const TOO_MANY_RAW_HASHES: &str = "raw string opened with more than 255 hashes";
const UNREADABLE: &str = "unreadable file";
const NOT_REGULAR: &str = "not a regular file";
const NOT_UTF8: &str = "not UTF-8";
const TOO_LARGE: &str = "larger than the source size cap";
const RESOLVES_ELSEWHERE: &str = "resolves outside its tracked path";
const OUTSIDE_ROOTS: &str = "outside the scanned source roots";
// Reasons for the walk itself.
const NO_ROOT: &str = "is under neither a scanned root nor a left-out root";
const EMPTY_ROOT: &str = "scanned root holds no tracked .rs file";

/// rustc's own limit on the hashes of a raw string.
const MAX_RAW_HASHES: usize = 255;
/// No tracked source is near this size; a larger file is refused unread.
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Punct(char),
}

/// Decode a non-raw string literal body starting at `i` (just past the
/// opening quote). Returns the text and the index past the closing quote.
fn cooked_string(b: &[char], mut i: usize) -> (String, usize) {
    let mut out = String::new();
    while i < b.len() {
        match b[i] {
            '"' => return (out, i + 1),
            '\\' if i + 1 < b.len() => {
                i += 1;
                match b[i] {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    '\n' => {
                        while i + 1 < b.len() && b[i + 1].is_whitespace() {
                            i += 1;
                        }
                    }
                    'x' => {
                        let hex: String = b[i + 1..(i + 3).min(b.len())].iter().collect();
                        if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            out.push(c);
                        }
                        i += 2;
                    }
                    'u' => {
                        let close = b[i..].iter().position(|&c| c == '}').map(|p| i + p);
                        if let Some(close) = close {
                            let hex: String = b[i + 2..close].iter().collect();
                            if let Some(c) =
                                u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                            {
                                out.push(c);
                            }
                            i = close;
                        }
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    (out, i)
}

/// A raw string body from `i` up to `"` followed by `hashes` `#`.
fn raw_string(b: &[char], mut i: usize, hashes: usize) -> (String, usize) {
    let start = i;
    while i < b.len() {
        if b[i] == '"'
            && b[i + 1..]
                .iter()
                .take(hashes)
                .filter(|&&c| c == '#')
                .count()
                == hashes
        {
            return (b[start..i].iter().collect(), i + 1 + hashes);
        }
        i += 1;
    }
    (b[start..].iter().collect(), i)
}

/// The end of a char literal opening at `i`, or `None` for a lifetime.
fn char_literal_end(b: &[char], i: usize) -> Option<usize> {
    if b.get(i + 1) == Some(&'\\') {
        let mut j = i + 3;
        while j < b.len() && b[j] != '\'' {
            j += 1;
        }
        return Some(j + 1);
    }
    (b.get(i + 2) == Some(&'\'')).then_some(i + 3)
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn lex(src: &str) -> Vec<Tok> {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < len {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '/' && chars.get(i + 1) == Some(&'/') {
            while i < len && chars[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1;
            i += 2;
            while i < len && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if ch == '"' {
            let (text, j) = cooked_string(&chars, i + 1);
            out.push(Tok::Str(text));
            i = j;
        } else if ch == '\'' {
            i = char_literal_end(&chars, i).unwrap_or(i + 1);
        } else if ch.is_alphabetic() || ch == '_' {
            let start = i;
            while i < len && is_ident_char(chars[i]) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let next = chars.get(i).copied();
            match (word.as_str(), next) {
                ("b" | "c", Some('"')) => {
                    let (text, j) = cooked_string(&chars, i + 1);
                    out.push(Tok::Str(text));
                    i = j;
                }
                ("b", Some('\'')) => i = char_literal_end(&chars, i).unwrap_or(i + 1),
                ("r" | "br" | "cr", Some('"' | '#')) => {
                    let mut j = i;
                    while j < len && chars[j] == '#' {
                        j += 1;
                    }
                    let hashes = j - i;
                    if chars.get(j) == Some(&'"') {
                        let (text, k) = raw_string(&chars, j + 1, hashes);
                        out.push(Tok::Str(text));
                        i = k;
                    } else if word == "r" && hashes == 1 {
                        let start = j;
                        while j < len && is_ident_char(chars[j]) {
                            j += 1;
                        }
                        out.push(Tok::Ident(chars[start..j].iter().collect()));
                        i = j;
                    } else {
                        out.push(Tok::Ident(word));
                    }
                }
                _ => out.push(Tok::Ident(word)),
            }
        } else if ch.is_ascii_digit() {
            while i < len && is_ident_char(chars[i]) {
                i += 1;
            }
        } else {
            out.push(Tok::Punct(ch));
            i += 1;
        }
    }
    out
}

/// The index of the `)` matching the `(` at `open`.
fn close_paren(toks: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (j, t) in toks.iter().enumerate().skip(open) {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether the method chain after the call closing at `close` reaches a fold.
fn chain_folds(toks: &[Tok], mut close: usize) -> bool {
    loop {
        let (Some(Tok::Punct('.')), Some(Tok::Ident(method))) =
            (toks.get(close + 1), toks.get(close + 2))
        else {
            return false;
        };
        if FOLDS.contains(&method.as_str()) {
            return true;
        }
        if toks.get(close + 3) != Some(&Tok::Punct('(')) {
            return false;
        }
        match close_paren(toks, close + 3) {
            Some(next) => close = next,
            None => return false,
        }
    }
}

fn counts(src: &str) -> BTreeMap<Class, usize> {
    let toks = lex(src);
    let mut out: BTreeMap<Class, usize> = Class::ALL.iter().map(|&c| (c, 0)).collect();
    let mut bump = |class| *out.entry(class).or_default() += 1;
    for (k, tok) in toks.iter().enumerate() {
        match tok {
            Tok::Ident(name) => {
                match name.as_str() {
                    "HEADER_AGENT_ID" => bump(HeaderName),
                    "ANONYMOUS_INVALID" => bump(Sentinel),
                    _ => {}
                }
                if name == "resolve_http_agent_id" {
                    bump(Resolver);
                }
                if FUNNEL_CALLS.contains(&name.as_str())
                    && toks.get(k + 1) == Some(&Tok::Punct('('))
                    && close_paren(&toks, k + 1).is_some_and(|close| chain_folds(&toks, close))
                {
                    bump(Fold);
                }
            }
            Tok::Str(text) => {
                let lower = text.to_lowercase();
                for _ in lower.matches(HEADER_NEEDLE) {
                    bump(HeaderName);
                }
                for _ in lower.matches(SENTINEL_NEEDLE) {
                    bump(Sentinel);
                }
            }
            Tok::Punct(_) => {}
        }
    }
    out
}

/// The offenders among `files` (`(repo-relative path, source)`), sorted.
fn offenders(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, src) in files {
        for (class, n) in counts(src) {
            let row = ALLOW.iter().find(|a| a.file == path && a.class == class);
            let ok = match row.map(|a| a.grant) {
                None => n == 0,
                Some(Exactly(k)) => n == k,
                Some(AnyNonZero) => n > 0,
            };
            if !ok {
                let granted = match row.map(|a| a.grant) {
                    None => "0".to_owned(),
                    Some(Exactly(k)) => k.to_string(),
                    Some(AnyNonZero) => "1 or more".to_owned(),
                };
                found.push(format!("{path}: {} {n} (allowed {granted})", class.label()));
            }
        }
    }
    for row in ALLOW {
        if !files.iter().any(|(p, _)| p == row.file) {
            found.push(format!(
                "{}: allow row for {} names no scanned file ({})",
                row.file,
                row.class.label(),
                row.reason
            ));
        }
    }
    found.sort();
    found
}

fn tracked_rs(root: &Path) -> Vec<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.rs"])
        .output()
        .expect("run git ls-files");
    assert!(out.status.success(), "git ls-files failed: {out:?}");
    String::from_utf8(out.stdout)
        .expect("tracked paths are UTF-8")
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The real tree: every tracked `.rs` file under a scanned root holds exactly
/// what [`ALLOW`] grants, and every tracked root is scanned or left out with
/// a reason.
#[test]
fn every_agent_id_site_in_the_tree_is_allow_listed_9616() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut problems = Vec::new();
    for path in tracked_rs(root) {
        let top = path.split_once('/').map_or(".", |(top, _)| top);
        if LEFT_OUT.iter().any(|(r, _)| *r == top) {
            continue;
        }
        if !SCANNED_ROOTS.contains(&top) {
            problems.push(format!(
                "{path}: tracked root {top} is neither scanned nor left out"
            ));
            continue;
        }
        let src = std::fs::read_to_string(root.join(&path)).expect("read tracked source");
        files.push((path, src));
    }
    for (left, reason) in LEFT_OUT {
        assert!(
            root.join(left).is_dir(),
            "left-out root {left} is gone ({reason})"
        );
    }
    problems.extend(offenders(&files));
    assert_eq!(problems, Vec::<String>::new());
}

/// A synthetic handler file with no allow row.
const PROBE: &str = "src/handlers/links.rs";
/// A synthetic file outside `src/handlers`, to pin that the scan is src-wide.
const PROBE_OUTSIDE_HANDLERS: &str = "src/sync_client.rs";

// The four forms the round-1 verdict named.
const VERDICT_GET_LITERAL: &str =
    r#"fn f(h: &HeaderMap) -> Option<&str> { h.get("x-agent-id").and_then(|v| v.to_str().ok()) }"#;
const VERDICT_GET_ALL_FIRST: &str =
    "fn f(h: &HeaderMap) { let _ = h.get_all(crate::HEADER_AGENT_ID).iter().next(); }";
const VERDICT_GET_REF: &str = "fn f(h: &HeaderMap) { let _ = h.get(&crate::HEADER_AGENT_ID); }";
const VERDICT_RENAMED_FALLBACK: &str = r#"fn f(claimed: Option<&str>) -> String { resolve_http_agent_id(None, claimed).unwrap_or_else(|_| "ai:http".into()) }"#;
// Spelling variants.
const UPPER_CASE: &str = r#"fn f(h: &HeaderMap) { let _ = h.get("X-AGENT-ID"); }"#;
const LINE_SPLIT_STRING: &str =
    "fn f(h: &HeaderMap) { let _ = h.get(\"x-agent-\\\n        id\"); }";
const LINE_SPLIT_CALL: &str = "fn f(h: &HeaderMap) {\n    let _ = h\n        .get(\n            crate::HEADER_AGENT_ID,\n        );\n}";
const ALIASED: &str =
    "use crate::HEADER_AGENT_ID as WHO;\nfn f(h: &HeaderMap) { let _ = h.get(WHO); }";
const ESCAPED: &str = r#"fn f(h: &HeaderMap) { let _ = h.get("x\x2dagent\u{2d}id"); }"#;
const RAW_STRING: &str = r##"fn f(h: &HeaderMap) { let _ = h.get(r#"X-Agent-Id"#); }"##;
const BYTE_STRING: &str = r#"fn f() { let _ = HeaderName::from_bytes(b"x-agent-id"); }"#;
const FRAGMENTS: &str = r#"fn f() -> String { format!("{}{}", "X-Agent", "-Id") }"#;
const CONST_TABLE: &str = r#"const NAMES: &[&str] = &["x-agent-id"];"#;
const MATCH_ARM: &str = r#"fn f(n: &str) -> bool { match n { "x-agent-id" => true, _ => false } }"#;
const RAW_IDENT_RESOLVER: &str =
    "fn f(h: Option<&str>) { let _ = r#resolve_http_agent_id(None, h); }";
const SENTINEL_LITERAL: &str = r#"fn f(h: &HeaderMap) -> String { resolve_caller(h, None).unwrap_or_else(|_| "anonymous:invalid".to_string()) }"#;
const SENTINEL_CONST: &str =
    "fn f() -> &'static str { crate::identity::sentinels::ANONYMOUS_INVALID }";
const FOLD_THROUGH_MAP: &str =
    "fn f(h: &HeaderMap) -> Option<String> { resolve_caller(h, None).map(|c| c).ok() }";
const FOLD_HEADER_READ: &str =
    "fn f(h: &HeaderMap) -> Option<&str> { header_agent_id(h).unwrap_or(None) }";
const FOLD_PARITY: &str =
    "fn f(h: &HeaderMap) -> String { resolve_caller_agent_id(None, h, None).unwrap_or_default() }";
const FOLD_HTTP_CALLER: &str =
    "fn f(h: &HeaderMap) -> String { http_caller(h).map_or_else(|_| String::new(), |c| c) }";

// Round-2 red shims (PR 9661): the entry points the round-2 rows call, with
// the behaviour of the round-1 head, so each new row fails by assertion. The
// fix commit replaces them.

/// [`offenders`] of one file, without the stale-row check.
fn one(path: &str, src: &str) -> Vec<String> {
    offenders(&[(path.to_owned(), src.to_owned())])
        .into_iter()
        .filter(|line| !line.contains("names no scanned file"))
        .collect()
}

fn one_read(path: &str, read: Result<String, &'static str>) -> Vec<String> {
    read.map_or_else(|_| Vec::new(), |src| one(path, &src))
}

fn open_source(root: &Path, rel: &str) -> Result<String, &'static str> {
    let bytes = std::fs::read(root.join(rel)).unwrap_or_default();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn plan(tracked: &[String]) -> (Vec<String>, Vec<String>) {
    let mut open = Vec::new();
    let mut problems = Vec::new();
    for path in tracked {
        let top = path.split_once('/').map_or(".", |(top, _)| top);
        if LEFT_OUT.iter().any(|(r, _)| *r == top) {
            continue;
        }
        if SCANNED_ROOTS.contains(&top) {
            open.push(path.clone());
        } else {
            problems.push(format!(
                "{path}: tracked root {top} is neither scanned nor left out"
            ));
        }
    }
    (open, problems)
}

/// Every deny form is refused with its exact offender line.
#[test]
fn deny_corpus_is_refused_with_the_exact_offender_9616() {
    let header = |p: &str| format!("{p}: header-name 1 (allowed 0)");
    let resolver = |p: &str| format!("{p}: raw-resolver 1 (allowed 0)");
    let sentinel = |p: &str| format!("{p}: anonymous-invalid 1 (allowed 0)");
    let fold = |p: &str| format!("{p}: refusal-folded 1 (allowed 0)");
    let rows: &[(&str, &str, Vec<String>)] = &[
        (
            "verdict get literal",
            VERDICT_GET_LITERAL,
            vec![header(PROBE)],
        ),
        (
            "verdict get_all first",
            VERDICT_GET_ALL_FIRST,
            vec![header(PROBE)],
        ),
        ("verdict get &const", VERDICT_GET_REF, vec![header(PROBE)]),
        (
            "verdict renamed fallback",
            VERDICT_RENAMED_FALLBACK,
            vec![resolver(PROBE), fold(PROBE)],
        ),
        ("upper case", UPPER_CASE, vec![header(PROBE)]),
        ("line-split string", LINE_SPLIT_STRING, vec![header(PROBE)]),
        ("line-split call", LINE_SPLIT_CALL, vec![header(PROBE)]),
        ("aliased const", ALIASED, vec![header(PROBE)]),
        ("escaped", ESCAPED, vec![header(PROBE)]),
        ("raw string", RAW_STRING, vec![header(PROBE)]),
        ("byte string", BYTE_STRING, vec![header(PROBE)]),
        ("fragments", FRAGMENTS, vec![header(PROBE)]),
        ("const table", CONST_TABLE, vec![header(PROBE)]),
        ("match arm", MATCH_ARM, vec![header(PROBE)]),
        (
            "raw ident resolver",
            RAW_IDENT_RESOLVER,
            vec![resolver(PROBE)],
        ),
        (
            "sentinel literal",
            SENTINEL_LITERAL,
            vec![fold(PROBE), sentinel(PROBE)],
        ),
        ("sentinel const", SENTINEL_CONST, vec![sentinel(PROBE)]),
        ("fold through map", FOLD_THROUGH_MAP, vec![fold(PROBE)]),
        ("fold header read", FOLD_HEADER_READ, vec![fold(PROBE)]),
        ("fold parity", FOLD_PARITY, vec![fold(PROBE)]),
        ("fold http_caller", FOLD_HTTP_CALLER, vec![fold(PROBE)]),
    ];
    for (name, src, want) in rows {
        let mut want = want.clone();
        want.sort();
        assert_eq!(one(PROBE, src), want, "{name}");
    }
    assert_eq!(
        one(PROBE_OUTSIDE_HANDLERS, VERDICT_GET_LITERAL),
        vec![header(PROBE_OUTSIDE_HANDLERS)]
    );
    // A second read in an allow-listed file breaks its exact count.
    assert_eq!(
        one("src/mtls_agent_binding.rs", VERDICT_GET_REF),
        vec!["src/mtls_agent_binding.rs: header-name 1 (allowed 4)".to_owned()]
    );
}

const COMMENT_ONLY: &str =
    "// reads X-Agent-Id via h.get(\"x-agent-id\") and HEADER_AGENT_ID\nfn f() {}";
const DOC_AND_NESTED_BLOCK: &str = "/// the X-Agent-Id header\n/* HEADER_AGENT_ID /* nested x-agent-id */ resolve_http_agent_id(None, h).ok() */\nfn f() {}";
const CHAR_AND_LIFETIME: &str = "fn f<'a>(x: &'a str) -> char { let _ = x; '\"' } // x-agent-id\nfn g() -> char { '\\'' } // ANONYMOUS_INVALID";
const FUNNEL_USE: &str = "fn f(headers: &HeaderMap) -> Response {\n    let caller = match crate::handlers::caller_identity::header_agent_id(headers) {\n        Err(r) => return r.into_response(),\n        Ok(v) => v,\n    };\n    let _ = http_caller(headers)?;\n    let _ = resolve_caller(headers, caller).map_err(IntoResponse::into_response)?;\n    todo!()\n}";

/// Allowed forms raise no offender.
#[test]
fn allow_corpus_raises_no_offender_9616() {
    for (name, src) in [
        ("comment only", COMMENT_ONLY),
        ("doc and nested block comment", DOC_AND_NESTED_BLOCK),
        ("char literal and lifetime", CHAR_AND_LIFETIME),
        ("funnel use", FUNNEL_USE),
    ] {
        assert_eq!(one(PROBE, src), Vec::<String>::new(), "{name}");
    }
}

/// Size and time bound: a 200K-line source is counted in linear time.
#[test]
fn ratchet_scan_is_bounded_on_a_large_source_9616() {
    const LINES: usize = 200_000;
    let src = "let _ = h.get(crate::HEADER_AGENT_ID); // x-agent-id\n".repeat(LINES);
    let start = std::time::Instant::now();
    let n = counts(&src)[&HeaderName];
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(n, LINES);
}

// Round 2 (PR 9661): every compile-time join of the header name.
const CONCAT_PLAIN: &str = r#"fn f(h: &HeaderMap) { let _ = h.get(concat!("x-", "agent-id")); }"#;
const CONCAT_NESTED: &str =
    r#"fn f() -> &'static str { concat!("x", concat!("-ag", "ent"), "-id") }"#;
const CONCAT_CONST: &str = "const NAME: &str = concat!(\"X-Ag\", \"ent-Id\");\nfn f(h: &HeaderMap) { let _ = h.get(NAME); }";
const CONCAT_BRACKET: &str = r#"const NAME: &str = concat!["x-a", "gent-id"];"#;
const CONCAT_STRINGIFY: &str = r#"const NAME: &str = concat!("x-", stringify!(agent), "-id");"#;
const ADJACENT_PAIR: &str = r#"const PARTS: [&str; 2] = ["x-ag", "ent-id"];"#;
const ADJACENT_TRIPLE: &str = r#"fn f() -> String { ["x-a", "gent", "-id"].concat() }"#;
const CHAR_ARRAY: &str =
    "const NAME: [char; 10] = ['x', '-', 'a', 'g', 'e', 'n', 't', '-', 'i', 'd'];";
const BYTE_CHAR_ARRAY: &str =
    "const NAME: [u8; 10] = [b'x', b'-', b'a', b'g', b'e', b'n', b't', b'-', b'i', b'd'];";
const LONE_FRAGMENT: &str = r#"fn f(head: &str) -> String { format!("{head}agent-id") }"#;
const LONE_FRAGMENT_RAW_BYTES: &str = r##"const TAIL: &[u8] = br#"-Agent-ID"#;"##;
const MACRO_TAIL: &str =
    r#"macro_rules! name { ($head:literal) => { concat!($head, "agent-id") }; }"#;
const SPLIT_CONSTS: &str = "const HEAD: &str = \"x-ag\";\nconst TAIL: &str = \"ent-id\";";

/// Every compile-time join is refused with its exact offender line.
#[test]
fn compile_time_joins_are_refused_with_the_exact_offender_9616() {
    let header = vec![format!("{PROBE}: header-name 1 (allowed 0)")];
    let fragment = vec![format!("{PROBE}: header-fragment 1 (allowed 0)")];
    let rows: &[(&str, &str, &Vec<String>)] = &[
        ("concat", CONCAT_PLAIN, &header),
        ("nested concat", CONCAT_NESTED, &header),
        ("const built from concat", CONCAT_CONST, &header),
        ("concat with brackets", CONCAT_BRACKET, &header),
        ("concat of stringify", CONCAT_STRINGIFY, &header),
        ("adjacent pair", ADJACENT_PAIR, &header),
        ("adjacent triple", ADJACENT_TRIPLE, &header),
        ("char array", CHAR_ARRAY, &header),
        ("byte char array", BYTE_CHAR_ARRAY, &header),
        ("lone fragment", LONE_FRAGMENT, &fragment),
        (
            "lone fragment, raw bytes",
            LONE_FRAGMENT_RAW_BYTES,
            &fragment,
        ),
        ("macro tail", MACRO_TAIL, &fragment),
        ("split constants", SPLIT_CONSTS, &fragment),
    ];
    for (name, src, want) in rows {
        assert_eq!(&one(PROBE, src), *want, "{name}");
    }
}

const UNRELATED_HEADERS: &str = r#"fn f(h: &HeaderMap) { let _ = (h.get("x-api-key"), h.get("x-request-id"), h.get("user-agent")); }"#;
const FLAG_TEXT: &str = r#"fn f() -> &'static str { "pass --agent-id <ID> or set AGENT_ID" }"#;
const COMMENTED_JOIN: &str =
    "// concat!(\"x-\", \"agent-id\")\n/* [\"x-ag\", \"ent-id\"] and \"agent-id\" */\nfn f() {}";
const CONCAT_UNRELATED: &str = r#"const NAME: &str = concat!("x-", "api", "-key");"#;

/// Forms that cannot yield the header name raise no offender.
#[test]
fn round_2_allow_corpus_raises_no_offender_9616() {
    for (name, src) in [
        ("unrelated headers", UNRELATED_HEADERS),
        ("command-line flag text", FLAG_TEXT),
        ("joins inside comments", COMMENTED_JOIN),
        ("concat of an unrelated header", CONCAT_UNRELATED),
    ] {
        assert_eq!(one(PROBE, src), Vec::<String>::new(), "{name}");
    }
}

const CASE_MODES: usize = 3;

/// `text` as written, in upper case, or in alternating case.
fn cased(text: &str, mode: usize) -> String {
    match mode {
        0 => text.to_owned(),
        1 => text.to_uppercase(),
        _ => text
            .chars()
            .enumerate()
            .map(|(k, c)| {
                if k % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect(),
    }
}

/// A refused name stays refused under every case change and every re-split:
/// all cut positions, in two and in three pieces, joined by `concat!`, laid
/// side by side, or kept in separate constants. The name is ASCII, so every
/// cut is a char boundary.
#[test]
fn a_refused_name_stays_refused_under_case_change_and_re_split_9616() {
    let header = vec![format!("{PROBE}: header-name 1 (allowed 0)")];
    let fragment = vec![format!("{PROBE}: header-fragment 1 (allowed 0)")];
    // What two separate constants yield, by cut position 1 to 9.
    let separate = [
        &fragment, &fragment, &fragment, &fragment, &fragment, &fragment, &header, &header, &header,
    ];
    assert_eq!(separate.len(), HEADER_NAME.len() - 1);
    for mode in 0..CASE_MODES {
        let name = cased(HEADER_NAME, mode);
        let whole = format!("const N: &str = \"{name}\";");
        assert_eq!(one(PROBE, &whole), header, "{whole}");
        for cut in 1..name.len() {
            let (a, rest) = name.split_at(cut);
            let joined = format!("const N: &str = concat!(\"{a}\", \"{rest}\");");
            assert_eq!(one(PROBE, &joined), header, "{joined}");
            let beside = format!("const N: [&str; 2] = [\"{a}\", \"{rest}\"];");
            assert_eq!(one(PROBE, &beside), header, "{beside}");
            let apart = format!("const A: &str = \"{a}\";\nconst B: &str = \"{rest}\";");
            assert_eq!(&one(PROBE, &apart), separate[cut - 1], "{apart}");
            for cut2 in 1..rest.len() {
                let (b, c) = rest.split_at(cut2);
                let three = format!("const N: &str = concat!(\"{a}\", \"{b}\", \"{c}\");");
                assert_eq!(one(PROBE, &three), header, "{three}");
            }
        }
    }
}

/// The lexer never ends a file silently in an open state, and a file that
/// could not be read is an offender: one row per degenerate input, each with
/// its exact offender line.
#[test]
fn a_file_in_an_open_or_unread_state_is_refused_whole_9616() {
    let line = |reason: &str| vec![format!("{PROBE}: {reason}")];
    let raw = |hashes: usize| {
        let h = "#".repeat(hashes);
        format!("const S: &str = r{h}\"x\"{h};")
    };
    let read = "fn f(h: &HeaderMap) { let _ = h.get(\"x-agent-id\"); }";
    let rows: Vec<(&str, Result<String, &'static str>, Vec<String>)> = vec![
        (
            "block comment",
            Ok(format!("/* never closed\n{read}")),
            line(UNTERMINATED_BLOCK_COMMENT),
        ),
        (
            "nested block comment, inner one closed",
            Ok(format!("/* a /* b */ still open\n{read}")),
            line(UNTERMINATED_BLOCK_COMMENT),
        ),
        (
            "block comment opened at the end",
            Ok("fn f() {}\n/*".to_owned()),
            line(UNTERMINATED_BLOCK_COMMENT),
        ),
        (
            "block comment nested 1000 deep",
            Ok("/*".repeat(1_000)),
            line(UNTERMINATED_BLOCK_COMMENT),
        ),
        (
            "raw string",
            Ok("fn f() { let _ = r#\"x-agent-id\"; }".to_owned()),
            line(UNTERMINATED_RAW_STRING),
        ),
        (
            "raw string closed with too few hashes",
            Ok("const S: &[u8] = br##\"x-agent-id\"#;".to_owned()),
            line(UNTERMINATED_RAW_STRING),
        ),
        (
            "string",
            Ok("fn f() { let _ = \"x-agent-id; }".to_owned()),
            line(UNTERMINATED_STRING),
        ),
        (
            "string ending in a backslash",
            Ok("const S: &[u8] = b\"x-agent-id\\".to_owned()),
            line(UNTERMINATED_STRING),
        ),
        (
            "char",
            Ok("fn f() -> char { '\\n }".to_owned()),
            line(UNTERMINATED_CHAR),
        ),
        (
            "raw string, one hash over the limit",
            Ok(raw(MAX_RAW_HASHES + 1)),
            line(TOO_MANY_RAW_HASHES),
        ),
        (
            "raw string at the hash limit",
            Ok(raw(MAX_RAW_HASHES)),
            Vec::new(),
        ),
        ("unreadable", Err(UNREADABLE), line(UNREADABLE)),
        ("not regular", Err(NOT_REGULAR), line(NOT_REGULAR)),
        ("not UTF-8", Err(NOT_UTF8), line(NOT_UTF8)),
        ("too large", Err(TOO_LARGE), line(TOO_LARGE)),
        (
            "resolves elsewhere",
            Err(RESOLVES_ELSEWHERE),
            line(RESOLVES_ELSEWHERE),
        ),
        ("outside the roots", Err(OUTSIDE_ROOTS), line(OUTSIDE_ROOTS)),
    ];
    for (name, read, want) in rows {
        assert_eq!(one_read(PROBE, read), want, "{name}");
    }
}

/// One row per file state: [`open_source`] returns the text of a regular
/// UTF-8 `.rs` file under a scanned root and refuses every other path with
/// its exact reason, so no path outside the roots is ever read.
#[test]
fn open_source_refuses_every_degenerate_or_outside_path_9616() {
    const OK_SRC: &str = "fn f() {}";
    const OUTSIDE_SRC: &str = "fn outside() {}";
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let root = dir.path();
    let put = |rel: &str, bytes: &[u8]| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    let cap = usize::try_from(MAX_SOURCE_BYTES).unwrap();
    put("src/ok.rs", OK_SRC.as_bytes());
    put("src/bad.rs", &[0xff, 0xfe, b'\n']);
    put("src/cap.rs", &vec![b' '; cap]);
    put("src/big.rs", &vec![b' '; cap + 1]);
    put("src/notes.md", OUTSIDE_SRC.as_bytes());
    for outside in [
        "elsewhere/a.rs",
        "srcx/a.rs",
        "benchmarks/notes.rs",
        "tests/a.rs",
    ] {
        put(outside, OUTSIDE_SRC.as_bytes());
    }
    std::fs::create_dir_all(root.join("src/dir.rs")).unwrap();
    let absolute = root.join("src/ok.rs").canonicalize().unwrap();
    let mut rows: Vec<(&str, Result<String, &'static str>)> = vec![
        ("src/ok.rs", Ok(OK_SRC.to_owned())),
        ("src/cap.rs", Ok(" ".repeat(cap))),
        ("src/big.rs", Err(TOO_LARGE)),
        ("src/missing.rs", Err(UNREADABLE)),
        ("src/bad.rs", Err(NOT_UTF8)),
        ("src/dir.rs", Err(NOT_REGULAR)),
        ("src/notes.md", Err(OUTSIDE_ROOTS)),
        ("elsewhere/a.rs", Err(OUTSIDE_ROOTS)),
        ("srcx/a.rs", Err(OUTSIDE_ROOTS)),
        ("benchmarks/notes.rs", Err(OUTSIDE_ROOTS)),
        ("tests/a.rs", Err(OUTSIDE_ROOTS)),
        ("src/../elsewhere/a.rs", Err(OUTSIDE_ROOTS)),
        ("./src/ok.rs", Err(OUTSIDE_ROOTS)),
        ("src//ok.rs", Err(OUTSIDE_ROOTS)),
        (absolute.to_str().unwrap(), Err(OUTSIDE_ROOTS)),
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../elsewhere/a.rs", root.join("src/link.rs")).unwrap();
        std::os::unix::fs::symlink("../elsewhere", root.join("src/linked")).unwrap();
        rows.push(("src/link.rs", Err(RESOLVES_ELSEWHERE)));
        rows.push(("src/linked/a.rs", Err(RESOLVES_ELSEWHERE)));
    }
    // A long text is compared by its length, so a red row stays readable.
    let brief = |read: Result<String, &'static str>| {
        read.map(|text| {
            if text.len() > OK_SRC.len() {
                format!("{} bytes", text.len())
            } else {
                text
            }
        })
    };
    for (rel, want) in rows {
        assert_eq!(brief(open_source(root, rel)), brief(want), "{rel}");
    }
}

/// The walk is pinned to the listed source roots: a tracked `.rs` path under
/// any other directory is a problem and is never handed to [`open_source`].
#[test]
fn the_walk_opens_only_the_listed_source_roots_9616() {
    assert_eq!(
        SCANNED_ROOTS,
        [
            "src",
            "benches",
            "benchmarks/longmemeval_reflection",
            "examples",
            "fuzz",
            "loadtest",
            "tools",
        ]
    );
    let left_out: Vec<&str> = LEFT_OUT.iter().map(|(root, _)| *root).collect();
    assert_eq!(left_out, ["tests", "vendor"]);
    let inside = [
        "src/a.rs",
        "benches/b.rs",
        "benchmarks/longmemeval_reflection/runner.rs",
        "examples/e.rs",
        "fuzz/fuzz_targets/f.rs",
        "loadtest/src/main.rs",
        "tools/t/src/main.rs",
    ];
    let skipped = ["tests/a.rs", "vendor/v/src/lib.rs"];
    let outside = [
        "benchmarks/notes.rs",
        "benchmarks/other/src/main.rs",
        "srcx/a.rs",
        "src/../elsewhere/a.rs",
        "./src/a.rs",
        "/src/a.rs",
        "src//a.rs",
        "build.rs",
        "elsewhere/a.rs",
    ];
    let tracked: Vec<String> = inside
        .iter()
        .chain(&skipped)
        .chain(&outside)
        .map(|path| (*path).to_owned())
        .collect();
    let (open, problems) = plan(&tracked);
    assert_eq!(open, inside);
    assert_eq!(problems, outside.map(|path| format!("{path}: {NO_ROOT}")));
    // A scanned root with no tracked file is a problem, not a silent pass.
    let (open, problems) = plan(&["src/a.rs".to_owned()]);
    assert_eq!(open, ["src/a.rs"]);
    assert_eq!(
        problems,
        [
            "benches",
            "benchmarks/longmemeval_reflection",
            "examples",
            "fuzz",
            "loadtest",
            "tools",
        ]
        .map(|root| format!("{root}: {EMPTY_ROOT}"))
    );
}
