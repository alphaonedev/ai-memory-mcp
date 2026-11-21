// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9616 source ratchet: an ALLOWLIST over every tracked `.rs` file under
//! the listed source roots ([`SCANNED_ROOTS`]), refusing by default. It opens
//! no other file ([`open_source`]).
//!
//! Each scanned file is lexed (comments dropped, string and char literals
//! decoded, char literals and lifetimes told apart), every `concat!` call is
//! folded into the one literal the compiler makes of it, and literals that
//! follow one another with at most a comma between them are joined into one
//! run. Five counts are taken:
//!
//! * [`Class::HeaderName`]: the `HEADER_AGENT_ID` identifier, plus every
//!   literal run (plain, raw, byte, escaped, line-continued, `concat!`, an
//!   array of pieces or of chars) whose text holds `x-agent` in any case. An
//!   alias is counted at its `use` line.
//! * [`Class::Fragment`]: a literal run that holds `agent-id` in any case
//!   with neither `x-` nor `--` (a command-line flag) before it, plus one
//!   when runs of the file that hold neither needle can be put end to end to
//!   spell the name (pieces kept in separate constants).
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
//! directory cannot hide a read. A file that ends inside a comment, a string
//! or a char literal, or that cannot be read as a regular UTF-8 file at its
//! tracked path within the size cap, is an offender with its reason
//! (`<file>: <reason>`). One run lists every offender.
//!
//! What stays out of reach is a header name that code builds (at run time,
//! for example by `format!`, or in a `const fn`) from pieces that hold no
//! needle and do not tile the name within one file: pieces kept in two
//! files, a piece sliced out of a longer literal, and a further tiling in a
//! file whose row already grants one (the tile count is 0 or 1 per file;
//! `src/storage/mod.rs` has such a row). For the fold count, a refusal
//! discarded by a `match` arm is not seen either. The behaviour census in
//! the parent module pins every route for both.

use std::collections::BTreeMap;
use std::path::Path;

/// The counted construct classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    HeaderName,
    Resolver,
    Sentinel,
    Fold,
    Fragment,
}

impl Class {
    const ALL: [Self; 5] = [
        Self::HeaderName,
        Self::Resolver,
        Self::Sentinel,
        Self::Fold,
        Self::Fragment,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Fragment => "header-fragment",
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

use Class::{Fold, Fragment, HeaderName, Resolver, Sentinel};
use Grant::{AnyNonZero, Exactly};

/// Reason shared by the rows for a clap `long = "agent-id"` attribute.
const CLI_FLAG: &str = "clap long flag name `agent-id`: a command-line argument, never a header";

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
        Exactly(3),
        "outbound header writes on the forwarded request",
    ),
    allow(
        "src/mcp/tools/store/forward_key_9367_tests.rs",
        HeaderName,
        Exactly(4),
        "cfg(test): asserts the header line of the request the forward sites sent; reads no \
         inbound header",
    ),
    allow(
        "src/mcp/tools/store/forward_key_daemon_9367_tests.rs",
        HeaderName,
        Exactly(1),
        "cfg(test): writes the header on a raw loopback request; reads no inbound header",
    ),
    allow(
        "examples/fed_issue.rs",
        Fragment,
        Exactly(1),
        "help text about certificate subject ids (`subject-agent-ids`)",
    ),
    allow(
        "src/cli/commands/entity_register.rs",
        Fragment,
        Exactly(1),
        CLI_FLAG,
    ),
    allow("src/cli/commands/inbox.rs", Fragment, Exactly(1), CLI_FLAG),
    allow(
        "src/cli/commands/kg_invalidate.rs",
        Fragment,
        Exactly(1),
        CLI_FLAG,
    ),
    allow(
        "src/cli/commands/notify.rs",
        Fragment,
        Exactly(1),
        "clap long flag name `target-agent-id`: a command-line argument, never a header",
    ),
    allow(
        "src/cli/commands/reflect.rs",
        Fragment,
        Exactly(1),
        CLI_FLAG,
    ),
    allow("src/cli/commands/replay.rs", Fragment, Exactly(1), CLI_FLAG),
    allow(
        "src/cli/commands/swarm_rewind.rs",
        Fragment,
        Exactly(1),
        CLI_FLAG,
    ),
    allow(
        "src/cli/governance_check_action.rs",
        Fragment,
        Exactly(1),
        CLI_FLAG,
    ),
    allow("src/cli/wake_listen.rs", Fragment, Exactly(1), CLI_FLAG),
    allow(
        "src/handlers/agent_api_key.rs",
        Fragment,
        Exactly(1),
        "message text: the signed-approval grammar names `<approver-agent-id>`",
    ),
    allow(
        "src/handlers/identity_binding.rs",
        Fragment,
        Exactly(1),
        "message text: the `ai-memory agents bind-api-key <agent-id>` command line",
    ),
    allow(
        "src/mtls_agent_binding.rs",
        Fragment,
        Exactly(2),
        "the map-file grammar `<sha256-hex> <agent-id>`, in a constant and in one message",
    ),
    allow(
        "src/tls.rs",
        Fragment,
        Exactly(1),
        "message text: `(agent-id shape)` of a certificate subject",
    ),
    allow(
        "src/storage/mod.rs",
        Fragment,
        Exactly(1),
        "no literal holds a needle; unrelated short literals of this 35K-line file (`x`, `-`, \
         `agent`, `id`) tile the name. The tile count is at most one per file, so a second \
         tiling here is not told apart",
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

/// The explicit source roots the ratchet walks: tracked `.rs` files under
/// these directories are the only files it opens.
const SCANNED_ROOTS: &[&str] = &[
    "src",
    "benches",
    "benchmarks/longmemeval_reflection",
    "examples",
    "fuzz",
    "loadtest",
    "tools",
];

/// Tracked directories that hold `.rs` files and are not scanned, each with
/// its reason.
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
/// The hyphenated tail of the name. It is counted wherever neither
/// [`NAME_HEAD`] (the text is then a header name already) nor [`FLAG_HEAD`]
/// stands before it.
const FRAGMENT_NEEDLE: &str = "agent-id";
const NAME_HEAD: &str = "x-";
/// A command-line flag (`--agent-id`): no join puts two hyphens in the name.
const FLAG_HEAD: &str = "--";
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
/// The longest escape after its backslash, `u{10FFFF}`, in chars.
const MAX_UNICODE_ESCAPE: usize = 10;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Tok {
    Ident(String),
    Str(String),
    /// A char or byte-char literal, decoded.
    Chr(String),
    Punct(char),
}

/// Decode the escape whose first char after the backslash is at `i`, append
/// what it denotes and return the index past it. Bounded: no escape looks
/// further than [`MAX_UNICODE_ESCAPE`] chars ahead.
fn escape(b: &[char], i: usize, out: &mut String) -> usize {
    let scalar = |hex: &[char]| {
        let hex: String = hex.iter().collect();
        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
    };
    match b.get(i) {
        None => i,
        Some('n') => {
            out.push('\n');
            i + 1
        }
        Some('t') => {
            out.push('\t');
            i + 1
        }
        Some('r') => {
            out.push('\r');
            i + 1
        }
        Some('0') => {
            out.push('\0');
            i + 1
        }
        Some('\n') => {
            let mut j = i + 1;
            while b.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            j
        }
        Some('x') => {
            let end = (i + 3).min(b.len());
            out.extend(scalar(&b[i + 1..end]));
            end
        }
        Some('u') => {
            let close = b[i..]
                .iter()
                .take(MAX_UNICODE_ESCAPE)
                .position(|&c| c == '}')
                .map(|p| i + p);
            match close {
                Some(close) if b.get(i + 1) == Some(&'{') => {
                    out.extend(scalar(&b[i + 2..close]));
                    close + 1
                }
                _ => i + 1,
            }
        }
        Some(&other) => {
            out.push(other);
            i + 1
        }
    }
}

/// Decode a non-raw string literal body starting at `i` (just past the
/// opening quote). Returns the text and the index past the closing quote.
fn cooked_string(b: &[char], mut i: usize) -> Result<(String, usize), &'static str> {
    let mut out = String::new();
    while let Some(&c) = b.get(i) {
        match c {
            '"' => return Ok((out, i + 1)),
            '\\' => i = escape(b, i + 1, &mut out),
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Err(UNTERMINATED_STRING)
}

/// A raw string body from `i` up to `"` followed by `hashes` `#`.
fn raw_string(b: &[char], mut i: usize, hashes: usize) -> Result<(String, usize), &'static str> {
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
            return Ok((b[start..i].iter().collect(), i + 1 + hashes));
        }
        i += 1;
    }
    Err(UNTERMINATED_RAW_STRING)
}

/// The char literal opening at the quote at `i`: its decoded text and the
/// index past its closing quote, or `None` for a lifetime.
fn char_literal(b: &[char], i: usize) -> Result<Option<(String, usize)>, &'static str> {
    if b.get(i + 1) == Some(&'\\') {
        let mut text = String::new();
        let j = escape(b, i + 2, &mut text);
        return if b.get(j) == Some(&'\'') {
            Ok(Some((text, j + 1)))
        } else {
            Err(UNTERMINATED_CHAR)
        };
    }
    Ok(match (b.get(i + 1), b.get(i + 2)) {
        (Some(c), Some('\'')) => Some((c.to_string(), i + 3)),
        _ => None,
    })
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The tokens of `src`, or the reason the file ends in an open state. A file
/// never ends silently inside a comment, a string or a char literal.
pub(super) fn lex(src: &str) -> Result<Vec<Tok>, &'static str> {
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
            let mut depth = 1usize;
            i += 2;
            while depth > 0 {
                match (chars.get(i), chars.get(i + 1)) {
                    (None, _) => return Err(UNTERMINATED_BLOCK_COMMENT),
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        i += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
        } else if ch == '"' {
            let (text, j) = cooked_string(&chars, i + 1)?;
            out.push(Tok::Str(text));
            i = j;
        } else if ch == '\'' {
            if let Some((text, j)) = char_literal(&chars, i)? {
                out.push(Tok::Chr(text));
                i = j;
            } else {
                i += 1;
            }
        } else if ch.is_alphabetic() || ch == '_' {
            let start = i;
            while i < len && is_ident_char(chars[i]) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let next = chars.get(i).copied();
            match (word.as_str(), next) {
                ("b" | "c", Some('"')) => {
                    let (text, j) = cooked_string(&chars, i + 1)?;
                    out.push(Tok::Str(text));
                    i = j;
                }
                ("b", Some('\'')) => {
                    if let Some((text, j)) = char_literal(&chars, i)? {
                        out.push(Tok::Chr(text));
                        i = j;
                    } else {
                        out.push(Tok::Ident(word));
                    }
                }
                ("r" | "br" | "cr", Some('"' | '#')) => {
                    let mut j = i;
                    while j < len && chars[j] == '#' {
                        j += 1;
                    }
                    let hashes = j - i;
                    if chars.get(j) == Some(&'"') {
                        if hashes > MAX_RAW_HASHES {
                            return Err(TOO_MANY_RAW_HASHES);
                        }
                        let (text, k) = raw_string(&chars, j + 1, hashes)?;
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
    Ok(out)
}

/// Replace every `concat!` call (any bracket, nested calls included) by one
/// `Str` token holding its arguments joined, as the compiler joins them. An
/// identifier that is not a macro name and any other punctuation are kept as
/// text, so `stringify!` arguments join too.
fn fold_concat(toks: &[Tok]) -> Vec<Tok> {
    let mut out = Vec::with_capacity(toks.len());
    let mut k = 0;
    while k < toks.len() {
        let opens = matches!(&toks[k], Tok::Ident(name) if name == "concat")
            && toks.get(k + 1) == Some(&Tok::Punct('!'))
            && matches!(toks.get(k + 2), Some(Tok::Punct('(' | '[' | '{')));
        if !opens {
            out.push(toks[k].clone());
            k += 1;
            continue;
        }
        let mut depth = 0usize;
        let mut text = String::new();
        let mut j = k + 2;
        while let Some(tok) = toks.get(j) {
            match tok {
                Tok::Punct('(' | '[' | '{') => depth += 1,
                Tok::Punct(')' | ']' | '}') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Tok::Punct(',' | '!') => {}
                Tok::Punct(c) => text.push(*c),
                Tok::Str(s) | Tok::Chr(s) => text.push_str(s),
                Tok::Ident(name) => {
                    if toks.get(j + 1) != Some(&Tok::Punct('!')) {
                        text.push_str(name);
                    }
                }
            }
            j += 1;
        }
        out.push(Tok::Str(text));
        k = j + 1;
    }
    out
}

/// The joined text of every run of string and char literals that follow one
/// another with at most one comma between them (array rows, call and macro
/// arguments). A literal on its own is a run of one.
fn literal_runs(toks: &[Tok]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut k = 0;
    while k < toks.len() {
        let (Tok::Str(first) | Tok::Chr(first)) = &toks[k] else {
            k += 1;
            continue;
        };
        let mut text = first.clone();
        k += 1;
        loop {
            let comma = usize::from(toks.get(k) == Some(&Tok::Punct(',')));
            let Some(Tok::Str(next) | Tok::Chr(next)) = toks.get(k + comma) else {
                break;
            };
            text.push_str(next);
            k += comma + 1;
        }
        runs.push(text);
    }
    runs
}

/// Whether literal runs of one file, none of which holds a needle, can be
/// put end to end to hold the header name: a first one ending with the head
/// of the name, any number equal to a middle slice, a last one starting with
/// the rest. Catches fragments that are not adjacent (separate constants, a
/// macro that expands to one piece).
fn runs_tile_the_name(runs: &[String]) -> bool {
    let n = HEADER_NAME.len();
    let mut head = vec![false; n + 1];
    let mut tail = vec![false; n + 1];
    let mut middle = vec![vec![false; n + 1]; n + 1];
    for lower in runs {
        if lower.contains(HEADER_NEEDLE) || lower.contains(FRAGMENT_NEEDLE) {
            continue;
        }
        for cut in 1..n {
            head[cut] |= lower.ends_with(&HEADER_NAME[..cut]);
            tail[cut] |= lower.starts_with(&HEADER_NAME[cut..]);
            for from in 1..cut {
                middle[from][cut] |= lower == &HEADER_NAME[from..cut];
            }
        }
    }
    let mut reach = head;
    for cut in 1..n {
        reach[cut] = reach[cut] || (1..cut).any(|from| reach[from] && middle[from][cut]);
    }
    (1..n).any(|cut| reach[cut] && tail[cut])
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

/// The count of each class in `src`, or the reason the file is refused whole.
fn counts(src: &str) -> Result<BTreeMap<Class, usize>, &'static str> {
    let toks = fold_concat(&lex(src)?);
    let mut out: BTreeMap<Class, usize> = Class::ALL.iter().map(|&c| (c, 0)).collect();
    let mut add = |class, n: usize| *out.entry(class).or_default() += n;
    for (k, tok) in toks.iter().enumerate() {
        let Tok::Ident(name) = tok else { continue };
        match name.as_str() {
            "HEADER_AGENT_ID" => add(HeaderName, 1),
            "ANONYMOUS_INVALID" => add(Sentinel, 1),
            "resolve_http_agent_id" => add(Resolver, 1),
            _ => {}
        }
        if FUNNEL_CALLS.contains(&name.as_str())
            && toks.get(k + 1) == Some(&Tok::Punct('('))
            && close_paren(&toks, k + 1).is_some_and(|close| chain_folds(&toks, close))
        {
            add(Fold, 1);
        }
    }
    let runs: Vec<String> = literal_runs(&toks)
        .iter()
        .map(|run| run.to_lowercase())
        .collect();
    for lower in &runs {
        add(HeaderName, lower.matches(HEADER_NEEDLE).count());
        add(Sentinel, lower.matches(SENTINEL_NEEDLE).count());
        // `at` is the start of an ASCII match, so the cut is a char boundary.
        let bare = lower
            .match_indices(FRAGMENT_NEEDLE)
            .filter(|(at, _)| {
                let before = &lower[..*at];
                !before.ends_with(NAME_HEAD) && !before.ends_with(FLAG_HEAD)
            })
            .count();
        add(Fragment, bare);
    }
    add(Fragment, usize::from(runs_tile_the_name(&runs)));
    Ok(out)
}

/// A scanned file: its repo-relative path and its source, or the reason it
/// could not be read.
type Scanned = (String, Result<String, &'static str>);

/// The offenders among `files`, sorted.
fn offenders(files: &[Scanned]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, read) in files {
        let counted = match read {
            Ok(src) => counts(src),
            Err(reason) => Err(*reason),
        };
        let counted = match counted {
            Ok(counted) => counted,
            Err(reason) => {
                found.push(format!("{path}: {reason}"));
                continue;
            }
        };
        for (class, n) in counted {
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

/// Whether `path` is inside the directory `root` (whole path components).
fn under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Where a repo-relative path stands for the walk.
#[derive(Debug, PartialEq)]
enum Place {
    Scanned,
    LeftOut,
    Unknown,
}

/// A path is scanned only when it is a `.rs` file under a scanned root and
/// has no empty, `.` or `..` component (so no absolute and no climbing path).
fn place(path: &str) -> Place {
    let plain = path
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..");
    // Case-sensitive on purpose: the walk lists `*.rs`, the form cargo builds.
    let rust = Path::new(path).extension().is_some_and(|ext| ext == "rs");
    if !plain || !rust {
        Place::Unknown
    } else if SCANNED_ROOTS.iter().any(|root| under(path, root)) {
        Place::Scanned
    } else if LEFT_OUT.iter().any(|(root, _)| under(path, root)) {
        Place::LeftOut
    } else {
        Place::Unknown
    }
}

/// The walk over the tracked `.rs` paths: the paths to open, and a problem
/// for every path under no listed root and every scanned root that is empty.
fn plan(tracked: &[String]) -> (Vec<String>, Vec<String>) {
    let mut open = Vec::new();
    let mut problems = Vec::new();
    for path in tracked {
        match place(path) {
            Place::Scanned => open.push(path.clone()),
            Place::LeftOut => {}
            Place::Unknown => problems.push(format!("{path}: {NO_ROOT}")),
        }
    }
    for root in SCANNED_ROOTS {
        if !open.iter().any(|path| under(path, root)) {
            problems.push(format!("{root}: {EMPTY_ROOT}"));
        }
    }
    (open, problems)
}

/// The one place the ratchet opens a file. It refuses every path that is not
/// a `.rs` file under a scanned root before touching the file system, then a
/// path that a symlink leads away from its tracked place, then (on the opened
/// descriptor) anything that is not a regular UTF-8 file within the size cap.
fn open_source(root: &Path, rel: &str) -> Result<String, &'static str> {
    use std::io::Read as _;
    if place(rel) != Place::Scanned {
        return Err(OUTSIDE_ROOTS);
    }
    let tracked = root.canonicalize().map_err(|_| UNREADABLE)?.join(rel);
    let resolved = root.join(rel).canonicalize().map_err(|_| UNREADABLE)?;
    if resolved != tracked {
        return Err(RESOLVES_ELSEWHERE);
    }
    let file = std::fs::File::open(&resolved).map_err(|_| UNREADABLE)?;
    if !file.metadata().map_err(|_| UNREADABLE)?.is_file() {
        return Err(NOT_REGULAR);
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UNREADABLE)?;
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_SOURCE_BYTES) {
        return Err(TOO_LARGE);
    }
    String::from_utf8(bytes).map_err(|_| NOT_UTF8)
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
/// what [`ALLOW`] grants, every tracked `.rs` file is under a scanned or a
/// left-out root, and every file is opened through [`open_source`].
#[test]
fn every_agent_id_site_in_the_tree_is_allow_listed_9616() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (open, mut problems) = plan(&tracked_rs(root));
    let files: Vec<Scanned> = open
        .into_iter()
        .map(|path| {
            let read = open_source(root, &path);
            (path, read)
        })
        .collect();
    for (left, reason) in LEFT_OUT {
        assert!(
            root.join(left).is_dir(),
            "left-out root {left} is gone ({reason})"
        );
    }
    problems.extend(offenders(&files));
    assert_eq!(problems, Vec::<String>::new());
}

/// The offenders of one file read as `read`, without the stale-row check
/// (the corpus is one file).
fn one_read(path: &str, read: Result<String, &'static str>) -> Vec<String> {
    offenders(&[(path.to_owned(), read)])
        .into_iter()
        .filter(|line| !line.contains("names no scanned file"))
        .collect()
}

fn one(path: &str, src: &str) -> Vec<String> {
    one_read(path, Ok(src.to_owned()))
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
    // A second read in an allow-listed file breaks its exact count, and a
    // row whose sites are gone (here the grammar text) is an offender too.
    assert_eq!(
        one("src/mtls_agent_binding.rs", VERDICT_GET_REF),
        vec![
            "src/mtls_agent_binding.rs: header-fragment 0 (allowed 2)".to_owned(),
            "src/mtls_agent_binding.rs: header-name 1 (allowed 4)".to_owned(),
        ]
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
    let n = counts(&src).expect("the source ends in no open state")[&HeaderName];
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
