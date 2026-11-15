// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4193 (WP-EGRESS #6053, PR #9311 round 1) — CLASS guard: every non-test
//! `reqwest` client construction in `src/**/*.rs` is either built by
//! `egress_policy::inference_client_builder()` or is on ONE named allowlist
//! ([`ALLOWLIST`]) with a reason per entry.
//!
//! The structural cell of `tests/inference_egress_proxy_redirect_4193.rs`
//! pins the four `[llm]` constructors by name; it proves the fixed sites
//! only. A new default `reqwest` client anywhere else (the round-1 mutation:
//! a stray `reqwest::Client::builder()` probing `{base}/api/tags` from
//! `src/egress.rs`) left every behavioural cell green. This cell walks the
//! whole source tree instead, so the class itself is guarded.
//!
//! Forms this guard recognises (it pins exactly these, it does not claim
//! completeness over every Rust spelling):
//! * a construction form is matched on the PATH, with or without a call
//!   (`reqwest::Client::builder` passed as a fn value counts), and a
//!   renaming import of a construction item (`use reqwest::Client as H`,
//!   `use reqwest::get`) is a finding of its own;
//!
//! Forms this guard does NOT recognise (latent: no such site exists in
//! `src/` today; tracked: #9314, the egress lane owes one red-first probe row
//! each, <https://github.com/alphaonedev/ai-memory-mcp/issues/9314#issuecomment-6892371185>):
//! * a typed `Default::default()` that returns a client;
//! * a crate alias `use reqwest as X;` followed by `X::get(..)`;
//! * UFCS `<reqwest::Client as Default>::default()`.
//!
//! Within the recognised forms the guard is fail-closed:
//! * only code that is test-only in EVERY build is skipped: an item or
//!   statement under `#[cfg(test)]` / `#[cfg(all(test, ..))]`, a file
//!   declared `#[cfg(test)] mod x;` (and the files below it), and a file
//!   whose depth-0 inner attribute is `#![cfg(test)]`. `#[cfg(any(test,
//!   ..))]` and `#[cfg(not(test))]` are production; a file no declaration
//!   reaches is production;
//! * an unlisted site, a stale allowlist entry (no site left) and a count
//!   drift on a listed function are each a finding;
//! * a walk that saw fewer than [`MIN_SRC_FILES`] files fails, so an empty
//!   or mis-rooted walk can never pass.
//!
//! The scanner blanks comments, string / raw-string / char literals before
//! matching (byte offsets and line numbers preserved), so prose that names a
//! constructor is never a site and a brace inside a literal never moves the
//! item boundaries. One pass, no backtracking: linear in the input, pinned
//! by the [`LARGE_INPUT_BYTES`] / [`LARGE_INPUT_CEILING`] cell.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One allowlisted production construction site.
struct Allowed {
    /// Path relative to the crate root, `/`-separated.
    file: &'static str,
    /// Innermost enclosing `fn` name (`<module>` outside any fn).
    func: &'static str,
    /// Exact number of construction sites in that fn (drift is a finding).
    count: usize,
    /// Why the site is not an unrouted inference client. Starts with one of
    /// [`REASON_CLASSES`].
    reason: &'static str,
    /// What the client carries to the remote: `none`, or which credential
    /// and which data (X-10). Never empty.
    credential: &'static str,
    /// Redirect policy, read from the fn body and checked against it.
    redirect: Redirect,
    /// Env-proxy behaviour, read from the fn body and checked against it.
    proxy: Proxy,
}

/// Redirect policy of a construction site's fn body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redirect {
    /// No `.redirect(..)`: reqwest follows up to 10 hops.
    DefaultFollow,
    /// `Policy::none()`.
    Refused,
    /// `Policy::limited(..)`.
    Limited,
    /// Set per posture by the policy itself (`policy-routed:` entries only).
    PostureDependent,
    /// Observed only: a `.redirect(..)` this scanner cannot classify, or
    /// more than one policy in one body. Never matches a declaration.
    Unclassified,
}

/// Env-proxy behaviour of a construction site's fn body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proxy {
    /// `.no_proxy()`.
    Disabled,
    /// Neither `.no_proxy()` nor `.proxy(..)`: reqwest honours the env vars.
    HonoursEnv,
    /// Set per posture by the policy itself (`policy-routed:` entries only).
    PostureDependent,
    /// Observed only: an explicit `.proxy(..)`, or both forms in one body.
    Unclassified,
}

impl Redirect {
    fn as_str(self) -> &'static str {
        match self {
            Self::DefaultFollow => "default-follow",
            Self::Refused => "none",
            Self::Limited => "limited",
            Self::PostureDependent => "posture-dependent",
            Self::Unclassified => "unclassified",
        }
    }
}

impl Proxy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "no_proxy",
            Self::HonoursEnv => "honours-env",
            Self::PostureDependent => "posture-dependent",
            Self::Unclassified => "unclassified",
        }
    }
}

/// Read the redirect and proxy facts from one fn body (comments and
/// literals already blanked, so prose naming a policy never counts).
fn body_facts(body: &[u8]) -> (Redirect, Proxy) {
    let compact: String = body
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|&b| char::from(b))
        .collect();
    let none = compact.contains("Policy::none()");
    let limited = compact.contains("Policy::limited(");
    let any_redirect = compact.contains(".redirect(");
    let redirect = match (none, limited, any_redirect) {
        (false, false, false) => Redirect::DefaultFollow,
        (true, false, true) => Redirect::Refused,
        (false, true, true) => Redirect::Limited,
        _ => Redirect::Unclassified,
    };
    let no_proxy = compact.contains(".no_proxy()");
    let explicit = compact.contains(".proxy(");
    let proxy = match (no_proxy, explicit) {
        (true, false) => Proxy::Disabled,
        (false, false) => Proxy::HonoursEnv,
        _ => Proxy::Unclassified,
    };
    (redirect, proxy)
}

/// The reason classes an allowlist entry may carry.
const REASON_CLASSES: [&str; 3] = ["non-inference:", "policy-routed:", "tracked #"];

/// Every production `reqwest` construction site that is not built by
/// `inference_client_builder()`. Seeded from the PR #9311 round-1 security
/// verdict; its test-only entries (`daemon_runtime.rs` serve test,
/// `test_support.rs`, `url_display.rs` test) are skipped by the scanner as
/// `cfg(test)` code, so listing them would be a stale entry.
const ALLOWLIST: [Allowed; 10] = [
    Allowed {
        file: "src/llm/egress_policy.rs",
        func: "inference_client_builder",
        count: 1,
        reason: "policy-routed: the composition point itself; every [llm] OllamaClient constructor and both model pulls build through it; restricted postures refuse redirects and env proxies, the allow posture is tracked #9314",
        credential: "provider bearer (when configured) + prompts and memory content",
        redirect: Redirect::PostureDependent,
        proxy: Proxy::PostureDependent,
    },
    Allowed {
        file: "src/subscriptions.rs",
        func: "prewarm_dispatch_tls",
        count: 1,
        reason: "non-inference: webhook TLS warm-up; builds a blocking client only (src/subscriptions.rs:1578-1584), sends no request and opens no connection",
        credential: "none",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::Disabled,
    },
    Allowed {
        file: "src/subscriptions.rs",
        func: "send",
        count: 1,
        reason: "non-inference: webhook dispatch; SSRF address pin, no_proxy and Policy::none (#6053)",
        credential: "HMAC signature header + event body",
        redirect: Redirect::Refused,
        proxy: Proxy::Disabled,
    },
    Allowed {
        file: "src/daemon_runtime.rs",
        func: "run_sync_daemon_with_shutdown",
        count: 1,
        reason: "non-inference: sync daemon peer client (not an LLM endpoint); default redirect and env-proxy behaviour tracked #9318",
        credential: "x-api-key + memory rows",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/federation/peer.rs",
        func: "build",
        count: 1,
        reason: "non-inference: federation peer client; Policy::none, missing no_proxy tracked #9315",
        credential: "mTLS identity + api key + memory rows",
        redirect: Redirect::Refused,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/mcp/tools/store/transport.rs",
        func: "forward_to_http",
        count: 1,
        reason: "non-inference: remote store transport (memory_store forwarding to a daemon); default redirect and env-proxy behaviour tracked #9318",
        credential: "X-Agent-Id principal header + memory body",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/cli/doctor.rs",
        func: "section_llm_reachability_from_resolved",
        count: 1,
        reason: "tracked #6222 / #8191: doctor LLM reachability probe builds its own client",
        credential: "LLM provider bearer",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/cli/doctor.rs",
        func: "section_embeddings_reachability_1598",
        count: 1,
        reason: "tracked #6222 / #8191: doctor embeddings reachability probe builds its own client",
        credential: "embeddings provider bearer",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/cli/doctor.rs",
        func: "http_get_json",
        count: 1,
        reason: "non-inference: doctor remote daemon JSON fetch (no inference bearer); default redirect and env-proxy behaviour tracked #9318",
        credential: "x-api-key + optional mTLS identity",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
    Allowed {
        file: "src/cli/sync.rs",
        func: "build_sync_client",
        count: 1,
        reason: "non-inference: sync CLI peer client; default redirect and env-proxy behaviour tracked #9318",
        credential: "optional mTLS identity; the sync loop adds x-api-key + memory rows per request",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    },
];

/// Floor on the number of `.rs` files the walk must see.
const MIN_SRC_FILES: usize = 200;

/// Wall-clock ceiling for the whole-tree walk (read + scan + classify).
const WALK_CEILING: Duration = Duration::from_secs(30);

/// Size of the synthetic input of the linear-time bound cell.
const LARGE_INPUT_BYTES: usize = 400_000;

/// Wall-clock ceiling for scanning [`LARGE_INPUT_BYTES`].
const LARGE_INPUT_CEILING: Duration = Duration::from_secs(3);

// ─── Lexer: blank comments and literals, keep offsets ───────────────────

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// Byte length of the UTF-8 char starting with `lead`.
fn utf8_len(lead: u8) -> usize {
    match lead {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

fn blank_range(out: &mut [u8], from: usize, to: usize) {
    for b in &mut out[from..to] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// Replace every comment and the CONTENT of every string, raw-string and
/// char literal with spaces (newlines kept), so later passes see only code.
/// A literal's delimiters are blanked too; offsets are unchanged.
fn blank_non_code(src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    let len = src.len();
    let mut i = 0;
    while i < len {
        let byte = src[i];
        let next = src.get(i + 1).copied();
        if byte == b'/' && next == Some(b'/') {
            let end = src[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(len, |p| i + p);
            blank_range(&mut out, i, end);
            i = end;
        } else if byte == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            let mut j = i;
            while j < len {
                if src[j] == b'/' && src.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if src[j] == b'*' && src.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank_range(&mut out, i, j.min(len));
            i = j;
        } else if byte == b'r' && (i == 0 || !is_ident_byte(src[i - 1]) || raw_prefix(src, i)) {
            // Raw string `r"…"` / `r#"…"#` (also after `byte` / `c`); `r#ident`
            // (raw identifier) has no quote after the hashes and is code.
            let mut j = i + 1;
            while j < len && src[j] == b'#' {
                j += 1;
            }
            if j < len && src[j] == b'"' {
                let hashes = j - i - 1;
                let mut k = j + 1;
                let end = loop {
                    if k >= len {
                        break len;
                    }
                    if src[k] == b'"'
                        && src[k + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|&&c| c == b'#')
                            .count()
                            == hashes
                    {
                        break (k + 1 + hashes).min(len);
                    }
                    k += 1;
                };
                blank_range(&mut out, i, end);
                i = end;
            } else {
                i += 1;
            }
        } else if byte == b'"' {
            let mut j = i + 1;
            while j < len && src[j] != b'"' {
                j += if src[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(len);
            blank_range(&mut out, i, end);
            i = end;
        } else if byte == b'\'' {
            // Char literal or lifetime / label.
            if next == Some(b'\\') {
                let mut j = i + 2;
                while j < len && src[j] != b'\'' {
                    j += if src[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(len);
                blank_range(&mut out, i, end);
                i = end;
            } else if let Some(lead) = next {
                let close = i + 1 + utf8_len(lead);
                if src.get(close) == Some(&b'\'') {
                    blank_range(&mut out, i, close + 1);
                    i = close + 1;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// `br"…"` / `cr"…"`: the `r` follows a one-letter literal prefix.
fn raw_prefix(src: &[u8], r_at: usize) -> bool {
    r_at >= 1
        && matches!(src[r_at - 1], b'b' | b'c')
        && (r_at == 1 || !is_ident_byte(src[r_at - 2]))
}

// ─── Scanner: sites, test-only regions, module declarations ─────────────

/// A production construction site.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    line: usize,
    func: String,
    form: String,
    /// Byte offset of the `{` of the innermost enclosing fn body (the key
    /// into [`FileScan::fn_facts`]); `None` outside any fn.
    fn_at: Option<usize>,
}

/// One brace frame of the scan.
struct Frame {
    /// `Some((fn name, offset of its `{`))` for a fn body.
    func: Option<(String, usize)>,
    /// A site was found directly in this fn (its facts are read at `}`).
    has_site: bool,
}

/// An out-of-line `mod name;` declaration.
#[derive(Debug, Clone)]
struct ModDecl {
    name: String,
    path_attr: Option<String>,
    gated: bool,
}

#[derive(Debug, Default)]
struct FileScan {
    sites: Vec<Site>,
    mods: Vec<ModDecl>,
    file_test_only: bool,
    /// Redirect / proxy facts of every fn body that holds a site, keyed by
    /// the offset of the body's `{`. A body is read once, at its `}`.
    fn_facts: BTreeMap<usize, (Redirect, Proxy)>,
}

fn skip_ws(code: &[u8], mut i: usize) -> usize {
    while i < code.len() && code[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn read_ident(code: &[u8], i: usize) -> Option<(String, usize)> {
    if i >= code.len() || !is_ident_byte(code[i]) || code[i].is_ascii_digit() {
        return None;
    }
    let mut j = i;
    while j < code.len() && is_ident_byte(code[j]) {
        j += 1;
    }
    let mut word = String::from_utf8_lossy(&code[i..j]).into_owned();
    // Raw identifier `r#name`.
    if word == "r"
        && code.get(j) == Some(&b'#')
        && let Some((rest, k)) = read_ident(code, j + 1)
    {
        word = rest;
        j = k;
    }
    Some((word, j))
}

/// Index one past the `]` that closes the `[` at `open`.
fn close_bracket(code: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, &b) in code.iter().enumerate().skip(open) {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Split `a, b(c, d), e` at depth-0 commas.
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// `cfg(test)` or `cfg(all(.., test, ..))`: test-only in every build.
fn is_test_only_cfg(attr_body: &str) -> bool {
    let compact: String = attr_body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact == "cfg(test)" {
        return true;
    }
    compact
        .strip_prefix("cfg(all(")
        .and_then(|rest| rest.strip_suffix("))"))
        .is_some_and(|inner| split_top_level(inner).iter().any(|p| p == "test"))
}

/// End of the item or statement that starts at `i` (after its attributes):
/// a `let` / expression statement ends at its depth-0 `;`; an item ends at
/// its depth-0 `;` or at the `}` that closes its first depth-0 `{`.
fn item_end(code: &[u8], i: usize) -> usize {
    let is_let = read_ident(code, i).is_some_and(|(w, _)| w == "let");
    let mut depth = 0usize;
    for (k, &b) in code.iter().enumerate().skip(i) {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                if depth == 0 {
                    // Closing an enclosing block: the item ended before it.
                    return k;
                }
                depth -= 1;
                if depth == 0 && b == b'}' && !is_let {
                    return k + 1;
                }
            }
            b';' if depth == 0 => return k + 1,
            _ => {}
        }
    }
    code.len()
}

/// Skip `#[..]` attributes from `i`; return the first non-attribute index
/// and the `#[path = "…"]` value if one was among them (read from `raw`).
fn skip_attrs(code: &[u8], raw: &[u8], mut i: usize) -> (usize, Option<String>) {
    let mut path_attr = None;
    loop {
        i = skip_ws(code, i);
        if code.get(i) == Some(&b'#') && code.get(i + 1) == Some(&b'[') {
            let end = close_bracket(code, i + 1);
            let raw_attr = String::from_utf8_lossy(&raw[i + 2..end.saturating_sub(1)]).into_owned();
            if let Some(p) = path_attr_value(&raw_attr) {
                path_attr = Some(p);
            }
            i = end;
        } else {
            return (i, path_attr);
        }
    }
}

fn path_attr_value(raw_attr: &str) -> Option<String> {
    let rest = raw_attr
        .trim()
        .strip_prefix("path")?
        .trim_start()
        .strip_prefix('=')?;
    let rest = rest.trim();
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

/// If `mod <name> ;` starts at `i` (after `pub` / `pub(..)`), return it.
fn out_of_line_mod(code: &[u8], mut i: usize) -> Option<String> {
    let (mut word, mut j) = read_ident(code, i)?;
    if word == "pub" {
        i = skip_ws(code, j);
        if code.get(i) == Some(&b'(') {
            i = code[i..]
                .iter()
                .position(|&c| c == b')')
                .map(|p| i + p + 1)?;
        }
        (word, j) = read_ident(code, skip_ws(code, i))?;
    }
    if word != "mod" {
        return None;
    }
    let (name, k) = read_ident(code, skip_ws(code, j))?;
    (code.get(skip_ws(code, k)) == Some(&b';')).then_some(name)
}

/// The construction form named by `segments`, if it is one.
fn construction_form(segments: &[String]) -> Option<String> {
    let n = segments.len();
    let last = segments.last()?.as_str();
    let prev = if n >= 2 { segments[n - 2].as_str() } else { "" };
    let hit = matches!(
        (prev, last),
        ("Client", "builder" | "new" | "default") | ("ClientBuilder", "new" | "default")
    ) || (last == "get"
        && segments.first().is_some_and(|s| s == "reqwest")
        && (n == 2 || (n == 3 && segments[1] == "blocking")));
    hit.then(|| segments.join("::"))
}

/// Byte offset of the start of every line (index 0 = line 1).
fn line_starts(code: &[u8]) -> Vec<usize> {
    std::iter::once(0)
        .chain(
            code.iter()
                .enumerate()
                .filter(|(_, b)| **b == b'\n')
                .map(|(k, _)| k + 1),
        )
        .collect()
}

/// 1-based line of byte `at` (binary search: the scan stays linear).
fn line_of(starts: &[usize], at: usize) -> usize {
    starts.partition_point(|&s| s <= at)
}

/// A `use` tree that renames or imports a construction item of `reqwest`.
fn alias_form(use_tree: &str) -> Option<String> {
    let compact: String = use_tree.split_whitespace().collect::<Vec<_>>().join(" ");
    if !compact.contains("reqwest") {
        return None;
    }
    let renames = ["Client as ", "ClientBuilder as "]
        .iter()
        .any(|p| compact.contains(p));
    let imports_get = compact
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "get");
    (renames || imports_get).then(|| format!("use {}", compact.trim()))
}

/// Scan one file. `raw` is the original text (for `#[path]` values).
fn scan_file(raw: &str) -> FileScan {
    let raw = raw.as_bytes();
    let code = blank_non_code(raw);
    let starts = line_starts(&code);
    let mut scan = FileScan::default();
    let mut frames: Vec<Frame> = Vec::new();
    let mut pending_fn: Option<String> = None;
    let mut i = 0;
    let len = code.len();
    while i < len {
        let byte = code[i];
        if byte == b'#' {
            let inner = code.get(i + 1) == Some(&b'!');
            let open = if inner { i + 2 } else { i + 1 };
            if code.get(open) == Some(&b'[') {
                let end = close_bracket(&code, open);
                let body =
                    String::from_utf8_lossy(&code[open + 1..end.saturating_sub(1)]).into_owned();
                if is_test_only_cfg(&body) {
                    if inner {
                        if frames.is_empty() {
                            scan.file_test_only = true;
                            return scan;
                        }
                        // Inner cfg(test) inside a block: not modelled, so
                        // the block stays production (fail-closed).
                        i = end;
                        continue;
                    }
                    let (item_at, path_attr) = skip_attrs(&code, raw, end);
                    if let Some(name) = out_of_line_mod(&code, item_at) {
                        scan.mods.push(ModDecl {
                            name,
                            path_attr,
                            gated: true,
                        });
                    }
                    i = item_end(&code, item_at);
                    continue;
                }
                if !inner {
                    // A non-test attribute: an out-of-line mod may follow it
                    // with a `#[path]`; let the mod branch below see it.
                    let (item_at, path_attr) = skip_attrs(&code, raw, i);
                    if let Some(name) = out_of_line_mod(&code, item_at) {
                        scan.mods.push(ModDecl {
                            name,
                            path_attr,
                            gated: false,
                        });
                        i = item_end(&code, item_at);
                        continue;
                    }
                }
                i = end;
                continue;
            }
            i += 1;
            continue;
        }
        match byte {
            b'{' => {
                frames.push(Frame {
                    func: pending_fn.take().map(|name| (name, i)),
                    has_site: false,
                });
                i += 1;
                continue;
            }
            b'}' => {
                if let Some(Frame {
                    func: Some((_, open)),
                    has_site: true,
                }) = frames.pop()
                {
                    scan.fn_facts.insert(open, body_facts(&code[open..=i]));
                }
                i += 1;
                continue;
            }
            b';' => {
                pending_fn = None;
                i += 1;
                continue;
            }
            _ => {}
        }
        if is_ident_byte(byte) && (i == 0 || !is_ident_byte(code[i - 1])) {
            if let Some(name) = out_of_line_mod(&code, i) {
                scan.mods.push(ModDecl {
                    name,
                    path_attr: None,
                    gated: false,
                });
                i = item_end(&code, i);
                continue;
            }
            let Some((word, after)) = read_ident(&code, i) else {
                i += 1;
                continue;
            };
            if word == "fn"
                && let Some((name, k)) = read_ident(&code, skip_ws(&code, after))
            {
                pending_fn = Some(name);
                i = k;
                continue;
            }
            if word == "use" {
                let end = item_end(&code, i);
                let tree = String::from_utf8_lossy(&code[after..end])
                    .trim_end_matches(';')
                    .to_string();
                if let Some(form) = alias_form(&tree) {
                    let (func, fn_at) = enclosing_fn(&mut frames);
                    scan.sites.push(Site {
                        line: line_of(&starts, i),
                        func,
                        form,
                        fn_at,
                    });
                }
                i = end;
                continue;
            }
            // A path `a::byte::c` (whitespace allowed around `::`).
            let mut segments = vec![word];
            let mut j = after;
            loop {
                let k = skip_ws(&code, j);
                if code.get(k) == Some(&b':')
                    && code.get(k + 1) == Some(&b':')
                    && let Some((seg, seg_end)) = read_ident(&code, skip_ws(&code, k + 2))
                {
                    segments.push(seg);
                    j = seg_end;
                    continue;
                }
                break;
            }
            if let Some(form) = construction_form(&segments) {
                let (func, fn_at) = enclosing_fn(&mut frames);
                scan.sites.push(Site {
                    line: line_of(&starts, i),
                    func,
                    form,
                    fn_at,
                });
            }
            i = j;
            continue;
        }
        i += 1;
    }
    scan
}

/// Innermost enclosing fn name and body offset; marks that frame so its
/// facts are read when its `}` is reached.
fn enclosing_fn(frames: &mut [Frame]) -> (String, Option<usize>) {
    match frames.iter_mut().rev().find(|f| f.func.is_some()) {
        Some(frame) => {
            frame.has_site = true;
            let (name, open) = frame.func.clone().unwrap_or_default();
            (name, Some(open))
        }
        None => ("<module>".to_string(), None),
    }
}

// ─── Tree: test-only files, classification ──────────────────────────────

/// Normalise `a/./b/../c` into `a/c` (paths stay `/`-separated).
fn normalise(p: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    parts.join("/")
}

/// Candidate files for `decl` declared in `file`.
fn decl_targets(file: &str, decl: &ModDecl) -> Vec<String> {
    let path = Path::new(file);
    let parent = path.parent().unwrap_or(Path::new(""));
    if let Some(attr) = &decl.path_attr {
        return vec![normalise(&parent.join(attr))];
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = if matches!(stem.as_str(), "mod" | "lib" | "main") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    vec![
        normalise(&base.join(format!("{}.rs", decl.name))),
        normalise(&base.join(&decl.name).join("mod.rs")),
    ]
}

/// Classify a whole source tree (`(relative path, text)` pairs) against an
/// allowlist. Returns the findings (empty = the invariant holds).
fn classify(files: &[(String, String)], allow: &[Allowed]) -> Vec<String> {
    let scans: BTreeMap<&str, FileScan> = files
        .iter()
        .map(|(p, t)| (p.as_str(), scan_file(t)))
        .collect();
    // Fixpoint: a file is test-only if its own inner attribute says so, or a
    // gated declaration (or any declaration in a test-only file) reaches it.
    let mut test_only: BTreeSet<String> = scans
        .iter()
        .filter(|(_, s)| s.file_test_only)
        .map(|(p, _)| (*p).to_string())
        .collect();
    loop {
        let before = test_only.len();
        for (file, scan) in &scans {
            let parent_test = test_only.contains(*file);
            for decl in &scan.mods {
                if decl.gated || parent_test {
                    for target in decl_targets(file, decl) {
                        if scans.contains_key(target.as_str()) {
                            test_only.insert(target);
                        }
                    }
                }
            }
        }
        if test_only.len() == before {
            break;
        }
    }
    let mut found: BTreeMap<(String, String), Vec<&Site>> = BTreeMap::new();
    for (file, scan) in &scans {
        if test_only.contains(*file) {
            continue;
        }
        for site in &scan.sites {
            found
                .entry(((*file).to_string(), site.func.clone()))
                .or_default()
                .push(site);
        }
    }
    let mut findings = Vec::new();
    for entry in allow {
        if !REASON_CLASSES.iter().any(|c| entry.reason.starts_with(c)) {
            findings.push(format!(
                "reason: {}:{} reason must start with one of {REASON_CLASSES:?}",
                entry.file, entry.func
            ));
        }
        let key = (entry.file.to_string(), entry.func.to_string());
        match found.get(&key) {
            None => findings.push(format!(
                "stale: {}:{} is allowlisted but has no construction site",
                entry.file, entry.func
            )),
            Some(sites) if sites.len() != entry.count => findings.push(format!(
                "count: {}:{} allowlisted {} site(s), found {}",
                entry.file,
                entry.func,
                entry.count,
                sites.len()
            )),
            Some(_) => {}
        }
        if let Some(sites) = found.get(&key) {
            let facts = scans.get(entry.file).map(|s| &s.fn_facts);
            findings.extend(facts_findings(entry, sites, facts));
        }
    }
    for ((file, func), sites) in &found {
        if allow.iter().any(|a| a.file == file && a.func == func) {
            continue;
        }
        for site in sites {
            findings.push(format!(
                "unlisted: {file}:{func}:L{} form={}",
                site.line, site.form
            ));
        }
    }
    findings
}

/// X-10: an entry's declared credential / redirect / proxy facts must be
/// what the source of every one of its sites shows, and a credentialed
/// non-inference client that follows redirects or honours env proxies must
/// name its tracking issue in the reason.
fn facts_findings(
    entry: &Allowed,
    sites: &[&Site],
    facts: Option<&BTreeMap<usize, (Redirect, Proxy)>>,
) -> Vec<String> {
    let id = format!("{}:{}", entry.file, entry.func);
    let mut out = Vec::new();
    if entry.credential.trim().is_empty() {
        out.push(format!(
            "facts: {id} credential is empty (say `none` or which)"
        ));
    }
    let posture =
        entry.redirect == Redirect::PostureDependent || entry.proxy == Proxy::PostureDependent;
    if posture {
        if !entry.reason.starts_with("policy-routed:") {
            out.push(format!(
                "facts: {id} posture-dependent facts are only for a policy-routed: entry"
            ));
        }
    } else {
        let mut observed: BTreeSet<(&str, &str)> = BTreeSet::new();
        for site in sites {
            let (r, p) = site
                .fn_at
                .and_then(|at| facts.and_then(|f| f.get(&at)).copied())
                .unwrap_or((Redirect::Unclassified, Proxy::Unclassified));
            observed.insert((r.as_str(), p.as_str()));
        }
        let declared = (entry.redirect.as_str(), entry.proxy.as_str());
        if observed.iter().any(|o| *o != declared) {
            let shown: Vec<String> = observed
                .iter()
                .map(|(r, p)| format!("redirect={r} proxy={p}"))
                .collect();
            out.push(format!(
                "facts: {id} declares redirect={} proxy={}, source shows {}",
                declared.0,
                declared.1,
                shown.join(" / ")
            ));
        }
    }
    let leaky = entry.redirect == Redirect::DefaultFollow || entry.proxy == Proxy::HonoursEnv;
    if entry.reason.starts_with("non-inference:")
        && entry.credential.trim() != "none"
        && leaky
        && !entry.reason.contains("tracked #")
    {
        out.push(format!(
            "untracked: {id} carries a credential and follows redirects or honours env proxies; the reason must name its tracking issue"
        ));
    }
    out
}

fn collect_rs(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_rs(&p, root, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let rel = normalise(p.strip_prefix(root).expect("under root"));
            let text =
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            out.push((rel, text));
        }
    }
}

// ─── The class guard over the real tree ─────────────────────────────────

#[test]
fn every_reqwest_client_is_policy_routed_or_allowlisted_4193() {
    let started = Instant::now();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs(&root.join("src"), root, &mut files);
    assert!(
        files.len() >= MIN_SRC_FILES,
        "#4193 class guard: the walk saw {} files (< {MIN_SRC_FILES}); a mis-rooted walk must not pass",
        files.len()
    );
    let findings = classify(&files, &ALLOWLIST);
    let elapsed = started.elapsed();
    assert!(
        findings.is_empty(),
        "#4193 class guard: every non-test reqwest client in src/ must be built by \
         egress_policy::inference_client_builder() or be on ALLOWLIST with a reason \
         ({} finding(s)):\n{}",
        findings.len(),
        findings.join("\n")
    );
    assert!(
        elapsed < WALK_CEILING,
        "#4193 class guard: the walk took {elapsed:?} (ceiling {WALK_CEILING:?})"
    );
}

// ─── Self-tests: the scanner over synthetic trees ───────────────────────

fn tree(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect()
}

/// Every construction form the guard must see, one per row, with the
/// `form=` text the finding must carry.
const FORM_ROWS: [(&str, &str); 12] = [
    (
        "let c = reqwest::Client::builder().build();",
        "reqwest::Client::builder",
    ),
    (
        "let c = reqwest::blocking::Client::builder().build();",
        "reqwest::blocking::Client::builder",
    ),
    (
        "let c = reqwest::ClientBuilder::new().build();",
        "reqwest::ClientBuilder::new",
    ),
    ("let c = reqwest::Client::new();", "reqwest::Client::new"),
    (
        "let c = reqwest::Client::default();",
        "reqwest::Client::default",
    ),
    ("let r = reqwest::get(u);", "reqwest::get"),
    (
        "let r = reqwest::blocking::get(u);",
        "reqwest::blocking::get",
    ),
    ("let c = Client::builder();", "Client::builder"),
    ("let c = ClientBuilder::new();", "ClientBuilder::new"),
    (
        "let c = reqwest :: Client :: builder ();",
        "reqwest::Client::builder",
    ),
    (
        "let f = reqwest::Client::builder;",
        "reqwest::Client::builder",
    ),
    ("let c = r#reqwest::Client::new();", "reqwest::Client::new"),
];

#[test]
fn class_guard_detects_every_construction_form_4193() {
    for (stmt, form) in FORM_ROWS {
        let src = format!("fn probe() {{\n    {stmt}\n}}\n");
        let findings = classify(&tree(&[("src/x.rs", &src)]), &[]);
        assert_eq!(
            findings,
            vec![format!("unlisted: src/x.rs:probe:L2 form={form}")],
            "row `{stmt}`"
        );
    }
    // A renaming import of a construction item is a finding of its own (a recognised form; crate aliases are tracked #9314).
    for (use_line, rendered) in [
        (
            "use reqwest::Client as Http;",
            "use reqwest::Client as Http",
        ),
        (
            "use reqwest::{ClientBuilder as B, Url};",
            "use reqwest::{ClientBuilder as B, Url}",
        ),
        ("use reqwest::blocking::get;", "use reqwest::blocking::get"),
    ] {
        let src = format!("{use_line}\nfn probe() {{}}\n");
        let findings = classify(&tree(&[("src/x.rs", &src)]), &[]);
        assert_eq!(
            findings,
            vec![format!("unlisted: src/x.rs:<module>:L1 form={rendered}")],
            "row `{use_line}`"
        );
    }
    // A plain import of the type is not a construction.
    let plain =
        "use reqwest::Client;\nfn f(c: &reqwest::Client) -> reqwest::ClientBuilder { todo!() }\n";
    assert_eq!(
        classify(&tree(&[("src/x.rs", plain)]), &[]),
        Vec::<String>::new()
    );
}

#[test]
fn class_guard_skips_only_code_that_is_test_only_in_every_build_4193() {
    let skipped = r##"
// reqwest::Client::builder() in a line comment
/* reqwest::Client::new() in /* a nested */ block comment */
/// reqwest::Client::builder() in a doc comment
const S: &str = "reqwest::Client::builder() { in a string";
const R: &str = r#"reqwest::Client::new() } in a raw string"#;
const C: char = '{';
fn lifetimes<'a>(x: &'a str) -> &'a str { let _q = '}'; x }

#[cfg(test)]
mod tests {
    fn t() { let _ = reqwest::Client::builder(); let _b = '}'; }
}

#[cfg(all(unix, test))]
fn gated() { let _ = reqwest::Client::new(); }

fn body() {
    #[cfg(test)]
    let _c = { reqwest::Client::new() };
    #[cfg(test)]
    mod_level_stmt();
}

#[cfg(test)]
mod t_file;
#[cfg(test)]
#[path = "x_extra_tests.rs"]
mod extra;
mod prod_child;

fn after_all_of_it() {
    let _ = reqwest::Client::builder();
}
"##;
    let files = tree(&[
        ("src/x.rs", skipped),
        (
            "src/x/t_file.rs",
            "fn a() { let _ = reqwest::Client::new(); }\nmod deeper;\n",
        ),
        (
            "src/x/t_file/deeper.rs",
            "fn b() { let _ = reqwest::Client::new(); }\n",
        ),
        (
            "src/x_extra_tests.rs",
            "fn c() { let _ = reqwest::Client::new(); }\n",
        ),
        (
            "src/inner_gated.rs",
            "#![cfg(test)]\nfn d() { let _ = reqwest::Client::new(); }\n",
        ),
        (
            "src/x/prod_child.rs",
            "fn e() { let _ = reqwest::Client::new(); }\n",
        ),
    ]);
    let findings = classify(&files, &[]);
    assert_eq!(
        findings,
        vec![
            "unlisted: src/x.rs:after_all_of_it:L33 form=reqwest::Client::builder".to_string(),
            "unlisted: src/x/prod_child.rs:e:L1 form=reqwest::Client::new".to_string(),
        ],
        "only the production fn after the skipped regions and the ungated child file are sites"
    );

    // Production cfgs are NOT skipped: `any(test, ..)` and `not(test)` both
    // compile into some non-test build.
    for cfg in [
        "#[cfg(any(test, feature = \"x\"))]",
        "#[cfg(not(test))]",
        "#[cfg(feature = \"test\")]",
    ] {
        let src = format!("{cfg}\nfn p() {{ let _ = reqwest::Client::new(); }}\n");
        let findings = classify(&tree(&[("src/y.rs", &src)]), &[]);
        assert_eq!(
            findings,
            vec!["unlisted: src/y.rs:p:L2 form=reqwest::Client::new".to_string()],
            "`{cfg}` is production"
        );
    }

    // An inner `#![cfg(test)]` inside a block is not modelled: production.
    let nested = "mod m {\n    #![cfg(test)]\n    fn q() { let _ = reqwest::Client::new(); }\n}\n";
    assert_eq!(
        classify(&tree(&[("src/z.rs", nested)]), &[]),
        vec!["unlisted: src/z.rs:q:L3 form=reqwest::Client::new".to_string()]
    );
}

#[test]
fn class_guard_reports_unlisted_stale_count_and_reason_findings_4193() {
    let src = "fn listed() { let _a = reqwest::Client::new(); let _b = reqwest::Client::new(); }\n\
               fn stray() { let _ = reqwest::Client::builder(); }\n";
    let allow = [
        Allowed {
            file: "src/a.rs",
            func: "listed",
            count: 1,
            reason: "non-inference: fixture",
            credential: "none",
            redirect: Redirect::DefaultFollow,
            proxy: Proxy::HonoursEnv,
        },
        Allowed {
            file: "src/a.rs",
            func: "gone",
            count: 1,
            reason: "tracked #0: fixture",
            credential: "none",
            redirect: Redirect::DefaultFollow,
            proxy: Proxy::HonoursEnv,
        },
        Allowed {
            file: "src/a.rs",
            func: "listed",
            count: 2,
            reason: "because",
            credential: "none",
            redirect: Redirect::DefaultFollow,
            proxy: Proxy::HonoursEnv,
        },
    ];
    let findings = classify(&tree(&[("src/a.rs", src)]), &allow);
    assert_eq!(
        findings,
        vec![
            "count: src/a.rs:listed allowlisted 1 site(s), found 2".to_string(),
            "stale: src/a.rs:gone is allowlisted but has no construction site".to_string(),
            format!("reason: src/a.rs:listed reason must start with one of {REASON_CLASSES:?}"),
            "unlisted: src/a.rs:stray:L2 form=reqwest::Client::builder".to_string(),
        ]
    );
    // The real allowlist: every entry has a known reason class and a count.
    for entry in &ALLOWLIST {
        assert!(
            REASON_CLASSES.iter().any(|c| entry.reason.starts_with(c)),
            "{}:{} reason `{}`",
            entry.file,
            entry.func,
            entry.reason
        );
        assert!(entry.count >= 1, "{}:{} count 0", entry.file, entry.func);
    }
}

/// One row of the X-10 facts self-test: (fn name, fn body, declared
/// credential, redirect, proxy, reason, the findings the row must produce).
type FactsRow = (
    &'static str,
    &'static str,
    &'static str,
    Redirect,
    Proxy,
    &'static str,
    &'static [&'static str],
);

const FACTS_ROWS: [FactsRow; 9] = [
    // Declared facts that match the source: no finding.
    (
        "refused",
        "reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy().build()",
        "none",
        Redirect::Refused,
        Proxy::Disabled,
        "non-inference: fixture",
        &[],
    ),
    (
        "limited",
        "reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(3)).build()",
        "none",
        Redirect::Limited,
        Proxy::HonoursEnv,
        "non-inference: fixture",
        &[],
    ),
    // A declaration that claims more than the source does.
    (
        "claims",
        "reqwest::Client::new()",
        "none",
        Redirect::Refused,
        Proxy::Disabled,
        "non-inference: fixture",
        &[
            "facts: src/f.rs:claims declares redirect=none proxy=no_proxy, source shows redirect=default-follow proxy=honours-env",
        ],
    ),
    // A policy named only in a comment is not a policy.
    (
        "commented",
        "// .no_proxy() and Policy::none()\n    reqwest::Client::new()",
        "none",
        Redirect::Refused,
        Proxy::Disabled,
        "non-inference: fixture",
        &[
            "facts: src/f.rs:commented declares redirect=none proxy=no_proxy, source shows redirect=default-follow proxy=honours-env",
        ],
    ),
    // A redirect policy or proxy the scanner cannot classify never matches.
    (
        "custom",
        "reqwest::Client::builder().redirect(p).proxy(x).build()",
        "none",
        Redirect::DefaultFollow,
        Proxy::HonoursEnv,
        "non-inference: fixture",
        &[
            "facts: src/f.rs:custom declares redirect=default-follow proxy=honours-env, source shows redirect=unclassified proxy=unclassified",
        ],
    ),
    // A credentialed client that leaks must name its tracking issue.
    (
        "cred",
        "reqwest::Client::new()",
        "x-api-key",
        Redirect::DefaultFollow,
        Proxy::HonoursEnv,
        "non-inference: fixture",
        &[
            "untracked: src/f.rs:cred carries a credential and follows redirects or honours env proxies; the reason must name its tracking issue",
        ],
    ),
    (
        "cred_tracked",
        "reqwest::Client::new()",
        "x-api-key",
        Redirect::DefaultFollow,
        Proxy::HonoursEnv,
        "non-inference: fixture, tracked #1",
        &[],
    ),
    // An empty credential is a finding.
    (
        "blank",
        "reqwest::Client::new()",
        " ",
        Redirect::DefaultFollow,
        Proxy::HonoursEnv,
        "non-inference: fixture",
        &[
            "facts: src/f.rs:blank credential is empty (say `none` or which)",
            "untracked: src/f.rs:blank carries a credential and follows redirects or honours env proxies; the reason must name its tracking issue",
        ],
    ),
    // Posture-dependent is reserved for the policy-routed composition point.
    (
        "posture",
        "reqwest::Client::new()",
        "none",
        Redirect::PostureDependent,
        Proxy::PostureDependent,
        "non-inference: fixture",
        &["facts: src/f.rs:posture posture-dependent facts are only for a policy-routed: entry"],
    ),
];

#[test]
fn class_guard_checks_declared_egress_facts_against_the_source_4193() {
    for (func, body, credential, redirect, proxy, reason, want) in FACTS_ROWS {
        let src = format!("fn {func}() {{\n    let _c = {body};\n}}\n");
        let allow = [Allowed {
            file: "src/f.rs",
            func,
            count: 1,
            reason,
            credential,
            redirect,
            proxy,
        }];
        let findings = classify(&tree(&[("src/f.rs", &src)]), &allow);
        let want: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(findings, want, "row `{func}`");
    }
    // The facts are read from the innermost fn: an outer fn's policy does not
    // cover a nested fn's client.
    let nested = "fn outer() {\n    fn inner() { let _c = reqwest::Client::new(); }\n    let _p = reqwest::redirect::Policy::none();\n}\n";
    let allow = [Allowed {
        file: "src/n.rs",
        func: "inner",
        count: 1,
        reason: "non-inference: fixture",
        credential: "none",
        redirect: Redirect::DefaultFollow,
        proxy: Proxy::HonoursEnv,
    }];
    assert_eq!(
        classify(&tree(&[("src/n.rs", nested)]), &allow),
        Vec::<String>::new()
    );
}

#[test]
fn class_guard_scan_is_linear_on_a_large_input_4193() {
    let unit = "#[cfg(test)]\nmod t { fn f() { let _ = reqwest::Client::new(); /* { */ let _s = \"}\"; } }\n\
                fn g() { let _ = reqwest::Client::builder(); }\n";
    let reps = LARGE_INPUT_BYTES / unit.len() + 1;
    let src = unit.repeat(reps);
    assert!(src.len() >= LARGE_INPUT_BYTES);
    let started = Instant::now();
    let scan = scan_file(&src);
    let elapsed = started.elapsed();
    assert_eq!(
        scan.sites.len(),
        reps,
        "one production site per unit; the cfg(test) one is skipped"
    );
    assert!(
        scan.sites.iter().all(|s| s.func == "g"),
        "every site is in `g`"
    );
    assert!(
        elapsed < LARGE_INPUT_CEILING,
        "#4193 class guard: {} bytes scanned in {elapsed:?} (ceiling {LARGE_INPUT_CEILING:?})",
        src.len()
    );
}
