// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 — detectors for four common credential forms the anchored prefix
//! table in the parent module does not cover:
//!
//! 1. a URL userinfo password (`scheme://user:pass@host`) for the database
//!    and broker schemes in [`CREDENTIAL_URL_SCHEMES`];
//! 2. a `password` / `passwd` / `pwd` key followed by `:` or `=` and a value;
//! 3. a Slack token (`xox[abprs]-` + token characters);
//! 4. a Stripe live key (`sk_live_` / `rk_live_` + token characters).
//!
//! Every scan is a single forward pass over ASCII bytes: each cursor only
//! moves forward and a scanned value or token is never re-scanned, so the
//! cost is linear in the input (the #8854 quadratic shape is not reproduced
//! here). Every slice boundary is an ASCII byte position, so multi-byte UTF-8
//! input can never split a code point.
//!
//! Placeholders are accepted by an explicit named list or shape
//! ([`is_placeholder_value`]); value length never decides.

use super::{REDACTION_PLACEHOLDER, token_at};

pub(super) const KIND_URL_USERINFO_PASSWORD: &str = "url_userinfo_password";
pub(super) const KIND_PASSWORD_ASSIGNMENT: &str = "password_assignment";
pub(super) const KIND_SLACK_TOKEN: &str = "slack_token";
pub(super) const KIND_STRIPE_LIVE_KEY: &str = "stripe_live_key";

/// The separator between a URL scheme and its authority.
const URL_SCHEME_SEPARATOR: &str = "://";
/// Schemes whose userinfo password is screened (compared case-insensitively).
const CREDENTIAL_URL_SCHEMES: [&str; 9] = [
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "mongodb",
    "mongodb+srv",
];
/// Longest entry of [`CREDENTIAL_URL_SCHEMES`]; bounds the backward scheme walk.
const MAX_CREDENTIAL_SCHEME_LEN: usize = 11;
/// The documentation pair `user:password` with the literal words accepted.
const DOC_URL_USER: &str = "user";
const DOC_URL_PASSWORD: &str = "password";

/// Assignment keys, longest first so `password` wins over a shorter key.
const PASSWORD_KEYS: [&str; 3] = ["password", "passwd", "pwd"];

const SLACK_PREFIX: &str = "xox";
/// The Slack token type letters allowed after [`SLACK_PREFIX`].
const SLACK_TYPE_CHARS: &[u8] = b"abprs";
const SLACK_TYPE_SEPARATOR: u8 = b'-';
/// Minimum token-character run after `xox?-` for a Slack token.
const MIN_SLACK_BODY_LEN: usize = 10;

const STRIPE_LIVE_PREFIXES: [&str; 2] = ["sk_live_", "rk_live_"];
/// Minimum token-character run after a Stripe live prefix.
const MIN_STRIPE_BODY_LEN: usize = 16;

/// A masked value made only of `*` with at least this many characters.
const MIN_MASK_RUN: usize = 3;
const MASK_CHAR: u8 = b'*';

/// A detector: returns the byte spans to replace, ascending, non-overlapping.
type Detector = fn(&str) -> Vec<(usize, usize)>;

/// Run the four detectors in order (each over the previous one's output, as
/// the parent table does) and return the rewritten content when any fired.
pub(super) fn redact_credential_forms(
    content: &str,
    kinds: &mut Vec<&'static str>,
) -> Option<String> {
    let detectors: [(Detector, &'static str); 4] = [
        (stripe_live_key_spans, KIND_STRIPE_LIVE_KEY),
        (slack_token_spans, KIND_SLACK_TOKEN),
        (url_userinfo_password_spans, KIND_URL_USERINFO_PASSWORD),
        (password_assignment_spans, KIND_PASSWORD_ASSIGNMENT),
    ];
    let mut current: Option<String> = None;
    for (detect, kind) in detectors {
        let text = current.as_deref().unwrap_or(content);
        let spans = detect(text);
        if !spans.is_empty() {
            kinds.push(kind);
            current = Some(replace_spans(text, &spans));
        }
    }
    current
}

/// Replace each span with [`REDACTION_PLACEHOLDER`].
fn replace_spans(content: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(content.len());
    let mut cursor = 0usize;
    for &(start, end) in spans {
        out.push_str(&content[cursor..start]);
        out.push_str(REDACTION_PLACEHOLDER);
        cursor = end;
    }
    out.push_str(&content[cursor..]);
    out
}

/// True when the byte before `at` cannot continue an identifier (so a
/// prefix inside a word, e.g. `risk_live_`, is not a Stripe key).
fn at_word_start(bytes: &[u8], at: usize) -> bool {
    at == 0 || !bytes[at - 1].is_ascii_alphanumeric()
}

/// Named placeholder shapes accepted as a value: the redaction placeholder
/// itself (so a stored masked row re-screens clean), `<…>`, `${…}`,
/// `$IDENT`, and a run of at least [`MIN_MASK_RUN`] `*`.
fn is_placeholder_value(v: &str) -> bool {
    let b = v.as_bytes();
    v == REDACTION_PLACEHOLDER
        || (b.len() >= 2 && b[0] == b'<' && b[b.len() - 1] == b'>')
        || (v.starts_with("${") && v.ends_with('}'))
        || is_env_reference(v)
        || (b.len() >= MIN_MASK_RUN && b.iter().all(|&c| c == MASK_CHAR))
}

/// `$` followed by a shell identifier (`[A-Za-z_][A-Za-z0-9_]*`).
fn is_env_reference(v: &str) -> bool {
    let Some(name) = v.strip_prefix('$') else {
        return false;
    };
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

// ── 1. URL userinfo password ──────────────────────────────────────────────

/// True when the scheme ending right before `sep` is a credential scheme.
/// The walk back is bounded by [`MAX_CREDENTIAL_SCHEME_LEN`] + 1 bytes.
fn credential_scheme_before(bytes: &[u8], sep: usize) -> bool {
    let mut start = sep;
    while start > 0
        && sep - start <= MAX_CREDENTIAL_SCHEME_LEN
        && (bytes[start - 1].is_ascii_alphanumeric()
            || matches!(bytes[start - 1], b'+' | b'.' | b'-'))
    {
        start -= 1;
    }
    let scheme = &bytes[start..sep];
    CREDENTIAL_URL_SCHEMES
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s.as_bytes()))
}

/// End of the authority that starts at `from`: the first `/`, `?`, `#`,
/// quote, backtick or ASCII whitespace, else the end of input.
fn authority_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len()
        && !matches!(bytes[end], b'/' | b'?' | b'#' | b'"' | b'\'' | b'`')
        && !bytes[end].is_ascii_whitespace()
    {
        end += 1;
    }
    end
}

fn url_userinfo_password_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = content[from..].find(URL_SCHEME_SEPARATOR) {
        let sep = from + rel;
        let auth_start = sep + URL_SCHEME_SEPARATOR.len();
        if !credential_scheme_before(bytes, sep) {
            from = auth_start;
            continue;
        }
        let auth_end = authority_end(bytes, auth_start);
        let authority = &bytes[auth_start..auth_end];
        // Userinfo ends at the LAST `@` of the authority; the password is
        // everything after the first `:` of the userinfo.
        if let Some(at) = authority.iter().rposition(|&c| c == b'@')
            && let Some(colon) = authority[..at].iter().position(|&c| c == b':')
        {
            let user = &content[auth_start..auth_start + colon];
            let pw_start = auth_start + colon + 1;
            let pw_end = auth_start + at;
            let password = &content[pw_start..pw_end];
            let doc_pair = user == DOC_URL_USER && password == DOC_URL_PASSWORD;
            if !password.is_empty() && !doc_pair && !is_placeholder_value(password) {
                spans.push((pw_start, pw_end));
            }
        }
        from = auth_end;
    }
    spans
}

// ── 2. password / passwd / pwd assignment ─────────────────────────────────

/// Length of the assignment key at `at` (ASCII case-insensitive), if any.
fn password_key_len_at(bytes: &[u8], at: usize) -> Option<usize> {
    PASSWORD_KEYS.iter().find_map(|key| {
        let k = key.as_bytes();
        bytes
            .get(at..at + k.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(k))
            .then_some(k.len())
    })
}

fn skip_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    at
}

fn password_assignment_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(key_len) = password_key_len_at(bytes, i) else {
            i += 1;
            continue;
        };
        // Key as a word on its right side: an optional closing quote (JSON
        // / YAML keys), optional blanks, then `:` or `=`. `passwords are`
        // and `password_hash` fail here.
        let mut j = i + key_len;
        if j < bytes.len() && matches!(bytes[j], b'"' | b'\'') {
            j += 1;
        }
        j = skip_blanks(bytes, j);
        if j >= bytes.len() || !matches!(bytes[j], b':' | b'=') {
            i += key_len;
            continue;
        }
        // `password == x` is a comparison, not an assignment.
        if bytes[j] == b'=' && bytes.get(j + 1) == Some(&b'=') {
            i = j + 2;
            continue;
        }
        j = skip_blanks(bytes, j + 1);
        let quote = match bytes.get(j) {
            Some(&q @ (b'"' | b'\'')) => {
                j += 1;
                Some(q)
            }
            _ => None,
        };
        let value_start = j;
        let mut value_end = j;
        while value_end < bytes.len() {
            let c = bytes[value_end];
            let stop = match quote {
                Some(q) => c == q || c == b'\n',
                None => c.is_ascii_whitespace() || matches!(c, b',' | b';' | b'&' | b'"' | b'\''),
            };
            if stop {
                break;
            }
            value_end += 1;
        }
        let value = &content[value_start..value_end];
        if !value.is_empty() && !is_placeholder_value(value) {
            spans.push((value_start, value_end));
        }
        // Never re-scan the value: the cursor only moves forward.
        i = value_end.max(i + key_len);
    }
    spans
}

// ── 3 + 4. Slack token / Stripe live key ──────────────────────────────────

fn slack_token_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = content[from..].find(SLACK_PREFIX) {
        let start = from + rel;
        let type_at = start + SLACK_PREFIX.len();
        let typed = bytes
            .get(type_at)
            .is_some_and(|c| SLACK_TYPE_CHARS.contains(c))
            && bytes.get(type_at + 1) == Some(&SLACK_TYPE_SEPARATOR);
        if !(typed && at_word_start(bytes, start)) {
            // `start` is an ASCII `x`, so `start + 1` is a char boundary.
            from = start + 1;
            continue;
        }
        let body_start = type_at + 2;
        let body_end = body_start + token_at(content, body_start).len();
        if body_end - body_start >= MIN_SLACK_BODY_LEN {
            spans.push((start, body_end));
        }
        from = body_end;
    }
    spans
}

fn stripe_live_key_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    for prefix in STRIPE_LIVE_PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = content[from..].find(prefix) {
            let start = from + rel;
            let body_start = start + prefix.len();
            let body_end = body_start + token_at(content, body_start).len();
            if at_word_start(bytes, start) && body_end - body_start >= MIN_STRIPE_BODY_LEN {
                spans.push((start, body_end));
            }
            from = body_end;
        }
    }
    // The two prefixes scan independently; restore ascending order and drop
    // any span nested inside an earlier one.
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for span in spans {
        match merged.last() {
            Some(&(_, end)) if span.0 < end => {}
            _ => merged.push(span),
        }
    }
    merged
}
