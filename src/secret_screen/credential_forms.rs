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

/// End of the URL token that starts at `from`: the first ASCII whitespace,
/// else the end of input. No other byte ends it (#8855): a password may hold
/// any byte, so a per-byte terminator (`/` `?` `#` a quote) would hide its
/// `@` and pass the URL whole. The userinfo then ends at the LAST `@` of
/// the token; a neighbour `@` in a path, query or JSON tail only widens the
/// mask of a line that is refused anyway.
fn authority_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
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

/// Base type names (before any `<` / `[`) that mark an unquoted value after
/// `:` as a type annotation (`password: String`), not a credential.
const ANNOTATION_TYPE_NAMES: [&str; 16] = [
    "String",
    "str",
    "string",
    "Option",
    "Secret",
    "SecretString",
    "SecretBox",
    "Zeroizing",
    "Vec",
    "Box",
    "Cow",
    "Arc",
    "bool",
    "bytes",
    "Bytes",
    "number",
];
/// Rust reference-type sigil: `password: &str`, `password: &'a str`.
const REFERENCE_TYPE_SIGIL: u8 = b'&';
/// Prefixes of an unquoted value that reads the secret from the environment
/// at run time instead of holding it. Matched with `starts_with`, so every
/// entry ends in the delimiter its lookup grammar requires (`[` `(` `.`
/// `{`), never in an identifier byte: a bare `os.environ` would accept
/// `os.environ_<secret>` (#8855). Pinned by the child test module.
const ENV_LOOKUP_PREFIXES: [&str; 12] = [
    "os.environ[",
    "os.environ.get(",
    "os.getenv(",
    "getenv(",
    "env::var(",
    "std::env::var(",
    "process.env.",
    "ENV[",
    "ENV.fetch(",
    "System.getenv(",
    "Environment.GetEnvironmentVariable(",
    "$ENV{",
];
/// Unquoted null literals: an absent value, not a credential.
const NULL_LITERALS: [&str; 5] = ["null", "None", "nil", "undefined", "NULL"];
/// Documentation ellipses standing in for an elided value.
const ELLIPSIS_PLACEHOLDERS: [&str; 2] = ["…", "..."];

/// A format-string hole: `{}` or `{IDENT}` (`password: {msg}`).
fn is_format_hole(v: &str) -> bool {
    v.strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(|name| name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
}

/// True when an unquoted value after `:` (not led by
/// [`REFERENCE_TYPE_SIGIL`]) is a type annotation shape.
fn is_type_annotation(v: &str) -> bool {
    let base = v.split(['<', '[']).next().unwrap_or(v);
    ANNOTATION_TYPE_NAMES.contains(&base)
}

/// The markdown code-span delimiter.
const CODE_SPAN_DELIMITER: char = '`';
/// The lifetime marker of a reference type (`&'a str`).
const LIFETIME_SIGIL: u8 = b'\'';
/// The mutability keyword of a reference type (`&mut String`).
const MUT_KEYWORD: &[u8] = b"mut";

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn ident_end(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && is_ident_byte(bytes[at]) {
        at += 1;
    }
    at
}

/// For a value led by [`REFERENCE_TYPE_SIGIL`] at `at`: the end of the type
/// name when the shape is `&` [`'lifetime` blanks] [`mut` blanks] NAME with
/// NAME in [`ANNOTATION_TYPE_NAMES`]; `None` for anything else (a credential
/// such as `&S3cr3t`, or a YAML anchor). Bounded: each byte is read once.
fn reference_annotation_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut k = at + 1;
    if bytes.get(k) == Some(&LIFETIME_SIGIL) {
        let lifetime_end = ident_end(bytes, k + 1);
        let after = skip_blanks(bytes, lifetime_end);
        if lifetime_end == k + 1 || after == lifetime_end {
            return None;
        }
        k = after;
    }
    let mut_end = k + MUT_KEYWORD.len();
    if bytes.get(k..mut_end) == Some(MUT_KEYWORD) {
        let after = skip_blanks(bytes, mut_end);
        if after > mut_end {
            k = after;
        }
    }
    let name_end = ident_end(bytes, k);
    let name = std::str::from_utf8(&bytes[k..name_end]).ok()?;
    ANNOTATION_TYPE_NAMES.contains(&name).then_some(name_end)
}

/// Named non-credential shapes of an UNQUOTED assignment value. A quoted
/// value is a literal and only [`is_placeholder_value`] applies to it.
fn is_non_credential_unquoted(v: &str) -> bool {
    NULL_LITERALS.contains(&v)
        || ELLIPSIS_PLACEHOLDERS.contains(&v)
        || is_format_hole(v)
        || ENV_LOOKUP_PREFIXES.iter().any(|p| v.starts_with(p))
}

/// An assignment operator at `j`: `:` / `=`, plus the two-byte `:=` and
/// `=>`. Returns the operator length, or `None` for a comparison (`==`)
/// or any other byte.
fn assignment_operator_len(bytes: &[u8], j: usize) -> Option<usize> {
    match (bytes.get(j), bytes.get(j + 1)) {
        (Some(b'='), Some(b'=')) => None,
        (Some(b':'), Some(b'=')) | (Some(b'='), Some(b'>')) => Some(2),
        (Some(b':' | b'='), _) => Some(1),
        _ => None,
    }
}

/// The escape byte inside a quoted value: `\q` and `\\` never close it.
const QUOTE_ESCAPE: u8 = b'\\';

fn is_line_end(c: u8) -> bool {
    matches!(c, b'\n' | b'\r')
}

/// The value that starts at `j` (after blanks): `(start, end, quoted)`.
/// The only ways a value ends (#8855): ASCII whitespace or the end of input
/// for an unquoted value; for a value that OPENED with a quote, only that
/// quote, a line end (LF or CR) or the end of input. Inside a quoted value
/// an escaped byte ([`QUOTE_ESCAPE`] then any byte but a line end) and a
/// doubled quote are part of the value, so `"a\"b"` and `'a''b'` are masked
/// whole. No other byte ends a value, so a byte inside a credential never
/// cuts the mask short (a per-byte terminator list fails open for every
/// byte it forgets). Every end is an ASCII byte or the end of input, so it
/// is a char boundary; each byte is read once.
fn value_at(bytes: &[u8], j: usize) -> (usize, usize, bool) {
    let j = skip_blanks(bytes, j);
    let quote = match bytes.get(j) {
        Some(&q @ (b'"' | b'\'')) => Some(q),
        _ => None,
    };
    let start = if quote.is_some() { j + 1 } else { j };
    let mut end = start;
    while end < bytes.len() {
        let c = bytes[end];
        match quote {
            None if c.is_ascii_whitespace() => break,
            None => end += 1,
            Some(_) if is_line_end(c) => break,
            Some(q) => {
                let next = bytes.get(end + 1).copied();
                let escaped = c == QUOTE_ESCAPE && next.is_some_and(|n| !is_line_end(n));
                if escaped || (c == q && next == Some(q)) {
                    end += 2;
                } else if c == q {
                    break;
                } else {
                    end += 1;
                }
            }
        }
    }
    (start, end, quote.is_some())
}

/// The operator after a password key that ends at `key_end`: an optional
/// closing quote (JSON / YAML keys) and subscript bracket
/// (`config['password']`), optional blanks, then an assignment operator.
/// Returns the operator position and its length (`None` when there is no
/// operator, so `passwords are`, `password_hash` and `password == x` fail).
fn operator_after_key(bytes: &[u8], key_end: usize) -> (usize, Option<usize>) {
    let mut j = key_end;
    if matches!(bytes.get(j), Some(b'"' | b'\'')) {
        j += 1;
    }
    if bytes.get(j) == Some(&b']') {
        j += 1;
    }
    j = skip_blanks(bytes, j);
    (j, assignment_operator_len(bytes, j))
}

/// True when `bytes[start..end]` holds a password assignment of its own
/// (`os.environ&pwd=X`, `<x&passwd:X>`). Such a value is never accepted as
/// a named non-credential shape: the shape would otherwise swallow the
/// nested secret, since the outer scan resumes past the whole value. One
/// forward walk; the blanks after a key are walked at most once more.
fn holds_password_assignment(bytes: &[u8], start: usize, end: usize) -> bool {
    (start..end).any(|k| {
        password_key_len_at(bytes, k).is_some_and(|key_len| {
            let (op_at, op_len) = operator_after_key(bytes, k + key_len);
            op_len.is_some() && op_at < end
        })
    })
}

/// Bytes a named non-credential shape may carry at its right edge without
/// being part of it: the closing backtick of a markdown code span
/// (`` `pwd=…` ``) and a list separator (`password: null,`).
const JUDGED_TRAILERS: [char; 3] = [CODE_SPAN_DELIMITER, ',', ';'];

/// The unquoted value as the named-shape checks judge it: without the
/// [`JUDGED_TRAILERS`] at its end. Only the judgement drops them; the
/// masked span still covers the whole value, so a secret holding one is
/// masked whole.
fn judged_value(v: &str) -> &str {
    v.trim_end_matches(JUDGED_TRAILERS)
}

/// End of the line that holds `from`, without the trailing blanks: the
/// mask end of a [`REFERENCE_TYPE_SIGIL`]-led value that names no type.
fn line_content_end(bytes: &[u8], from: usize) -> usize {
    let mut line_end = from;
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    let mut end = line_end;
    while end > from && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

/// After a type annotation ending at `from`, the `=` of an initializer on
/// the same declaration (`password: &'static str = "x"`), if any. The walk
/// stops at a line end, `;` `,` `)` `{` `}`, so it never leaves the
/// declaration, and the caller resumes past it (no byte is walked twice).
fn initializer_after(bytes: &[u8], from: usize) -> (Option<usize>, usize) {
    let mut k = from;
    while k < bytes.len() && !matches!(bytes[k], b'\n' | b';' | b',' | b')' | b'{' | b'}') {
        if bytes[k] == b'=' {
            return match assignment_operator_len(bytes, k) {
                Some(len) => (Some(k + len), k + len),
                None => (None, k + 2),
            };
        }
        k += 1;
    }
    (None, k)
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
        let (j, op_len) = operator_after_key(bytes, i + key_len);
        let Some(op_len) = op_len else {
            i = j.max(i + key_len);
            continue;
        };
        let is_colon = bytes[j] == b':' && op_len == 1;
        let (mut start, mut end, mut quoted) = value_at(bytes, j + op_len);
        let mut resume = end;
        let ref_led = is_colon && !quoted && bytes.get(start) == Some(&REFERENCE_TYPE_SIGIL);
        let annotation_end = if ref_led {
            reference_annotation_end(bytes, start)
        } else if is_colon && !quoted {
            // The annotation ends at its judged edge, so an initializer
            // search never starts past a `,` that ends the declaration.
            // An annotation holding a nested assignment
            // (`Option<&pwd=X>`) is not an annotation.
            let judged = judged_value(&content[start..end]);
            (is_type_annotation(judged) && !holds_password_assignment(bytes, start, end))
                .then_some(start + judged.len())
        } else {
            None
        };
        if ref_led && annotation_end.is_none() {
            // `&` naming no type: a credential, or a YAML anchor whose
            // anchored value follows on the same line; mask to the line end.
            end = line_content_end(bytes, start);
            spans.push((start, end));
            i = end.max(resume).max(i + key_len);
            continue;
        }
        // `password: String` is an annotation; an initializer after it
        // (`password: String = "x"`) is the value that is screened.
        if let Some(ann_end) = annotation_end {
            let (init, after) = initializer_after(bytes, ann_end);
            resume = after;
            match init {
                Some(at) => {
                    (start, end, quoted) = value_at(bytes, at);
                    resume = end;
                }
                None => {
                    i = resume.max(i + key_len);
                    continue;
                }
            }
        }
        let value = if quoted {
            &content[start..end]
        } else {
            judged_value(&content[start..end])
        };
        // A named non-credential shape is accepted only when it holds no
        // password assignment of its own (#8855); else the whole value is
        // masked, never the nested secret left behind.
        let accepted = !holds_password_assignment(bytes, start, end)
            && (value.is_empty()
                || is_placeholder_value(value)
                || (!quoted && is_non_credential_unquoted(value)));
        if !accepted {
            spans.push((start, end));
        }
        // Never re-scan the value: the cursor only moves forward.
        i = resume.max(i + key_len);
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

#[cfg(test)]
mod tests_9351;

#[cfg(test)]
mod tests {
    use super::{ENV_LOOKUP_PREFIXES, is_ident_byte};

    /// #8855 class invariant: an env-lookup prefix is matched with
    /// `starts_with`, so an entry ending in an identifier byte would accept
    /// any value that merely extends it (`os.environ_<secret>`). Every entry
    /// must end in the delimiter its lookup grammar requires, so a future
    /// bare entry is red here by construction.
    #[test]
    fn no_env_lookup_prefix_ends_in_an_identifier_character_8855() {
        for prefix in ENV_LOOKUP_PREFIXES {
            let last = prefix.as_bytes().last().copied();
            assert!(
                last.is_some_and(|c| !is_ident_byte(c)),
                "8855: env-lookup prefix {prefix:?} ends in an identifier character"
            );
        }
    }
}
