// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 — detectors for four common credential forms the anchored prefix
//! table in the parent module does not cover. Round 2 makes each one fail
//! closed by construction instead of by a list of forms:
//!
//! 1. a URL userinfo password (`scheme://user:pass@host`) for ANY RFC 3986
//!    scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`), not a scheme
//!    list (invariant (c));
//! 2. a credential-named key with a value (invariants (a) and (b)): a key is
//!    credential-named when its normalised name (ASCII case folded,
//!    [`KEY_SEPARATORS`] dropped) CONTAINS a [`CREDENTIAL_KEY_WORDS`] entry,
//!    so no prefix or suffix clears it; its non-empty value is a finding
//!    unless the WHOLE value is proven a pure reference with no literal part
//!    ([`is_pure_reference`]). A default, a fallback, a literal beside a
//!    reference, a value on the next line, a block scalar and a continuation
//!    line are all findings, and the mask covers the whole logical value;
//! 3. a Slack token (`xox[abeprs]-`, `xapp-`, case-insensitive) and a Slack
//!    incoming-webhook path;
//! 4. a Stripe secret key (`sk_` / `rk_` live or test, `whsec_`,
//!    case-insensitive).
//!
//! Every scan is a single forward pass over ASCII bytes: each cursor only
//! moves forward and a scanned value or token is never re-scanned, so the
//! cost is linear in the input (the #8854 quadratic shape is not reproduced
//! here). Every slice boundary is an ASCII byte position, so multi-byte UTF-8
//! input can never split a code point. Forms that hide behind escapes,
//! invisible characters, fullwidth or homoglyph letters and `%XX` escapes
//! are caught by the decoded views of the parent's screen (`views.rs`,
//! invariant (d)), and the redacted copy is screened again there
//! (invariant (e)).

use super::{REDACTION_PLACEHOLDER, token_at};

pub(super) const KIND_URL_USERINFO_PASSWORD: &str = "url_userinfo_password";
pub(super) const KIND_PASSWORD_ASSIGNMENT: &str = "password_assignment";
pub(super) const KIND_SLACK_TOKEN: &str = "slack_token";
pub(super) const KIND_STRIPE_LIVE_KEY: &str = "stripe_live_key";

/// The separator between a URL scheme and its authority.
const URL_SCHEME_SEPARATOR: &str = "://";
/// The documentation pair `user:password` with the literal words accepted.
const DOC_URL_USER: &str = "user";
const DOC_URL_PASSWORD: &str = "password";

/// Credential words a normalised key name is screened for (invariant (a)).
const CREDENTIAL_KEY_WORDS: [&[u8]; 3] = [b"password", b"passwd", b"pwd"];
/// Longest [`CREDENTIAL_KEY_WORDS`] entry: the rolling window of the
/// normalised-name match.
const MAX_CREDENTIAL_WORD_LEN: usize = 8;
/// Bytes a key name may hold that its normalised form drops.
const KEY_SEPARATORS: [u8; 3] = [b'_', b'.', b'-'];
/// A key led by this byte is a command-line flag (`--password VALUE`).
const CLI_FLAG_SIGIL: u8 = b'-';
/// An operator-less key (`machine h login u password VALUE`) masks the next
/// token when it is secret-shaped: at least this many bytes, with an ASCII
/// letter and an ASCII digit. Prose words after a key stay clean.
const MIN_SECRET_SHAPED_LEN: usize = 8;

const SLACK_PREFIX: &[u8] = b"xox";
/// The Slack token type letters allowed after [`SLACK_PREFIX`].
const SLACK_TYPE_CHARS: &[u8] = b"abeprs";
const SLACK_TYPE_SEPARATOR: u8 = b'-';
/// The Slack app-level token prefix.
const SLACK_APP_PREFIX: &[u8] = b"xapp-";
/// Minimum token-character run after a Slack prefix for a Slack token.
const MIN_SLACK_BODY_LEN: usize = 10;
/// The Slack incoming-webhook path; the path after it is the secret.
const SLACK_WEBHOOK_PATH: &[u8] = b"hooks.slack.com/services/";

/// Stripe secret-key prefixes (compared case-insensitively). Publishable
/// keys (`pk_`) are public by design and are not listed.
const STRIPE_SECRET_PREFIXES: [&[u8]; 5] = [
    b"sk_live_",
    b"rk_live_",
    b"sk_test_",
    b"rk_test_",
    b"whsec_",
];
/// Minimum token-character run after a Stripe prefix.
const MIN_STRIPE_BODY_LEN: usize = 16;

/// A masked value made only of `*` with at least this many characters.
const MIN_MASK_RUN: usize = 3;
const MASK_CHAR: u8 = b'*';
/// The sigil of a shell parameter reference.
const DOLLAR: char = '$';

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

/// Sort spans and drop any span that starts inside an earlier one, so
/// [`replace_spans`] gets ascending, non-overlapping input.
fn merge_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.0 < last.1 => last.1 = last.1.max(span.1),
            _ => merged.push(span),
        }
    }
    merged
}

/// True when the byte before `at` cannot continue an identifier (so a
/// prefix inside a word, e.g. `risk_live_`, is not a Stripe key).
fn at_word_start(bytes: &[u8], at: usize) -> bool {
    at == 0 || !bytes[at - 1].is_ascii_alphanumeric()
}

/// The first position at or after `from` where `needle` starts, ASCII
/// case-insensitively. The needle is a short constant, so the walk is
/// linear in the input.
fn find_ascii_ci(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let last = bytes.len().checked_sub(needle.len())?;
    (from..=last).find(|&i| bytes[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Named placeholder shapes accepted as a URL userinfo password: the
/// redaction placeholder itself (so a stored masked row re-screens clean),
/// `<…>`, `${IDENT}`, `$IDENT`, and a run of at least [`MIN_MASK_RUN`] `*`.
///
/// Each shape is judged over the WHOLE value (#9351): `<…>` holds no inner
/// `<` / `>`, and `${…}` is exactly `${IDENT}`.
fn is_placeholder_value(v: &str) -> bool {
    v == REDACTION_PLACEHOLDER
        || is_mask_run(v)
        || shape_grammar::is_angle_placeholder(v)
        || shape_grammar::is_brace_reference(v)
        || is_env_reference(v)
}

fn is_mask_run(v: &str) -> bool {
    v.len() >= MIN_MASK_RUN && v.bytes().all(|c| c == MASK_CHAR)
}

/// `$` followed by a shell identifier (`[A-Za-z_][A-Za-z0-9_]*`).
fn is_env_reference(v: &str) -> bool {
    let Some(name) = v.strip_prefix(DOLLAR) else {
        return false;
    };
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// An environment-variable name in UPPER_SNAKE form (`[A-Z_][A-Z0-9_]*`).
fn is_upper_snake(name: &str) -> bool {
    let mut b = name.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == b'_')
        && b.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// `$NAME` or `${NAME}` with an UPPER_SNAKE name and nothing else.
///
/// decision: a pure reference names an UPPER_SNAKE variable over any
/// identifier because a literal glued to a reference (`$A<literal>`) is
/// otherwise indistinguishable from a longer name.
fn is_upper_reference(v: &str) -> bool {
    v.strip_prefix(DOLLAR).is_some_and(|rest| {
        is_upper_snake(rest)
            || rest
                .strip_prefix('{')
                .and_then(|r| r.strip_suffix('}'))
                .is_some_and(is_upper_snake)
    })
}

/// Invariant (b): true only when the WHOLE value is proven to carry no
/// literal part: the redaction placeholder, a `*` mask run, an UPPER_SNAKE
/// `$NAME` / `${NAME}` reference; and, unquoted only, one whole env lookup
/// ([`shape_grammar::env_lookup_shape`]), a null literal or an ellipsis.
/// A quoted value is a literal string, so a lookup or `null` inside quotes
/// is not a reference. Everything else is a finding.
fn is_pure_reference(v: &str, quoted: bool) -> bool {
    if v == REDACTION_PLACEHOLDER || is_mask_run(v) || is_upper_reference(v) {
        return true;
    }
    !quoted
        && (shape_grammar::env_lookup_shape(v) == shape_grammar::EnvShape::Whole
            || NULL_LITERALS.contains(&v)
            || ELLIPSIS_PLACEHOLDERS.contains(&v))
}

// ── 1. URL userinfo password ──────────────────────────────────────────────

/// A byte of an RFC 3986 scheme: `ALPHA / DIGIT / "+" / "-" / "."`.
fn is_scheme_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-')
}

/// True when a scheme ends right before `sep`: the run of scheme bytes
/// before it (walked back no further than `floor`, the previous scan point,
/// so the walk is linear) holds an ASCII letter, i.e. its longest
/// ALPHA-led suffix is a non-empty RFC 3986 scheme.
///
/// decision: judge any RFC 3986 scheme (longest ALPHA-led suffix) over a
/// scheme list because the scheme grammar is the invariant (c).
fn scheme_before(bytes: &[u8], sep: usize, floor: usize) -> bool {
    let mut start = sep;
    while start > floor && is_scheme_byte(bytes[start - 1]) {
        start -= 1;
    }
    bytes[start..sep].iter().any(u8::is_ascii_alphabetic)
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

/// True when the authority opens with an RFC 3986 IP-literal host
/// (`[` hex digits, `:` and `.` `]`), then an optional all-digit port, then
/// the end or a path / query / fragment. Userinfo always precedes the host,
/// so such an authority holds none and a later `@` is in its path
/// (`http://[::1]:8080/a@b`). A bracket run of any other shape is judged
/// as userinfo as before.
fn ip_literal_host_first(authority: &[u8]) -> bool {
    let Some(rest) = authority.strip_prefix(b"[") else {
        return false;
    };
    let Some(close) = rest.iter().position(|&c| c == b']') else {
        return false;
    };
    if !rest[..close]
        .iter()
        .all(|&c| c.is_ascii_hexdigit() || matches!(c, b':' | b'.'))
    {
        return false;
    }
    let after = &rest[close + 1..];
    let mut k = 0usize;
    if after.first() == Some(&b':') {
        k = 1;
        while after.get(k).is_some_and(u8::is_ascii_digit) {
            k += 1;
        }
    }
    after.get(k).is_none_or(|c| matches!(c, b'/' | b'?' | b'#'))
}

fn url_userinfo_password_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = content[from..].find(URL_SCHEME_SEPARATOR) {
        let sep = from + rel;
        let auth_start = sep + URL_SCHEME_SEPARATOR.len();
        if !scheme_before(bytes, sep, from) {
            from = auth_start;
            continue;
        }
        let auth_end = authority_end(bytes, auth_start);
        let authority = &bytes[auth_start..auth_end];
        if ip_literal_host_first(authority) {
            from = auth_end;
            continue;
        }
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

// ── 2. credential-named key assignment ────────────────────────────────────

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
/// at run time instead of holding it. Every entry ends in the delimiter its
/// lookup grammar requires (`[` `(` `.` `{`), never in an identifier byte: a
/// bare `os.environ` would accept `os.environ_<secret>` (#8855). An entry
/// only names the HEAD of the grammar [`shape_grammar::env_lookup_shape`]
/// walks over the whole value (#9351); a head match alone accepts nothing.
/// Pinned by the child test modules.
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
/// expression when the shape is `&` [`'lifetime` blanks] [`mut` blanks] TYPE
/// with TYPE a whole [`shape_grammar::walk_type`] expression followed only by
/// what [`shape_grammar::annotation_suffix_ok`] allows (#9351: `&str.x`,
/// `&str@x` and `&String<X>x` are not annotations); `None` for anything else
/// (a credential such as `&S3cr3t`, or a YAML anchor). Each byte is read once.
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
    match shape_grammar::walk_type(bytes, k) {
        shape_grammar::TypeWalk::End(e) if shape_grammar::annotation_suffix_ok(bytes, e) => Some(e),
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

/// A byte of a key name: identifier bytes plus [`KEY_SEPARATORS`].
fn is_key_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || KEY_SEPARATORS.contains(&c)
}

fn key_run_end(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && is_key_byte(bytes[at]) {
        at += 1;
    }
    at
}

/// Invariant (a): true when the key name, ASCII case folded with
/// [`KEY_SEPARATORS`] dropped, CONTAINS a [`CREDENTIAL_KEY_WORDS`] entry
/// (`DB_PASSWORD_PROD`, `password2`, `passwordConfirm`, `user-password`).
/// One forward walk with a fixed window.
fn is_credential_key(name: &[u8]) -> bool {
    let mut window = [0u8; MAX_CREDENTIAL_WORD_LEN];
    let mut filled = 0usize;
    for &c in name {
        if KEY_SEPARATORS.contains(&c) {
            continue;
        }
        window.copy_within(1.., 0);
        window[MAX_CREDENTIAL_WORD_LEN - 1] = c.to_ascii_lowercase();
        filled = (filled + 1).min(MAX_CREDENTIAL_WORD_LEN);
        let tail = &window[MAX_CREDENTIAL_WORD_LEN - filled..];
        if CREDENTIAL_KEY_WORDS.iter().any(|w| tail.ends_with(w)) {
            return true;
        }
    }
    false
}

/// The operator after a credential key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Operator {
    /// First byte after the operator.
    end: usize,
    /// A single `:` (YAML / JSON / struct field): only this operator can
    /// lead a type annotation or a block scalar.
    colon: bool,
    /// A comparison (`==` `===` `!=` `!==`): a bare identifier after it
    /// names a variable, not a literal.
    comparison: bool,
}

/// The operator after a key `key_start..key_end`: an optional closing quote
/// (plain or escaped, for JSON keys) and subscript bracket
/// (`config['password']`), optional blanks, then `=`, `:`, `:=`, `=>`, a
/// comparison (`==` `===` `!=` `!==`: the value compared is a literal too),
/// `,` after a quoted key (a function argument), or `>` after `<key` (an XML
/// element). `::` is a path separator, not an operator.
fn operator_after_key(bytes: &[u8], key_start: usize, key_end: usize) -> Option<Operator> {
    let mut j = key_end;
    let mut quoted_key = false;
    match (bytes.get(j), bytes.get(j + 1)) {
        (Some(b'"' | b'\''), _) => {
            j += 1;
            quoted_key = true;
        }
        (Some(&QUOTE_ESCAPE), Some(b'"' | b'\'')) => {
            j += 2;
            quoted_key = true;
        }
        _ => {}
    }
    if bytes.get(j) == Some(&b']') {
        j += 1;
    }
    j = skip_blanks(bytes, j);
    let rest = bytes.get(j..).unwrap_or_default();
    let op = |len: usize, colon: bool| {
        Some(Operator {
            end: j + len,
            colon,
            comparison: false,
        })
    };
    let comparison = |len: usize| {
        Some(Operator {
            end: j + len,
            colon: false,
            comparison: true,
        })
    };
    if rest.starts_with(b"===") || rest.starts_with(b"!==") {
        return comparison(3);
    }
    if rest.starts_with(b"==") || rest.starts_with(b"!=") {
        return comparison(2);
    }
    if rest.starts_with(b":=") || rest.starts_with(b"=>") {
        return op(2, false);
    }
    if rest.starts_with(b"::") {
        return None;
    }
    let xml_element = key_start > 0 && bytes[key_start - 1] == b'<';
    match rest.first() {
        Some(b'=') => op(1, false),
        Some(b':') => op(1, true),
        Some(b',') if quoted_key => op(1, false),
        Some(b'>') if xml_element && xml_element_closes(bytes, j + 1) => op(1, false),
        _ => None,
    }
}

/// True when the element text from `from` runs to a closing tag: the next
/// `<` opens `</`. `<password>` as a bare placeholder is no element. The
/// walk stops at the next `<`, which every later `<key` needs, so the
/// probes never overlap and the scan stays linear.
fn xml_element_closes(bytes: &[u8], from: usize) -> bool {
    bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|&c| c == b'<'))
        .is_some_and(|p| bytes.get(from + p + 1) == Some(&b'/'))
}

/// True when `bytes[start..end]` holds a credential assignment of its own
/// (`Option<&pwd=X>`). Such a value is never accepted as a type annotation:
/// the annotation would otherwise swallow the nested secret, since the
/// outer scan resumes past the whole value. One forward walk.
fn holds_password_assignment(bytes: &[u8], start: usize, end: usize) -> bool {
    let mut k = start;
    while k < end {
        if !is_key_byte(bytes[k]) {
            k += 1;
            continue;
        }
        let run_end = key_run_end(bytes, k).min(end);
        if is_credential_key(&bytes[k..run_end])
            && operator_after_key(bytes, k, run_end).is_some_and(|op| op.end <= end)
        {
            return true;
        }
        k = run_end;
    }
    false
}

/// Bytes a judged value may carry at its right edge without being part of
/// it: the closing backtick of a markdown code span (`` `pwd=$X` ``) and a
/// list separator (`password: null,`).
const JUDGED_TRAILERS: [char; 3] = [CODE_SPAN_DELIMITER, ',', ';'];

/// The unquoted value as [`is_pure_reference`] judges it: without the
/// [`JUDGED_TRAILERS`] at its end. Only the judgement drops them; the
/// masked span still covers the whole value.
fn judged_value(v: &str) -> &str {
    v.trim_end_matches(JUDGED_TRAILERS)
}

/// End of the line that holds `from`, without the trailing blanks.
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

/// The first line-end byte (LF or CR) at or after `from`, else the end.
fn line_break_from(bytes: &[u8], mut from: usize) -> usize {
    while from < bytes.len() && !is_line_end(bytes[from]) {
        from += 1;
    }
    from
}

/// The start of the line after the line-end byte at `at` (CRLF aware).
fn line_start_after(bytes: &[u8], at: usize) -> usize {
    if bytes.get(at) == Some(&b'\r') && bytes.get(at + 1) == Some(&b'\n') {
        at + 2
    } else {
        at + 1
    }
}

/// Indentation (leading blanks) of the line that holds `at`. Called only
/// for a key whose value is empty on its line, so each line is walked back
/// at most once.
fn line_indent(bytes: &[u8], at: usize) -> usize {
    let line_start = bytes[..at]
        .iter()
        .rposition(|&c| is_line_end(c))
        .map_or(0, |p| p + 1);
    skip_blanks(bytes, line_start) - line_start
}

/// True when the bytes after a value ending at `at` close the statement:
/// after blanks, the end of input, a line end, a comment, or a separator
/// or closer of the enclosing construct. Anything else after a value is a
/// literal beside it (a fallback, a default, a concatenation).
fn tail_terminates(bytes: &[u8], at: usize) -> bool {
    let k = skip_blanks(bytes, at);
    bytes
        .get(k)
        .is_none_or(|&c| matches!(c, b'\n' | b'\r' | b'#' | b';' | b',' | b')' | b'}' | b']'))
}

/// Words that join a second value to the one before them
/// (`$X or "pw"`, `os.environ["X"] or "pw"`): after a value they make the
/// tail part of the value.
const FALLBACK_KEYWORDS: [&[u8]; 4] = [b"or", b"and", b"if", b"else"];

/// True when the bytes after a value ending at `at` are context, not more of
/// the value: they close the statement ([`tail_terminates`]), or, after at
/// least one blank, they start a word that is not a [`FALLBACK_KEYWORDS`]
/// entry, a shell `&&` list or a single `|` pipe. Anything else (a glued
/// byte, a quote, `+`, `||`, `??`, `.`, `(`, a fallback word) joins a second
/// part to the value, and the whole line is then the value.
fn tail_is_context(bytes: &[u8], at: usize) -> bool {
    if tail_terminates(bytes, at) {
        return true;
    }
    let k = skip_blanks(bytes, at);
    if k == at {
        return false;
    }
    let rest = &bytes[k..];
    if rest.starts_with(b"&&") {
        return true;
    }
    match rest.first() {
        Some(b'|') => rest.get(1) != Some(&b'|'),
        Some(&c) if is_ident_byte(c) => {
            let word = &rest[..ident_end(rest, 0)];
            !FALLBACK_KEYWORDS
                .iter()
                .any(|w| word.eq_ignore_ascii_case(w))
        }
        Some(&c) => !c.is_ascii(),
        None => true,
    }
}

/// True when the value opens more brackets than it closes: the value runs
/// on past its blank (`${X:- pw}`, `os.environ["X" pw]`), so the line from
/// the value is masked (the #9351 ruling for a broken lookup).
fn has_unclosed_opener(v: &[u8]) -> bool {
    let open = v.iter().filter(|c| matches!(c, b'(' | b'[' | b'{')).count();
    let close = v.iter().filter(|c| matches!(c, b')' | b']' | b'}')).count();
    open > close
}

/// Mask from `from` to the end of its line (at least to `min_end`); returns
/// the resume position.
fn mask_line(bytes: &[u8], from: usize, min_end: usize, spans: &mut Vec<(usize, usize)>) -> usize {
    let end = line_content_end(bytes, from).max(min_end);
    spans.push((from, end));
    end
}

/// The scan: every key run that is credential-named is judged; the cursor
/// only moves forward and never re-enters a judged value.
fn password_assignment_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_key_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let key_end = key_run_end(bytes, i);
        let resume = if is_credential_key(&bytes[i..key_end]) {
            screen_key(content, i, key_end, &mut spans)
        } else {
            key_end
        };
        i = resume.max(key_end);
    }
    spans
}

/// Judge one credential key; returns the resume position.
fn screen_key(
    content: &str,
    key_start: usize,
    key_end: usize,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = content.as_bytes();
    if let Some(op) = operator_after_key(bytes, key_start, key_end) {
        return value_after_operator(content, key_start, op, spans);
    }
    if !bytes
        .get(key_end)
        .is_some_and(|&c| matches!(c, b' ' | b'\t'))
    {
        return key_end;
    }
    let v = skip_blanks(bytes, key_end);
    if bytes.get(v).is_none_or(|&c| is_line_end(c)) {
        return key_end;
    }
    if bytes[key_start] == CLI_FLAG_SIGIL {
        return inline_value(content, v, false, spans);
    }
    let token_end = shape_grammar::token_end(bytes, v);
    let token = &content[v..token_end];
    if is_secret_shaped(token) && !is_pure_reference(token, false) {
        spans.push((v, token_end));
        return token_end;
    }
    key_end
}

/// A token that looks like a credential: at least [`MIN_SECRET_SHAPED_LEN`]
/// bytes with an ASCII letter and an ASCII digit.
fn is_secret_shaped(token: &str) -> bool {
    token.len() >= MIN_SECRET_SHAPED_LEN
        && token.bytes().any(|c| c.is_ascii_digit())
        && token.bytes().any(|c| c.is_ascii_alphabetic())
}

/// The value after an operator: a value on the next line, a continuation
/// line, a block scalar, or an inline value (invariant (b): every form
/// whose whole value is not a pure reference is masked whole).
fn value_after_operator(
    content: &str,
    key_start: usize,
    op: Operator,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = content.as_bytes();
    let v = skip_blanks(bytes, op.end);
    let Some(&c) = bytes.get(v) else {
        return v;
    };
    if is_line_end(c) {
        return next_line_value(content, key_start, v, op.colon, spans);
    }
    if c == QUOTE_ESCAPE && bytes.get(v + 1).is_some_and(|&n| is_line_end(n)) {
        // `password = \` then the value on the continuation line.
        let next = line_start_after(bytes, v + 1);
        let end = line_content_end(bytes, next.min(bytes.len())).max(v + 1);
        spans.push((v, end));
        return end;
    }
    if op.comparison
        && let Some(end) = compared_variable_end(bytes, v)
    {
        return end;
    }
    if op.colon
        && let Some(header_end) = block_header_end(bytes, v)
    {
        return block_scalar(content, key_start, header_end, spans);
    }
    inline_value(content, v, op.colon, spans)
}

/// After a comparison: the end of a bare variable name at `v` (an ASCII
/// letter or `_`, then identifier bytes and `.`) that is not secret-shaped
/// and is followed by a blank, a closer or the end. A quoted value, a
/// number and a secret-shaped token stay literals and are judged as values.
fn compared_variable_end(bytes: &[u8], v: usize) -> Option<usize> {
    let first = *bytes.get(v)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = v;
    while bytes
        .get(end)
        .is_some_and(|&c| is_ident_byte(c) || c == b'.')
    {
        end += 1;
    }
    let name = std::str::from_utf8(&bytes[v..end]).ok()?;
    let closed = bytes.get(end).is_none_or(|&c| {
        c.is_ascii_whitespace() || matches!(c, b')' | b'{' | b';' | b',' | b'&' | b'|')
    });
    (closed && !is_secret_shaped(name)).then_some(end)
}

/// A YAML block-scalar header at `v` (`|` or `>`, then chomping and
/// indentation indicators, then blanks and a line end): the header end.
fn block_header_end(bytes: &[u8], v: usize) -> Option<usize> {
    if !matches!(bytes.get(v), Some(b'|' | b'>')) {
        return None;
    }
    let mut k = v + 1;
    while bytes
        .get(k)
        .is_some_and(|&c| matches!(c, b'-' | b'+') || c.is_ascii_digit())
    {
        k += 1;
    }
    let k = skip_blanks(bytes, k);
    bytes.get(k).is_none_or(|&c| is_line_end(c)).then_some(k)
}

/// The block scalar after a header ending at `header_end`: the following
/// lines indented deeper than the key's line (blank lines inside). The
/// whole content, first byte to last, is judged as one value and masked as
/// one span.
fn block_scalar(
    content: &str,
    key_start: usize,
    header_end: usize,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = content.as_bytes();
    let indent = line_indent(bytes, key_start);
    let mut first: Option<usize> = None;
    let mut last = header_end;
    let mut k = header_end;
    while k < bytes.len() {
        let line_start = line_start_after(bytes, k);
        let first_byte = skip_blanks(bytes, line_start);
        let line_break = line_break_from(bytes, first_byte);
        if first_byte == line_break {
            k = line_break;
            continue;
        }
        if first_byte - line_start <= indent {
            break;
        }
        first.get_or_insert(first_byte);
        last = line_content_end(bytes, first_byte).min(line_break);
        k = line_break;
    }
    let Some(first) = first else {
        return header_end;
    };
    if !is_pure_reference(&content[first..last], false) {
        spans.push((first, last));
    }
    last
}

/// The value on the line after a key whose value is empty on its own line:
/// taken when that line is indented deeper than the key's line, or when it
/// is a single token with no `=` that does not end in `:` (a key of its
/// own). Returns the resume position.
fn next_line_value(
    content: &str,
    key_start: usize,
    line_end: usize,
    colon: bool,
    spans: &mut Vec<(usize, usize)>,
) -> usize {
    let bytes = content.as_bytes();
    let line_start = line_start_after(bytes, line_end);
    let first_byte = skip_blanks(bytes, line_start);
    let line_break = line_break_from(bytes, first_byte);
    if first_byte == line_break {
        return line_end;
    }
    let line = &bytes[first_byte..line_content_end(bytes, first_byte).min(line_break)];
    let deeper = first_byte - line_start > line_indent(bytes, key_start);
    let single_token = !line.iter().any(u8::is_ascii_whitespace)
        && !line.contains(&b'=')
        && line.last() != Some(&b':');
    if !(deeper || single_token) {
        return line_end;
    }
    inline_value(content, first_byte, colon, spans)
}

/// Judge the value that starts at `v` on its line. Returns the resume
/// position.
fn inline_value(content: &str, v: usize, colon: bool, spans: &mut Vec<(usize, usize)>) -> usize {
    let bytes = content.as_bytes();
    let Some(&c) = bytes.get(v) else {
        return v;
    };
    if is_line_end(c) {
        return v;
    }
    if c == QUOTE_ESCAPE && matches!(bytes.get(v + 1), Some(b'"' | b'\'')) {
        // An escaped quote (a JSON string inside a string): the extent is
        // the escape grammar of the outer string, so the line is the value.
        return mask_line(bytes, v, v + 2, spans);
    }
    if matches!(c, b'"' | b'\'') {
        let (start, end, _) = value_at(bytes, v);
        let close_end = if bytes.get(end) == Some(&c) {
            end + 1
        } else {
            end
        };
        if !tail_is_context(bytes, close_end) {
            return mask_line(bytes, start, end, spans);
        }
        let literal = &content[start..end];
        if !literal.is_empty() && !is_pure_reference(literal, true) {
            spans.push((start, end));
        }
        return close_end;
    }
    let token_end = shape_grammar::token_end(bytes, v);
    let token = &content[v..token_end];
    let judged = judged_value(token);
    if judged.is_empty() {
        // Only trailers (`` `password=` `` in prose): no value at all.
        return token_end;
    }
    // A closing code-span backtick ends the statement: what follows is prose.
    let context = token.ends_with(CODE_SPAN_DELIMITER) || tail_is_context(bytes, token_end);
    if is_pure_reference(judged, false) {
        if context {
            return token_end;
        }
        return mask_line(bytes, v, token_end, spans);
    }
    if colon && let Some(resume) = annotation(content, v, token_end, spans) {
        return resume;
    }
    if context && !has_unclosed_opener(token.as_bytes()) {
        spans.push((v, token_end));
        return token_end;
    }
    mask_line(bytes, v, token_end, spans)
}

/// A type annotation after `:` (`password: String`, `pwd: &str`): `None`
/// when the value names no type. An accepted annotation resumes right after
/// the type, so a key later on the same line is still screened; an
/// initializer (`password: String = "x"`) is judged as the value. A broken
/// or suffixed type is masked.
fn annotation(
    content: &str,
    v: usize,
    token_end: usize,
    spans: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let bytes = content.as_bytes();
    let end = if bytes[v] == REFERENCE_TYPE_SIGIL {
        // `&` naming no whole type: a credential, or a YAML anchor whose
        // anchored value follows on the same line; mask to the line end.
        let Some(e) = reference_annotation_end(bytes, v) else {
            return Some(mask_line(bytes, v, token_end, spans));
        };
        e
    } else {
        if holds_password_assignment(bytes, v, token_end) {
            return None;
        }
        match shape_grammar::walk_type(bytes, v) {
            shape_grammar::TypeWalk::NotType => return None,
            shape_grammar::TypeWalk::End(e) if shape_grammar::annotation_suffix_ok(bytes, e) => e,
            // A complete type then bytes no annotation holds: the token
            // from the type start is the finding.
            shape_grammar::TypeWalk::End(e) => {
                let mask_end = shape_grammar::token_end(bytes, e).max(token_end);
                spans.push((v, mask_end));
                return Some(mask_end);
            }
            // Unclosed, mismatched or over-nested: the line is the finding.
            shape_grammar::TypeWalk::Broken => {
                return Some(mask_line(bytes, v, token_end, spans));
            }
        }
    };
    let k = skip_blanks(bytes, end);
    if bytes.get(k) == Some(&b'=') && bytes.get(k + 1) != Some(&b'=') {
        let at = skip_blanks(bytes, k + 1);
        return Some(inline_value(content, at, false, spans));
    }
    Some(end)
}

// ── 3 + 4. Slack token / Stripe secret key ────────────────────────────────

/// Spans of `prefix` (ASCII case-insensitive, at a word start) followed by
/// at least `min_body` token characters.
fn prefixed_token_spans(
    content: &str,
    prefix: &[u8],
    min_body: usize,
    spans: &mut Vec<(usize, usize)>,
) {
    let bytes = content.as_bytes();
    let mut from = 0usize;
    while let Some(start) = find_ascii_ci(bytes, from, prefix) {
        let body_start = start + prefix.len();
        let body_end = body_start + token_at(content, body_start).len();
        if at_word_start(bytes, start) && body_end - body_start >= min_body {
            spans.push((start, body_end));
            from = body_end;
        } else {
            // `start` is an ASCII byte, so `start + 1` is a char boundary.
            from = start + 1;
        }
    }
}

fn slack_token_spans(content: &str) -> Vec<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(start) = find_ascii_ci(bytes, from, SLACK_PREFIX) {
        let type_at = start + SLACK_PREFIX.len();
        let typed = bytes
            .get(type_at)
            .is_some_and(|c| SLACK_TYPE_CHARS.contains(&c.to_ascii_lowercase()))
            && bytes.get(type_at + 1) == Some(&SLACK_TYPE_SEPARATOR);
        if !(typed && at_word_start(bytes, start)) {
            from = start + 1;
            continue;
        }
        let body_start = type_at + 2;
        let body_end = body_start + token_at(content, body_start).len();
        if body_end - body_start >= MIN_SLACK_BODY_LEN {
            spans.push((start, body_end));
            from = body_end;
        } else {
            from = start + 1;
        }
    }
    prefixed_token_spans(content, SLACK_APP_PREFIX, MIN_SLACK_BODY_LEN, &mut spans);
    // The webhook path after `hooks.slack.com/services/` is the secret.
    let mut from = 0usize;
    while let Some(at) = find_ascii_ci(bytes, from, SLACK_WEBHOOK_PATH) {
        let body_start = at + SLACK_WEBHOOK_PATH.len();
        let body_end = body_start + token_at(content, body_start).len();
        if body_end > body_start {
            spans.push((body_start, body_end));
        }
        from = body_end;
    }
    merge_spans(spans)
}

fn stripe_live_key_spans(content: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for prefix in STRIPE_SECRET_PREFIXES {
        prefixed_token_spans(content, prefix, MIN_STRIPE_BODY_LEN, &mut spans);
    }
    merge_spans(spans)
}

mod shape_grammar;

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
