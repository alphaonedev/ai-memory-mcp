// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3432 — the shared CONFIG-REDACTION funnel.
//!
//! # The defect this closes
//!
//! `ai-memory config check` was added by #3197 precisely so a
//! secret-bearing `config.toml` could never be echoed into container
//! logs. `ai-memory config migrate --dry-run` then printed the ENTIRE
//! resolved config table — `[reranker] api_key`, the legacy top-level
//! `api_key`, `[hooks.subscription] hmac_secret`, everything — in
//! cleartext, and `migrate`'s parse-error arms interpolated the `toml`
//! crate's `Display`, which renders the offending SOURCE LINE under a
//! gutter (exactly what #3197 declined to do). `ai-memory install`
//! (dry-run by default) printed a unified diff of the MCP client config,
//! whose `mcpServers.<x>.env` blocks hold vendor API keys — the very
//! blocks `config migrate --also-clean-claude-json` exists to delete.
//!
//! One verb was hardened; its siblings printed the same secrets.
//!
//! # The control
//!
//! Every config-printing surface renders through THIS module, and the
//! redaction is decided here — never at a call site:
//!
//! * [`render_redacted_toml`] for a whole config table (`config migrate
//!   --dry-run`);
//! * [`redact_config_line`] for line-oriented output (`install`'s diff),
//!   which covers TOML `key = "v"` and JSON `"key": "v"` alike;
//! * [`redact_parse_error`] for any parser error that would otherwise
//!   echo the offending source.
//!
//! All three sit on the same two layers, so neither can be the weak one:
//!
//! 1. **By field NAME, structurally.** [`is_secret_value_key`] matches a
//!    curated set of secret-VALUE suffixes on the key, recursively, at
//!    any depth, in any section — including sections that do not exist
//!    yet. This is deliberately not a list of known secret fields: a new
//!    `[whatever] api_key` is masked the day it is added, with no patch
//!    here.
//! 2. **By value SHAPE, as a backstop.** Every remaining string is run
//!    through [`crate::secret_screen::redact_for_storage`], the same
//!    detector the storage lane uses (vendor-prefixed tokens, AWS keys,
//!    JWTs, PEM blocks). That catches a credential parked in a field
//!    whose NAME looks innocent.
//!
//! # What is deliberately NOT redacted
//!
//! The POINTER fields (`api_key_env`, `api_key_file`, and anything else
//! ending `_env` / `_file` / `_source`) stay visible. They name an
//! environment variable or a path — not a secret — and they are the
//! whole point of the migration an operator is inspecting: masking them
//! would hide whether `api_key` was correctly rewritten to
//! `api_key_env`, which would make the verb useless and push operators
//! back to `cat config.toml`. Non-secret values (tier, db, model,
//! base_url) stay verbatim for the same reason: a redactor nobody can
//! use is a redactor that gets bypassed.
//!
//! # One accepted OVER-masking, on purpose
//!
//! The bare `key` suffix also matches a PATH-valued field — a TLS
//! `key = "/etc/ai-memory/server.key"` renders as
//! `key = "<redacted>"`, hiding a path that is not itself a secret.
//! That is deliberate and must not be "fixed" by special-casing it:
//! a field literally named `key` is the single most likely place for an
//! operator to paste a raw credential, and a rule that tries to tell
//! "this `key` holds a path" from "this `key` holds a secret" by
//! inspecting the VALUE is exactly the guess that leaks the one time it
//! guesses wrong. Masking a path costs an operator one `ls`; masking
//! nothing costs them a credential. The companion `*_key_file` /
//! `*_key_env` pointers are unaffected and remain the readable way to
//! see where key material lives.
//!
//! # Display-only
//!
//! Nothing here ever touches a durable artifact. `config migrate` writes
//! the UNREDACTED migration to disk (a masked `api_key` written back
//! would be silent credential destruction — the unintentional-data-loss
//! class); `install --apply` writes the UNREDACTED client config. The
//! mask exists on the operator's terminal and in their logs, nowhere
//! else.

use std::borrow::Cow;

/// The placeholder every redacted config value is replaced with.
///
/// Aliases the crate-canonical [`crate::REDACTED_PLACEHOLDER`] rather than
/// minting a second spelling (the pm-v3.1 no-duplicated-literal rule), and
/// stays a named handle so this lane's masking is greppable. It is
/// deliberately NOT
/// [`crate::secret_screen::REDACTION_PLACEHOLDER`] (`[REDACTED:secret]`):
/// that one marks "a credential-SHAPED span was found inside this value",
/// while this one marks "this field is secret BY NAME and was masked
/// wholesale". Both can appear in one rendering, and telling them apart is
/// useful.
pub const CONFIG_REDACTION_MASK: &str = crate::REDACTED_PLACEHOLDER;

/// Key suffixes whose VALUE is a credential.
///
/// Matched as the whole key or as a `_`-delimited suffix, case-insensitively
/// — so `api_key`, `hmac_secret`, `ANTHROPIC_API_KEY` and `db_passphrase`
/// match, while `keyword_search`, `key_source`, `api_key_source`,
/// `secret_screen_mode`, `capability_tokens_enabled` and `max_seq_tokens`
/// do not. The `_`-delimited rule is what keeps the false-positive rate at
/// zero across the current config surface while still catching fields
/// nobody has written yet.
const SECRET_VALUE_KEY_SUFFIXES: &[&str] = &[
    "key",
    "secret",
    "token",
    "password",
    "passphrase",
    "credential",
    "credentials",
];

/// Does `key` name a field whose VALUE is a credential?
///
/// See [`SECRET_VALUE_KEY_SUFFIXES`] for the matching rule and the
/// deliberate exclusions.
#[must_use]
pub fn is_secret_value_key(key: &str) -> bool {
    let lowered = key.trim().to_ascii_lowercase();
    SECRET_VALUE_KEY_SUFFIXES
        .iter()
        .any(|suffix| match lowered.strip_suffix(suffix) {
            Some("") => true,
            Some(prefix) => prefix.ends_with('_'),
            None => false,
        })
}

/// Redact a parsed config tree in place.
///
/// Recurses through tables and arrays. Under a secret-named key EVERY
/// scalar is masked, not just strings — an `api_key = 1234567890` is a
/// credential too, and a type-based carve-out would be a hole. Outside a
/// secret-named key, strings still go through the value-shape backstop.
pub fn redact_toml_value(value: &mut toml::Value) {
    redact_in(value, false);
}

fn redact_in(value: &mut toml::Value, under_secret_key: bool) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                let secret = under_secret_key || is_secret_value_key(key);
                redact_in(child, secret);
            }
        }
        toml::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_in(item, under_secret_key);
            }
        }
        // Scalars.
        other => {
            if under_secret_key {
                *other = toml::Value::String(CONFIG_REDACTION_MASK.to_string());
            } else if let toml::Value::String(s) = other
                && let Some(screened) = crate::secret_screen::redact_for_storage(s)
            {
                *s = screened;
            }
        }
    }
}

/// Render a config table for HUMAN DISPLAY, redacted.
///
/// The caller keeps the unredacted table for whatever it actually writes;
/// this is the terminal/log copy. A serialisation failure returns an
/// explicit diagnostic rather than an empty string, so "nothing printed"
/// can never be misread as "the config is empty".
#[must_use]
pub fn render_redacted_toml(table: &toml::map::Map<String, toml::Value>) -> String {
    let mut value = toml::Value::Table(table.clone());
    redact_toml_value(&mut value);
    toml::to_string_pretty(&value).unwrap_or_else(|e| {
        format!("(config could not be rendered for display: {e}; nothing was written)\n")
    })
}

/// Byte spans of every secret-named field's VALUE on one line.
///
/// v1.0.0 #3432 amendment 1 — the pre-amendment form split on the FIRST
/// `=` / `:` only. That is fine for a pretty-printed file, one pair per
/// line, and wrong for the shape `install`'s diff actually renders: its
/// `before` side is the operator's file AS WRITTEN, and a minified
/// client config puts the whole tree on one line —
/// `{"mcpServers":{"x":{"env":{"ANTHROPIC_API_KEY":"…"}}}}`. There the
/// first separator sits after `"mcpServers"`, the name layer never fires,
/// and the credential survived unless it happened to be vendor-shaped.
/// A TOML inline table (`auth = { token = "…" }`) has the same defect.
///
/// So: scan the WHOLE line and return every value span whose key is
/// secret-named. The scan is quote-aware, which is what keeps a `:`
/// inside `base_url = "http://127.0.0.1:11434"` from being mistaken for
/// a separator, and container-aware, so `"env": {` opens a nested object
/// rather than swallowing the rest of the line as one bare value.
fn secret_value_spans(line: &str) -> Vec<(usize, usize)> {
    /// Characters that end an unquoted scalar value.
    fn ends_bare_value(b: u8) -> bool {
        matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'"' | b'\'')
    }
    /// Characters that may appear in an unquoted key token.
    fn is_key_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
    }
    /// Consume a quoted token starting at `i` (which indexes the opening
    /// quote); returns the index just past the closing quote.
    fn skip_quoted(b: &[u8], mut i: usize) -> usize {
        let quote = b[i];
        i += 1;
        while i < b.len() {
            if b[i] == b'\\' {
                i = (i + 2).min(b.len());
                continue;
            }
            if b[i] == quote {
                return i + 1;
            }
            i += 1;
        }
        b.len()
    }

    let b = line.as_bytes();
    let n = b.len();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    // Byte span of the most recent token, which is the candidate KEY when
    // the next non-space character turns out to be a separator.
    let mut pending_key: Option<(usize, usize)> = None;
    let mut i = 0usize;

    while i < n {
        match b[i] {
            b'"' | b'\'' => {
                let start = i;
                i = skip_quoted(b, i);
                pending_key = Some((start, i));
            }
            b'=' | b':' => {
                let key_is_secret = pending_key.is_some_and(|(s, e)| {
                    is_secret_value_key(line[s..e].trim_matches(['"', '\'']))
                });
                pending_key = None;
                i += 1;
                while i < n && (b[i] == b' ' || b[i] == b'\t') {
                    i += 1;
                }
                if i >= n {
                    break;
                }
                // A container open is not a scalar value: keep scanning
                // INSIDE it so nested secret keys are still reached.
                if b[i] == b'{' || b[i] == b'[' {
                    continue;
                }
                let vstart = i;
                if b[i] == b'"' || b[i] == b'\'' {
                    i = skip_quoted(b, i);
                } else {
                    while i < n && !ends_bare_value(b[i]) {
                        i += 1;
                    }
                }
                if key_is_secret && i > vstart {
                    spans.push((vstart, i));
                }
            }
            c if is_key_char(c) => {
                let start = i;
                while i < n && is_key_char(b[i]) {
                    i += 1;
                }
                pending_key = Some((start, i));
            }
            _ => i += 1,
        }
    }
    spans
}

/// Redact one line of line-oriented config output (a diff line, a log
/// line, a rendered `key = value` pair).
///
/// Handles TOML (`api_key = "…"`), TOML inline tables
/// (`auth = { token = "…" }`), pretty JSON (`"ANTHROPIC_API_KEY": "…"`)
/// and MINIFIED JSON (a whole client config on one line) with one rule:
/// EVERY value whose key is secret-named is masked, wherever it sits on
/// the line. A line with no such pair — a `[section]` header, a brace, a
/// comment — still goes through the value-shape backstop, and so does the
/// masked remainder, so a credential in a non-secret-named field on the
/// same line is still caught.
#[must_use]
pub fn redact_config_line(line: &str) -> Cow<'_, str> {
    let spans = secret_value_spans(line);
    if spans.is_empty() {
        return match crate::secret_screen::redact_for_storage(line) {
            Some(screened) => Cow::Owned(screened),
            None => Cow::Borrowed(line),
        };
    }
    // Replace only the VALUE spans, so the separator, the surrounding
    // braces and any trailing comma survive and the redacted diff still
    // reads as the shape it replaced.
    let mut out = String::with_capacity(line.len());
    let mut prev = 0usize;
    for (start, end) in spans {
        out.push_str(&line[prev..start]);
        out.push('"');
        out.push_str(CONFIG_REDACTION_MASK);
        out.push('"');
        prev = end;
    }
    out.push_str(&line[prev..]);
    // Second layer over the remainder (a credential can still sit in a
    // field this line's name rule did not match).
    Cow::Owned(crate::secret_screen::redact_for_storage(&out).unwrap_or(out))
}

/// Render a parser error WITHOUT its echoed source.
///
/// The `toml` crate's `Display` renders the offending line under a
/// gutter:
///
/// ```text
/// TOML parse error at line 3, column 11
///   |
/// 3 | api_key = "sk-live-…"
///   |           ^^^^^^^^^^^
/// invalid type: string, expected a boolean
/// ```
///
/// #3197 dealt with that by dropping the `Display` entirely, which is
/// safe but leaves the operator with "not valid TOML" and no position.
/// This keeps the position and the diagnosis and drops the gutter block
/// that carries the value, then runs the remainder through the
/// value-shape backstop — strictly more actionable than #3197's answer
/// and strictly safer than interpolating the raw `Display`.
///
/// # The message BODY carries values too (#3432 amendment 2)
///
/// Dropping the gutter is not sufficient. `serde`'s type errors embed the
/// unexpected VALUE in the message body, OUTSIDE any gutter:
///
/// ```text
/// TOML parse error at line 9, column 15
///   |
/// 9 | hmac_secret = 987654321321
///   |               ^^^^^^^^^^^^
/// invalid type: integer `987654321321`, expected a string
/// ```
///
/// The last line survives the gutter filter, and the value-shape screen
/// only catches it if it happens to look like a vendor credential — a
/// plain high-entropy string or a numeric secret walks straight through.
/// So every backtick- or double-quote-delimited payload in the kept text
/// is masked as well. The position, the error CLASS and the `expected …`
/// tail (unquoted prose) all survive, which is what an operator actually
/// needs to fix the file.
///
/// The cost is real and accepted: `unknown field \`api_key\`, expected one
/// of \`tier\`, \`db\`` loses the field names too. Naming the offending
/// field would be nicer, but a rule that keeps SOME quoted payloads needs
/// to decide which are values and which are identifiers — from a string
/// the parser has already flattened — and getting that wrong leaks a
/// credential. The position tells the operator which line it is.
#[must_use]
pub fn redact_parse_error<E: std::fmt::Display + ?Sized>(err: &E) -> String {
    let rendered = err.to_string();
    let kept: Vec<&str> = rendered
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_source_echo_line(line))
        .collect();
    let joined = mask_quoted_payloads(&kept.join("; "));
    crate::secret_screen::redact_for_storage(&joined).unwrap_or(joined)
}

/// Replace the contents of every backtick- or double-quote-delimited span
/// with [`CONFIG_REDACTION_MASK`].
///
/// The delimiters are preserved so the message still reads as a message.
/// An UNTERMINATED delimiter masks to end-of-string rather than being
/// ignored — fail-closed: a truncated error message must not be the way a
/// payload survives.
fn mask_quoted_payloads(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open_at) = rest.find(['`', '"']) {
        let delim = rest.as_bytes()[open_at];
        out.push_str(&rest[..open_at]);
        out.push(delim as char);
        out.push_str(CONFIG_REDACTION_MASK);
        out.push(delim as char);
        let after_open = &rest[open_at + 1..];
        match after_open.find(delim as char) {
            Some(close_at) => rest = &after_open[close_at + 1..],
            // Unterminated: everything after the delimiter is payload.
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Is this a line of the `toml` crate's source-echo gutter?
///
/// Two shapes: the bare gutter / caret rows (`|`, `| ^^^^`) and the
/// numbered source row (`3 | api_key = "…"`). A legitimate message that
/// merely contains a `|` (`expected one of \`a\` | \`b\``) is kept,
/// because its left side is not a bare line number.
fn is_source_echo_line(line: &str) -> bool {
    if line.starts_with('|') {
        return true;
    }
    match line.split_once('|') {
        Some((head, _)) => {
            let head = head.trim();
            !head.is_empty() && head.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_keys_are_recognised_by_suffix_3432() {
        for key in [
            "api_key",
            "API_KEY",
            "ANTHROPIC_API_KEY",
            "hmac_secret",
            "secret",
            "key",
            "auth_token",
            "db_passphrase",
            "password",
            "aws_credentials",
        ] {
            assert!(is_secret_value_key(key), "{key} must be treated as secret");
        }
    }

    #[test]
    fn pointer_and_lookalike_keys_are_not_redacted_3432() {
        // The `_env` / `_file` pointers are the SAFE alternative operators
        // migrate TO — masking them would hide the migration's whole point.
        // The rest are real config fields whose names merely contain a
        // secret word; over-redacting them would make the output useless.
        for key in [
            "api_key_env",
            "api_key_file",
            "api_key_source",
            "key_source",
            "keyword_search",
            "secret_screen_mode",
            "capability_tokens_enabled",
            "max_seq_tokens",
        ] {
            assert!(
                !is_secret_value_key(key),
                "{key} must NOT be treated as secret"
            );
        }
    }

    #[test]
    fn nested_secret_values_are_masked_at_any_depth_3432() {
        let mut value: toml::Value = toml::from_str(
            r#"
tier = "smart"
api_key = "legacy-top-level-secret"
[reranker]
enabled = true
api_key = "reranker-secret-must-not-leak"
[llm]
backend = "xai"
api_key_env = "XAI_API_KEY"
[llm.auto_tag]
api_key = "auto-tag-secret-must-not-leak"
[hooks.subscription]
hmac_secret = "hmac-secret-must-not-leak"
"#,
        )
        .expect("fixture parses");
        redact_toml_value(&mut value);
        let rendered = toml::to_string_pretty(&value).expect("render");
        for secret in [
            "legacy-top-level-secret",
            "reranker-secret-must-not-leak",
            "auto-tag-secret-must-not-leak",
            "hmac-secret-must-not-leak",
        ] {
            assert!(
                !rendered.contains(secret),
                "leaked {secret} in:\n{rendered}"
            );
        }
        // ALLOWED: the shape stays readable and the pointer stays visible.
        assert!(rendered.contains("tier = \"smart\""), "{rendered}");
        assert!(rendered.contains("backend = \"xai\""), "{rendered}");
        assert!(
            rendered.contains("api_key_env = \"XAI_API_KEY\""),
            "the env pointer must stay visible: {rendered}"
        );
        assert!(rendered.contains("enabled = true"), "{rendered}");
        assert!(rendered.contains(CONFIG_REDACTION_MASK), "{rendered}");
    }

    #[test]
    fn non_string_secret_scalars_are_masked_too_3432() {
        let mut value: toml::Value =
            toml::from_str("api_key = 1234567890\n").expect("fixture parses");
        redact_toml_value(&mut value);
        let rendered = toml::to_string_pretty(&value).expect("render");
        assert!(!rendered.contains("1234567890"), "{rendered}");
    }

    #[test]
    fn line_redaction_covers_toml_and_json_shapes_3432() {
        assert_eq!(
            redact_config_line("api_key = \"sk-must-not-leak\"").trim(),
            format!("api_key = \"{CONFIG_REDACTION_MASK}\"")
        );
        let json = redact_config_line("+      \"ANTHROPIC_API_KEY\": \"sk-must-not-leak\",");
        assert!(!json.contains("sk-must-not-leak"), "{json}");
        assert!(json.ends_with(','), "the JSON comma must survive: {json}");
        // Pointer + ordinary values pass through untouched.
        assert_eq!(
            redact_config_line("api_key_env = \"XAI_API_KEY\""),
            "api_key_env = \"XAI_API_KEY\""
        );
        assert_eq!(
            redact_config_line("base_url = \"http://127.0.0.1:11434\""),
            "base_url = \"http://127.0.0.1:11434\""
        );
        assert_eq!(redact_config_line("[reranker]"), "[reranker]");
    }

    /// AMENDMENT 1 (DENIED) — a MINIFIED client config puts the whole tree
    /// on one line, so the first `:` sits after `"mcpServers"`. The
    /// pre-amendment first-separator rule never reached the credential, and
    /// the value here is deliberately NOT vendor-shaped so the value-shape
    /// backstop cannot rescue it either.
    #[test]
    fn minified_single_line_json_masks_every_secret_pair_3432() {
        let line = concat!(
            r#"{"theme":"dark","mcpServers":{"x":{"command":"b","env":"#,
            r#"{"ANTHROPIC_API_KEY":"plain-value-3432","HMAC_SECRET":"other-plain-3432"}}}}"#
        );
        let got = redact_config_line(line);
        assert!(!got.contains("plain-value-3432"), "leaked: {got}");
        assert!(!got.contains("other-plain-3432"), "leaked: {got}");
        // ALLOWED: the structure and the non-secret values still read.
        assert!(got.contains(r#""ANTHROPIC_API_KEY""#), "{got}");
        assert!(got.contains(r#""HMAC_SECRET""#), "{got}");
        assert!(got.contains(r#""theme":"dark""#), "{got}");
        assert!(got.contains(r#""command":"b""#), "{got}");
        assert_eq!(
            got.matches(CONFIG_REDACTION_MASK).count(),
            2,
            "both pairs must be masked, not just the first: {got}"
        );
    }

    /// AMENDMENT 1 (DENIED) — a TOML inline table has the same shape: the
    /// first `=` belongs to the non-secret outer key.
    #[test]
    fn toml_inline_table_masks_the_nested_secret_3432() {
        let got = redact_config_line(r#"auth = { user = "alice", token = "plain-inline-3432" }"#);
        assert!(!got.contains("plain-inline-3432"), "leaked: {got}");
        assert!(got.contains(r#"user = "alice""#), "{got}");
        assert!(got.contains("token = "), "{got}");
    }

    /// A `:` inside a quoted value is NOT a separator — the scan is
    /// quote-aware, so a URL keeps its port.
    #[test]
    fn quoted_colon_is_not_a_separator_3432() {
        assert_eq!(
            redact_config_line(r#"base_url = "http://127.0.0.1:11434""#),
            r#"base_url = "http://127.0.0.1:11434""#
        );
    }

    /// AMENDMENT 2 (DENIED) — `serde`'s `invalid type` message embeds the
    /// unexpected VALUE in the body, outside any gutter, and a numeric
    /// secret is not vendor-shaped so the value-shape screen misses it.
    #[test]
    fn parse_error_masks_a_value_embedded_in_the_message_body_3432() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct HasStringSecret {
            hmac_secret: String,
        }
        let err = toml::from_str::<HasStringSecret>("hmac_secret = 987654321321\n")
            .expect_err("an integer where a string is expected must fail");
        let raw = err.to_string();
        assert!(
            raw.contains("987654321321"),
            "fixture precondition: the raw Display must embed the value, got: {raw}"
        );
        let redacted = redact_parse_error(&err);
        assert!(
            !redacted.contains("987654321321"),
            "the message body leaked the value: {redacted}"
        );
        // ALLOWED: the class and the `expected …` tail survive.
        assert!(redacted.contains("invalid type"), "{redacted}");
        assert!(redacted.contains("expected"), "{redacted}");
    }

    /// An UNTERMINATED delimiter must mask to end-of-string, never fall
    /// through — a truncated message must not be how a payload survives.
    #[test]
    fn unterminated_quote_masks_to_end_of_string_3432() {
        let got = mask_quoted_payloads("invalid value `dangling-secret-3432");
        assert!(!got.contains("dangling-secret-3432"), "{got}");
        assert!(got.contains(CONFIG_REDACTION_MASK), "{got}");
    }

    #[test]
    fn parse_error_drops_the_echoed_source_line_3432() {
        let err = toml::from_str::<toml::Value>("api_key = \"sekrit-must-not-leak\"unclosed\n")
            .expect_err("fixture must fail to parse");
        let redacted = redact_parse_error(&err);
        assert!(
            !redacted.contains("sekrit-must-not-leak"),
            "the echoed source line leaked: {redacted}"
        );
        // ALLOWED: the position survives, so the operator can still fix it.
        assert!(
            redacted.contains("line") || redacted.contains("TOML parse error"),
            "the position must survive: {redacted}"
        );
        assert!(!redacted.contains('\n'), "must be one line: {redacted}");
    }

    #[test]
    fn parse_error_keeps_a_message_containing_a_pipe_3432() {
        // A diagnosis line that merely contains `|` is not a gutter row, so
        // the line SURVIVES the gutter filter. Its backticked payloads are
        // then masked by amendment 2 — the accepted cost of not having to
        // guess which quoted spans are identifiers and which are values.
        let got = redact_parse_error("expected one of `a` | `b`");
        assert!(got.starts_with("expected one of "), "{got}");
        assert!(got.contains(" | "), "the prose structure survives: {got}");
        assert_eq!(
            got.matches(CONFIG_REDACTION_MASK).count(),
            2,
            "both backticked payloads must be masked: {got}"
        );
    }
}
