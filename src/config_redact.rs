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

/// Redact one line of line-oriented config output (a diff line, a log
/// line, a rendered `key = value` pair).
///
/// Handles TOML (`api_key = "…"`) and JSON (`"ANTHROPIC_API_KEY": "…"`)
/// with one rule: everything to the right of the first `=` / `:` is
/// masked when the left side names a secret. A line with no separator —
/// a `[section]` header, a brace, a comment — still goes through the
/// value-shape backstop.
#[must_use]
pub fn redact_config_line(line: &str) -> Cow<'_, str> {
    if let Some(sep_at) = line.find(['=', ':']) {
        let (lhs, rhs) = line.split_at(sep_at);
        let key = lhs
            .trim()
            // Tolerate a unified-diff marker and JSON/TOML quoting so the
            // same rule works on `+  "ANTHROPIC_API_KEY"` and on `api_key`.
            .trim_start_matches(['+', '-', ' '])
            .trim()
            .trim_matches(['"', '\'']);
        if is_secret_value_key(key) {
            // Preserve the separator and a trailing JSON comma so the
            // redacted diff still reads as the shape it replaced.
            let separator = rhs.chars().next().unwrap_or('=');
            let trailing = if rhs.trim_end().ends_with(',') {
                ","
            } else {
                ""
            };
            return Cow::Owned(format!(
                "{lhs}{separator} \"{CONFIG_REDACTION_MASK}\"{trailing}"
            ));
        }
    }
    match crate::secret_screen::redact_for_storage(line) {
        Some(screened) => Cow::Owned(screened),
        None => Cow::Borrowed(line),
    }
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
#[must_use]
pub fn redact_parse_error<E: std::fmt::Display + ?Sized>(err: &E) -> String {
    let rendered = err.to_string();
    let kept: Vec<&str> = rendered
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_source_echo_line(line))
        .collect();
    let joined = kept.join("; ");
    crate::secret_screen::redact_for_storage(&joined).unwrap_or(joined)
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
        // A diagnosis line that merely contains `|` is not a gutter row.
        assert_eq!(
            redact_parse_error("expected one of `a` | `b`"),
            "expected one of `a` | `b`"
        );
    }
}
