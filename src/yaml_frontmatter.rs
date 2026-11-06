//! Shared crate-internal YAML frontmatter scalar encoder (#8493).
//!
//! One encoder serves every Markdown-with-frontmatter renderer
//! (`export_reflections`, `persona`); there is no second copy.

/// API-09: distinguish string fields from schema-defined timestamps.
#[derive(Clone, Copy)]
pub(crate) enum YamlScalarKind {
    StoredString,
    Timestamp,
}

/// Unicode 18 `General_Category=Cf`, including supplementary-plane controls.
/// Source: unicode.org/Public/18.0.0/ucd/extracted/DerivedGeneralCategory.txt.
/// CONST-01: this classification depends only on the scalar value.
const fn is_yaml_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// Named conservative plain-string alphabet for YAML 1.1 and 1.2 readers.
const SAFE_PLAIN_PUNCTUATION: &[u8] = b" -_./";
const SAFE_PLAIN_RESERVED_WORDS: &[&str] = &[
    "null", "~", "true", "false", "yes", "no", "on", "off", "y", "n",
];
// CONST-01: the canonical lowercase UUID form is exactly 8-4-4-4-12 hex digits.
const CANONICAL_UUID_GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];
const YAML_TIMESTAMP_YEARS: std::ops::RangeInclusive<i32> = 1..=9999;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// OWNERSHIP-05: validate borrowed UUID groups without parsing or reformatting.
fn yaml_canonical_uuid(s: &str) -> bool {
    let mut groups = s.split('-');
    for length in CANONICAL_UUID_GROUP_LENGTHS {
        let Some(group) = groups.next() else {
            return false;
        };
        if group.len() != length
            || !group
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return false;
        }
    }
    groups.next().is_none()
}

/// TOOL-03: plain strings are canonical lowercase UUIDs or letter-leading safe
/// ASCII values, with slash allowed only inside the latter form.
/// OWNERSHIP-05: inspect borrowed bytes without allocating a lowercase copy.
/// R3: reader-specific regressions extend the test table, not this predicate.
fn yaml_safe_plain(s: &str) -> bool {
    yaml_canonical_uuid(s)
        || (s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && s.trim() == s
            && !s.ends_with('/')
            && s.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || SAFE_PLAIN_PUNCTUATION.contains(&byte))
            && !SAFE_PLAIN_RESERVED_WORDS
                .iter()
                .any(|word| s.eq_ignore_ascii_case(word)))
}

/// Quote strings outside `SAFE_PLAIN` and escape controls without line folding.
/// U+FFFE/U+FFFF also require escapes because YAML excludes them from printable text.
/// Schema timestamps retain plain bytes only for years 0001-9999 and seconds 00-59.
pub(crate) fn yaml_scalar(s: &str, kind: YamlScalarKind) -> String {
    use chrono::{Datelike as _, Timelike as _};
    use std::fmt::Write as _;

    let plain_timestamp = matches!(kind, YamlScalarKind::Timestamp)
        && s.is_ascii()
        && s.trim() == s
        && !s.bytes().any(|byte| byte.is_ascii_control())
        && chrono::DateTime::parse_from_rfc3339(s).is_ok_and(|timestamp| {
            // Chrono encodes a leap second as second 59 with excess nanoseconds.
            YAML_TIMESTAMP_YEARS.contains(&timestamp.year())
                && timestamp.nanosecond() < NANOS_PER_SECOND
        });
    let needs_quote = !yaml_safe_plain(s) && !plain_timestamp;
    if needs_quote {
        let mut escaped = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control()
                    || is_yaml_format_control(c)
                    || matches!(c, '\u{2028}' | '\u{2029}' | '\u{fffe}' | '\u{ffff}') =>
                {
                    // YAML 1.2 §5.7: \u has exactly four hex digits; \U has eight.
                    // ERRORS-19: fmt::Write for String is infallible.
                    let _ = if u16::try_from(c).is_ok() {
                        write!(escaped, "\\u{:04x}", u32::from(c))
                    } else {
                        write!(escaped, "\\U{:08x}", u32::from(c))
                    };
                }
                c => escaped.push(c),
            }
        }
        escaped.push('"');
        escaped
    } else {
        s.to_string()
    }
}

#[cfg(test)]
// R3 class ratchet: add reader-specific forms here, never a production denylist arm.
// Columns: stored value, safe plain string, created_at-only timestamp exception.
pub(crate) const YAML_SCHEMA_FORMS_8605_R7: &[(&str, bool, bool)] = &[
    ("", false, false),
    ("~", false, false),
    ("null", false, false),
    ("NULL", false, false),
    ("NuLl", false, false),
    ("true", false, false),
    ("FALSE", false, false),
    ("TrUe", false, false),
    ("yes", false, false),
    ("NO", false, false),
    ("oN", false, false),
    ("Off", false, false),
    ("2026", false, false),
    ("0", false, false),
    ("01", false, false),
    ("184467440737095516160", false, false),
    ("1.0", false, false),
    (".5", false, false),
    ("5.", false, false),
    ("0x1f", false, false),
    ("0o17", false, false),
    ("1e3", false, false),
    ("1E-3", false, false),
    (".inf", false, false),
    (".INF", false, false),
    (".nan", false, false),
    (".NaN", false, false),
    ("+1", false, false),
    ("-1", false, false),
    ("+word", false, false),
    ("-word", false, false),
    ("0b101", false, false),
    ("0b0", false, false),
    ("1_000", false, false),
    ("0x_1F", false, false),
    ("1_0.5", false, false),
    ("1:30", false, false),
    ("190:20:30.15", false, false),
    ("2026-11-05", false, false),
    ("=", false, false),
    ("<<", false, false),
    ("y", false, false),
    ("Y", false, false),
    ("n", false, false),
    ("N", false, false),
    ("plain title", true, false),
    ("source-id", true, false),
    ("unsigned", true, false),
    ("plain-id", true, false),
    ("yaml-export", true, false),
    ("ai:test", false, false),
    ("2026-01-01T00:00:00Z", false, true),
    ("\u{fffe}", false, false),
    ("\u{ffff}", false, false),
    ("123e4567-e89b-42d3-a456-426614174000", true, false),
    ("abcdef01-2345-4678-9abc-def012345678", true, false),
    ("123E4567-E89B-42D3-A456-426614174000", false, false),
    ("123e4567-e89b-42d3-a456-42661417400", false, false),
    ("123e4567-e89b-42d3-a456-42661417400g", false, false),
    ("team/alpha", true, false),
    ("/team", false, false),
    ("team/", false, false),
    ("What's next?", false, false),
    ("lesson (draft)", false, false),
    ("Café notes", false, false),
    ("1234-12-12", false, false),
    ("12:34:56", false, false),
    ("1e5", false, false),
    ("2026-06-30T23:59:60Z", false, false),
    ("0000-01-01T00:00:00Z", false, false),
    ("0001-01-01T00:00:00Z", false, true),
    ("9999-12-31T23:59:59Z", false, true),
];
