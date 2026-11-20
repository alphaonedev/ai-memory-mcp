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

/// #9636 — the one hidden-character list of the crate: the format controls
/// above plus the line and paragraph separators U+2028/U+2029. Every printer
/// of stored or peer text calls this (the YAML encoder below and the
/// `ai-memory verify` text and JSON printers); `hidden_char_list_ratchet_9636`
/// fails when a second list appears under `src/`.
pub(crate) const fn is_hidden_text_char(c: char) -> bool {
    is_yaml_format_control(c) || matches!(c, '\u{2028}' | '\u{2029}')
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
                    || is_hidden_text_char(c)
                    || matches!(c, '\u{fffe}' | '\u{ffff}') =>
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

/// #9636 class ratchet: one hidden-character list under `src/`. A char
/// literal whose scalar `is_hidden_text_char` accepts, written next to `|`
/// or `..=`, is a member of a pattern list; only this file may hold one.
#[cfg(test)]
mod hidden_char_list_ratchet_9636_tests {
    use super::is_hidden_text_char;
    use std::path::{Path, PathBuf};

    /// The file that holds the one list.
    const ONE_LIST_FILE: &str = "src/yaml_frontmatter.rs";

    /// Lists that exist at base 6c67b17b and are tracked for removal; each
    /// count may only fall. PRE-EXISTING: #9664 (the FTS sanitizer list).
    const BASELINED_LISTS: &[(&str, usize)] = &[("src/storage/mod.rs", 16)];

    /// The longest hex run of a `\u{..}` escape.
    const MAX_ESCAPE_HEX_DIGITS: usize = 6;

    /// Scalars of the char literals on one line, with the byte span of each.
    fn char_literals(line: &str) -> Vec<(usize, usize, char)> {
        const ESCAPE_OPEN: &str = "'\\u{";
        const ESCAPE_CLOSE: &str = "}'";
        let mut found = Vec::new();
        let mut at = 0;
        while let Some(offset) = line[at..].find('\'') {
            let start = at + offset;
            let rest = &line[start..];
            if let Some(body) = rest.strip_prefix(ESCAPE_OPEN) {
                if let Some(close) = body.find(ESCAPE_CLOSE) {
                    let hex = &body[..close];
                    let scalar = (1..=MAX_ESCAPE_HEX_DIGITS)
                        .contains(&hex.len())
                        .then(|| u32::from_str_radix(hex, 16).ok())
                        .flatten()
                        .and_then(char::from_u32);
                    if let Some(c) = scalar {
                        let end = start + ESCAPE_OPEN.len() + close + ESCAPE_CLOSE.len();
                        found.push((start, end, c));
                        at = end;
                        continue;
                    }
                }
            } else {
                let mut chars = rest[1..].chars();
                if let (Some(c), Some('\'')) = (chars.next(), chars.next())
                    && c != '\\'
                    && c != '\''
                {
                    let end = start + 1 + c.len_utf8() + 1;
                    found.push((start, end, c));
                    at = end;
                    continue;
                }
            }
            at = start + 1;
        }
        found
    }

    /// Hidden char literals in pattern-list position in `text`.
    fn list_members(text: &str) -> usize {
        text.lines()
            .map(|line| {
                char_literals(line)
                    .into_iter()
                    .filter(|&(start, end, c)| {
                        let before = line[..start].trim_end();
                        let after = line[end..].trim_start();
                        is_hidden_text_char(c)
                            && (before.ends_with('|')
                                || before.ends_with("..=")
                                || after.starts_with('|')
                                || after.starts_with("..="))
                    })
                    .count()
            })
            .sum()
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn hidden_char_list_scanner_reads_list_forms_9636() {
        let cases: &[(&str, usize)] = &[
            ("    '\\u{200b}'..='\\u{200f}'", 2),
            ("        | '\\u{feff}'", 1),
            ("matches!(c, '\\u{2028}' | '\\u{2029}')", 2),
            ("matches!(c, '\u{200b}' | 'a')", 1),
            ("    '\\u{61c}'", 0),
            ("s.contains('\\u{2028}')", 0),
            ("'\\u{41}' | '\\u{42}'", 0),
            ("\"\\\\u{200b}\" | x", 0),
            ("'\\u{zz}' | '\\u{110000}' | '\\u{1234567}'", 0),
            ("'\\'' | '\\u{e007f}'", 1),
        ];
        for (text, want) in cases {
            assert_eq!(list_members(text), *want, "{text}");
        }
    }

    #[test]
    fn hidden_char_list_ratchet_9636() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_files(&root.join("src"), &mut files);
        files.sort();
        let mut one_list_members = 0;
        let mut extra = Vec::new();
        for path in &files {
            let rel = path
                .strip_prefix(root)
                .expect("under the crate root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{rel}: {e}"));
            let got = list_members(&text);
            if rel == ONE_LIST_FILE {
                one_list_members = got;
                continue;
            }
            let allowed = BASELINED_LISTS
                .iter()
                .find(|(file, _)| *file == rel)
                .map_or(0, |&(_, count)| count);
            if got > allowed {
                extra.push(format!(
                    "{rel}: {got} hidden-char list members (allowed {allowed})"
                ));
            }
        }
        assert!(one_list_members > 0, "{ONE_LIST_FILE} holds no list");
        assert!(
            extra.is_empty(),
            "a second hidden-character list: call crate::yaml_frontmatter::is_hidden_text_char instead: {extra:?}"
        );
    }
}
