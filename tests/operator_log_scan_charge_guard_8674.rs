// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8674: every search an operator-log scanner makes is charged to the
//! cfg(test) work counter, so the op-count bounds in
//! `src/logging/scan_work_tests.rs` see all scanner work. A search that is not
//! the first argument of a charged call, and is not named in [`ALLOWED`] with
//! the charge that covers it, fails here with its exact `file:line`.
//! Deterministic: this reads source text and never measures time.

use std::path::Path;

/// Scanner files read whole.
const SCANNER_FILES: &[&str] = &["src/logging/url_scan.rs", "src/logging/credential_scan.rs"];
/// The file whose named scanner functions are read; the rest of it is not a scanner.
const LOGGING_FILE: &str = "src/logging.rs";
const LOGGING_SCANNERS: &[&str] = &[
    "redact_url_password",
    "redact_urls_in_message",
    "map_urls_in_message",
    "redact_bare_targets",
    "connection_value_end",
    "map_url_runs",
    "next_url_span",
    "credentialed_authority",
    "render_operator_url",
];
/// Calls that charge the search passed as their first argument.
const CHARGED_CALLS: &[&str] = &["charged_find", "charged_rfind"];
/// Methods whose cost grows with the haystack.
const SEARCH_METHODS: &[&str] = &[
    "find",
    "rfind",
    "find_map",
    "contains",
    "matches",
    "rmatches",
    "match_indices",
    "rmatch_indices",
    "position",
    "rposition",
    "lines",
];
/// Method families: every `split*`, `rsplit*` and `trim*` spelling.
const SEARCH_FAMILIES: &[&str] = &["split", "rsplit", "trim"];
/// Prefix and suffix probes cost a constant only with a constant-width needle.
const NEEDLE_PROBES: &[&str] = &["starts_with", "ends_with", "strip_prefix", "strip_suffix"];
/// Iterators that walk the haystack, unless only one end element is taken.
const WALKING_ITERATORS: &[&str] = &["chars", "bytes", "char_indices"];
/// One end element is constant work (`Chars::last` is `next_back`).
const ONE_ELEMENT: &[&str] = &["next", "next_back", "last"];

/// `(file, method, trimmed source line, the charge that covers it)`.
type Allowed = (&'static str, &'static str, &'static str, &'static str);

const URL_SCAN: &str = "src/logging/url_scan.rs";
const CREDENTIAL_SCAN: &str = "src/logging/credential_scan.rs";

/// Reviewed uncharged forms. A row that no finding matches is itself a failure.
const ALLOWED: &[Allowed] = &[
    (
        URL_SCAN,
        "char_indices",
        "for (offset, ch) in text.char_indices() {",
        "the cursor charges offset + 3 on a hit and text.len() on a miss",
    ),
    (
        URL_SCAN,
        "char_indices",
        "for (relative, ch) in text[authority_start..].char_indices() {",
        "the authority cursor charges `examined - authority_start` after the loop",
    ),
    (
        URL_SCAN,
        "contains",
        "if CREDENTIAL_LINE_ENDS.contains(&ch)",
        "fixed two-entry table lookup per cursor byte",
    ),
    (
        URL_SCAN,
        "contains",
        "if whitespace || AUTHORITY_TERMINATORS.contains(&ch) {",
        "fixed three-entry table lookup per cursor byte",
    ),
    (
        URL_SCAN,
        "contains",
        "if AUTHORITY_TERMINATORS.contains(&ch) && run.authority_end == text.len() {",
        "fixed three-entry table lookup per cursor byte",
    ),
    (
        URL_SCAN,
        "contains",
        "if KEYLESS_URL_TERMINATORS.contains(&ch) {",
        "fixed three-entry table lookup per cursor byte",
    ),
    (
        URL_SCAN,
        "contains",
        "if whitespace || KEYLESS_URL_TERMINATORS.contains(&ch) {",
        "fixed three-entry table lookup per cursor byte",
    ),
    (
        URL_SCAN,
        "contains",
        "if AUTHORITY_TERMINATORS.contains(&ch) {",
        "fixed three-entry table lookup per cursor byte",
    ),
    (
        CREDENTIAL_SCAN,
        "char_indices",
        "for (offset, separator) in msg.char_indices() {",
        "the separator cursor charges msg.len() before the loop",
    ),
    (
        CREDENTIAL_SCAN,
        "trim_start",
        "let start = msg.len() - value.trim_start().len();",
        "charged with the value as `start - offset + end + 1`",
    ),
    (
        CREDENTIAL_SCAN,
        "trim_end",
        "let prefix = prefix.trim_end();",
        "charged as `untrimmed - prefix.len() + 1`",
    ),
    (
        CREDENTIAL_SCAN,
        "rsplit_once",
        ".rsplit_once(|ch: char| {",
        "charged as `key.len() + 1`: the backward walk stops after the key",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "!(folded.is_alphanumeric() || CREDENTIAL_KEY_PUNCTUATION.contains(&folded))",
        "fixed two-entry table lookup per key character",
    ),
    (
        CREDENTIAL_SCAN,
        "chars",
        ".chars()",
        "normalization walk, charged as key.len()",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        ".filter(|ch| !CREDENTIAL_KEY_PUNCTUATION.contains(ch))",
        "fixed two-entry table lookup per key character",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "EXACT_CREDENTIAL_KEYS.contains(&normalized.as_str())",
        "charged as the sum of the exact key lengths",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        ".any(|name| normalized.contains(name))",
        "charged as normalized.len() per credential noun",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "let folded = if (FULLWIDTH_ASCII_START..=FULLWIDTH_ASCII_END).contains(&code) {",
        "constant range test",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "} else if (MATHEMATICAL_LATIN_START..=MATHEMATICAL_LATIN_END).contains(&code) {",
        "constant range test",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "} else if (MATHEMATICAL_DIGIT_START..=MATHEMATICAL_DIGIT_END).contains(&code) {",
        "constant range test",
    ),
    (
        CREDENTIAL_SCAN,
        "find",
        "} else if let Some((_, folded)) = LETTERLIKE_LATIN.iter().find(|(letter, _)| *letter == ch) {",
        "fixed 32-entry table lookup per key character",
    ),
    (
        CREDENTIAL_SCAN,
        "contains",
        "} else if CREDENTIAL_KEY_DASHES.contains(&ch) {",
        "fixed eight-entry table lookup per key character",
    ),
    (
        LOGGING_FILE,
        "char_indices",
        "for (offset, ch) in value.char_indices() {",
        "connection_value_end: the caller charges `start - offset + end + 1`",
    ),
    (
        LOGGING_FILE,
        "contains",
        "} else if quote.is_none() && CREDENTIAL_LINE_ENDS.contains(&ch) {",
        "fixed two-entry table lookup per value byte",
    ),
];

/// One uncharged search: `(file, 1-based line, method, trimmed source line)`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    method: String,
    text: String,
}

/// Replace comment text and literal contents with spaces, keeping every byte
/// offset, every newline and the literal delimiters.
fn blank_comments_and_literals(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let blank = |out: &mut String, ch: char| {
        if ch == '\n' {
            out.push('\n');
        } else {
            out.extend(std::iter::repeat_n(' ', ch.len_utf8()));
        }
    };
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                blank(&mut out, chars[i]);
                i += 1;
            }
        } else if ch == '/' && next == Some('*') {
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                blank(&mut out, chars[i]);
                i += 1;
            }
            for _ in 0..2 {
                if let Some(&end) = chars.get(i) {
                    blank(&mut out, end);
                    i += 1;
                }
            }
        } else if ch == 'r' && matches!(next, Some('"' | '#')) && is_raw_string_start(&chars, i) {
            let hashes = chars[i + 1..].iter().take_while(|c| **c == '#').count();
            let open = i + 1 + hashes;
            out.push('r');
            out.extend(std::iter::repeat_n('#', hashes));
            out.push('"');
            i = open + 1;
            while i < chars.len() {
                let closes = chars[i] == '"'
                    && chars[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|c| **c == '#')
                        .count()
                        == hashes;
                if closes {
                    out.push('"');
                    out.extend(std::iter::repeat_n('#', hashes));
                    i += 1 + hashes;
                    break;
                }
                blank(&mut out, chars[i]);
                i += 1;
            }
        } else if ch == '"' {
            out.push('"');
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    blank(&mut out, chars[i]);
                    i += 1;
                }
                if let Some(&inner) = chars.get(i) {
                    blank(&mut out, inner);
                    i += 1;
                }
            }
            if i < chars.len() {
                out.push('"');
                i += 1;
            }
        } else if ch == '\'' && char_literal_end(&chars, i).is_some() {
            let end = char_literal_end(&chars, i).unwrap_or(i);
            out.push('\'');
            for &inner in &chars[i + 1..end] {
                blank(&mut out, inner);
            }
            out.push('\'');
            i = end + 1;
        } else {
            out.push(ch);
            i += 1;
        }
    }
    out
}

/// `r"`, `r#"` start a raw string only when `r` does not end an identifier.
fn is_raw_string_start(chars: &[char], at: usize) -> bool {
    let after = chars[at + 1..].iter().find(|c| **c != '#');
    let joined = at > 0 && (chars[at - 1].is_alphanumeric() || chars[at - 1] == '_');
    after == Some(&'"') && !joined
}

/// Index of the closing quote of a char literal at `at`; `None` for a lifetime.
fn char_literal_end(chars: &[char], at: usize) -> Option<usize> {
    match chars.get(at + 1)? {
        '\\' => (at + 2..chars.len().min(at + 14)).find(|&j| chars[j] == '\'' && j > at + 2),
        _ => (chars.get(at + 2) == Some(&'\'')).then_some(at + 2),
    }
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Byte ranges of the named functions, signature through closing brace.
fn function_ranges(clean: &str, names: &[&str]) -> Result<Vec<std::ops::Range<usize>>, String> {
    let bytes = clean.as_bytes();
    let mut ranges = Vec::new();
    for name in names {
        let needle = format!("fn {name}");
        let starts: Vec<usize> = clean
            .match_indices(&needle)
            .map(|(at, _)| at)
            .filter(|&at| {
                let end = at + needle.len();
                (at == 0 || !is_ident(bytes[at - 1]))
                    && bytes.get(end).is_some_and(|b| matches!(b, b'(' | b'<'))
            })
            .collect();
        let [start] = starts[..] else {
            return Err(format!(
                "scanner `{name}` must be defined exactly once, found {}",
                starts.len()
            ));
        };
        let open = clean[start..]
            .find('{')
            .map(|at| start + at)
            .ok_or_else(|| format!("scanner `{name}` has no body"))?;
        let mut depth = 0usize;
        let mut close = None;
        for (at, byte) in bytes.iter().enumerate().skip(open) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(at + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.ok_or_else(|| format!("scanner `{name}` body is unbalanced"))?;
        ranges.push(start..close);
    }
    Ok(ranges)
}

/// True when the call at `dot` is the first argument of a charged call.
fn first_argument_of_charged_call(clean: &str, dot: usize) -> bool {
    let bytes = clean.as_bytes();
    let (mut parens, mut braces) = (0usize, 0usize);
    let mut comma = false;
    let mut at = dot;
    while at > 0 {
        at -= 1;
        match bytes[at] {
            b')' => parens += 1,
            b'(' if parens > 0 => parens -= 1,
            b'(' => {
                let ident_end = clean[..at].trim_end().len();
                let ident_start = clean[..ident_end]
                    .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .map_or(0, |i| i + 1);
                if !comma && CHARGED_CALLS.contains(&&clean[ident_start..ident_end]) {
                    return true;
                }
                comma = false;
            }
            b',' if parens == 0 && braces == 0 => comma = true,
            b'}' => braces += 1,
            b'{' if braces > 0 => braces -= 1,
            b'{' => return false,
            b';' if parens == 0 && braces == 0 => return false,
            _ => {}
        }
    }
    false
}

/// The text between the `(` at `open` and its matching `)`.
fn argument_text(clean: &str, open: usize) -> Option<(&str, usize)> {
    let mut depth = 0usize;
    for (at, byte) in clean.bytes().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&clean[open + 1..at], at));
                }
            }
            _ => {}
        }
    }
    None
}

/// A literal, or a SCREAMING_CASE constant path, has a fixed width.
fn constant_width(argument: &str) -> bool {
    let argument = argument.trim().trim_start_matches('&');
    let last = argument.rsplit("::").next().unwrap_or(argument);
    argument.starts_with(['"', '\''])
        || argument.starts_with("b\"")
        || argument.starts_with("r\"")
        || argument.starts_with("r#")
        || (!last.is_empty()
            && last
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && last.bytes().any(|b| b.is_ascii_uppercase()))
}

/// The method name of a `.name(` call at `dot`, with the index of its `(`.
fn method_call(clean: &str, dot: usize) -> Option<(&str, usize)> {
    let bytes = clean.as_bytes();
    if dot > 0 && bytes[dot - 1] == b'.' {
        return None;
    }
    let name_end = (dot + 1..bytes.len())
        .find(|&i| !is_ident(bytes[i]))
        .unwrap_or(bytes.len());
    let name = &clean[dot + 1..name_end];
    if name.is_empty() || name.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let mut open = name_end;
    if clean[open..].starts_with("::<") {
        open += clean[open..].find('>')? + 1;
    }
    (bytes.get(open) == Some(&b'(')).then_some((name, open))
}

fn is_search(name: &str) -> bool {
    SEARCH_METHODS.contains(&name) || SEARCH_FAMILIES.iter().any(|f| name.starts_with(f))
}

/// Every uncharged search in `ranges` of `source`.
fn uncharged_searches(file: &str, source: &str, ranges: &[std::ops::Range<usize>]) -> Vec<Finding> {
    let clean = blank_comments_and_literals(source);
    let mut findings = Vec::new();
    for range in ranges {
        for (dot, _) in clean[range.clone()].match_indices('.') {
            let dot = range.start + dot;
            let Some((name, open)) = method_call(&clean, dot) else {
                continue;
            };
            let uncharged = if is_search(name) {
                !first_argument_of_charged_call(&clean, dot)
            } else if NEEDLE_PROBES.contains(&name) {
                argument_text(&clean, open).is_some_and(|(arg, _)| !constant_width(arg))
                    && !first_argument_of_charged_call(&clean, dot)
            } else if WALKING_ITERATORS.contains(&name) {
                let after = argument_text(&clean, open).map_or(open, |(_, close)| close + 1);
                let rest = clean[after..].trim_start();
                let one = rest.strip_prefix('.').and_then(|rest| {
                    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
                    Some(ONE_ELEMENT.contains(&&rest[..end]) && rest[end..].starts_with('('))
                });
                one != Some(true)
            } else {
                false
            };
            if uncharged {
                let line = source[..dot].matches('\n').count() + 1;
                let text = source.lines().nth(line - 1).unwrap_or_default().trim();
                findings.push(Finding {
                    file: file.to_owned(),
                    line,
                    method: name.to_owned(),
                    text: text.to_owned(),
                });
            }
        }
    }
    findings
}

/// Failures: each finding no row allows, then each row that allowed nothing.
fn audit(findings: &[Finding], allowed: &[Allowed]) -> Vec<String> {
    let mut used = vec![false; allowed.len()];
    let mut failures = Vec::new();
    for finding in findings {
        let row = allowed.iter().position(|(file, method, text, _)| {
            *file == finding.file && *method == finding.method && *text == finding.text
        });
        match row {
            Some(row) => used[row] = true,
            None => failures.push(format!(
                "{}:{}: uncharged `.{}(`: {}",
                finding.file, finding.line, finding.method, finding.text
            )),
        }
    }
    for ((file, method, text, _), used) in allowed.iter().zip(used) {
        if !used {
            failures.push(format!("{file}: stale allow-list row `.{method}(`: {text}"));
        }
    }
    failures
}

fn whole(source: &str) -> Vec<std::ops::Range<usize>> {
    vec![0..source.len()]
}

#[test]
fn every_operator_log_search_is_charged_8674() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |file: &str| {
        std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("#8674 read {file}: {e}"))
    };
    let mut findings = Vec::new();
    for file in SCANNER_FILES {
        let source = read(file);
        findings.extend(uncharged_searches(file, &source, &whole(&source)));
    }
    let logging = read(LOGGING_FILE);
    let clean = blank_comments_and_literals(&logging);
    let ranges = function_ranges(&clean, LOGGING_SCANNERS).unwrap_or_else(|e| panic!("#8674 {e}"));
    findings.extend(uncharged_searches(LOGGING_FILE, &logging, &ranges));
    let failures = audit(&findings, ALLOWED);
    assert!(
        failures.is_empty(),
        "#8674: an operator-log scanner search is not charged to the work counter; wrap it \
         in charged_find / charged_rfind, or allow it with the charge that covers it:\n{}",
        failures.join("\n")
    );
}

/// `(fixture body, the methods reported)`: each forbidden form is reported.
const FORBIDDEN: &[(&str, &[&str])] = &[
    ("let _ = text.find(':');", &["find"]),
    ("let _ = text.rfind('@');", &["rfind"]),
    (
        "let _ = std::hint::black_box(msg[..n].rfind('\\0'));",
        &["rfind"],
    ),
    ("let _ = text.contains(needle);", &["contains"]),
    ("let _ = text.split(':').next();", &["split"]),
    ("let _ = text.split_once(':');", &["split_once"]),
    ("let _ = text.rsplit_once(':');", &["rsplit_once"]),
    (
        "let _ = text.split_whitespace().count();",
        &["split_whitespace"],
    ),
    ("let _ = text.matches(':').count();", &["matches"]),
    ("let _ = text.rmatches(':').count();", &["rmatches"]),
    ("let _ = text.trim();", &["trim"]),
    ("let _ = text.trim_end_matches(' ');", &["trim_end_matches"]),
    ("let _ = text.starts_with(prefix);", &["starts_with"]),
    ("let _ = text.ends_with(&suffix[..n]);", &["ends_with"]),
    ("let _ = bytes.iter().position(|b| *b == 0);", &["position"]),
    (
        "let _ = bytes.iter().rposition(|b| *b == 0);",
        &["rposition"],
    ),
    ("for ch in text.chars() {}", &["chars"]),
    ("let _ = text.bytes().count();", &["bytes"]),
    ("for (i, ch) in text.char_indices() {}", &["char_indices"]),
    ("let _ = text\n        .find(':');", &["find"]),
    (
        "let _ = charged_find(a.find(x), a.find(y).unwrap_or(0));",
        &["find"],
    ),
    (
        "let _ = other(charged_find(a.find(x), n), b.find(y));",
        &["find"],
    ),
    (
        "let n = charged_find(a.find(x), n); let _ = b.find(y);",
        &["find"],
    ),
    ("let _ = f(|c| c == '('); let _ = a.find(x);", &["find"]),
    ("let _ = text.find::<char>(':');", &["find"]),
];

/// Each allowed form is not reported.
const PERMITTED: &[&str] = &[
    "let _ = charged_find(text.find(':'), text.len());",
    "let _ = url_scan::charged_rfind(text.rfind('@'), text.len());",
    "let _ = charged_find(\n        local[a..b].find(char::is_whitespace),\n        n,\n    );",
    "let _ = charged_find(std::hint::black_box(&msg[..n]).rfind('\\0'), n);",
    "let _ = text.starts_with(SCHEME_SEPARATOR);",
    "let _ = text.starts_with(super::SCHEME_SEPARATOR);",
    "let _ = text.starts_with(\"://\");",
    "let _ = text.ends_with('/');",
    "let _ = text.chars().next();",
    "let _ = text.chars().last();",
    "let _ = text.chars().next_back();",
    "// let _ = text.find(':');",
    "/* let _ = text.find(':'); */",
    "let _ = \"text.find(':')\";",
    "let _ = r#\"text.find(':')\"#;",
    "let _ = text[..n].len();",
    "let _ = text.len();",
];

fn fixture_methods(body: &str) -> Vec<String> {
    let source = format!("fn probe() {{\n    {body}\n}}\n");
    uncharged_searches("fixture.rs", &source, &whole(&source))
        .into_iter()
        .map(|finding| finding.method)
        .collect()
}

#[test]
fn charge_guard_reports_each_forbidden_form_8674() {
    for (body, expected) in FORBIDDEN {
        assert_eq!(
            fixture_methods(body),
            expected.to_vec(),
            "#8674 guard must report exactly {expected:?} in: {body}"
        );
    }
}

#[test]
fn charge_guard_passes_each_allowed_form_8674() {
    for body in PERMITTED {
        assert_eq!(
            fixture_methods(body),
            Vec::<String>::new(),
            "#8674 guard must not report: {body}"
        );
    }
}

#[test]
fn charge_guard_reports_line_stale_rows_and_missing_scanners_8674() {
    let source = "fn probe() {\n    let a = 1;\n    let _ = text.find(':');\n}\n";
    let findings = uncharged_searches("fixture.rs", source, &whole(source));
    let stale: &[Allowed] = &[("fixture.rs", "rfind", "gone();", "stale")];
    assert_eq!(
        audit(&findings, stale),
        vec![
            "fixture.rs:3: uncharged `.find(`: let _ = text.find(':');".to_owned(),
            "fixture.rs: stale allow-list row `.rfind(`: gone();".to_owned(),
        ]
    );
    let exact: &[Allowed] = &[("fixture.rs", "find", "let _ = text.find(':');", "fixture")];
    assert_eq!(audit(&findings, exact), Vec::<String>::new());
    let second = "fn probe() {\n    let _ = text.find(':').or(text.rfind(':'));\n}\n";
    let findings = uncharged_searches("fixture.rs", second, &whole(second));
    let one_method: &[Allowed] = &[(
        "fixture.rs",
        "find",
        "let _ = text.find(':').or(text.rfind(':'));",
        "fixture",
    )];
    assert_eq!(
        audit(&findings, one_method),
        vec![
            "fixture.rs:2: uncharged `.rfind(`: let _ = text.find(':').or(text.rfind(':'));"
                .to_owned()
        ]
    );
    let clean = blank_comments_and_literals(source);
    assert_eq!(
        function_ranges(&clean, &["absent"]),
        Err("scanner `absent` must be defined exactly once, found 0".to_owned())
    );
    let scoped = function_ranges(&clean, &["probe"]).expect("probe is defined once");
    assert_eq!(scoped, vec![0..source.len() - 1]);
}
