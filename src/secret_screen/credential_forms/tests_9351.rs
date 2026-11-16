// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9351 — an accepted non-credential shape is accepted only when the WHOLE
//! judged value, first byte to last, matches that shape's grammar.
//!
//! These cells live beside the helpers so the red table iterates the real
//! [`ENV_LOOKUP_PREFIXES`] and [`ANNOTATION_TYPE_NAMES`] tables (no hand copy):
//! a future entry is covered by construction. Every cell asserts the exact
//! redacted output and the exact finding kind, never "some finding".

use std::time::{Duration, Instant};

use super::{
    ANNOTATION_TYPE_NAMES, ENV_LOOKUP_PREFIXES, KIND_PASSWORD_ASSIGNMENT,
    KIND_URL_USERINFO_PASSWORD, redact_credential_forms,
};
use crate::secret_screen::REDACTION_PLACEHOLDER;

/// Obviously fake secret bytes (split so no contiguous literal is a token).
const SECRET: &str = concat!("Hn4r", "Xp7Qs2");
/// The env variable name every lookup cell reads.
const ENV_NAME: &str = "X";
/// The two assignment forms each cell runs.
const OPERATORS: [&str; 2] = ["=", ": "];
/// Text after the value on the same line, then a following line.
const SAME_LINE_TAIL: &str = " rest";
const NEXT_LINE: &str = "\nuser: bob";
/// A byte that no shape grammar accounts for after a closed shape.
const STRAY_BYTE: &str = "-";
/// Fallback operators that follow an env lookup in code.
const FALLBACK_TOKENS: [&str; 4] = ["or", "||", "??", "//"];
/// The bytes a reference annotation may never be followed by.
const REFERENCE_NEXT_BYTES: [char; 5] = ['.', '-', ':', '/', '@'];
/// The reference prefixes before the type name.
const REFERENCE_PREFIXES: [&str; 3] = ["&", "&'a ", "&mut "];
/// The bracket kinds of a type expression: opener, its closer, a wrong closer.
const TYPE_BRACKETS: [(char, char, char); 2] = [('<', '>', ']'), ('[', ']', '>')];
/// Size of every bound input, and the wall-clock ceiling of one scan of it.
const BOUND_INPUT_BYTES: usize = 100_000;
const LINEAR_SCAN_CEILING: Duration = Duration::from_secs(2);
/// Repeated unit of a malformed 100K tail (holds a byte no grammar accepts).
const MALFORMED_UNIT: &str = "Ab9!";
/// One bracket level past the walker's nesting cap of 64.
const NESTING_BEYOND_CAP: usize = 65;

/// The closer the head's last byte opens (`None` for the `process.env.` head).
fn closer_of(prefix: &str) -> Option<char> {
    match prefix.as_bytes().last() {
        Some(b'[') => Some(']'),
        Some(b'(') => Some(')'),
        Some(b'{') => Some('}'),
        _ => None,
    }
}

/// `(kinds, redacted)` of one input through the four detectors.
fn run(input: &str) -> (Vec<&'static str>, Option<String>) {
    let mut kinds = Vec::new();
    let out = redact_credential_forms(input, &mut kinds);
    (kinds, out)
}

/// Collect a mismatch line when `input` is not masked to exactly `expected`
/// with exactly `kind`.
fn check_masked(
    misses: &mut Vec<String>,
    name: &str,
    input: &str,
    expected: &str,
    kind: &'static str,
) {
    let (kinds, out) = run(input);
    if kinds != vec![kind] || out.as_deref() != Some(expected) {
        misses.push(format!(
            "{name}: {input:?} -> kinds {kinds:?}, out {out:?}; want {expected:?}"
        ));
    }
}

fn check_accepted(misses: &mut Vec<String>, name: &str, input: &str) {
    let (kinds, out) = run(input);
    if !kinds.is_empty() || out.is_some() {
        misses.push(format!("{name}: {input:?} must stay accepted, got {out:?}"));
    }
}

fn assert_no_misses(cell: &str, misses: &[String]) {
    assert!(
        misses.is_empty(),
        "9351 {cell}: {} cells failed:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// Every `ENV_LOOKUP_PREFIXES` entry x every tail form is a finding.
#[test]
fn env_lookup_every_prefix_tail_form_is_a_finding_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let mut misses = Vec::new();
    for p in ENV_LOOKUP_PREFIXES {
        let c = closer_of(p).map(String::from).unwrap_or_default();
        for op in OPERATORS {
            let token_masked = format!("password{op}{ph}{SAME_LINE_TAIL}{NEXT_LINE}");
            let line_masked = format!("password{op}{ph}{NEXT_LINE}");
            let mut forms = vec![
                (
                    "closer_then_bytes",
                    format!("{p}{ENV_NAME}{c}{STRAY_BYTE}{SECRET}"),
                    &token_masked,
                ),
                (
                    "quoted_name_then_bytes",
                    format!("{p}\"{ENV_NAME}\"{c}{SECRET}"),
                    &token_masked,
                ),
                (
                    "nested_open_bracket",
                    format!("{p}[{SECRET}]{c}"),
                    &token_masked,
                ),
            ];
            if !c.is_empty() {
                forms.push(("no_closer", format!("{p}{SECRET}"), &line_masked));
                forms.push((
                    "blank_then_bytes",
                    format!("{p}\"{ENV_NAME}\" {SECRET}{c}"),
                    &line_masked,
                ));
                forms.push((
                    "default_inside_lookup",
                    format!("{p}\"{ENV_NAME}\",\"{SECRET}\"{c}"),
                    &token_masked,
                ));
            }
            for (name, value, expected) in forms {
                let input = format!("password{op}{value}{SAME_LINE_TAIL}{NEXT_LINE}");
                check_masked(
                    &mut misses,
                    &format!("{p}/{name}"),
                    &input,
                    expected,
                    KIND_PASSWORD_ASSIGNMENT,
                );
            }
        }
    }
    assert_no_misses("env tail forms", &misses);
}

/// A trailing fallback after a whole lookup is a finding to the line end.
#[test]
fn env_lookup_every_prefix_fallback_is_a_finding_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let mut misses = Vec::new();
    for p in ENV_LOOKUP_PREFIXES {
        let lookup = match closer_of(p) {
            Some(c) => format!("{p}\"{ENV_NAME}\"{c}"),
            None => format!("{p}{ENV_NAME}"),
        };
        for op in OPERATORS {
            for fb in FALLBACK_TOKENS {
                let input = format!("password{op}{lookup} {fb} \"{SECRET}\"{NEXT_LINE}");
                let expected = format!("password{op}{ph}{NEXT_LINE}");
                check_masked(
                    &mut misses,
                    &format!("{p}/fallback {fb}"),
                    &input,
                    &expected,
                    KIND_PASSWORD_ASSIGNMENT,
                );
            }
        }
    }
    assert_no_misses("env fallback", &misses);
}

/// Positive control per entry: every well-formed lookup stays accepted.
#[test]
fn env_lookup_every_prefix_well_formed_is_accepted_9351() {
    let mut misses = Vec::new();
    for p in ENV_LOOKUP_PREFIXES {
        let lookups: Vec<String> = match closer_of(p) {
            Some(c) => vec![
                format!("{p}\"{ENV_NAME}\"{c}"),
                format!("{p}'{ENV_NAME}'{c}"),
                format!("{p}{ENV_NAME}{c}"),
                format!("{p}\"DB_PASSWORD\"{c}?"),
                format!("{p}\"{ENV_NAME}\"{c};"),
            ],
            None => vec![format!("{p}{ENV_NAME}"), format!("{p}DB_PASSWORD;")],
        };
        for lookup in lookups {
            for op in OPERATORS {
                let input = format!("password{op}{lookup}{SAME_LINE_TAIL}{NEXT_LINE}");
                check_accepted(&mut misses, p, &input);
            }
        }
    }
    assert_no_misses("env positive controls", &misses);
}

/// Measure one scan; it must finish under [`LINEAR_SCAN_CEILING`].
fn bounded_run(input: &str) -> (Vec<&'static str>, Option<String>) {
    let started = Instant::now();
    let out = run(input);
    let took = started.elapsed();
    assert!(
        took < LINEAR_SCAN_CEILING,
        "9351: one scan of {} bytes took {took:?}",
        input.len()
    );
    out
}

/// 100K: a malformed tail per entry is masked whole and a 100K well-formed
/// lookup per entry is accepted, each under the ceiling.
#[test]
fn env_lookup_every_prefix_100k_bounded_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let tail = MALFORMED_UNIT.repeat(BOUND_INPUT_BYTES / MALFORMED_UNIT.len());
    let long_name = ENV_NAME.repeat(BOUND_INPUT_BYTES);
    let mut misses = Vec::new();
    for p in ENV_LOOKUP_PREFIXES {
        let (bad, good) = match closer_of(p) {
            Some(c) => (
                format!("password={p}\"{ENV_NAME}\"{c}{tail}"),
                format!("password={p}\"{long_name}\"{c}"),
            ),
            None => (
                format!("password={p}{ENV_NAME}{tail}"),
                format!("password={p}{long_name}"),
            ),
        };
        let (kinds, out) = bounded_run(&bad);
        if kinds != vec![KIND_PASSWORD_ASSIGNMENT] || out != Some(format!("password={ph}")) {
            misses.push(format!("{p}/100k_tail: kinds {kinds:?}"));
        }
        let (kinds, out) = bounded_run(&good);
        if !kinds.is_empty() || out.is_some() {
            misses.push(format!("{p}/100k_well_formed: kinds {kinds:?}"));
        }
    }
    assert_no_misses("env 100K", &misses);
}

/// Every annotation type name x bracket kind x {unclosed, closed then bytes,
/// mismatched closer}, on the plain `:` path and the `&` path.
#[test]
fn type_annotation_every_name_bracket_form_is_a_finding_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let token_masked = format!("password: {ph}{SAME_LINE_TAIL}{NEXT_LINE}");
    let line_masked = format!("password: {ph}{NEXT_LINE}");
    let mut misses = Vec::new();
    for t in ANNOTATION_TYPE_NAMES {
        for (o, c, wrong) in TYPE_BRACKETS {
            let forms = [
                (
                    "unclosed",
                    format!("password: {t}{o}{ENV_NAME} {SECRET}{NEXT_LINE}"),
                    &line_masked,
                ),
                (
                    "closed_then_bytes",
                    format!("password: {t}{o}{ENV_NAME}{c}{SECRET}{SAME_LINE_TAIL}{NEXT_LINE}"),
                    &token_masked,
                ),
                (
                    "mismatched_closer",
                    format!("password: {t}{o}{ENV_NAME}{wrong}{SECRET}{SAME_LINE_TAIL}{NEXT_LINE}"),
                    &line_masked,
                ),
                (
                    "reference_closed_then_bytes",
                    format!("password: &{t}{o}{ENV_NAME}{c}{SECRET}{SAME_LINE_TAIL}{NEXT_LINE}"),
                    &line_masked,
                ),
            ];
            for (name, input, expected) in forms {
                check_masked(
                    &mut misses,
                    &format!("{t}{o}/{name}"),
                    &input,
                    expected,
                    KIND_PASSWORD_ASSIGNMENT,
                );
            }
        }
    }
    assert_no_misses("type bracket forms", &misses);
}

/// Positive control per type name: every well-formed annotation is accepted.
#[test]
fn type_annotation_every_name_well_formed_is_accepted_9351() {
    let mut misses = Vec::new();
    for t in ANNOTATION_TYPE_NAMES {
        let inputs = [
            format!("password: {t}"),
            format!("password: {t}<X>,{NEXT_LINE}"),
            format!("password: {t}<Option<X>>{SAME_LINE_TAIL}"),
            format!("password: {t}[X]"),
            format!("password: {t}<'a, X>"),
            format!("password: {t}<X::Y>;"),
            format!("password: {t}<X> = None"),
            format!("fn f(password: &{t}, pwd: &'a {t}<X>, passwd: &mut {t}) {{}}"),
        ];
        for input in inputs {
            check_accepted(&mut misses, t, &input);
        }
    }
    assert_no_misses("type positive controls", &misses);
}

/// `&` + type name + each byte a reference may not be followed by.
#[test]
fn reference_annotation_every_next_byte_is_a_finding_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let expected = format!("password: {ph}{NEXT_LINE}");
    let mut misses = Vec::new();
    for t in ANNOTATION_TYPE_NAMES {
        for pre in REFERENCE_PREFIXES {
            for b in REFERENCE_NEXT_BYTES {
                let input = format!("password: {pre}{t}{b}{SECRET}{SAME_LINE_TAIL}{NEXT_LINE}");
                check_masked(
                    &mut misses,
                    &format!("{pre}{t}{b}"),
                    &input,
                    &expected,
                    KIND_PASSWORD_ASSIGNMENT,
                );
            }
        }
    }
    assert_no_misses("reference next byte", &misses);
}

/// Type expressions at 100K: well-formed accepted, unclosed and over-nested
/// masked to the line end, each under the ceiling.
#[test]
fn type_annotation_100k_and_nesting_bounded_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let args = "X, ".repeat(BOUND_INPUT_BYTES / 3);
    let mut misses = Vec::new();
    let (kinds, out) = bounded_run(&format!("password: Option<{args}X>"));
    if !kinds.is_empty() || out.is_some() {
        misses.push(format!("100k_well_formed: kinds {kinds:?}"));
    }
    let cases = [
        (
            "100k_unclosed",
            format!("password: Option<{args}X{NEXT_LINE}"),
        ),
        (
            "100k_open_brackets",
            format!(
                "password: Option{}{NEXT_LINE}",
                "<".repeat(BOUND_INPUT_BYTES)
            ),
        ),
        (
            "nesting_beyond_cap",
            format!(
                "password: Option{}X{}{NEXT_LINE}",
                "<Vec".repeat(NESTING_BEYOND_CAP),
                ">".repeat(NESTING_BEYOND_CAP)
            ),
        ),
    ];
    for (name, input) in cases {
        let (kinds, out) = bounded_run(&input);
        if kinds != vec![KIND_PASSWORD_ASSIGNMENT]
            || out != Some(format!("password: {ph}{NEXT_LINE}"))
        {
            misses.push(format!("{name}: kinds {kinds:?}"));
        }
    }
    assert_no_misses("type 100K", &misses);
}

/// Sibling placeholder shapes judged by first and last byte: `${…}` is a
/// whole `${IDENT}` and `<…>` holds no inner `<` / `>`, on the assignment
/// and the URL userinfo paths.
#[test]
fn placeholder_shapes_judge_the_whole_value_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let mut misses = Vec::new();
    let rows = [
        (
            "brace_default",
            format!("password=${{X:-{SECRET}}}{SAME_LINE_TAIL}"),
            format!("password={ph}{SAME_LINE_TAIL}"),
            KIND_PASSWORD_ASSIGNMENT,
        ),
        (
            "brace_unclosed",
            format!("password=${{X:- {SECRET}}}{SAME_LINE_TAIL}{NEXT_LINE}"),
            format!("password={ph}{NEXT_LINE}"),
            KIND_PASSWORD_ASSIGNMENT,
        ),
        (
            "angle_closed_then_bytes",
            format!("password=<a>{SECRET}>{SAME_LINE_TAIL}"),
            format!("password={ph}{SAME_LINE_TAIL}"),
            KIND_PASSWORD_ASSIGNMENT,
        ),
        (
            "url_brace_default",
            format!("postgres://u:${{X:-{SECRET}}}@db/x"),
            format!("postgres://u:{ph}@db/x"),
            KIND_URL_USERINFO_PASSWORD,
        ),
    ];
    for (name, input, expected, kind) in rows {
        check_masked(&mut misses, name, &input, &expected, kind);
    }
    // #8855 r2 tightening (invariant (b)): an angle value is literal text and
    // a fallback is a finding even between two references; both were
    // accepted controls before round 2.
    for (name, input, expected) in [
        (
            "r2_angle_value",
            "password: <your-password>".to_string(),
            format!("password: {ph}"),
        ),
        (
            "r2_reference_fallback",
            "password=${DB_PASSWORD} or ${DB_PASSWORD}".to_string(),
            format!("password={ph}"),
        ),
    ] {
        check_masked(
            &mut misses,
            name,
            &input,
            &expected,
            KIND_PASSWORD_ASSIGNMENT,
        );
    }
    for input in ["password=${DB_PASSWORD}", "postgres://u:${DB_PASS}@db/x"] {
        check_accepted(&mut misses, "placeholder_control", input);
    }
    assert_no_misses("placeholders", &misses);
}
