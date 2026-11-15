// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9351 — the password-assignment detector accepts an unquoted value as a
//! named non-credential shape only when the WHOLE judged value matches that
//! shape's grammar. Bytes after an env lookup's closer, after a balanced
//! type expression or after a reference's type name, an unclosed or
//! mismatched bracket, and a trailing fallback default are all findings.
//!
//! These cells run the public funnels: `screen` (exact redaction and kind)
//! and the caller validator (exact refusal reason, value never echoed). The
//! table-driven cells over every `ENV_LOOKUP_PREFIXES` and
//! `ANNOTATION_TYPE_NAMES` entry live beside the detector
//! (`src/secret_screen/credential_forms/tests_9351.rs`).
//!
//! Every credential-shaped fixture is assembled with `concat!`.

use std::sync::mpsc;
use std::time::Duration;

use ai_memory::secret_screen::{
    REDACTION_PLACEHOLDER, ScreenOutcome, SecretScreenMode, screen, set_screen_mode,
};
use ai_memory::validate;

/// The exact kind tag the refusal reason carries.
const KIND_PASSWORD: &str = "password_assignment";
/// Obviously fake secret bytes.
const SECRET: &str = concat!("Hn4r", "Xp7Qs2");
/// Wall-clock ceiling of one `screen` over a 100K input.
const LINEAR_SCAN_CEILING: Duration = Duration::from_secs(2);
/// Size of every bound input.
const BOUND_INPUT_CHARS: usize = 100_000;
/// Text after the value on its line, and a following line.
const TAIL: &str = " rest";
const NEXT_LINE: &str = "\nuser: bob";

fn kinds_of(content: &str) -> Vec<&'static str> {
    match screen(content) {
        ScreenOutcome::Clean => vec![],
        ScreenOutcome::Hit { kinds, .. } => kinds,
    }
}

fn redacted_of(content: &str) -> String {
    match screen(content) {
        ScreenOutcome::Clean => content.to_string(),
        ScreenOutcome::Hit { redacted, .. } => redacted,
    }
}

fn expected_reason(kind: &str) -> String {
    format!(
        "content rejected: appears to contain credential material ({kind}); \
         set AI_MEMORY_SECRET_SCREEN_MODE=redact to store a masked copy, \
         or =off to disable screening"
    )
}

/// Each row: exact kind, exact redaction, exact caller refusal reason, and
/// the secret never echoed by the refusal.
fn assert_refused_exactly(rows: &[(String, String)]) {
    set_screen_mode(SecretScreenMode::Refuse);
    let mut misses = Vec::new();
    for (input, expected) in rows {
        let kinds = kinds_of(input);
        let out = redacted_of(input);
        let err = validate::validate_content(input).map_err(|e| e.to_string());
        let reason_ok = err
            .as_ref()
            .err()
            .is_some_and(|e| e.contains(&expected_reason(KIND_PASSWORD)) && !e.contains(SECRET));
        if kinds != vec![KIND_PASSWORD] || &out != expected || !reason_ok {
            misses.push(format!(
                "{input:?}: kinds {kinds:?}, out {out:?}, refusal {err:?}; want {expected:?}"
            ));
        }
    }
    assert!(misses.is_empty(), "9351: {} rows:\n{}", misses.len(), misses.join("\n"));
}

fn assert_accepted(inputs: &[&str]) {
    set_screen_mode(SecretScreenMode::Refuse);
    for input in inputs {
        assert_eq!(kinds_of(input), Vec::<&str>::new(), "9351: {input:?} stays accepted");
        assert!(
            validate::validate_content(input).is_ok(),
            "9351: {input:?} passes the caller validator"
        );
    }
}

fn token_masked(op: &str) -> String {
    format!("password{op}{REDACTION_PLACEHOLDER}{TAIL}{NEXT_LINE}")
}

fn line_masked(op: &str) -> String {
    format!("password{op}{REDACTION_PLACEHOLDER}{NEXT_LINE}")
}

#[test]
fn env_lookup_tail_after_closer_is_refused_9351() {
    let mut rows = Vec::new();
    for op in ["=", ": "] {
        for value in [
            format!("os.environ[\"X\"]{SECRET}"),
            format!("os.getenv(\"X\")-{SECRET}"),
            format!("process.env.X-{SECRET}"),
            format!("ENV.fetch(\"X\",\"{SECRET}\")"),
            format!("$ENV{{X}}{SECRET}"),
            format!("std::env::var(\"X\")??{SECRET}"),
        ] {
            rows.push((format!("password{op}{value}{TAIL}{NEXT_LINE}"), token_masked(op)));
        }
        for value in [
            format!("os.environ[{SECRET}"),
            format!("getenv(\"X\" {SECRET})"),
        ] {
            rows.push((format!("password{op}{value}{TAIL}{NEXT_LINE}"), line_masked(op)));
        }
        rows.push((
            format!("password{op}os.environ.get(\"X\") or \"{SECRET}\"{NEXT_LINE}"),
            line_masked(op),
        ));
        rows.push((
            format!("password{op}process.env.X || '{SECRET}'{NEXT_LINE}"),
            line_masked(op),
        ));
    }
    assert_refused_exactly(&rows);
}

#[test]
fn type_annotation_bytes_after_balanced_end_are_refused_9351() {
    let op = ": ";
    let rows = vec![
        (
            format!("password: Option<X>{SECRET}{TAIL}{NEXT_LINE}"),
            token_masked(op),
        ),
        (
            format!("password: Vec<X]{SECRET}{TAIL}{NEXT_LINE}"),
            line_masked(op),
        ),
        (
            format!("password: Box<X {SECRET}{NEXT_LINE}"),
            line_masked(op),
        ),
        (
            format!("password: &str.{SECRET}{TAIL}{NEXT_LINE}"),
            line_masked(op),
        ),
        (
            format!("password: &'a str@{SECRET}{TAIL}{NEXT_LINE}"),
            line_masked(op),
        ),
        (
            format!("password: &String<X>{SECRET}{TAIL}{NEXT_LINE}"),
            line_masked(op),
        ),
    ];
    assert_refused_exactly(&rows);
}

#[test]
fn placeholder_with_trailing_bytes_is_refused_9351() {
    let rows = vec![
        (
            format!("password=${{X:-{SECRET}}}{TAIL}{NEXT_LINE}"),
            token_masked("="),
        ),
        (
            format!("password=<a>{SECRET}>{TAIL}{NEXT_LINE}"),
            token_masked("="),
        ),
    ];
    assert_refused_exactly(&rows);
}

/// Positive controls: the well-formed shapes stay accepted on the funnel.
#[test]
fn well_formed_shapes_stay_accepted_9351() {
    assert_accepted(&[
        "password = os.environ[\"DB_PASSWORD\"]",
        "password = os.getenv('DB_PASSWORD')",
        "let password = std::env::var(\"DB_PASSWORD\")?;",
        "const password = process.env.DB_PASSWORD;",
        "password: ${DB_PASSWORD}",
        "password=$ENV{X} tail",
        "struct Login { password: String, pwd: Option<SecretString> }",
        "fn f(password: &mut String, pwd: &'static str, passwd: &Option<Secret>) {}",
        "password: Option<Vec<u8>> = None",
        "password: <your-password>",
    ]);
}

fn screen_bounded(input: String) -> ScreenOutcome {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(screen(&input));
    });
    rx.recv_timeout(LINEAR_SCAN_CEILING)
        .unwrap_or_else(|_| panic!("9351: screen exceeded {LINEAR_SCAN_CEILING:?} on 100K"))
}

/// 100K malformed tails are masked whole, 100K well-formed shapes are
/// accepted, each scan under [`LINEAR_SCAN_CEILING`].
#[test]
fn bound_100k_shapes_9351() {
    let ph = REDACTION_PLACEHOLDER;
    let tail = "Ab9!".repeat(BOUND_INPUT_CHARS / 4);
    let open = "<".repeat(BOUND_INPUT_CHARS);
    let args = "X, ".repeat(BOUND_INPUT_CHARS / 3);
    let long_name = "X".repeat(BOUND_INPUT_CHARS);
    for (op, value) in [
        ("=", format!("os.environ[\"X\"]{tail}")),
        (": ", format!("Option{open}")),
        (": ", format!("&str.{tail}")),
    ] {
        match screen_bounded(format!("password{op}{value}")) {
            ScreenOutcome::Hit { kinds, redacted } => {
                assert_eq!(kinds, vec![KIND_PASSWORD]);
                assert_eq!(redacted, format!("password{op}{ph}"));
            }
            ScreenOutcome::Clean => panic!("9351: 100K malformed {:?}… accepted", &value[..12]),
        }
    }
    for good in [
        format!("password=os.environ[\"{long_name}\"]"),
        format!("password: Option<{args}X>"),
    ] {
        assert!(
            matches!(screen_bounded(good), ScreenOutcome::Clean),
            "9351: 100K well-formed shape refused"
        );
    }
}
