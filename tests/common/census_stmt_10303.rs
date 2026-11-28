// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10302, #10303: a site pin covers every token of the statement that holds
//! the site, and a digest is 32 hex digits. The two tables below are read by
//! this file and by the Python scanner test
//! (`scripts/ci/tests/test_census_rows_10286.py`); every expected token string
//! in them is written by hand in the pin encoding, never read back from a
//! scanner.

use super::*;

/// The statement table: each row is a text and its statements, in order,
/// each written as the pin encoding of its tokens.
const STMT_PARITY_10303: &str = include_str!("census_stmt_parity_10303.json");
/// The number of rows of [`STMT_PARITY_10303`].
const STMT_PARITY_ROWS_10303: usize = 23;
/// The mutant table: each row is a name, `change` or `same`, and two texts.
const STMT_MUTANTS_10303: &str = include_str!("census_stmt_mutants_10303.json");
/// The number of rows of [`STMT_MUTANTS_10303`].
const STMT_MUTANT_ROWS_10303: usize = 16;
/// SHA-256 of `TI1:a`, cut to 32 hex digits (from Python hashlib, not from
/// the census).
const TI1A_32: &str = "99db7ecf930b705fe1d777ca11b97ee4";
/// The site kind letters a pin is prefixed with.
const SITE_KINDS: [&str; 3] = ["T", "U", "E"];
/// Tokens of the many-statement linear input.
const LINEAR_TOKENS_10303: usize = 100_000;

fn stmt_rows() -> Vec<(String, Vec<String>)> {
    serde_json::from_str(STMT_PARITY_10303).expect("the #10303 statement table is a JSON list")
}

fn digests(text: &str) -> Vec<String> {
    census_r4_tests::sites(text)
        .into_iter()
        .map(|s| s.digest)
        .collect()
}

/// Every site of a table row pins one of the row's hand-written statements.
#[test]
fn every_site_pins_its_whole_statement_10303() {
    let rows = stmt_rows();
    assert_eq!(rows.len(), STMT_PARITY_ROWS_10303, "rows of the #10303 table");
    let mut bad = Vec::new();
    let mut seen = 0usize;
    for (i, (text, stmts)) in rows.iter().enumerate() {
        let allowed: BTreeSet<String> = stmts
            .iter()
            .flat_map(|s| SITE_KINDS.iter().map(|k| census_pins::digest(k, s)))
            .collect();
        for d in digests(text) {
            seen += 1;
            if !allowed.contains(&d) {
                bad.push(format!("row {i} {text:?}: site pin {d} is not a pin of a whole statement"));
            }
        }
    }
    assert_eq!(bad, Vec::<String>::new(), "#10303 statement pins");
    assert!(seen >= 6, "the table rows hold {seen} sites");
}

/// Every `change` row changes a pin, and every `same` row keeps all pins.
#[test]
fn statement_pin_mutants_10303() {
    let rows: Vec<(String, String, String, String)> =
        serde_json::from_str(STMT_MUTANTS_10303).expect("the #10303 mutant table is a JSON list");
    assert_eq!(rows.len(), STMT_MUTANT_ROWS_10303, "rows of the #10303 mutant table");
    let mut bad = Vec::new();
    for (name, want, a, b) in &rows {
        let (da, db) = (digests(a), digests(b));
        assert!(!da.is_empty(), "{name}: the text holds a site");
        assert_eq!(da.len(), db.len(), "{name}: the edit keeps the site count");
        let verdict = if da == db { "same" } else { "change" };
        if verdict != want {
            bad.push(format!("{name}: want {want}, the pins {verdict}"));
        }
    }
    assert_eq!(bad, Vec::<String>::new(), "#10303 mutants");
}

/// A digest is the first 32 hex digits of SHA-256 (#10302).
#[test]
fn a_digest_is_32_hex_digits_10302() {
    assert_eq!(census_pins::digest("T", "I1:a"), TI1A_32);
    for d in digests("fn f() { std::process::exit(1); }") {
        assert_eq!(d.len(), 32, "pin {d}");
    }
}

/// 100K tokens of short statements, each with a site, in linear time.
#[test]
fn many_statements_pin_in_linear_time_10303() {
    let unit = "std::process::exit(1);\n";
    let per = lex(unit).len();
    let reps = LINEAR_TOKENS_10303 / per + 1;
    let text = unit.repeat(reps);
    let t0 = std::time::Instant::now();
    let d = digests(&text);
    let dt = t0.elapsed();
    assert_eq!(d.len(), reps, "one site per statement");
    assert!(lex(&text).len() >= LINEAR_TOKENS_10303);
    assert!(
        dt < std::time::Duration::from_secs(20),
        "pins of {reps} statements took {dt:?}"
    );
}
