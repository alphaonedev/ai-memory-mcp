// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10299: an environment-name argument that is a name (`[&] [path ::] NAME`)
//! is a named constant only when NAME is bound somewhere in the tree by a
//! `const` or `static [mut]` item whose initializer is one string literal, and
//! NAME is bound nowhere else (by `let`, `for`, a closure or fn parameter, a
//! match-arm or `@` pattern, a struct field, or a `const` or `static` with any
//! other initializer). Every other name is red where it is passed. Each row
//! goes through the whole census of a one-file tree. The expected counts are
//! the hand-written table `census_env_name_10299.json`, which the Python
//! scanner's tests (`EnvName10299` in `scripts/ci/tests/test_census_rows_10286.py`)
//! read too, so the two scanners cannot drift.

use super::{Tree, census};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

/// The table both scanners read, written by hand: (file text, environment
/// names that are not ok).
const TABLE_10299: &str = include_str!("census_env_name_10299.json");
/// The number of rows of [`TABLE_10299`].
const ROWS_10299: usize = 28;
/// The file every row is written to.
const REL: &str = "src/e.rs";
/// Size floor of the bound fixture, its constants and match arms, and its
/// wall-clock ceiling.
const BOUND_BYTES_10299: usize = 100_000;
const BOUND_ITEMS_10299: usize = 2_500;
const BOUND_SECONDS_10299: u64 = 20;

fn rows() -> Vec<(String, usize)> {
    serde_json::from_str(TABLE_10299).expect("the #10299 table is a JSON array")
}

fn env_lines(text: &str) -> Vec<String> {
    let tree = Tree {
        files: vec![(REL.to_string(), text.as_bytes().to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{REL}:");
    census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head) && l.contains("ENV_NAME_ROWS"))
        .collect()
}

fn env_line(n: usize) -> String {
    format!(
        "{REL}: {n} environment names that are not one string literal or one named constant, ENV_NAME_ROWS has 0; a built name can switch proptest fork on (#10176)"
    )
}

fn want(n: usize) -> Vec<String> {
    if n == 0 { vec![] } else { vec![env_line(n)] }
}

#[test]
fn an_env_name_is_a_constant_only_when_a_literal_const_binds_it_10299() {
    let rows = rows();
    assert_eq!(rows.len(), ROWS_10299, "#10299 rows");
    let mut bad = Vec::new();
    for (i, (text, n)) in rows.iter().enumerate() {
        let got = env_lines(text);
        if got != want(*n) {
            bad.push(format!("row {i}: {text:?} gave {got:?}, want {n}"));
        }
    }
    assert!(bad.is_empty(), "#10299 env names:\n{}", bad.join("\n"));
}

/// A file of 100K+ bytes of literal constants, the calls that pass them and a
/// match of block arms is censused within the ceiling, and the one constant
/// that is also a match-arm binding is red.
#[test]
fn the_bound_name_pass_is_linear_on_a_100k_file_10299() {
    let mut text = String::from("use std::env::set_var;\nconst A7: &str = \"x\";\n");
    for i in 0..BOUND_ITEMS_10299 {
        writeln!(text, "const C{i}: &str = \"PROPTEST_FORK\";").expect("write to a String");
    }
    text.push_str("fn f(o: u8) {\n");
    for i in 0..BOUND_ITEMS_10299 {
        writeln!(text, "    set_var(C{i}, \"1\");").expect("write to a String");
    }
    text.push_str("    match o {\n");
    for i in 0..BOUND_ITEMS_10299 {
        writeln!(text, "        A{i} => match o {{ _ => {{}} }}").expect("write to a String");
    }
    text.push_str("    }\n    set_var(A7, \"1\");\n}\n");
    assert!(
        text.len() >= BOUND_BYTES_10299,
        "fixture is {} bytes",
        text.len()
    );
    let started = Instant::now();
    let got = env_lines(&text);
    let took = started.elapsed();
    assert_eq!(got, want(1), "#10299 bound fixture");
    assert!(
        took < Duration::from_secs(BOUND_SECONDS_10299),
        "#10299 bound fixture took {took:?}"
    );
}
