// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10301: every `.cargo/config.toml` and `.cargo/config` of the tree, at any
//! depth, is read. A `[patch]` of a watched crate, `paths`, any `source.*`, a
//! `rustflags` naming an extern or a watched crate and an `env.PROPTEST*` are
//! findings; a `build` or `target` key or a top-level table the census does
//! not understand is refused, and so is a config that is not UTF-8 or does
//! not parse. Each row goes through the whole census of a one-file tree. The
//! expected lines are the hand-written table `census_config_10301.json`,
//! which the Python scanner's tests (`CargoConfig10301` in
//! `scripts/ci/tests/test_census_rows_10286.py`) read too.

use super::{Tree, census};
use std::time::{Duration, Instant};

/// The table both scanners read, written by hand.
const TABLE_10301: &str = include_str!("census_config_10301.json");
/// The number of text rows and of byte rows of [`TABLE_10301`].
const ROWS_10301: usize = 21;
const BYTE_ROWS_10301: usize = 1;
/// Alias entries in the size-bound fixture (over 100K bytes) and its
/// wall-clock ceiling.
const BOUND_ENTRIES: usize = 6_000;
const BOUND_BYTES: usize = 100_000;
const BOUND_SECONDS: u64 = 20;
/// The tag every #10301 finding ends with.
const TAG: &str = "(#10301)";

#[derive(serde::Deserialize)]
struct Table {
    rows: Vec<(String, String, Vec<String>)>,
    bytes: Vec<(String, Vec<u8>, Vec<String>)>,
}

fn table() -> Table {
    serde_json::from_str(TABLE_10301).expect("the #10301 table is a JSON object")
}

fn config_lines(rel: &str, bytes: &[u8]) -> Vec<String> {
    let tree = Tree {
        files: vec![(rel.to_string(), bytes.to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{rel}:");
    let mut got: Vec<String> = census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head) && l.ends_with(TAG))
        .collect();
    got.sort();
    got
}

#[test]
fn every_cargo_config_form_is_read_or_refused_10301() {
    let t = table();
    assert_eq!(t.rows.len(), ROWS_10301, "#10301 text rows");
    assert_eq!(t.bytes.len(), BYTE_ROWS_10301, "#10301 byte rows");
    let mut bad = Vec::new();
    for (i, (rel, text, want)) in t.rows.iter().enumerate() {
        let got = config_lines(rel, text.as_bytes());
        if &got != want {
            bad.push(format!("row {i}: {rel} {text:?} gave {got:?}"));
        }
    }
    for (i, (rel, bytes, want)) in t.bytes.iter().enumerate() {
        let got = config_lines(rel, bytes);
        if &got != want {
            bad.push(format!("byte row {i}: {rel} {bytes:?} gave {got:?}"));
        }
    }
    assert!(bad.is_empty(), "#10301 cargo config:\n{}", bad.join("\n"));
}

#[test]
fn a_large_cargo_config_is_read_in_linear_time_10301() {
    let mut text = String::from("[alias]\n");
    for i in 0..BOUND_ENTRIES {
        text.push_str(&format!("a{i:05} = \"test\"\n"));
    }
    text.push_str("[patch.crates-io.libc]\npath = \"l\"\n");
    assert!(text.len() > BOUND_BYTES, "#10301 bound fixture size");
    let rel = ".cargo/config.toml";
    let start = Instant::now();
    let got = config_lines(rel, text.as_bytes());
    let took = start.elapsed();
    assert!(
        took < Duration::from_secs(BOUND_SECONDS),
        "#10301 a {}-byte config took {took:?}",
        text.len()
    );
    assert_eq!(
        got,
        vec![format!(
            "{rel}: patch.crates-io.libc patches the watched crate libc; a patched watched crate runs code the census never reads {TAG}"
        )],
        "#10301 bound fixture"
    );
}
