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

use super::census_cargo::{Leaf, parse, watched};
use super::{Tree, census};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// The directory cargo reads its configuration from, and its file names.
const CONFIG_DIR: &str = ".cargo";
const CONFIG_NAMES: [&str; 2] = ["config.toml", "config"];
/// Top-level tables that cannot replace a crate or start a process.
const CONFIG_PLAIN: [&str; 8] = [
    "alias",
    "cache",
    "cargo-new",
    "doc",
    "future-incompat-report",
    "http",
    "net",
    "term",
];
/// `build` keys that cannot replace a crate or start a process.
const BUILD_PLAIN: [&str; 5] = [
    "dep-info-basedir",
    "incremental",
    "jobs",
    "target",
    "target-dir",
];
/// The compiler-flag keys whose values are read.
const FLAG_KEYS: [&str; 2] = ["rustflags", "rustdocflags"];
/// The prefix of the proptest environment variables.
const ENV_PREFIX_PROPTEST: &str = "PROPTEST";

/// Whether `rel` is a file cargo reads its configuration from, at any depth.
pub(crate) fn is_config(rel: &str) -> bool {
    let mut parts = rel.rsplit('/');
    let name = parts.next().unwrap_or("");
    parts.next() == Some(CONFIG_DIR) && CONFIG_NAMES.contains(&name)
}

fn flag_hit(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        v.to_ascii_lowercase().contains("extern")
            || v.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .any(|w| !w.is_empty() && watched(w))
    })
}

/// The #10301 findings of one cargo config file, sorted and without repeats.
pub(crate) fn config_findings(rel: &str, bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return vec![format!(
            "{rel}: not UTF-8; an unreadable cargo config is not clean (#10301)"
        )];
    };
    let Ok(entries) = parse(text) else {
        return vec![format!(
            "{rel}: not TOML the census reads; an unparseable cargo config is not clean (#10301)"
        )];
    };
    let unknown = |shown: &str| {
        format!(
            "{rel}: {shown} is a cargo config form the census does not understand; a form it does not read is a process start nobody counted (#10301)"
        )
    };
    let flag = |shown: &str| {
        format!(
            "{rel}: {shown} names a watched crate or an extern in a compiler flag; a flag can replace a watched crate with code the census never reads (#10301)"
        )
    };
    let mut out = BTreeSet::new();
    for (path, leaf) in &entries {
        let value = match leaf {
            Leaf::Str(s) => Some(s.as_str()),
            Leaf::Other => None,
        };
        let seg = |i: usize| path.get(i).map(String::as_str);
        let upto = |n: usize| path[..n.min(path.len())].join(".");
        let key = seg(1);
        match seg(0).unwrap_or("") {
            "patch" => match seg(2) {
                Some(name) if watched(name) => {
                    out.insert(format!(
                        "{rel}: {} patches the watched crate {name}; a patched watched crate runs code the census never reads (#10301)",
                        upto(3)
                    ));
                }
                Some(_) if path.last().is_some_and(|l| l == "package") => {
                    if let Some(v) = value.filter(|v| watched(v)) {
                        out.insert(format!(
                            "{rel}: {} patches the watched crate {v}; a patched watched crate runs code the census never reads (#10301)",
                            upto(3)
                        ));
                    }
                }
                Some(_) => {}
                None => {
                    out.insert(unknown(&upto(path.len())));
                }
            },
            "paths" => {
                out.insert(format!(
                    "{rel}: paths overrides crates with local copies; a path override can replace a watched crate with code the census never reads (#10301)"
                ));
            }
            "source" => {
                out.insert(format!(
                    "{rel}: {} replaces a crate source; a replaced source can serve a watched crate the census never reads (#10301)",
                    upto(2)
                ));
            }
            "env" => match key {
                Some(k) if k.to_ascii_uppercase().starts_with(ENV_PREFIX_PROPTEST) => {
                    out.insert(format!(
                        "{rel}: {} sets a proptest variable for every cargo command; a config can switch proptest fork on (#10301)",
                        upto(2)
                    ));
                }
                Some(_) => {}
                None => {
                    out.insert(unknown("env"));
                }
            },
            "build" => match key {
                Some(k) if FLAG_KEYS.contains(&k) => {
                    if flag_hit(value) {
                        out.insert(flag(&upto(path.len())));
                    }
                }
                Some(k) if BUILD_PLAIN.contains(&k) => {}
                _ => {
                    out.insert(unknown(&upto(2)));
                }
            },
            "target" => match seg(2) {
                Some(k) if FLAG_KEYS.contains(&k) => {
                    if flag_hit(value) {
                        out.insert(flag(&upto(path.len())));
                    }
                }
                _ => {
                    out.insert(unknown(&upto(3)));
                }
            },
            top if CONFIG_PLAIN.contains(&top) => {}
            top => {
                out.insert(unknown(top));
            }
        }
    }
    out.into_iter().collect()
}

/// The table both scanners read, written by hand.
const TABLE_10301: &str = include_str!("census_config_10301.json");
/// The number of text rows and of byte rows of [`TABLE_10301`].
const ROWS_10301: usize = 23;
const BYTE_ROWS_10301: usize = 1;
/// Alias entries in the size-bound fixture (over 100K bytes) and its
/// wall-clock ceiling.
const BOUND_ENTRIES: usize = 7_000;
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
    text.extend((0..BOUND_ENTRIES).map(|i| format!("a{i:05} = \"test\"\n")));
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
