// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10314: the `assert_cmd` start forms `cargo_bin_cmd` (the macro that
//! expands to `assert_cmd::Command::new`) and `cargo_bin` (the constructor,
//! the trait method and the path macro) are process-start sites and watched
//! tokens wherever they are written, and a start written
//! `Command :: cargo_bin(..)` or `<alias> :: cargo_bin(..)` is one site, not
//! two. Each row goes through the whole census of a one-file tree. The
//! expected counts are the hand-written table `census_assert_cmd_10314.json`,
//! which the Python scanner's tests (`AssertCmd10314` in
//! `scripts/ci/tests/test_census_rows_10286.py`) read too.

use super::{ALIASED, DIRECT, Tree, WATCHED, census, lex, libc_start_names, starts, uncovered};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// The table both scanners read, written by hand: (file text, watched
/// tokens, start sites, lines of the uncovered-start findings).
const TABLE_10314: &str = include_str!("census_assert_cmd_10314.json");
/// The number of rows of [`TABLE_10314`].
const ROWS_10314: usize = 8;
/// The file every row is written to.
const REL: &str = "src/e.rs";
/// The `assert_cmd` start names, written out (never read from the census).
const ASSERT_CMD_NAMES: [&str; 2] = ["cargo_bin", "cargo_bin_cmd"];
/// Starts in the size-bound fixture and its wall-clock ceiling.
const BOUND_STARTS: usize = 100_000;
const BOUND_SECONDS: u64 = 20;

type Row = (String, usize, usize, Vec<usize>);

fn rows() -> Vec<Row> {
    serde_json::from_str(TABLE_10314).expect("the #10314 table is a JSON array")
}

fn lines_of(text: &str) -> Vec<String> {
    let tree = Tree {
        files: vec![(REL.to_string(), text.as_bytes().to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{REL}:");
    census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head))
        .collect()
}

#[test]
fn the_assert_cmd_forms_are_start_sites_and_watched_tokens_10314() {
    let rows = rows();
    assert_eq!(rows.len(), ROWS_10314, "#10314 rows");
    let mut bad = Vec::new();
    for (i, (text, tokens, sites, lines)) in rows.iter().enumerate() {
        let got = lines_of(text);
        let token_line = format!(
            "{REL}: {tokens} watched process, libc, nix or proptest tokens, TOKEN_ROWS has 0; every reference under any cfg, in any macro or by any path needs its exact row (#10176)"
        );
        let start_line = format!(
            "{REL}: {sites} process-start sites, START_ROWS has 0; a new or removed start needs its row (#10176)"
        );
        for want in [token_line, start_line] {
            if !got.contains(&want) {
                bad.push(format!("row {i}: {text:?} lacks {want:?}; got {got:?}"));
            }
        }
        let want_uncovered: BTreeSet<String> = lines.iter().map(|l| uncovered(REL, *l)).collect();
        let have_uncovered: BTreeSet<String> = got
            .iter()
            .filter(|l| l.contains(": process start with no #[expect("))
            .cloned()
            .collect();
        if have_uncovered != want_uncovered {
            bad.push(format!(
                "row {i}: {text:?} uncovered {have_uncovered:?}, want {want_uncovered:?}"
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "#10314 assert_cmd forms:\n{}",
        bad.join("\n")
    );
}

/// Every name that is a site by itself is renamable and a watched token, and
/// the `assert_cmd` names are among them.
#[test]
fn every_direct_name_is_aliased_and_watched_10314() {
    for name in ASSERT_CMD_NAMES {
        assert!(DIRECT.contains(&name), "{name} is in DIRECT (#10314)");
    }
    for name in DIRECT {
        assert!(
            ALIASED.contains(name),
            "{name} of DIRECT is in ALIASED (#10314)"
        );
        assert!(
            WATCHED.contains(name),
            "{name} of DIRECT is in WATCHED (#10314)"
        );
    }
}

/// `Command::cargo_bin` is one site each, and the scan stays linear.
#[test]
fn a_command_cargo_bin_start_is_counted_once_in_linear_time_10314() {
    let text = "fn f() {\n".to_string()
        + &"    let _ = Command::cargo_bin(\"x\");\n    let _ = Run::cargo_bin(\"x\");\n"
            .repeat(BOUND_STARTS / 2)
        + "}\n";
    let toks = lex(&text);
    let aliases: BTreeSet<String> = ["Run".to_string()].into();
    let t0 = Instant::now();
    let sites = starts(&toks, &aliases, &libc_start_names());
    let took = t0.elapsed();
    assert_eq!(sites.len(), BOUND_STARTS, "one site per start (#10314)");
    assert!(
        took < Duration::from_secs(BOUND_SECONDS),
        "{BOUND_STARTS} starts took {took:?} (#10314)"
    );
}
