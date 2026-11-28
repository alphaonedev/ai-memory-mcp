// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10300: every `include!` and `#[path]` of a walked file is a site of the
//! census (`include_str!` and `include_bytes!` name data that is never
//! compiled as Rust, so they are not sites). Each fixture below is a small
//! tree written on disk under `CARGO_TARGET_TMPDIR` (never `/tmp`), read with
//! [`read_tree`] and run through [`census`]; every expected line is written
//! out here by hand, never built by the census.

use super::*;

/// The directory that holds the fixture trees of this file.
fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("census_include_10300")
        .join(name)
}

/// Write a fresh fixture tree: `files` are (relative path, text) and `links`
/// are (relative path, link target); returns the census of the tree.
fn include_case(name: &str, files: &[(&str, &str)], links: &[(&str, &str)]) -> Vec<String> {
    let root = fixture_dir(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("#10300: clear the old fixture tree");
    }
    for (rel, text) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a fixture file has a parent"))
            .expect("#10300: create a fixture dir");
        std::fs::write(&p, text).expect("#10300: write a fixture file");
    }
    for (rel, to) in links {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a fixture link has a parent"))
            .expect("#10300: create a fixture dir");
        std::os::unix::fs::symlink(to, &p).expect("#10300: create a fixture link");
    }
    census(&read_tree(&root))
}

fn has(got: &[String], want: &str) {
    assert!(
        got.iter().any(|l| l == want),
        "missing line:\n  {want}\ncensus gave:\n  {}",
        got.join("\n  ")
    );
}

const START: &str = "fn f() { std::process::Command::new(\"x\"); }\n";

#[test]
fn an_include_of_a_non_rs_file_is_lexed_10300() {
    let got = include_case(
        "include_txt",
        &[
            ("src/a.rs", "include!(\"gen.txt\");\n"),
            ("src/gen.txt", START),
        ],
        &[],
    );
    has(
        &got,
        "src/gen.txt:1: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)",
    );
}

#[test]
fn a_path_module_in_a_skipped_dir_is_lexed_10300() {
    let got = include_case(
        "path_skipped",
        &[
            ("src/a.rs", "#[path = \"../target/m.rs\"]\nmod m;\n"),
            ("target/m.rs", START),
        ],
        &[],
    );
    has(
        &got,
        "target/m.rs:1: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)",
    );
}

#[test]
fn a_non_literal_include_argument_is_red_10300() {
    let got = include_case(
        "non_literal",
        &[("src/a.rs", "include!(concat!(\"b\", \".rs\"));\n")],
        &[],
    );
    has(
        &got,
        "src/a.rs:1: include! with an argument that is not one string literal; the census cannot resolve it (#10300)",
    );
}

#[test]
fn an_include_outside_the_root_is_red_10300() {
    let got = include_case(
        "outside_root",
        &[("src/a.rs", "include!(\"../../x\");\n")],
        &[],
    );
    has(
        &got,
        "src/a.rs:1: include! \"../../x\" leaves the repository root (#10300)",
    );
}

#[test]
fn an_include_of_a_link_is_red_10300() {
    let got = include_case(
        "link_target",
        &[
            ("src/a.rs", "include!(\"l.rs\");\n"),
            ("src/real.txt", START),
        ],
        &[("src/l.rs", "real.txt")],
    );
    has(
        &got,
        "src/a.rs:1: include! \"l.rs\" names src/l.rs, a symbolic link or a path through one; the census never follows links (#10300)",
    );
}
