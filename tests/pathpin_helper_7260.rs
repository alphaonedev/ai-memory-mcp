// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7260 — the `tests/common/pathpin.rs` fail-closed helper.
//!
//! A test that names a `src/` path literally scans nothing and passes when
//! the path moves. The helper panics on a missing path, or on fewer entries
//! than the pinned minimum, so a file move turns the test red. These tests
//! pin that behaviour (missing, zero matches, moved, present) and pin the
//! real tree: `src/` must resolve and hold Rust files.

#[path = "common/pathpin.rs"]
mod pathpin;

use std::fs;
use std::path::{Path, PathBuf};

/// A scratch tree under cargo's per-target tmp dir (never the system tmp).
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pathpin_7260_{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src/sub")).expect("create scratch tree");
    fs::write(dir.join("src/a.rs"), "pub fn a() {}\n").expect("write a.rs");
    fs::write(dir.join("src/sub/b.rs"), "pub fn b() {}\n").expect("write b.rs");
    fs::write(dir.join("src/notes.md"), "notes\n").expect("write notes.md");
    dir
}

#[test]
fn present_dir_resolves() {
    let tree = scratch("present_dir");
    assert_eq!(pathpin::pin_dir(tree.join("src")), tree.join("src"));
}

#[test]
#[should_panic(expected = "pathpin: missing directory")]
fn missing_dir_panics() {
    let tree = scratch("missing_dir");
    pathpin::pin_dir(tree.join("src/gone"));
}

#[test]
#[should_panic(expected = "pathpin: missing directory")]
fn moved_dir_panics() {
    let tree = scratch("moved_dir");
    fs::rename(tree.join("src"), tree.join("lib_moved")).expect("git mv stand-in");
    pathpin::pin_dir(tree.join("src"));
}

#[test]
fn present_file_resolves() {
    let tree = scratch("present_file");
    assert_eq!(
        pathpin::pin_file(tree.join("src/a.rs")),
        tree.join("src/a.rs")
    );
}

#[test]
#[should_panic(expected = "pathpin: missing file")]
fn missing_file_panics() {
    let tree = scratch("missing_file");
    pathpin::pin_file(tree.join("src/gone.rs"));
}

#[test]
#[should_panic(expected = "pathpin: missing file")]
fn moved_file_panics() {
    let tree = scratch("moved_file");
    fs::rename(tree.join("src/a.rs"), tree.join("src/a_moved.rs")).expect("git mv stand-in");
    pathpin::pin_file(tree.join("src/a.rs"));
}

#[test]
fn files_are_found_recursively_and_sorted() {
    let tree = scratch("files");
    let files = pathpin::pin_files(tree.join("src"), "*.rs", 2);
    assert_eq!(
        files,
        vec![tree.join("src/a.rs"), tree.join("src/sub/b.rs")]
    );
}

#[test]
#[should_panic(expected = "pathpin: 0 files")]
fn zero_glob_matches_panics() {
    let tree = scratch("zero_glob");
    pathpin::pin_files(tree.join("src"), "*.toml", 1);
}

#[test]
#[should_panic(expected = "pathpin: 2 files")]
fn fewer_than_the_minimum_panics() {
    let tree = scratch("min");
    pathpin::pin_files(tree.join("src"), "*.rs", 3);
}

#[test]
#[should_panic(expected = "pathpin: missing directory")]
fn files_in_a_missing_dir_panics() {
    let tree = scratch("files_missing");
    pathpin::pin_files(tree.join("nope"), "*.rs", 1);
}

#[test]
#[should_panic(expected = "pathpin: minimum must be at least 1")]
fn a_zero_minimum_is_refused() {
    let tree = scratch("zero_min");
    pathpin::pin_files(tree.join("src"), "*.rs", 0);
}

#[test]
fn rs_root_returns_the_directory_once_it_holds_enough_sources() {
    let tree = scratch("rs_root");
    assert_eq!(pathpin::pin_rs_root(tree.join("src"), 2), tree.join("src"));
}

#[test]
#[should_panic(expected = "pathpin: 2 files")]
fn rs_root_below_the_minimum_panics() {
    let tree = scratch("rs_root_min");
    pathpin::pin_rs_root(tree.join("src"), 10);
}

#[test]
fn real_tree_src_resolves_and_holds_rust_files() {
    let src = pathpin::pin_rs_root(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), 50);
    assert!(src.join("lib.rs").is_file());
}

#[test]
fn wildcard_matching_covers_star_and_question() {
    assert!(pathpin::glob_match("*.rs", "a.rs"));
    assert!(pathpin::glob_match("a?.rs", "ab.rs"));
    assert!(pathpin::glob_match("*", "anything"));
    assert!(!pathpin::glob_match("*.rs", "a.rs.bak"));
    assert!(!pathpin::glob_match("a?.rs", "a.rs"));
}
