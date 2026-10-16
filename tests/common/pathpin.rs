// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed path pins for tests that read or walk `src/` (#7260).
//!
//! A test that names a `src/` path literally scans nothing, and passes, once
//! the path moves. Every helper here panics with a message that names the
//! pinned path when it is missing, or when it yields fewer entries than the
//! minimum, so a `git mv` of the target turns the test red.
//!
//! Leaf module, `std` only. It is deliberately NOT declared in
//! `tests/common/mod.rs` (that module pulls `reqwest`, `ed25519_dalek` and
//! rusqlite into every binary that declares it); take it with the path idiom:
//!
//! ```ignore
//! #[path = "common/pathpin.rs"]
//! mod pathpin;
//! ```
//!
//! Globs match a file NAME (not a path) with `*` (any run) and `?` (one
//! character), recursively under the pinned directory. The Python twin is
//! `scripts/ci/pathpin.py`.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

/// The smallest minimum a pin accepts: zero would make the pin a no-op.
pub const MIN_PIN: usize = 1;

/// The glob that selects Rust sources.
pub const RS_GLOB: &str = "*.rs";

/// The floor for a walk over the whole crate source tree (601 `.rs` files today). A
/// partial move of the tree trips it as surely as a missing directory does.
pub const SRC_RS_MIN: usize = 100;

/// Resolve a pinned directory; panic when it is missing.
pub fn pin_dir(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    assert!(
        path.is_dir(),
        "pathpin: missing directory {} (the pinned path moved or was deleted)",
        path.display()
    );
    path.to_path_buf()
}

/// Resolve a pinned file; panic when it is missing.
pub fn pin_file(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    assert!(
        path.is_file(),
        "pathpin: missing file {} (the pinned path moved or was deleted)",
        path.display()
    );
    path.to_path_buf()
}

/// Pin `path` and return the sorted files under it whose NAME matches `glob`;
/// panic when the directory is missing or fewer than `min` files match.
pub fn pin_files(path: impl AsRef<Path>, glob: &str, min: usize) -> Vec<PathBuf> {
    assert!(
        min >= MIN_PIN,
        "pathpin: minimum must be at least {MIN_PIN}, got {min}"
    );
    let dir = pin_dir(path);
    let mut files = Vec::new();
    collect(&dir, glob, &mut files);
    files.sort();
    assert!(
        files.len() >= min,
        "pathpin: {} files match {glob} under {}, need at least {min} (0 files means the path moved or the glob is stale)",
        files.len(),
        dir.display()
    );
    files
}

/// Pin a walk root: the directory must exist and hold at least `min` `.rs`
/// files. Returns the directory itself so it drops into an existing walker:
/// `collect_rs(&pathpin::pin_rs_root(root.join("src"), 1), &mut files)`.
pub fn pin_rs_root(path: impl AsRef<Path>, min: usize) -> PathBuf {
    let dir = pin_dir(path);
    pin_files(&dir, RS_GLOB, min);
    dir
}

/// Assert a count a test computed itself is at least `min`, naming `what`.
pub fn pin_count(what: &str, found: usize, min: usize) {
    assert!(
        min >= MIN_PIN,
        "pathpin: minimum must be at least {MIN_PIN}, got {min}"
    );
    assert!(found >= min, "pathpin: {found} {what}, need at least {min}");
}

fn collect(dir: &Path, glob: &str, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("pathpin: read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("pathpin: dir entry under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect(&path, glob, out);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| glob_match(glob, n))
        {
            out.push(path);
        }
    }
}

/// Wildcard match of `name` against `pattern` (`*` any run, `?` one char).
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
