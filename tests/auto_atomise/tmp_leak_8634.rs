// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8634 class A: a test must leave its `TMPDIR` exactly as it found it.
//!
//! `shared_db_path()` in `core.rs` used to mint
//! `wt1d-auto-atomise-<uuid>.db` (plus its `-wal` / `-shm` sidecars) straight
//! in the temp directory and never remove it: one more file per run, 622,552
//! entries on a CI host. The invariant is checked from the outside: this cell
//! re-runs one real auto-atomise case in a CHILD copy of this very test
//! binary, with `TMPDIR` pointed at a fresh empty directory, and requires the
//! directory to be empty once the child process has exited.

use std::path::Path;
use std::process::Command;

/// The auto-atomise case the child runs; it opens the shared on-disk DB, so
/// it exercises the creation path the invariant is about.
const CHILD_CASE: &str = "core::test_auto_atomise_disabled_does_nothing";
/// Prefix of the empty `TMPDIR` handed to the child.
const CHILD_TMPDIR_PREFIX: &str = "auto-atomise-8634-tmpdir-";

/// Sorted names of every entry directly inside `dir`.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list the child TMPDIR")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn auto_atomise_run_leaves_its_tmpdir_empty_8634() {
    let child_tmp = tempfile::Builder::new()
        .prefix(CHILD_TMPDIR_PREFIX)
        .tempdir()
        .expect("fresh empty TMPDIR for the child");
    let exe = std::env::current_exe().expect("path of this test binary");
    let out = Command::new(exe)
        .args(["--exact", CHILD_CASE, "--test-threads=1"])
        .env("TMPDIR", child_tmp.path())
        .output()
        .expect("spawn the child test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the child case {CHILD_CASE} did not pass (status {:?}):\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let left = listing(child_tmp.path());
    assert!(
        left.is_empty(),
        "#8634: the auto_atomise run left {} entr{} in its TMPDIR {}: {left:?}",
        left.len(),
        if left.len() == 1 { "y" } else { "ies" },
        child_tmp.path().display()
    );
}
