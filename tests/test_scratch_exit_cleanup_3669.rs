// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3669 — process-lifetime test directories are removed when the test
//! process exits.
//!
//! The test runs twice. The outer run re-executes this test binary as a
//! child with [`CHILD_MARKER_ENV`] set. The child creates both kinds of
//! process-lifetime directory, writes a file into each, records their paths
//! in the marker file and returns, so the harness exits normally. The outer
//! run then checks that both directories are gone.
//!
//! Before #3669 the key-directory sandbox lived in a `static OnceLock<TempDir>`
//! whose destructor never runs, so the first assertion below failed: every
//! test binary that armed the sandbox left a directory of key material in
//! the temp root.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

/// Set in the child only: the file the child writes its directory paths to.
const CHILD_MARKER_ENV: &str = "AI_MEMORY_TEST_3669_CHILD_MARKER";

/// This test's own name, used to run exactly it in the child.
const TEST_NAME: &str = "process_lifetime_dirs_are_removed_at_process_exit_3669";

#[test]
fn process_lifetime_dirs_are_removed_at_process_exit_3669() {
    if let Some(marker) = std::env::var_os(CHILD_MARKER_ENV) {
        run_child(Path::new(&marker));
        return;
    }

    let out = tempfile::TempDir::new().expect("marker dir");
    let marker = out.path().join("paths.txt");
    let status = Command::new(std::env::current_exe().expect("current test binary"))
        .args(["--exact", TEST_NAME, "--test-threads=1", "--quiet"])
        .env(CHILD_MARKER_ENV, &marker)
        .status()
        .expect("spawn the child test process");
    assert!(status.success(), "child test process failed: {status}");

    let recorded = std::fs::read_to_string(&marker).expect("child wrote its paths");
    let dirs: Vec<&str> = recorded.lines().collect();
    assert_eq!(dirs.len(), 2, "child records two directories: {recorded:?}");
    for dir in dirs {
        assert!(
            !Path::new(dir).exists(),
            "{dir} must be removed when the process that created it exits"
        );
    }
}

/// The child: create the key-directory sandbox and a `process_lifetime_dir`,
/// put a file in each, record both paths and return.
fn run_child(marker: &Path) {
    let sandbox = ai_memory::identity::test_key_dir::install();
    std::fs::write(sandbox.join("probe.pub"), b"probe").expect("write into the sandbox");

    static SLOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    let scratch = ai_memory::test_scratch::process_lifetime_dir(&SLOT, || {
        tempfile::TempDir::new().expect("process-lifetime dir")
    });
    std::fs::write(scratch.join("db.sqlite"), b"probe").expect("write into the scratch dir");

    let paths = format!("{}\n{}\n", sandbox.display(), scratch.display());
    std::fs::write(marker, paths).expect("record the paths");
}
