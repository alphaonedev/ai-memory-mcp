// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7450 r2 -- `identity::test_key_dir::private_tempdir()` must allocate OUTSIDE
//! HOME even when `$TMPDIR` is rooted under HOME.
//!
//! The in-process pin (`private_tempdir_is_off_home_7450`) inherits whatever
//! `$TMPDIR` the runner has, so on a runner whose `TMPDIR` is already off HOME it
//! is green on the defect. This pin sets `HOME` and `TMPDIR` itself, in a child
//! process (the `tests/key_dir_isolation_3355.rs` shape; `$TMPDIR` and `$HOME`
//! are process-global, so a child keeps every other reader untouched, as in
//! `tests/test_key_dir_isolated_temp_root_3859.rs`). The contract therefore
//! holds on any runner, including one whose ambient `TMPDIR` is off HOME.
//!
//! The child binds `AI_MEMORY_KEY_DIR` to the private directory and resolves
//! the key directory through `default_key_dir()`, which runs the crate-private
//! #3355 `assert_isolated` guard (armed by `TEST_KEY_GUARD_ENV`).

use ai_memory::identity::test_key_dir::{TEST_KEY_GUARD_ENV, private_tempdir, resolved_home};
use std::process::Command;

const PROBE_ENV: &str = "PRIVATE_TEMPDIR_PROBE_7450";
const RAN_MARKER: &str = "probe-ran-7450";

#[test]
fn private_tempdir_probe() {
    if std::env::var_os(PROBE_ENV).is_none() {
        return;
    }
    let dir = private_tempdir();
    // SAFETY: this probe child runs only this test, in its own process; no
    // concurrent env reader exists.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", dir.path());
    }
    let resolved = ai_memory::identity::keypair::default_key_dir()
        .expect("#7450 default_key_dir resolves for the private directory");
    assert_eq!(resolved, dir.path());
    let home = resolved_home();
    let canonical_home = home.canonicalize().unwrap_or(home);
    let canonical_dir = dir.path().canonicalize().expect("canonicalize private dir");
    assert!(
        !canonical_dir.starts_with(&canonical_home),
        "#7450 private_tempdir resolved under HOME: {}",
        canonical_dir.display()
    );
    // Side effect the parent asserts: a child that ran zero tests exits 0.
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("HOME").expect("#7450 HOME set by parent"))
            .join(RAN_MARKER),
        b"ran",
    )
    .expect("#7450 write probe marker");
}

#[test]
fn private_tempdir_is_off_home_when_tmpdir_is_under_home_7450() {
    let home = tempfile::tempdir().unwrap();
    let tmp = home.path().join("tmp");
    std::fs::create_dir(&tmp).unwrap();
    let output = Command::new(std::env::current_exe().expect("#7450 resolve test binary"))
        .args(["--exact", "private_tempdir_probe", "--nocapture"])
        .env(PROBE_ENV, "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("HOME", home.path())
        .env("TMPDIR", &tmp)
        .env_remove("AI_MEMORY_KEY_DIR")
        .output()
        .expect("#7450 spawn probe child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
    assert!(
        output.status.success(),
        "#7450 child failed ({:?}); stderr tail (newest first):\n{}",
        output.status,
        tail.join("\n")
    );
    assert!(
        home.path().join(RAN_MARKER).is_file(),
        "#7450 probe child exited 0 without running the probe (renamed or filtered out?)"
    );
}
