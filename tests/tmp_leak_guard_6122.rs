// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Guard for #6122: sqlite-backed test fixtures must not leak temp entries.
//!
//! Integration suites used to keep a `NamedTempFile` / `TempDir` alive with
//! `std::mem::forget`, which left the primary db file, its `-wal` / `-shm`
//! sidecars and scratch directories in `TMPDIR` after every run. The fix is
//! `tests/common/tmp_retain.rs`, which parks the guard until process exit and
//! then removes the file, the sidecars and the directory.
//!
//! This guard re-runs the representative store setup/teardown of
//! `fed_owner_floor_4285` (a `NamedTempFile` backing a `SqliteStore`) in a
//! child process whose `TMPDIR` is a private directory, and fails when the
//! private directory has any entry left after the child exits. A second test
//! runs the same fixture with the old `mem::forget` shape to prove the
//! detector sees a leak, so the guard cannot pass vacuously.

#![cfg(feature = "sal")]

#[path = "common/tmp_retain.rs"]
mod tmp_retain;

use std::path::Path;
use std::process::Command;

const CHILD_ENV: &str = "AI_MEMORY_TMP_LEAK_GUARD_6122_CHILD";
const FORGET_ENV: &str = "AI_MEMORY_TMP_LEAK_GUARD_6122_FORGET";

/// The representative fixture: a `NamedTempFile`-backed `SqliteStore`, opened,
/// written through, and dropped, with the temp guard retained or forgotten.
fn store_setup_teardown(forget: bool) {
    if forget {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let path = tmp.path().to_path_buf();
        let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore");
        std::mem::forget(tmp);
        drop(store);
    } else {
        let tmp = tmp_retain::SidecarTempFile::new().expect("tempfile for SqliteStore");
        let path = tmp.path().to_path_buf();
        let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore");
        tmp_retain::retain(tmp);
        drop(store);
    }
}

/// Child entry point: inert unless the parent set the marker env var.
#[test]
fn child_fixture_6122() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    store_setup_teardown(std::env::var_os(FORGET_ENV).is_some());
}

fn leftovers(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read private TMPDIR")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Run the child fixture with a private `TMPDIR` and return what it left behind.
fn run_child_and_list(forget: bool) -> Vec<String> {
    let private = tempfile::Builder::new()
        .prefix(if forget { "forget" } else { "retain" })
        .tempdir()
        .expect("private TMPDIR");
    let exe = std::env::current_exe().expect("current test exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "child_fixture_6122", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env("TMPDIR", private.path())
        .env("AI_MEMORY_NO_CONFIG", "1");
    if forget {
        cmd.env(FORGET_ENV, "1");
    }
    let out = cmd.output().expect("spawn child fixture");
    assert!(
        out.status.success(),
        "child fixture failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    leftovers(private.path())
}

#[test]
fn store_fixture_leaves_no_tmp_entries_6122() {
    let left = run_child_and_list(false);
    assert!(
        left.is_empty(),
        "sqlite fixture leaked {} TMPDIR entries (#6122): {left:?}",
        left.len()
    );
}

#[test]
fn detector_sees_a_deliberate_forget_leak_6122() {
    let left = run_child_and_list(true);
    assert!(
        left.iter().any(|n| n.ends_with("-wal")) && left.iter().any(|n| n.ends_with("-shm")),
        "control leak must leave -wal and -shm sidecars, saw {left:?}"
    );
}
