// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6122 — integration tests must not leak sqlite `-wal` / `-shm` side files.
//!
//! The pattern under test is the one ~200 suites share: a scratch database on
//! a `NamedTempFile`, WAL-mode connections held by a long-lived owner (router,
//! store), and the file dropped before the owner. Each run is isolated in a
//! private directory so the count is exact.

#[path = "common/sqlite_tempfile.rs"]
mod sqlite_tempfile;

use sqlite_tempfile::{SqliteTempFile, side_files};

/// Orphaned side files left in `dir` after the scope of the scratch file.
fn leftovers(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn scratch_dir(tag: &str) -> tempfile::TempDir {
    let root = std::path::Path::new(".local-runs").join("tmp-leak-guard-6122");
    std::fs::create_dir_all(&root).expect("scratch root");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("scratch dir")
}

#[test]
fn file_dropped_before_connection_leaves_no_side_files_6122() {
    let dir = scratch_dir("order");
    {
        let f = SqliteTempFile::new_in(dir.path());
        let conn = ai_memory::db::open(f.path()).expect("db::open");
        // Mirrors the suites: the connection outlives the file handle.
        drop(f);
        drop(conn);
    }
    let left = leftovers(dir.path());
    assert!(
        left.is_empty(),
        "#6122: {} orphaned side file(s) left behind: {left:?}",
        left.len()
    );
}

#[test]
fn many_scopes_leave_no_side_files_6122() {
    let dir = scratch_dir("many");
    for _ in 0..20 {
        let f = SqliteTempFile::new_in(dir.path());
        let _conn = ai_memory::db::open(f.path()).expect("db::open");
        let _reader = ai_memory::db::open(f.path()).expect("reopen");
        // `f` declared first, so it drops LAST here; the leak needs the
        // reverse order, which the explicit drop below forces.
        drop(f);
    }
    let left = leftovers(dir.path());
    assert!(
        left.is_empty(),
        "#6122: {} orphaned side file(s) after 20 scopes: {left:?}",
        left.len()
    );
}

#[test]
fn side_files_names_cover_wal_shm_journal_6122() {
    let names: Vec<String> = side_files(std::path::Path::new("/x/.tmpAb"))
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert_eq!(
        names,
        ["/x/.tmpAb-wal", "/x/.tmpAb-shm", "/x/.tmpAb-journal"]
    );
}
