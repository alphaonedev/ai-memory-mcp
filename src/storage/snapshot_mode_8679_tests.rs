// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8679 round 2 - the pre-migration snapshot is as private as its source, and
//! the same-version trigger repair is decided under the writer lock.
//!
//! Invariant 2: every snapshot file written by `snapshot_before_migration` has
//! the source database's permission bits (owner-only when they cannot be read),
//! and its creation fails closed (no snapshot, no stray file, an error).
//!
//! F4: the repair deletes the derived `embed_skip` cache, so a racing open that
//! lost the writer lock to a repairing open must not repair a second time.

use crate::storage::{embed_skip, migrations};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Permission bits compared (the file-type bits are not part of the contract).
const MODE_MASK: u32 = 0o777;
/// Source modes the snapshot must reproduce: owner-only and group-readable.
const SOURCE_MODES: [u32; 2] = [0o600, 0o640];
/// A seeded cache row, so the repair's `DELETE FROM embed_skip` is observable.
const SEED_SKIP_SQL: &str = "INSERT INTO embed_skip \
    (memory_id, agent_id, key_fingerprint, reason, created_at) \
    VALUES ('m-8679', '', 'fp', 'oversize', '2026-01-01T00:00:00Z')";

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & MODE_MASK
}

fn source_db(dir: &Path, mode: u32) -> (rusqlite::Connection, PathBuf) {
    let path = dir.join("ai-memory.db");
    let conn = rusqlite::Connection::open(&path).expect("open source");
    conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
        .expect("seed source");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod source");
    (conn, path)
}

fn bak_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "bak"))
        .collect()
}

#[test]
fn snapshot_mode_equals_source_mode_8679() {
    for source_mode in SOURCE_MODES {
        let dir = tempfile::tempdir().expect("tempdir");
        let (conn, _path) = source_db(dir.path(), source_mode);
        let snapshot = migrations::snapshot_before_migration(&conn, 100, 100)
            .expect("snapshot")
            .expect("file-backed database yields a snapshot");
        assert_eq!(
            mode_of(&snapshot),
            source_mode,
            "snapshot of a {source_mode:o} source must carry the same permission bits"
        );
    }
}

#[test]
fn snapshot_creation_fails_closed_when_the_target_cannot_be_created_8679() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (conn, _path) = source_db(dir.path(), 0o600);
    // A read-only directory: the snapshot file cannot be created in it.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).expect("ro dir");
    let probe = dir.path().join("probe");
    if std::fs::write(&probe, b"x").is_ok() {
        // Running with privileges that ignore directory modes: nothing to prove.
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok();
        return;
    }
    let result = migrations::snapshot_before_migration(&conn, 100, 100);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("restore");
    assert!(result.is_err(), "no snapshot target means no migration");
    assert_eq!(
        bak_files(dir.path()),
        Vec::<PathBuf>::new(),
        "no stray file"
    );
}

fn healthy_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = crate::db::open(&dir.path().join("ai-memory.db")).expect("open tip database");
    (dir, conn)
}

fn clear_trigger_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN (?1, ?2)",
        rusqlite::params![
            embed_skip::TRIGGER_CLEAR_ON_CONTENT,
            embed_skip::TRIGGER_CLEAR_ON_EMBED
        ],
        |r| r.get(0),
    )
    .expect("count triggers")
}

fn skip_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM embed_skip", [], |r| r.get(0))
        .expect("count embed_skip")
}

#[test]
fn repair_is_skipped_when_a_racing_open_already_repaired_8679() {
    let (_dir, conn) = healthy_db();
    conn.execute(SEED_SKIP_SQL, []).expect("seed skip row");
    assert_eq!(clear_trigger_count(&conn), 2, "healthy store");
    // The caller's pre-lock probe saw a gap; by the time it holds the lock the
    // racing open has repaired. The re-probe under the lock must skip.
    let repaired = migrations::repair_under_writer_lock(&conn).expect("lock + re-probe");
    assert!(!repaired, "healthy under the lock: repair must be skipped");
    assert_eq!(
        skip_rows(&conn),
        1,
        "derived cache untouched by a skipped repair"
    );
}

#[test]
fn repair_runs_when_the_gap_is_still_present_under_the_lock_8679() {
    let (_dir, conn) = healthy_db();
    conn.execute(SEED_SKIP_SQL, []).expect("seed skip row");
    for trigger in [
        embed_skip::TRIGGER_CLEAR_ON_CONTENT,
        embed_skip::TRIGGER_CLEAR_ON_EMBED,
    ] {
        conn.execute_batch(&format!("DROP TRIGGER {trigger}"))
            .expect("open the gap");
    }
    assert_eq!(clear_trigger_count(&conn), 0);
    let repaired = migrations::repair_under_writer_lock(&conn).expect("repair");
    assert!(repaired, "gap still present: repair must run");
    assert_eq!(clear_trigger_count(&conn), 2, "triggers reinstalled");
    assert_eq!(skip_rows(&conn), 0, "stale cache cleared with the repair");
}
