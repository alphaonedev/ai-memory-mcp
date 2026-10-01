// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v1.0.0 #4207 — `ai-memory backup` must NEVER migrate the database it copies.
//!
//! The scheduled backup unit (`ai-memory-backup.timer`) runs the binary on
//! disk. After an in-place upgrade that binary is newer than a still-running
//! daemon. `backup` used to open its source through the MIGRATING `db::open`,
//! so the next tick stamped the live primary to the new schema, wrote a
//! pre-migration snapshot, and left the old daemon serving a schema it does
//! not understand. A backup only copies data out: it opens through the
//! unmigrated egress funnel (`db::open_unmigrated`, #2445).
//!
//! The cells drive the real binary (no mutation of the test process env).

use std::path::Path;

use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

fn stamp(db: &Path, version: i64) {
    let conn = Connection::open(db).expect("raw open");
    conn.execute("UPDATE schema_version SET version = ?1", [version])
        .expect("stamp");
}

fn stamped(db: &Path) -> i64 {
    let conn = Connection::open(db).expect("raw open");
    conn.query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .expect("read stamp")
}

/// Every file in the database's directory that is not the db, its WAL/SHM
/// sidecars, or the backup directory: a pre-migration snapshot would land here.
fn stray_files(dir: &Path, db: &Path) -> Vec<String> {
    let db_name = db.file_name().expect("name").to_string_lossy().into_owned();
    std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with(&db_name) || n.contains("pre-migration") || n.contains(".bak"))
        .filter(|n| n != "backups")
        .collect()
}

fn seeded_db_stamped_at(tmp: &TempDir, version: i64) -> std::path::PathBuf {
    let db = tmp.path().join("ai-memory.db");
    drop(ai_memory::db::open(&db).expect("create current-schema db"));
    stamp(&db, version);
    db
}

/// THE #4207 REGRESSION. A store one rung below the binary's schema (the state
/// a newer binary meets on a live DB before the daemon restarts) must come out
/// of `backup` still stamped at that rung, with no pre-migration snapshot.
#[test]
fn backup_leaves_an_older_schema_store_unmigrated_4207() {
    let tmp = TempDir::new().expect("tempdir");
    let below = ai_memory::db::current_schema_version_for_tests() - 1;
    let db = seeded_db_stamped_at(&tmp, below);
    let backups = tmp.path().join("backups");

    ai_memory(&db)
        .args(["backup", "--to", backups.to_str().expect("utf-8")])
        .assert()
        .success();

    assert_eq!(
        stamped(&db),
        below,
        "backup migrated the live database (schema stamp moved)"
    );
    assert_eq!(
        stray_files(tmp.path(), &db),
        Vec::<String>::new(),
        "backup wrote a pre-migration artifact next to the live database"
    );
    let snapshots: Vec<_> = std::fs::read_dir(&backups)
        .expect("backups dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".db"))
        .collect();
    assert_eq!(snapshots.len(), 1, "a snapshot must still be produced");
}

/// The manifest keeps recording the OBSERVED schema version, not the binary's.
#[test]
fn backup_manifest_records_the_observed_older_schema_4207() {
    let tmp = TempDir::new().expect("tempdir");
    let below = ai_memory::db::current_schema_version_for_tests() - 1;
    let db = seeded_db_stamped_at(&tmp, below);
    let backups = tmp.path().join("backups");

    ai_memory(&db)
        .args(["backup", "--to", backups.to_str().expect("utf-8"), "--json"])
        .assert()
        .success();

    let manifest = std::fs::read_dir(&backups)
        .expect("backups dir")
        .flatten()
        .find(|e| e.file_name().to_string_lossy().ends_with(".manifest.json"))
        .expect("manifest present");
    let text = std::fs::read_to_string(manifest.path()).expect("read manifest");
    assert!(
        text.contains(&format!("\"schema_version\":{below}"))
            || text.contains(&format!("\"schema_version\": {below}")),
        "manifest must record the observed schema version {below}: {text}"
    );
}
