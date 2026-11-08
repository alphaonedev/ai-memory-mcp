// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! v1.0.0 #8677 — cross-build database safety, SQLite arm, end to end.
//!
//! Data-integrity contract: a database opened by one ai-memory build must
//! never become unreadable or silently altered for another build. Fleet nodes
//! enforce this with a local guard hook; end users have no such hook, so the
//! product itself must guarantee it. Three cases are proven here with real
//! files and the production opener (`ai_memory::db::open`):
//!
//! 1. an OLDER build opens a database written by a NEWER build: typed
//!    refusal naming both schema versions and the fix, file byte-identical
//!    (sha256 before and after), no snapshot or sidecar file created;
//! 2. the CURRENT build opens a database from the PREVIOUS release: it takes
//!    the pre-migration snapshot, migrates, and reopens cleanly;
//! 3. a SECOND build at the SAME schema version opens the database: a healthy
//!    store is byte-identical, and the only allowed change is the documented
//!    derived-state repair (#4078), which is also preceded by a snapshot.
//!
//! "An older binary" is modelled by the current opener against a database
//! stamped ahead of the ladder tip: the guard decision depends only on the
//! recorded stamp versus the ladder tip, never on which binary wrote the rows.
//! Every fixture lives under the worktree's `.local-runs/`, never the live DB.
//!
//! The Postgres twin is `tests/postgres_cross_build_db_compat_8677.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ai_memory::db;
use ai_memory::storage::migrations::{
    current_schema_version, pre_migration_backup_infix_for_tests,
};
use ai_memory::storage::schema_guard::{ENV_ALLOW_SCHEMA_AHEAD, schema_ahead_of};
use sha2::{Digest, Sha256};

/// Scratch root for every fixture, under the worktree's gitignored `.local-runs/`.
const FIXTURE_ROOT: &str = ".local-runs/issue-8677-cross-build";
const DB_FILE_NAME: &str = "ai-memory.db";
const SEED_ID: &str = "m-8677";
const SEED_CONTENT: &str = "durable text that must survive every cross-build open";
/// How far ahead of the ladder tip the "newer build" stamped the database.
const NEWER_BUILD_SCHEMA_LEAD: i64 = 3;
/// The previous-release schema shape reproduced by [`PREVIOUS_RELEASE_SHAPE`].
const PREVIOUS_RELEASE_SCHEMA: i64 = 96;
/// The two derived-state triggers the #4078 repair reinstalls.
const CLEAR_TRIGGERS: [&str; 2] = [
    "memories_embed_skip_clear_on_content",
    "memories_embed_skip_clear_on_embed",
];

/// Reverse the documented additive v97-v100 migrations so the file has the
/// exact v96 shape the previous release wrote (same reversal as
/// `tests/embed_skip_upgrade_4078.rs`), then stamp v96.
const PREVIOUS_RELEASE_SHAPE: &str = "
DROP TRIGGER agent_pubkey_history_authoritative_insert_v97;
DROP TRIGGER agent_pubkey_history_authoritative_update_v97;
DROP TABLE agent_pubkey_history;
DROP TABLE agent_pubkey_challenges;
DROP VIEW inbox_namespace_aliases;
DROP TABLE sync_peer_contact;
DROP INDEX idx_memories_title_ns;
CREATE UNIQUE INDEX idx_memories_title_ns ON memories(title, namespace);
DELETE FROM schema_version;
INSERT INTO schema_version(version) VALUES (96);
";

/// Serialises the process-wide `ENV_ALLOW_SCHEMA_AHEAD` reads.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn no_hatch() {
    // SAFETY: process-wide env mutation, serialised by `env_lock`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
}

fn fixture_dir() -> tempfile::TempDir {
    let root = std::env::current_dir().expect("cwd").join(FIXTURE_ROOT);
    std::fs::create_dir_all(&root).expect("create fixture root");
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn sha256_hex(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).expect("read db file")))
}

/// Names of every entry in the directory (database, sidecars, snapshots).
fn dir_listing(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("read fixture dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// Pre-migration snapshots next to the database.
fn snapshots(dir: &Path) -> Vec<PathBuf> {
    let infix = pre_migration_backup_infix_for_tests();
    dir.read_dir()
        .expect("read fixture dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().contains(infix))
        })
        .collect()
}

fn seed(conn: &rusqlite::Connection) {
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
         confidence, source, metadata, access_count, created_at, updated_at) \
         VALUES (?1, 'long', 'ns', 't', ?2, '[]', 5, 1.0, 'api', '{}', 0, \
         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        rusqlite::params![SEED_ID, SEED_CONTENT],
    )
    .expect("seed row");
}

fn stamp(path: &Path, version: i64) {
    let conn = db::open_unmigrated(path).expect("stamp open");
    conn.execute("DELETE FROM schema_version", []).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![version],
    )
    .unwrap();
}

fn stamp_of(path: &Path) -> i64 {
    let conn = db::open_unmigrated(path).expect("read stamp");
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn seeded_content(path: &Path) -> String {
    let conn = db::open_unmigrated(path).expect("read row");
    conn.query_row(
        "SELECT content FROM memories WHERE id = ?1",
        rusqlite::params![SEED_ID],
        |r| r.get(0),
    )
    .expect("seed row must survive")
}

/// A database written by the current build (tip schema, one durable row).
fn current_build_db(dir: &Path) -> PathBuf {
    let path = dir.join(DB_FILE_NAME);
    let conn = db::open(&path).expect("current build creates the database");
    seed(&conn);
    path
}

// ---------------------------------------------------------------- case 1

#[test]
fn older_build_refuses_newer_database_byte_identical_with_actionable_text_8677() {
    let _g = env_lock();
    no_hatch();
    let dir = fixture_dir();
    let path = current_build_db(dir.path());
    let ahead = current_schema_version() + NEWER_BUILD_SCHEMA_LEAD;
    stamp(&path, ahead);

    let hash_before = sha256_hex(&path);
    let listing_before = dir_listing(dir.path());

    let err = db::open(&path).expect_err("a newer database must be refused");
    let typed = schema_ahead_of(&err).expect("typed SchemaAheadOfBinary verdict");
    assert_eq!(typed.observed, ahead, "refusal names the database schema");
    assert_eq!(
        typed.supported,
        current_schema_version(),
        "refusal names the binary schema"
    );

    let msg = err.to_string();
    // The end-user sentence: who wrote it, what this binary supports, the fix.
    assert!(
        msg.contains(&format!(
            "This database was written by a newer ai-memory build (schema v{ahead})"
        )),
        "must say a newer build wrote the database and name its schema: {msg}"
    );
    assert!(
        msg.contains(&format!(
            "this binary (ai-memory {}) supports schema v{}",
            ai_memory::PKG_VERSION,
            current_schema_version()
        )),
        "must name this binary's version and supported schema: {msg}"
    );
    assert!(
        msg.contains("upgrade ai-memory to the build that wrote this database"),
        "must name the upgrade fix: {msg}"
    );
    assert!(
        msg.contains("open a backup copy with --db <copy>"),
        "must name the backup-copy fix: {msg}"
    );

    assert_eq!(
        sha256_hex(&path),
        hash_before,
        "a refused open must leave the database byte-identical (sha256)"
    );
    assert_eq!(
        dir_listing(dir.path()),
        listing_before,
        "a refused open must create no sidecar, journal or snapshot file"
    );
    assert_eq!(
        snapshots(dir.path()),
        Vec::<PathBuf>::new(),
        "a refused open must take no snapshot"
    );
}

// ---------------------------------------------------------------- case 2

#[test]
fn current_build_snapshots_then_migrates_previous_release_database_8677() {
    let _g = env_lock();
    no_hatch();
    let dir = fixture_dir();
    let path = current_build_db(dir.path());
    {
        let conn = db::open_unmigrated(&path).expect("shape open");
        conn.execute_batch(PREVIOUS_RELEASE_SHAPE)
            .expect("restore previous-release shape");
    }
    assert_eq!(stamp_of(&path), PREVIOUS_RELEASE_SCHEMA);
    assert_eq!(
        snapshots(dir.path()),
        Vec::<PathBuf>::new(),
        "fixture has no snapshot"
    );
    let previous_release_hash = sha256_hex(&path);

    // Upgrade.
    drop(db::open(&path).expect("current build migrates the previous release"));

    let snaps = snapshots(dir.path());
    assert_eq!(
        snaps.len(),
        1,
        "exactly one pre-migration snapshot: {snaps:?}"
    );
    let snap_name = snaps[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        snap_name.contains(&format!(
            "v{PREVIOUS_RELEASE_SCHEMA}-to-v{}",
            current_schema_version()
        )),
        "snapshot names the from/to span: {snap_name}"
    );
    // The snapshot is the previous-release image: old stamp, durable row intact.
    assert_eq!(stamp_of(&snaps[0]), PREVIOUS_RELEASE_SCHEMA);
    assert_eq!(seeded_content(&snaps[0]), SEED_CONTENT);
    assert_ne!(sha256_hex(&path), previous_release_hash, "live db migrated");

    // Migrated database: tip stamp, row intact.
    assert_eq!(stamp_of(&path), current_schema_version());
    assert_eq!(seeded_content(&path), SEED_CONTENT);

    // Reopen cleanly: no second snapshot, no change.
    let migrated_hash = sha256_hex(&path);
    drop(db::open(&path).expect("reopen after migration"));
    assert_eq!(
        snapshots(dir.path()).len(),
        1,
        "reopen takes no new snapshot"
    );
    assert_eq!(sha256_hex(&path), migrated_hash, "reopen is a no-op");
}

// ---------------------------------------------------------------- case 3

#[test]
fn second_build_same_schema_healthy_open_is_a_byte_identical_noop_8677() {
    let _g = env_lock();
    no_hatch();
    let dir = fixture_dir();
    let path = current_build_db(dir.path());
    let hash_before = sha256_hex(&path);
    let listing_before = dir_listing(dir.path());

    drop(db::open(&path).expect("second build opens a healthy same-version db"));

    assert_eq!(
        sha256_hex(&path),
        hash_before,
        "healthy open changes nothing"
    );
    assert_eq!(dir_listing(dir.path()), listing_before);
    assert_eq!(stamp_of(&path), current_schema_version());
}

#[test]
fn second_build_same_schema_only_repairs_derived_state_after_a_snapshot_8677() {
    let _g = env_lock();
    no_hatch();
    let dir = fixture_dir();
    let path = current_build_db(dir.path());
    {
        // The #4078 damage: an older build left the schema stamped at the tip
        // after dropping the derived-cache clear triggers.
        let conn = db::open_unmigrated(&path).expect("damage open");
        for trigger in CLEAR_TRIGGERS {
            conn.execute_batch(&format!("DROP TRIGGER {trigger}"))
                .unwrap();
        }
    }
    let triggers = |p: &Path| -> i64 {
        db::open_unmigrated(p)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (?1, ?2)",
                rusqlite::params![CLEAR_TRIGGERS[0], CLEAR_TRIGGERS[1]],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(triggers(&path), 0);

    drop(db::open(&path).expect("second build repairs derived state"));

    // The only change allowed: the documented derived-state repair.
    assert_eq!(triggers(&path), 2, "derived triggers reinstalled");
    assert_eq!(stamp_of(&path), current_schema_version(), "stamp unchanged");
    assert_eq!(
        seeded_content(&path),
        SEED_CONTENT,
        "durable text unchanged"
    );

    // And the safety snapshot is still taken before that mutation.
    let snaps = snapshots(dir.path());
    assert_eq!(snaps.len(), 1, "one snapshot before the repair: {snaps:?}");
    let image = &snaps[0];
    assert_eq!(triggers(image), 0, "snapshot predates the repair");
    assert_eq!(seeded_content(image), SEED_CONTENT);
}
