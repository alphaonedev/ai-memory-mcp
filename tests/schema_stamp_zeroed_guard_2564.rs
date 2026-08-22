// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2564 — the LOW-end schema-stamp guard.
//!
//! #2445 refuses a stamp that is too HIGH. A stamp that is too LOW was
//! undefended, and low is strictly worse: `SELECT COALESCE(MAX(version), 0)`
//! means `DELETE FROM schema_version` (or an inserted `0`) reads as version 0,
//! which replays the ENTIRE v1 → tip ladder over a POPULATED database under
//! `BEGIN EXCLUSIVE` — with the pre-migration safety snapshot SUPPRESSED,
//! because that snapshot was gated on `version > 0`. Offered `999` (a loud
//! refusal) or `0` (a silent full-ladder replay with the backup disabled), an
//! adversary picks 0 every time.
//!
//! The fix makes the illegal state unrepresentable: `SchemaStamp` gains a
//! `Zeroed` variant, and every WRITE funnel reads it through
//! `operable_version()` (which cannot yield an `i64` for `Zeroed`) instead of
//! `version()` (which coerced it to a permissive `0`).
//!
//! The discriminator is STRUCTURAL, so the two LEGITIMATE stamp-0 databases
//! keep opening — a fresh install (tables but no rows) and a legacy pre-v2
//! database mid-upgrade (rows, but no `memories.confidence`, which acquiring
//! IS the v2 step). Both are pinned below; a guard that broke either would be
//! a self-DOS, not a fix.

use ai_memory::db;
use ai_memory::models::{Memory, Tier, default_metadata};
use ai_memory::storage::schema_guard::{
    self, BACKEND_SQLITE, SchemaStamp, schema_ahead_of, schema_stamp_zeroed,
};
use rusqlite::Connection;

/// The v1 `memories` shape — deliberately WITHOUT `confidence` (the column the
/// v2 ladder arm adds), which is what makes a legitimate stamp-0 database
/// distinguishable from a zeroed one.
const LEGACY_V1_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS memories (
        id               TEXT PRIMARY KEY,
        tier             TEXT NOT NULL,
        namespace        TEXT NOT NULL DEFAULT 'global',
        title            TEXT NOT NULL,
        content          TEXT NOT NULL,
        tags             TEXT NOT NULL DEFAULT '[]',
        priority         INTEGER NOT NULL DEFAULT 5,
        access_count     INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL,
        last_accessed_at TEXT,
        expires_at       TEXT
    );
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
    INSERT INTO schema_version (version) VALUES (0);
";

/// A scratch database in an auto-cleaned directory.
///
/// The `TempDir` guard is RETURNED, not dropped, and every call site binds it:
/// the pre-migration `VACUUM INTO` snapshot lands as a SIBLING of the database
/// file, so the directory must outlive the test body for
/// `a_populated_v0_database_gets_a_pre_migration_snapshot_2564` to see it —
/// and must then be removed, which a bare `std::env::temp_dir()` join never
/// does.
fn tmp_db(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("ai-memory-2564-{name}-"))
        .tempdir()
        .expect("scratch dir");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn seed_row(conn: &Connection) {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::storage::insert(
        conn,
        &Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "stamp-2564".to_string(),
            title: format!("row-{}", uuid::Uuid::new_v4()),
            content: "durable text".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: default_metadata(),
            ..Memory::default()
        },
    )
    .expect("seed durable row");
}

// ---------------------------------------------------------------------------
// The attack
// ---------------------------------------------------------------------------

/// Deleting the stamp row on a POPULATED database must refuse the next open
/// with the typed low-end verdict — not silently replay the ladder.
#[test]
fn deleted_stamp_on_a_populated_database_refuses_the_open_2564() {
    let (_scratch, path) = tmp_db("deleted-stamp");
    {
        let conn = db::open(&path).expect("first open migrates");
        seed_row(&conn);
    }
    {
        let conn = Connection::open(&path).expect("raw reopen");
        conn.execute("DELETE FROM schema_version", [])
            .expect("zero the stamp");
    }

    let err = db::open(&path).expect_err("a zeroed stamp on live data must refuse");
    let verdict = schema_stamp_zeroed(&err)
        .unwrap_or_else(|| panic!("expected the typed #2564 verdict, got: {err:#}"));
    assert_eq!(verdict.observed, 0);
    assert_eq!(verdict.backend, BACKEND_SQLITE);
    assert!(
        verdict.detail.contains("provably NOT a fresh one"),
        "operator message must say WHY it refused: {}",
        verdict.detail
    );
    assert!(
        schema_ahead_of(&err).is_none(),
        "#2564 is a distinct verdict from the #2445 schema-ahead one"
    );
}

/// An explicitly inserted `0` is the same attack by another spelling.
#[test]
fn inserted_zero_stamp_on_a_populated_database_refuses_the_open_2564() {
    let (_scratch, path) = tmp_db("inserted-zero");
    {
        let conn = db::open(&path).expect("first open migrates");
        seed_row(&conn);
    }
    {
        let conn = Connection::open(&path).expect("raw reopen");
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear");
        conn.execute("INSERT INTO schema_version (version) VALUES (0)", [])
            .expect("insert 0");
    }
    let err = db::open(&path).expect_err("an inserted 0 must refuse too");
    assert!(schema_stamp_zeroed(&err).is_some(), "got: {err:#}");
}

/// A NEGATIVE stamp is illegal unconditionally — no ladder ever writes one.
/// Pre-#2564 `cli::boot::read_schema_version`'s `u32::try_from(v).ok()` mapped
/// it to "unsupported" with NO warning while `observed > CURRENT` stayed
/// false, so it too was waved into a full ladder replay.
#[test]
fn negative_stamp_refuses_even_without_corroboration_2564() {
    let (_scratch, path) = tmp_db("negative-stamp");
    {
        let conn = db::open(&path).expect("first open migrates");
        seed_row(&conn);
    }
    {
        let conn = Connection::open(&path).expect("raw reopen");
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear");
        conn.execute("INSERT INTO schema_version (version) VALUES (-1)", [])
            .expect("insert negative");
    }
    let err = db::open(&path).expect_err("a negative stamp must refuse");
    let verdict = schema_stamp_zeroed(&err).unwrap_or_else(|| panic!("got: {err:#}"));
    assert_eq!(verdict.observed, -1);
}

/// The shared verdict is a RANGE check now, not a ceiling check.
#[test]
fn evaluate_refuses_a_negative_observed_version_2564() {
    let err = schema_guard::evaluate(-1, 90, BACKEND_SQLITE, "/tmp/x.db")
        .expect_err("a negative observed version is illegal at the low end");
    assert_eq!(err.observed, -1);
    // The sane range still passes untouched.
    assert!(schema_guard::evaluate(0, 90, BACKEND_SQLITE, "/tmp/x.db").is_ok());
    assert!(schema_guard::evaluate(90, 90, BACKEND_SQLITE, "/tmp/x.db").is_ok());
}

// ---------------------------------------------------------------------------
// The two databases that legitimately stamp 0 — a guard that broke either
// would be a self-DOS. These are the false-positive pins.
// ---------------------------------------------------------------------------

/// A brand-new database opens normally. The bootstrap DDL creates every table
/// BEFORE the first stamp is written, so "tables exist + stamp 0" is the
/// ordinary fresh-install state and must never be read as damage.
#[test]
fn a_fresh_database_still_opens_2564() {
    let (_scratch, path) = tmp_db("fresh");
    let conn = db::open(&path).expect("a fresh database must open");
    let v: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("stamp");
    assert_eq!(v, ai_memory::storage::migrations::current_schema_version());
}

/// An EMPTY database whose stamp was cleared still opens: the refusal protects
/// DATA, and there is none to protect here. Degrade, never over-refuse.
#[test]
fn a_zeroed_but_empty_database_still_opens_2564() {
    let (_scratch, path) = tmp_db("zeroed-empty");
    {
        db::open(&path).expect("first open migrates");
    }
    {
        let conn = Connection::open(&path).expect("raw reopen");
        conn.execute("DELETE FROM schema_version", [])
            .expect("zero the stamp");
    }
    db::open(&path).expect("an empty database has nothing to lose");
}

/// A LEGACY pre-v2 database legitimately stamps 0 AND holds rows — and it is
/// the database with the most ladder still to replay. It must keep migrating.
#[test]
fn a_legacy_pre_v2_database_with_rows_still_migrates_2564() {
    let (_scratch, path) = tmp_db("legacy-v1");
    {
        let conn = Connection::open(&path).expect("create legacy db");
        conn.execute_batch(LEGACY_V1_SCHEMA).expect("v1 schema");
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('legacy', 'short', 'ns', 't', 'c', \
             '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
            [],
        )
        .expect("seed a v1-shaped row");
    }
    let conn = db::open(&path).expect("a legacy v1 database must still upgrade");
    let v: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("stamp");
    assert_eq!(v, ai_memory::storage::migrations::current_schema_version());
    let kept: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = 'legacy'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(kept, 1, "the legacy row must survive the ladder");
}

/// #2564 (a) — the pre-migration safety snapshot is no longer gated on
/// `version > 0` alone. The legacy pre-v2 database above is the one case that
/// still legitimately replays the whole ladder over live data, so it is
/// exactly the one that must get a snapshot.
#[test]
fn a_populated_v0_database_gets_a_pre_migration_snapshot_2564() {
    let (_scratch, path) = tmp_db("legacy-snapshot");
    {
        let conn = Connection::open(&path).expect("create legacy db");
        conn.execute_batch(LEGACY_V1_SCHEMA).expect("v1 schema");
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('legacy', 'short', 'ns', 't', 'c', \
             '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
            [],
        )
        .expect("seed a v1-shaped row");
    }
    db::open(&path).expect("legacy upgrade");

    let infix = ai_memory::storage::migrations::pre_migration_backup_infix_for_tests();
    let dir = path.parent().expect("parent dir");
    let snapshots: Vec<_> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(infix))
        .collect();
    assert!(
        !snapshots.is_empty(),
        "#2564(a): a POPULATED database replaying the ladder from 0 must be \
         snapshotted first; found {snapshots:?} in {}",
        dir.display()
    );
}

/// #2564 (a), the ARCHIVED tier. A corpus that has been fully archived holds
/// ZERO `memories` rows while `archived_memories` holds all of its durable
/// text — and the v86/v87 ladder arms rewrite `archived_memories` renderings.
/// A `memories`-only snapshot probe would skip the backup on exactly that
/// database, so the probe covers both tiers.
///
/// This database is also the deliberate RESIDUAL of the refusal discriminator:
/// with no `memories` rows there is no corroboration that a zero stamp is
/// impossible, so the open is ALLOWED and the ladder replays. That is
/// reasoned, not overlooked — the replay's only data arms over this tier are
/// v86/v87, which are instant-preserving, idempotent and fail-safe on an
/// unparseable value, so the bounded harm is a no-op rewrite; and widening the
/// refusal to name `archived_memories` would make the whole probe statement
/// fail to prepare on a pre-v4 database, WEAKENING the case the guard exists
/// for. The snapshot fires regardless, which is the part that protects data.
#[test]
fn an_archived_only_database_still_gets_a_pre_migration_snapshot_2564() {
    let (_scratch, path) = tmp_db("archived-only");
    {
        let conn = db::open(&path).expect("first open migrates");
        seed_row(&conn);
        let id: String = conn
            .query_row("SELECT id FROM memories LIMIT 1", [], |r| r.get(0))
            .expect("seeded id");
        ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");
        let live: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .expect("count live");
        let cold: i64 = conn
            .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
            .expect("count cold");
        assert_eq!((live, cold), (0, 1), "the corpus must be archive-only");
    }
    {
        let conn = Connection::open(&path).expect("raw reopen");
        conn.execute("DELETE FROM schema_version", [])
            .expect("zero the stamp");
    }

    db::open(&path).expect("no corroboration -> the open is allowed (documented residual)");

    let infix = ai_memory::storage::migrations::pre_migration_backup_infix_for_tests();
    let dir = path.parent().expect("parent dir");
    let snapshots: Vec<_> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(infix))
        .collect();
    assert!(
        !snapshots.is_empty(),
        "#2564(a): durable text in the ARCHIVE tier must be snapshotted before \
         a from-zero ladder replay too; found {snapshots:?} in {}",
        dir.display()
    );
}

// ---------------------------------------------------------------------------
// Type-level: the illegal state is unrepresentable
// ---------------------------------------------------------------------------

/// `operable_version()` is the accessor every WRITE funnel uses precisely
/// because there is NO path from `Zeroed` to an `i64` through it — whereas
/// `version()` still reports the raw reading for diagnostics.
#[test]
fn zeroed_has_no_operable_version_2564() {
    assert_eq!(SchemaStamp::Fresh.version(), 0);
    assert_eq!(SchemaStamp::Known(87).version(), 87);
    assert_eq!(SchemaStamp::Zeroed(0).version(), 0);

    assert_eq!(
        SchemaStamp::Fresh.operable_version(BACKEND_SQLITE, "t"),
        Ok(0)
    );
    assert_eq!(
        SchemaStamp::Known(87).operable_version(BACKEND_SQLITE, "t"),
        Ok(87)
    );
    let refusal = SchemaStamp::Zeroed(0)
        .operable_version(BACKEND_SQLITE, "t")
        .expect_err("a zeroed stamp authorises nothing");
    assert_eq!(refusal.observed, 0);
}
