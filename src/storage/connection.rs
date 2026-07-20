// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Connection setup for the SQLite substrate. v0.7.0 L0.5-3 extracted
//! `open` + the SQLCipher passphrase helper out of `src/db.rs` into
//! this sub-module. Pure refactor — semantics unchanged.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

use super::migrations::{SCHEMA, migrate};

/// #2266 — exact, parse-tolerant RFC3339 instant projection for SQLite KG
/// predicates. Returning NULL for malformed text makes comparisons fail
/// closed without modifying the H2-signed source bytes.
pub const SQL_FN_RFC3339_EPOCH_MICROS: &str = "rfc3339_epoch_micros";

fn register_valid_time_functions(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;

    conn.create_scalar_function(
        SQL_FN_RFC3339_EPOCH_MICROS,
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let raw = ctx.get::<Option<String>>(0)?;
            Ok(raw.and_then(|value| {
                chrono::DateTime::parse_from_rfc3339(&value)
                    .ok()
                    .map(|instant| instant.timestamp_micros())
            }))
        },
    )
}

/// v0.7.0 fix campaign R1-M2 (#690) — defense-in-depth CHECK
/// constraints applied as `CREATE TRIGGER IF NOT EXISTS` statements
/// after the schema-version migration ladder runs. Sourced from
/// `migrations/sqlite/0023_v07_check_constraints.sql`.
///
/// We deliberately apply this OUTSIDE the version-bumped migration
/// ladder in [`super::migrations::migrate`] because that file is owned
/// by a parallel L0.7-2 stream during the v0.7.0 fix campaign. Running
/// the triggers from here keeps the substrate guard in place without
/// requiring a coordinated `CURRENT_SCHEMA_VERSION` bump. Both the
/// triggers and the surrounding bootstrap are idempotent — re-running
/// `open` (which happens on every fresh `db::open` call) is a no-op
/// after the first apply.
const CHECK_CONSTRAINT_TRIGGERS_SQLITE: &str =
    include_str!("../../migrations/sqlite/0023_v07_check_constraints.sql");

/// Manual-transaction SQL fragments (#1558 batch 5) — shared by every
/// site that drives an explicit immediate write transaction on a
/// rusqlite connection (`execute_batch(SQL_BEGIN_IMMEDIATE)` …
/// `execute_batch(SQL_COMMIT)` / `execute_batch(SQL_ROLLBACK)`).
/// `BEGIN IMMEDIATE` takes the write lock up front so lock contention
/// surfaces at BEGIN (retryable) instead of mid-transaction.
pub const SQL_BEGIN_IMMEDIATE: &str = "BEGIN IMMEDIATE";
pub const SQL_COMMIT: &str = "COMMIT";
pub const SQL_ROLLBACK: &str = "ROLLBACK";

/// #1579 B7 — default `PRAGMA mmap_size` in bytes (256 MiB).
///
/// The P1 perf-audit PRAGMA A/B on the 100k-row corpus found
/// `mmap_size=256MB` the only across-the-board winner (15-30% on
/// large-corpus reads: list p50 137 ms → 101 ms, recall-FTS p50
/// 658 ms → 569 ms; `temp_store=MEMORY` was a wash and
/// `cache_size=64MB` a regression). Memory-mapped I/O lets SQLite read
/// pages straight from the OS page cache instead of `read(2)` copies;
/// the value is an address-space reservation cap, NOT an allocation,
/// so idle databases pay nothing.
///
/// Operator override ladder (resolved by
/// `AppConfig::resolve_storage()` at boot and seeded here via
/// [`set_db_mmap_size`]): `AI_MEMORY_DB_MMAP_SIZE` env >
/// `[storage].db_mmap_size_bytes` config > this compiled default.
/// `0` disables memory-mapped I/O entirely (the stock SQLite
/// semantics); negative / unparseable values fall through to the next
/// ladder layer.
pub const DEFAULT_DB_MMAP_SIZE_BYTES: i64 = 256 * 1024 * 1024;

/// Process-wide resolved `PRAGMA mmap_size`, seeded once at boot from
/// `AppConfig::resolve_storage()` (the `crate::quotas::QuotaDefaults`
/// OnceLock precedent — `open` is called deep in paths where no
/// `AppConfig` is in scope). Unseeded processes (unit tests, library
/// embedders that bypass the CLI boot path) fall through to
/// [`DEFAULT_DB_MMAP_SIZE_BYTES`].
static DB_MMAP_SIZE_BYTES: std::sync::OnceLock<i64> = std::sync::OnceLock::new();

/// Seed the process-wide mmap size for every subsequent [`open`].
/// Idempotent — first writer wins; later calls are no-ops (matches
/// `crate::quotas::set_quota_defaults`).
pub fn set_db_mmap_size(bytes: i64) {
    let _ = DB_MMAP_SIZE_BYTES.set(bytes);
}

/// The effective `PRAGMA mmap_size` for this process.
fn db_mmap_size() -> i64 {
    *DB_MMAP_SIZE_BYTES
        .get()
        .unwrap_or(&DEFAULT_DB_MMAP_SIZE_BYTES)
}

/// v1.0.0 #1961 (R23/R7) — env knob selecting the `PRAGMA synchronous`
/// durability level applied by every [`open`].
///
/// The compiled default is `NORMAL` (the #1579 B7 performance posture):
/// under WAL, `NORMAL` fsyncs at each checkpoint but NOT at every commit,
/// so a **power loss** (not merely a process crash) can lose the tail of
/// acknowledged commits that were in the WAL but not yet checkpoint-fsync'd.
/// A power-loss-durable deployment sets `AI_MEMORY_DB_SYNCHRONOUS=FULL`
/// (or the harder `EXTRA`), which fsyncs the WAL at every commit so an
/// acknowledged write survives a power cut — at a throughput cost. The
/// `asi-hard` hardened profile ([`crate::security_profile`]) pins `FULL`.
pub const ENV_DB_SYNCHRONOUS: &str = "AI_MEMORY_DB_SYNCHRONOUS";

/// The compiled-default `PRAGMA synchronous` level. `NORMAL` keeps the
/// #1579 B7 performance posture byte-for-byte for deployments that do not
/// opt into power-loss durability.
pub const DEFAULT_DB_SYNCHRONOUS: &str = "NORMAL";

/// Resolve the effective `PRAGMA synchronous` token for this process.
///
/// Ladder: [`ENV_DB_SYNCHRONOUS`] env (case-insensitive; one of
/// `OFF` / `NORMAL` / `FULL` / `EXTRA`) > compiled
/// [`DEFAULT_DB_SYNCHRONOUS`]. An unset or unrecognised value falls
/// through to the default so a typo never silently weakens durability
/// below the compiled floor.
#[must_use]
pub fn db_synchronous() -> &'static str {
    match std::env::var(ENV_DB_SYNCHRONOUS) {
        Ok(v) => match v.trim().to_ascii_uppercase().as_str() {
            "OFF" => "OFF",
            "FULL" => "FULL",
            "EXTRA" => "EXTRA",
            "NORMAL" => "NORMAL",
            _ => DEFAULT_DB_SYNCHRONOUS,
        },
        Err(_) => DEFAULT_DB_SYNCHRONOUS,
    }
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).context("failed to open database")?;
    apply_sqlcipher_key(&conn)?;
    register_valid_time_functions(&conn).context("register valid-time SQL functions")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // v1.0.0 #1961 (R23/R7) — resolved `PRAGMA synchronous`. Default
    // `NORMAL` (perf posture); `AI_MEMORY_DB_SYNCHRONOUS=FULL` upgrades to
    // power-loss durability. The `asi-hard` profile pins `FULL`.
    conn.pragma_update(None, "synchronous", db_synchronous())?;
    // #1579 B7 — memory-mapped I/O. See DEFAULT_DB_MMAP_SIZE_BYTES for
    // the P1 A/B evidence + override ladder.
    conn.pragma_update(None, "mmap_size", db_mmap_size())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA)
        .context("failed to initialize schema")?;
    migrate(&conn)?;
    apply_check_constraint_triggers(&conn)
        .context("failed to apply R1-M2 CHECK-constraint triggers")?;
    // v1.0.0 #1946 (A1) — OPEN-TIME rollback-evidence head check. `db::open`
    // is the funnel every interface (CLI per-command, HTTP daemon, MCP stdio)
    // crosses; `open_read_only` is exempt (the writer's open already checked).
    // DEFAULT: emit evidence + WARN and CONTINUE (no self-DOS on legit DR).
    // REQUIRE-MODE (`AI_MEMORY_REQUIRE_ROLLBACK_CHECK`): refuse the open. A
    // deployment with no enrolled witness key has no off-table anchor → the
    // check withholds (Unknown) and this is a silent no-op.
    crate::governance::audit::enforce_rollback_check_at_open(&conn)
        .context("open-time rollback-evidence check")?;
    Ok(conn)
}

/// #1580 — open a **read-only** connection to an already-initialized
/// database for the HTTP WAL read-pool.
///
/// Unlike [`open`], this does NOT run the bootstrap `SCHEMA`, the
/// migration ladder, or the CHECK-trigger install: a read-only
/// connection cannot issue DDL, and the writer that seeded the pool
/// has already brought the on-disk schema to `CURRENT_SCHEMA_VERSION`.
/// The connection is opened with `SQLITE_OPEN_READ_ONLY`, the same WAL
/// reader pragmas the writer uses (`busy_timeout`, `mmap_size`), and a
/// belt-and-suspenders `PRAGMA query_only = ON` so a stray write on a
/// pool connection surfaces as an error instead of racing the
/// dedicated writer's `BEGIN IMMEDIATE`.
///
/// WAL multi-reader correctness: SQLite permits any number of
/// concurrent read transactions on distinct connections to the same
/// WAL database; the `-wal`/`-shm` files were created by the writer's
/// [`open`] (the pool is always seeded after the writer opens), so a
/// same-process read-only connection attaches to the existing shared
/// memory cleanly.
///
/// # Errors
///
/// Propagates connection-open failures, the SQLCipher unlock failure
/// (when built with `--features sqlcipher` and the passphrase is wrong),
/// or any PRAGMA failure.
pub fn open_read_only(path: &Path) -> Result<Connection> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .context("failed to open read-only database connection")?;
    apply_sqlcipher_key(&conn)?;
    register_valid_time_functions(&conn).context("register valid-time SQL functions")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // #1579 B7 — mirror the writer's memory-mapped I/O budget so the
    // read-pool shares the OS page cache reservation.
    conn.pragma_update(None, "mmap_size", db_mmap_size())?;
    // Enforce read-only at the SQL layer (defense in depth on top of
    // SQLITE_OPEN_READ_ONLY): any INSERT/UPDATE/DELETE on a pool
    // connection is rejected rather than silently contending the writer.
    conn.pragma_update(None, "query_only", "ON")?;
    Ok(conn)
}

/// Apply the defense-in-depth CHECK triggers from migration 0023.
///
/// `CREATE TRIGGER IF NOT EXISTS` is idempotent — re-running is a
/// no-op. We detect whether the triggers are already installed via a
/// single read against `sqlite_master` and skip the install entirely
/// when they exist; this keeps `db::open` lock-free on every-call-
/// after-the-first and avoids contending with concurrent writers on
/// startup (a 5-second-bounded boot path can't afford to wait on a
/// `BEGIN EXCLUSIVE` against a held writer transaction).
///
/// On the first install, we DO wrap the batch in `BEGIN IMMEDIATE`
/// (not `EXCLUSIVE`) so two parallel `open()` calls race deterministically
/// rather than dead-locking. Pre-existing rows that violate any of
/// the constraints are NOT migrated away (silent data loss is worse
/// than a known-violating row); we instead emit a `tracing::warn!`
/// count of violators so operators can surface them in their next
/// cleanup pass.
fn apply_check_constraint_triggers(conn: &Connection) -> Result<()> {
    // Cheap idempotency probe — if our sentinel trigger is present,
    // the migration already ran on this database. Pure read against
    // `sqlite_master`, no lock acquired.
    let already_installed: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type = 'trigger' AND name = 'memories_ck_tier_ins')",
            [],
            |r| r.get::<_, i64>(0).map(|n| n != 0),
        )
        .unwrap_or(false);
    if already_installed {
        return Ok(());
    }

    // Pre-flight: count any rows that violate the upcoming constraints.
    // Surfaces a loud warning rather than silently dropping bad data.
    // Each query is best-effort — a missing column (very old schema)
    // returns zero rather than failing the open() path.
    let count_violations =
        |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0) };
    let bad_tier = count_violations(
        "SELECT COUNT(*) FROM memories WHERE tier NOT IN ('short', 'mid', 'long')",
    );
    let bad_priority =
        count_violations("SELECT COUNT(*) FROM memories WHERE priority < 1 OR priority > 10");
    let bad_confidence = count_violations(
        "SELECT COUNT(*) FROM memories WHERE confidence < 0.0 OR confidence > 1.0",
    );
    let bad_relation = count_violations(
        "SELECT COUNT(*) FROM memory_links \
         WHERE relation NOT IN ('related_to', 'supersedes', 'contradicts', 'derived_from', 'reflects_on', 'derives_from', 'decomposes_into', 'depends_on', 'advances')",
    );
    let bad_attest = count_violations(
        "SELECT COUNT(*) FROM memory_links \
         WHERE attest_level IS NOT NULL \
           AND attest_level NOT IN ('unsigned', 'self_signed', 'peer_attested')",
    );
    let total_bad = bad_tier + bad_priority + bad_confidence + bad_relation + bad_attest;
    if total_bad > 0 {
        tracing::warn!(
            target: "ai_memory::storage::checks",
            "R1-M2 CHECK trigger install: \
             pre-existing constraint violations detected — \
             memories.tier={bad_tier}, memories.priority={bad_priority}, \
             memories.confidence={bad_confidence}, \
             memory_links.relation={bad_relation}, \
             memory_links.attest_level={bad_attest}. \
             Triggers will still install; future writes that touch these \
             rows will fail loudly until the values are repaired."
        );
    }

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        conn.execute_batch(CHECK_CONSTRAINT_TRIGGERS_SQLITE)
            .context("apply CHECK-constraint triggers")?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// v0.6.0.0 — apply the SQLCipher passphrase (PRAGMA key) when the
/// `sqlcipher` cargo feature is built-in AND a passphrase has been
/// provided via `AI_MEMORY_DB_PASSPHRASE` env var. The recommended
/// way to set the env var is via the `--db-passphrase-file <path>`
/// CLI flag, which reads the passphrase from a root-readable file
/// and exports the env for the daemon's lifetime only. Passing the
/// passphrase directly as an env var works but leaks to the process
/// list (`ps -E`, `/proc/<pid>/environ`).
///
/// When the `sqlcipher` feature is NOT enabled, this function is a
/// no-op — standard SQLite has no `PRAGMA key` so setting one errors.
#[cfg(feature = "sqlcipher")]
fn apply_sqlcipher_key(conn: &Connection) -> Result<()> {
    let Ok(passphrase) = std::env::var("AI_MEMORY_DB_PASSPHRASE") else {
        // #962 typed envelope — fatal boot refusal.
        return Err(anyhow::Error::new(
            super::error::StorageError::SqlcipherMissingPassphrase,
        ));
    };
    // PRAGMA key must be the FIRST operation on a new connection. The
    // passphrase is quoted with SQL string-literal quoting rules.
    let escaped = passphrase.replace('\'', "''");
    conn.pragma_update(None, "key", format!("'{escaped}'"))
        .context("PRAGMA key failed (wrong passphrase or unencrypted DB?)")?;
    // Verify the key opened the database by running a cheap query.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .context("SQLCipher unlock verification failed — wrong passphrase?")?;
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
#[allow(clippy::unnecessary_wraps)]
fn apply_sqlcipher_key(_conn: &Connection) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// L0.7-6 Tier E unit coverage. The `open` path is already exercised through
// every db-related integration test; these tests pin the idempotency probe
// for the R1-M2 CHECK trigger install and the sqlcipher no-op fall-through.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_time_projection_accepts_sql_null_2266() {
        let conn = Connection::open_in_memory().expect("open in-memory database");
        register_valid_time_functions(&conn).expect("register valid-time functions");

        let projected: Option<i64> = conn
            .query_row("SELECT rfc3339_epoch_micros(NULL)", [], |row| row.get(0))
            .expect("SQL NULL must project to SQL NULL");

        assert_eq!(projected, None);
    }

    #[test]
    fn open_round_trip_creates_db_and_runs_migrations() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open initial");
        // schema_version table must exist and be populated.
        let v: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .expect("schema_version readable");
        assert!(v > 0, "expected positive schema version, got {v}");
    }

    #[test]
    fn open_twice_is_idempotent_for_check_triggers() {
        // R1-M2 doc: re-running open() is a no-op for the trigger install
        // because the sentinel `memories_ck_tier_ins` short-circuits the
        // CREATE TRIGGER batch. This test exercises both branches: first
        // open installs triggers; second open hits the already-installed
        // probe and returns early without running CREATE TRIGGER.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // First open.
        let _conn1 = open(tmp.path()).expect("first open");
        // Second open against the same path.
        let conn2 = open(tmp.path()).expect("re-open idempotent");
        // Sentinel trigger must exist.
        let n: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'trigger' AND name = 'memories_ck_tier_ins'",
                [],
                |r| r.get(0),
            )
            .expect("trigger query");
        assert_eq!(n, 1, "sentinel trigger must be installed exactly once");
    }

    #[test]
    fn open_applies_wal_journal_mode() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("journal_mode");
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn open_applies_default_mmap_size() {
        // #1579 B7 — `open` must apply the compiled 256 MiB mmap
        // default when the process never seeded `set_db_mmap_size`
        // (the unit-test / library-embedder posture). The OnceLock is
        // process-global, but nothing in the test binary seeds it —
        // `daemon_runtime::run` is the only production writer — so the
        // fallback branch is the one under test.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open");
        let mmap: i64 = conn
            .query_row("PRAGMA mmap_size", [], |r| r.get(0))
            .expect("mmap_size");
        assert_eq!(
            mmap, DEFAULT_DB_MMAP_SIZE_BYTES,
            "open() must apply the P1-proven 256 MiB mmap_size default"
        );
    }

    #[test]
    fn db_synchronous_defaults_to_normal_when_unset() {
        // v1.0.0 #1961 — with no `AI_MEMORY_DB_SYNCHRONOUS` override the
        // compiled default is `NORMAL` (the #1579 B7 perf posture). The
        // test binary never sets the var, so this exercises the
        // fall-through arm; the FULL/EXTRA arms are exercised end-to-end
        // by the power-loss integration harness (which sets the env in a
        // dedicated child process, avoiding an in-process env race).
        assert_eq!(db_synchronous(), DEFAULT_DB_SYNCHRONOUS);
        assert_eq!(DEFAULT_DB_SYNCHRONOUS, "NORMAL");
    }

    #[test]
    fn open_applies_resolved_synchronous_pragma() {
        // `open` must apply the resolved `PRAGMA synchronous`. Unseeded /
        // no-env → NORMAL (which SQLite reports as the integer 1).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open");
        let sync: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .expect("synchronous");
        // 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA.
        assert_eq!(sync, 1, "default open() must apply synchronous=NORMAL");
    }

    #[test]
    fn open_enables_foreign_keys() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open");
        let fk: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("foreign_keys");
        assert_eq!(fk, 1, "open() must enable foreign_keys");
    }

    /// Helper: confirm a named index is registered in `sqlite_master`.
    fn index_present(conn: &Connection, name: &str) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                rusqlite::params![name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        n == 1
    }

    /// Helper: column existence on a table.
    fn column_present(conn: &Connection, table: &str, column: &str) -> bool {
        let sql = format!("PRAGMA table_info({table})");
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut rows = stmt.query([]).expect("PRAGMA query");
        while let Some(row) = rows.next().expect("PRAGMA next") {
            let name: String = row.get(1).expect("col name");
            if name == column {
                return true;
            }
        }
        false
    }

    /// Regression for #797: a pre-v36 DB shape (no `atom_of` /
    /// `atomised_into` / `source_uri` / `confidence_source` /
    /// `mentioned_entity_id` columns on `memories`) must `open()`
    /// cleanly. Before the fix, the bootstrap SCHEMA issued
    /// `CREATE INDEX … ON memories(atom_of)` before `migrate` ran the
    /// v36 ALTER, so SQLite refused with `no such column: atom_of`.
    ///
    /// We synthesise the legacy shape by opening a fresh v42 DB, then
    /// stripping the v36+ columns and re-stamping `schema_version = 34`.
    /// Re-opening must drive the migration ladder forward to
    /// `CURRENT_SCHEMA_VERSION` and re-attach every partial index the
    /// bootstrap used to crash on.
    #[test]
    fn open_succeeds_on_legacy_pre_v36_memories_shape() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        {
            let conn = open(tmp.path()).expect("seed: fresh open");
            for ix in [
                "idx_memories_atom_of",
                "idx_memories_atomised_into",
                "idx_personas_by_entity",
                "idx_memories_source_uri",
                "idx_memories_confidence_source",
                "idx_memories_mentioned_entity",
            ] {
                conn.execute(&format!("DROP INDEX IF EXISTS {ix}"), [])
                    .expect("drop index");
            }
            for col in [
                "mentioned_entity_id",
                "confidence_decayed_at",
                "confidence_signals",
                "confidence_source",
                "source_span",
                "source_uri",
                "citations",
                "persona_version",
                "entity_id",
                "atom_of",
                "atomised_into",
            ] {
                conn.execute(&format!("ALTER TABLE memories DROP COLUMN {col}"), [])
                    .unwrap_or_else(|e| panic!("DROP COLUMN {col}: {e}"));
            }
            conn.execute("DROP TABLE IF EXISTS confidence_shadow_observations", [])
                .expect("drop shadow table");
            conn.execute("DROP TABLE IF EXISTS signed_events_dlq", [])
                .expect("drop dlq");
            conn.execute("DELETE FROM schema_version", [])
                .expect("clear version");
            conn.execute("INSERT INTO schema_version (version) VALUES (34)", [])
                .expect("stamp v34");
        }

        let conn = open(tmp.path()).expect("legacy-upgrade open must succeed");

        let v: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .expect("read schema_version");
        assert!(
            v >= 42,
            "migrate ladder must reach CURRENT_SCHEMA_VERSION; got {v}"
        );

        for col in [
            "atom_of",
            "atomised_into",
            "entity_id",
            "persona_version",
            "citations",
            "source_uri",
            "source_span",
            "confidence_source",
            "confidence_signals",
            "confidence_decayed_at",
            "mentioned_entity_id",
        ] {
            assert!(
                column_present(&conn, "memories", col),
                "memories.{col} must be ALTER-added by the migrate ladder"
            );
        }

        for ix in [
            "idx_memories_atom_of",
            "idx_memories_atomised_into",
            "idx_memories_source_uri",
            "idx_memories_confidence_source",
            "idx_memories_mentioned_entity",
            "idx_shadow_obs_namespace_source_observed",
        ] {
            assert!(
                index_present(&conn, ix),
                "index {ix} must exist after legacy upgrade"
            );
        }
    }

    /// Regression for #797: a v39/v40-era shadow table (no `source`
    /// column) must also `open()` cleanly. Before the fix, the
    /// bootstrap created `idx_shadow_obs_namespace_source_observed`
    /// against the missing column.
    #[test]
    fn open_succeeds_on_legacy_pre_v41_shadow_shape() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        {
            let conn = open(tmp.path()).expect("seed: fresh open");
            conn.execute(
                "DROP INDEX IF EXISTS idx_shadow_obs_namespace_source_observed",
                [],
            )
            .expect("drop compound shadow index");
            conn.execute(
                "ALTER TABLE confidence_shadow_observations DROP COLUMN source",
                [],
            )
            .expect("drop shadow.source");
            conn.execute("DELETE FROM schema_version", [])
                .expect("clear version");
            conn.execute("INSERT INTO schema_version (version) VALUES (40)", [])
                .expect("stamp v40");
        }

        let conn = open(tmp.path()).expect("v40 legacy-upgrade open must succeed");
        assert!(
            column_present(&conn, "confidence_shadow_observations", "source"),
            "v41 migrate arm must ALTER-add shadow.source"
        );
        assert!(
            index_present(&conn, "idx_shadow_obs_namespace_source_observed"),
            "v41 compound shadow index must be re-attached"
        );
    }

    #[test]
    fn check_trigger_rejects_bad_tier_insert() {
        // R1-M2 trigger contract: a write that violates the closed-set
        // CHECK on memories.tier must surface as an error. This test
        // exercises the trigger's actual rejection branch, not just the
        // install. We bypass the validator by writing directly with
        // rusqlite::execute so the trigger is the only thing standing
        // between the bad row and persistence.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(tmp.path()).expect("open");
        let now = chrono::Utc::now().to_rfc3339();
        let res = conn.execute(
            "INSERT INTO memories \
             (id, tier, namespace, title, content, tags, priority, confidence, \
              source, access_count, created_at, updated_at, metadata, reflection_depth) \
             VALUES (?1, 'NOT_A_TIER', 'test', 't', 'c', '[]', 5, 1.0, \
                     'src', 0, ?2, ?2, '{}', 0)",
            rusqlite::params!["bad-tier-id", now],
        );
        assert!(
            res.is_err(),
            "INSERT with bad tier must be rejected by R1-M2 trigger"
        );
    }
}
