// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Connection setup for the SQLite substrate. v0.7.0 L0.5-3 extracted
//! `open` + the SQLCipher passphrase helper out of `src/db.rs` into
//! this sub-module. Pure refactor — semantics unchanged.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

use super::migrations::{SCHEMA, migrate};
use super::schema_guard::{BACKEND_SQLITE, SchemaStamp};

/// Shared `anyhow` context for the valid-time UDF registration, referenced by
/// name at every open funnel (`open`, `open_read_only`, `open_unmigrated`)
/// rather than repeated as a literal — pm-v3.1 no-hardcoded-literals.
const MSG_REGISTER_VALID_TIME_FNS: &str = "register valid-time SQL functions";

/// v1.0.0 #2445 — probe for the presence of the `schema_version` relation.
///
/// A missing relation is a genuinely FRESH database; a relation that is
/// present but unreadable is damage. Separating the two is what lets
/// [`probe_schema_stamp`] be tri-state instead of coercing every failure to
/// zero — see the [`super::schema_guard`] module docs for why that
/// distinction is load-bearing.
const SQL_SCHEMA_VERSION_TABLE_PRESENT: &str =
    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'";

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

/// v1.0.0 #3163 — the plain (DEFERRED) BEGIN, used by the CLI `mine` import's
/// chunked transaction. Hoisted out of `cli/io.rs` as an inline literal so
/// every transaction verb in the substrate is spelled once, here
/// (pm-v3.1 no-hardcoded-literals). DEFERRED is correct there because the
/// importer owns its own process-private connection and takes no lock until
/// its first write.
pub const SQL_BEGIN_DEFERRED: &str = "BEGIN";

/// v1.0.0 #3163 — the migration ladder's exclusive-lock BEGIN, hoisted out
/// of `migrations.rs` as an inline literal so every transaction verb in the
/// substrate is spelled once, here (pm-v3.1 no-hardcoded-literals).
/// `BEGIN EXCLUSIVE` additionally blocks READERS for the whole ladder, which
/// is what keeps a concurrent process from observing a half-migrated schema.
pub const SQL_BEGIN_EXCLUSIVE: &str = "BEGIN EXCLUSIVE";

/// v1.0.0 #3163 — the RAII drop-guard for the explicit-`BEGIN IMMEDIATE`
/// write-transaction pattern.
///
/// # Why this type exists
///
/// The substrate drives write transactions manually — `execute_batch(`
/// [`SQL_BEGIN_IMMEDIATE`]`)` … `execute_batch(`[`SQL_COMMIT`]`)`, with a
/// hand-written `execute_batch(`[`SQL_ROLLBACK`]`)` on each `Err` arm.
/// That shape is correct on the happy path and on the arms someone
/// remembered to write, but it is NOT unwind-safe: `Cargo.toml` keeps
/// `panic = "unwind"`, and a panic between the BEGIN and the COMMIT skips
/// every hand-written ROLLBACK.
///
/// That matters because the daemon's writer is a SINGLE
/// `rusqlite::Connection` shared behind a `tokio::sync::Mutex`, and a
/// `tokio` mutex does **not** poison. An unwind therefore releases the
/// mutex with the connection still inside an open write transaction, and
/// the next writer inherits it: its own `BEGIN IMMEDIATE` fails with
/// "cannot start a transaction within a transaction", or its statements
/// silently join the orphaned transaction and become visible on someone
/// else's COMMIT. Both outcomes are mixed state, which the project's prime
/// directive forbids outright.
///
/// `WriteTxn` closes that hole structurally rather than by discipline: the
/// transaction is ended by [`Drop`], which runs on an unwind exactly as it
/// runs on an early `?` return. The worst case after a panic is a
/// ROLLED-BACK transaction on a usable connection — degrade, never corrupt.
///
/// # Contract
///
/// - [`WriteTxn::begin`] issues `BEGIN IMMEDIATE` (write lock taken up
///   front, so contention surfaces at BEGIN and is retryable).
/// - [`WriteTxn::commit`] is the ONLY way to keep the work. A failed
///   COMMIT still leaves the guard armed, so the drop rolls back.
/// - Every other exit — an early `?`, an explicit [`WriteTxn::rollback`],
///   or a panic unwind — rolls back.
/// - The guard borrows the connection SHAREDLY (`&'c Connection`), so the
///   surrounding code keeps using `conn` verbatim; adopting the guard is a
///   line-for-line swap at the BEGIN/COMMIT/ROLLBACK statements, not a
///   restructure of the transaction body.
///
/// # Panics in `Drop`
///
/// Never. A failing ROLLBACK is logged at ERROR and swallowed
/// (rust-1.98 OWNERSHIP-25: a panic in a destructor during an unwind
/// aborts the process). The connection is left for the next
/// [`ensure_autocommit`] sweep, which fails the request closed rather than
/// writing into a foreign transaction.
pub struct WriteTxn<'c> {
    conn: &'c Connection,
    /// `true` once the transaction has been terminated (committed or
    /// rolled back), which makes [`Drop`] a no-op.
    finished: bool,
}

impl<'c> WriteTxn<'c> {
    /// Open an immediate write transaction on `conn`.
    ///
    /// # Errors
    ///
    /// Propagates the `rusqlite` error from `BEGIN IMMEDIATE` — most
    /// commonly `SQLITE_BUSY` when another connection holds the write
    /// lock (retryable), or a nested-transaction error when the caller is
    /// already inside one. No guard is constructed on failure, so nothing
    /// is left to roll back.
    pub fn begin(conn: &'c Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(SQL_BEGIN_IMMEDIATE)?;
        Ok(Self {
            conn,
            finished: false,
        })
    }

    /// Open a DEFERRED transaction on `conn` — the chunked-import boundary,
    /// which takes no write lock until its first write.
    ///
    /// # Errors
    ///
    /// Propagates the `rusqlite` error from `BEGIN`. As with
    /// [`WriteTxn::begin`], no guard is constructed on failure.
    pub fn begin_deferred(conn: &'c Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(SQL_BEGIN_DEFERRED)?;
        Ok(Self {
            conn,
            finished: false,
        })
    }

    /// Open an EXCLUSIVE write transaction on `conn` — the schema-migration
    /// ladder's boundary, which must also exclude readers.
    ///
    /// # Errors
    ///
    /// Propagates the `rusqlite` error from `BEGIN EXCLUSIVE`. As with
    /// [`WriteTxn::begin`], no guard is constructed on failure.
    pub fn begin_exclusive(conn: &'c Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(SQL_BEGIN_EXCLUSIVE)?;
        Ok(Self {
            conn,
            finished: false,
        })
    }

    /// Commit the transaction, consuming the guard.
    ///
    /// # Errors
    ///
    /// Propagates the `rusqlite` error from `COMMIT`. The guard stays
    /// ARMED on failure, so the drop that follows this call rolls the
    /// transaction back — a half-committed connection is never handed on.
    pub fn commit(mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch(SQL_COMMIT)?;
        // Only a SUCCESSFUL commit disarms the guard. On the error path we
        // fall through with `finished == false` so `Drop` rolls back.
        self.finished = true;
        Ok(())
    }

    /// Roll the transaction back explicitly, consuming the guard.
    ///
    /// Equivalent to dropping the guard; provided so call sites that used
    /// to write `let _ = conn.execute_batch(SQL_ROLLBACK);` keep saying
    /// what they mean instead of relying on an invisible drop.
    pub fn rollback(mut self) {
        self.finish();
    }

    /// Terminate the transaction with a ROLLBACK unless it is already
    /// terminated. Infallible by construction — see the type-level
    /// "Panics in `Drop`" note.
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        // A connection already back in autocommit has nothing open: the
        // COMMIT landed, or SQLite auto-rolled the transaction back after
        // a fatal statement error. Issuing ROLLBACK there would only log a
        // spurious "cannot rollback - no transaction is active".
        if self.conn.is_autocommit() {
            return;
        }
        if let Err(e) = self.conn.execute_batch(SQL_ROLLBACK) {
            tracing::error!(
                target: TXN_GUARD_TRACE_TARGET,
                error = %e,
                "#3163 WriteTxn: ROLLBACK failed while unwinding a write \
                 transaction; the shared writer connection is still inside a \
                 transaction and the next ensure_autocommit sweep will fail \
                 the request closed rather than write into it"
            );
        }
    }
}

impl Drop for WriteTxn<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Tracing target for the #3163 transaction-integrity guards.
const TXN_GUARD_TRACE_TARGET: &str = "ai_memory::storage::txn_guard";

/// v1.0.0 #3163 — the mutex-boundary integrity sweep for a SHARED writer
/// connection.
///
/// [`WriteTxn`] makes it structurally impossible for an unwind to leave one
/// of the substrate's OWN write transactions open. This is the
/// defense-in-depth layer behind it: called on both sides of every closure
/// that borrows the daemon's shared writer connection
/// (`crate::handlers::transport::db_op`), it guarantees the connection is in
/// autocommit before another caller is allowed to touch it — no matter which
/// code opened the transaction or how it was abandoned.
///
/// Returns `Ok(true)` when an orphaned transaction was found and rolled
/// back (the caller should log that as a defect), `Ok(false)` when the
/// connection was already clean.
///
/// # Errors
///
/// Returns the `rusqlite` error when the connection is inside a transaction
/// that could NOT be rolled back. That is the fail-closed case: the caller
/// must refuse the operation rather than run new statements inside an
/// unknown transaction. The check is retried on the next acquisition, so a
/// transient failure self-heals without any poison flag or reopen.
pub fn ensure_autocommit(conn: &Connection) -> rusqlite::Result<bool> {
    if conn.is_autocommit() {
        return Ok(false);
    }
    conn.execute_batch(SQL_ROLLBACK)?;
    Ok(true)
}

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

/// v1.0.0 #2445 — read the recorded schema version WITHOUT coercing a failure
/// into "fresh".
///
/// # Errors
///
/// Propagates the probe / read failure. A read error is NOT the same as an
/// absent relation: coercing it to `0` would send a POPULATED database
/// through the entire v1 → tip ladder with the pre-migration safety snapshot
/// suppressed (it is gated on `version > 0`). See [`super::schema_guard`].
pub fn probe_schema_stamp(conn: &Connection) -> Result<SchemaStamp> {
    let present: i64 = conn
        .query_row(SQL_SCHEMA_VERSION_TABLE_PRESENT, [], |r| r.get(0))
        .context("probe for the schema_version relation")?;
    if present == 0 {
        return Ok(SchemaStamp::Fresh);
    }
    let version: i64 = conn
        .query_row(super::migrations::SELECT_SCHEMA_VERSION_SQL, [], |r| {
            r.get(0)
        })
        .context("read the recorded schema version")?;
    Ok(SchemaStamp::Known(version))
}

/// v1.0.0 #2445 — the shared downgrade guard for EVERY sqlite funnel that
/// opens a connection this process will WRITE through.
///
/// [`open`] applies it before any bootstrap DDL, and the handful of
/// production sites that construct a raw [`Connection`] outside this module
/// (the governance hook, `governance install-defaults`, `calibrate
/// confidence`, the webhook dispatcher) call it directly — `db::open` is the
/// funnel every INTERFACE crosses, but it is not the funnel every WRITE
/// crosses, and a guard that only covers the former is the #2488 lesson
/// waiting to repeat.
///
/// # Errors
///
/// [`super::schema_guard::SchemaAheadOfBinary`] when the database is newer
/// than this binary's ladder produces, or the probe failure when the recorded
/// version cannot be read.
pub fn assert_schema_not_ahead(conn: &Connection, target: &str) -> Result<()> {
    resolve_schema_posture(conn, target).map(|_| ())
}

/// v1.0.0 #2445 — the guard's verdict, for the ONE caller that must act on the
/// difference between "permitted normally" and "permitted only by the hatch".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaPosture {
    /// `observed <= supported` — the ordinary steady-state / upgrade case.
    Normal,
    /// `observed > supported`, admitted ONLY because the operator hatch names
    /// this exact version. The database must be handed back EXACTLY as found.
    AheadButAuthorised,
}

/// v1.0.0 #2445 — evaluate the guard and report WHICH way it passed.
///
/// [`assert_schema_not_ahead`] is the ergonomic wrapper for call sites that
/// only need pass/fail. [`open`] needs the distinction: under the hatch it must
/// SKIP the bootstrap DDL, the ladder and the trigger install, because
/// replaying an older binary's `CREATE … IF NOT EXISTS` set over a newer
/// database is the #2424 class — the exact window the guard exists to close. A
/// hatch that re-opened it would be worse than no guard at all.
///
/// # Errors
///
/// [`super::schema_guard::SchemaAheadOfBinary`] when the database is newer than
/// this binary's ladder produces and no matching hatch is in force, or the
/// probe failure when the recorded version cannot be read.
pub fn resolve_schema_posture(conn: &Connection, target: &str) -> Result<SchemaPosture> {
    let observed = probe_schema_stamp(conn)?.version();
    let supported = super::migrations::current_schema_version();
    super::schema_guard::evaluate(observed, supported, BACKEND_SQLITE, target)?;
    Ok(if observed > supported {
        SchemaPosture::AheadButAuthorised
    } else {
        SchemaPosture::Normal
    })
}

/// Shared pragma application for [`open`] and [`open_unmigrated`] so the two
/// funnels can never drift in connection posture — only in whether they go on
/// to apply the bootstrap schema + ladder.
fn apply_writer_pragmas(conn: &Connection) -> Result<()> {
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
    Ok(())
}

/// v1.0.0 #2445 — open an EXISTING database WITHOUT applying the bootstrap
/// schema, the migration ladder, the CHECK triggers, or the downgrade guard.
///
/// This is the EGRESS funnel. When [`open`] refuses a schema-ahead database,
/// `ai-memory backup` falls back to this so an operator can still snapshot
/// their durable text with the binary they have on hand — the North Star reads
/// the memory TEXT as the source of truth and the schema shape as a derived
/// property of it, so a guard whose observable effect is "you may not take a
/// backup" would invert the very directive it serves.
///
/// It is NOT a read-only connection: `VACUUM INTO` is refused under
/// `PRAGMA query_only = ON` (verified), so [`open_read_only`] cannot serve the
/// backup path. Callers MUST NOT use this funnel to write memory rows.
///
/// # Errors
///
/// Propagates connection-open failures, the SQLCipher unlock failure, or any
/// PRAGMA failure.
pub fn open_unmigrated(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).context("failed to open database")?;
    apply_sqlcipher_key(&conn)?;
    register_valid_time_functions(&conn).context(MSG_REGISTER_VALID_TIME_FNS)?;
    apply_writer_pragmas(&conn)?;
    Ok(conn)
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).context("failed to open database")?;
    apply_sqlcipher_key(&conn)?;
    register_valid_time_functions(&conn).context(MSG_REGISTER_VALID_TIME_FNS)?;
    apply_writer_pragmas(&conn)?;
    // v1.0.0 #2445 — the DOWNGRADE guard, deliberately placed HERE: after the
    // pragma block (so `busy_timeout` is already in force and ordinary
    // write-lock contention is retried rather than misread as damage) and
    // BEFORE `execute_batch(SCHEMA)`. Refusing inside `migrate` alone — the
    // issue's literal suggestion — would leave this binary's `CREATE … IF NOT
    // EXISTS` bootstrap set replaying over a NEWER database first, which can
    // resurrect a table or index the newer ladder deliberately removed. #2424
    // proved bootstrap-vs-ladder shape disagreement is a live class here.
    if resolve_schema_posture(&conn, &path.display().to_string())?
        == SchemaPosture::AheadButAuthorised
    {
        // The operator hatch authorised THIS database. Hand it back exactly as
        // found: no bootstrap replay, no ladder, no trigger install, and no
        // rollback-evidence check (that check APPENDS a signed evidence row,
        // and appending to `signed_events` — one of the very tables whose shape
        // is in question — is precisely what must not happen here). Skipping
        // the bootstrap is not an optimisation: replaying an older binary's
        // `CREATE … IF NOT EXISTS` set over a newer schema is the #2424 class,
        // so a hatch that ran it would re-open the window the guard closes.
        return Ok(conn);
    }
    conn.execute_batch(SCHEMA)
        .context("failed to initialize schema")?;
    migrate(&conn)?;
    apply_check_constraint_triggers(&conn)
        .context("failed to apply R1-M2 CHECK-constraint triggers")?;
    // v1.0.0 #1946 (A1) — OPEN-TIME rollback-evidence head check. `db::open`
    // is the funnel every interface BOOT (CLI per-command, HTTP daemon, MCP
    // stdio) crosses — but NOT every write: #2445 catalogued the production
    // sites that construct a raw `rusqlite::Connection` and write through it
    // (`src/cli/governance_check_action.rs`, `governance_install_defaults.rs`,
    // `commands/calibrate_confidence.rs`, `src/subscriptions.rs`), which this
    // check does not reach either. `open_read_only` is exempt (the writer's
    // open already checked).
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
    register_valid_time_functions(&conn).context(MSG_REGISTER_VALID_TIME_FNS)?;
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

    let write_txn = WriteTxn::begin(conn)?;
    let result = (|| -> Result<()> {
        conn.execute_batch(CHECK_CONSTRAINT_TRIGGERS_SQLITE)
            .context("apply CHECK-constraint triggers")?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            write_txn.commit()?;
            Ok(())
        }
        Err(e) => {
            write_txn.rollback();
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
    fn read_only_connection_registers_valid_time_projection_2266() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("valid-time.sqlite3");
        let writer = open(&path).expect("create and migrate database");
        drop(writer);

        let reader = open_read_only(&path).expect("open read-only database");
        let (offset, null_value, malformed): (Option<i64>, Option<i64>, Option<i64>) = reader
            .query_row(
                "SELECT rfc3339_epoch_micros('2026-01-01T01:00:00+01:00'), \
                        rfc3339_epoch_micros(NULL), \
                        rfc3339_epoch_micros('not-rfc3339')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read-only connection must expose valid-time projection");

        assert_eq!(offset, Some(1_767_225_600_000_000));
        assert_eq!(null_value, None);
        assert_eq!(malformed, None);
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

    // -----------------------------------------------------------------
    // v1.0.0 #3163 — `WriteTxn` unwind/commit-failure contract
    // -----------------------------------------------------------------

    /// A bare connection with one table, deliberately NOT the full schema —
    /// these tests pin the transaction guard, not the substrate.
    fn txn_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .expect("create t");
        conn
    }

    fn row_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count")
    }

    #[test]
    fn write_txn_commit_persists_and_returns_to_autocommit() {
        let conn = txn_test_conn();
        let write_txn = WriteTxn::begin(&conn).expect("begin");
        assert!(
            !conn.is_autocommit(),
            "BEGIN IMMEDIATE must leave the connection inside a transaction"
        );
        conn.execute("INSERT INTO t (id) VALUES (1)", [])
            .expect("insert");
        write_txn.commit().expect("commit");
        assert!(conn.is_autocommit(), "COMMIT must restore autocommit");
        assert_eq!(row_count(&conn), 1, "committed row must survive");
    }

    #[test]
    fn write_txn_explicit_rollback_discards_the_partial_write() {
        let conn = txn_test_conn();
        let write_txn = WriteTxn::begin(&conn).expect("begin");
        conn.execute("INSERT INTO t (id) VALUES (1)", [])
            .expect("insert");
        write_txn.rollback();
        assert!(conn.is_autocommit(), "ROLLBACK must restore autocommit");
        assert_eq!(row_count(&conn), 0, "rolled-back row must not be visible");
    }

    #[test]
    fn write_txn_drop_without_commit_rolls_back() {
        let conn = txn_test_conn();
        {
            let _write_txn = WriteTxn::begin(&conn).expect("begin");
            conn.execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("insert");
            // No commit — the guard falls out of scope here.
        }
        assert!(conn.is_autocommit(), "drop must end the transaction");
        assert_eq!(row_count(&conn), 0, "uncommitted row must not be visible");
    }

    /// THE #3163 regression: a PANIC between BEGIN and COMMIT must leave the
    /// connection usable and the partial write invisible. Pre-fix the
    /// hand-written `match result { Err(_) => ROLLBACK }` arms were skipped by
    /// the unwind and the transaction stayed open forever.
    #[test]
    fn write_txn_rolls_back_on_panic_unwind_and_connection_stays_usable() {
        let conn = txn_test_conn();

        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _write_txn = WriteTxn::begin(&conn).expect("begin");
            conn.execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("partial write");
            panic!("#3163: injected panic between BEGIN and COMMIT");
        }));
        assert!(unwound.is_err(), "the injected panic must have unwound");

        // (c) the connection is back in autocommit …
        assert!(
            conn.is_autocommit(),
            "#3163: an unwind must not leave the shared writer inside a transaction"
        );
        // (a) … the partial write is NOT visible …
        assert_eq!(
            row_count(&conn),
            0,
            "#3163: the partial write must have been rolled back by the guard"
        );
        // (b) … and the next write on the SAME connection succeeds.
        let write_txn = WriteTxn::begin(&conn).expect("#3163: next BEGIN must succeed");
        conn.execute("INSERT INTO t (id) VALUES (2)", [])
            .expect("post-unwind write");
        write_txn.commit().expect("post-unwind commit");
        assert_eq!(row_count(&conn), 1, "the post-unwind write must persist");
    }

    /// The #3163 addendum: the house pattern propagated a COMMIT failure with
    /// `?` and NEVER rolled back, stranding the shared writer mid-transaction
    /// so the next caller saw `is_autocommit() == false`, skipped its own
    /// BEGIN, and silently joined the orphaned transaction.
    ///
    /// A DEFERRED foreign-key violation is the deterministic injection: SQLite
    /// reports the violation at COMMIT time with `SQLITE_CONSTRAINT` and
    /// deliberately leaves the transaction OPEN, which is exactly the shape
    /// the guard has to survive.
    #[test]
    fn write_txn_rolls_back_when_commit_itself_fails() {
        let conn = Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch(
            "CREATE TABLE parent (id INTEGER PRIMARY KEY);\n\
             CREATE TABLE t (\n\
                 id INTEGER PRIMARY KEY,\n\
                 parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED\n\
             );",
        )
        .expect("create schema");
        conn.execute_batch("PRAGMA foreign_keys = ON")
            .expect("enable FK enforcement");

        let write_txn = WriteTxn::begin(&conn).expect("begin");
        conn.execute("INSERT INTO t (id, parent_id) VALUES (1, 999)", [])
            .expect("deferred FK violation is accepted until COMMIT");
        let err = write_txn
            .commit()
            .expect_err("COMMIT must fail on the deferred FK violation");
        assert!(
            format!("{err}")
                .to_ascii_lowercase()
                .contains("foreign key"),
            "expected a foreign-key COMMIT failure, got: {err}"
        );

        // The guard's drop ran on the `?`-return out of `commit()`.
        assert!(
            conn.is_autocommit(),
            "#3163 addendum: a FAILED COMMIT must not strand the writer inside \
             a transaction"
        );
        assert_eq!(row_count(&conn), 0, "the violating row must not survive");

        // And the next write on the same connection succeeds — the exact
        // property the addendum says was broken.
        conn.execute("INSERT INTO parent (id) VALUES (999)", [])
            .expect("next write must succeed");
        let write_txn = WriteTxn::begin(&conn).expect("next BEGIN must succeed");
        conn.execute("INSERT INTO t (id, parent_id) VALUES (2, 999)", [])
            .expect("insert");
        write_txn.commit().expect("second commit must succeed");
        assert_eq!(row_count(&conn), 1, "the post-failure write must persist");
    }

    #[test]
    fn ensure_autocommit_is_a_no_op_on_a_clean_connection() {
        let conn = txn_test_conn();
        assert!(
            !ensure_autocommit(&conn).expect("clean sweep"),
            "a connection already in autocommit must report nothing to do"
        );
        assert!(conn.is_autocommit());
    }

    /// The mutex-boundary sweep must clear a transaction the substrate did NOT
    /// open through [`WriteTxn`] — a future call site, or code this crate does
    /// not own. This is the defense-in-depth half of #3163.
    #[test]
    fn ensure_autocommit_rolls_back_an_unguarded_transaction() {
        let conn = txn_test_conn();
        conn.execute_batch(SQL_BEGIN_IMMEDIATE)
            .expect("raw BEGIN, deliberately unguarded");
        conn.execute("INSERT INTO t (id) VALUES (1)", [])
            .expect("partial write");

        assert!(
            ensure_autocommit(&conn).expect("sweep must succeed"),
            "the sweep must REPORT that it found and rolled back a transaction"
        );
        assert!(conn.is_autocommit(), "the connection must be usable again");
        assert_eq!(
            row_count(&conn),
            0,
            "the unguarded write must be rolled back"
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
