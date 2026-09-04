// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3344 — durable skip cache for permanently unembeddable rows.
//!
//! Boot and the live embedding-backfill worker used to re-read the same
//! undecryptable (and oversize) rows on every pass and re-WARN each one
//! (`embed: skipping encrypted row whose envelope failed to decrypt (#1779)`
//! plus the postgres batch twin `#2317`). This module persists a skip
//! marker keyed by `memory_id` + the agent's current encryption-key
//! fingerprint so those rows drop out of `list_unembedded` / the sqlite
//! unembedded scan without a re-read. Restoring or rotating the key
//! changes the fingerprint; [`invalidate_stale_sqlite`] (and the postgres
//! twin) drops the stale marker and the next scan retries — the healing
//! path the issue requires.
//!
//! The table holds NO durable memory truth: it is a derived cache,
//! regenerable by re-scanning. Persist failures are logged and swallowed
//! so a skip-cache fault can never block daemon readiness (North Star:
//! degrade, never corrupt).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::encryption::agent_encryption_key_fingerprint;

/// Skip-cache relation name (SSOT for the table, shared by the DDL doc
/// twins and every statement in this module).
pub const TABLE: &str = "embed_skip";

/// Predicate excluding remembered-unembeddable rows from an unembedded
/// scan (#3344). Leading ` AND` so it composes onto an existing WHERE.
pub const SQL_AND_NOT_SKIPPED: &str = " AND id NOT IN (SELECT memory_id FROM embed_skip)";

/// Embedded SQLite DDL doc twin, applied by the additive v96 migration arm.
pub const MIGRATION_V96_SQLITE: &str =
    include_str!("../../migrations/sqlite/0080_v96_embed_skip.sql");

/// Embedded Postgres DDL doc twin, applied by [`PostgresStore::migrate_v96`].
pub const MIGRATION_V96_POSTGRES: &str =
    include_str!("../../migrations/postgres/0053_v96_embed_skip.sql");

/// Transactional teardown for the Postgres v96 embedding-dependent trigger.
///
/// `migrate_embedding_dim` runs this only after its embedding-NULL update has
/// fired the trigger, then recreates the trigger before committing. PostgreSQL
/// transactional DDL means any later failure rolls the drop back with the rest
/// of the conversion.
pub(crate) const POSTGRES_DROP_CLEAR_TRIGGER: &str =
    "DROP TRIGGER IF EXISTS memories_embed_skip_clear ON memories";

/// Canonical recreation of the v96 clear trigger after an embedding column
/// type conversion.
pub(crate) const POSTGRES_CREATE_CLEAR_TRIGGER: &str = "\
CREATE TRIGGER memories_embed_skip_clear
AFTER UPDATE OF content, encrypted_envelope, embedding ON memories
FOR EACH ROW
EXECUTE FUNCTION trg_embed_skip_clear()";

/// SQLite trigger: content / envelope rewrite drops the skip so the next
/// scan retries. Ladder-owned (v96); not in bootstrap `SCHEMA`.
pub const TRIGGER_CLEAR_ON_CONTENT: &str = "memories_embed_skip_clear_on_content";

/// SQLite trigger: a successful embedding write drops the skip.
/// References `NEW.embedding`, so it is illegal on a mid-ladder
/// `memories` table that has not yet grown that column (v3 ALTER;
/// bootstrap `SCHEMA` does not carry `embedding`).
pub const TRIGGER_CLEAR_ON_EMBED: &str = "memories_embed_skip_clear_on_embed";

const SQL_DROP_CLEAR_TRIGGERS: &str = "\
DROP TRIGGER IF EXISTS memories_embed_skip_clear_on_content;\n\
DROP TRIGGER IF EXISTS memories_embed_skip_clear_on_embed;";

/// Table + index only (no memories triggers). Used when `memories` has
/// not yet grown `embedding` so SQLite cannot validate `NEW.embedding`.
const SQL_TABLE_AND_INDEX: &str = r"
CREATE TABLE IF NOT EXISTS embed_skip (
    memory_id        TEXT NOT NULL PRIMARY KEY,
    agent_id         TEXT NOT NULL DEFAULT '',
    key_fingerprint  TEXT NOT NULL,
    reason           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    CHECK (reason IN ('undecryptable', 'oversize'))
);
CREATE INDEX IF NOT EXISTS idx_embed_skip_fp
    ON embed_skip(key_fingerprint);
";

/// Drop the memories-clearing skip triggers. Idempotent.
///
/// Call before any SQLite rebuild / `ALTER TABLE` that revalidates
/// trigger bodies (v50 `agent_quotas` shadow swap, memories column
/// ALTERs, …). A leftover bootstrap trigger whose `WHEN` clause names
/// `NEW.embedding` fails those DDL steps on a mid-ladder table with
/// `error in trigger memories_embed_skip_clear_on_embed: no such
/// column: NEW.embedding` (#3344).
///
/// # Errors
///
/// Propagates a rusqlite failure. `DROP TRIGGER IF EXISTS` itself is
/// a no-op when the trigger is absent.
pub fn drop_sqlite_clear_triggers(conn: &Connection) -> Result<()> {
    conn.execute_batch(SQL_DROP_CLEAR_TRIGGERS)
        .context("drop embed_skip memories clear triggers")?;
    Ok(())
}

fn sqlite_memories_has_column(conn: &Connection, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(memories)")
        .context("prepare PRAGMA table_info(memories)")?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .context("query PRAGMA table_info(memories)")?;
    for col in cols {
        if col.context("read memories column name")? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply the v96 SQLite DDL.
///
/// The `embed_skip` table is always created. The memories-clearing
/// triggers are created ONLY when `memories.embedding` exists (v3
/// adds it; bootstrap `SCHEMA` does not). ERRORS-09: do not install a
/// trigger whose `WHEN` clause is illegal on the current table shape.
///
/// # Errors
///
/// Propagates a rusqlite failure applying the DDL.
pub fn apply_sqlite_v96(conn: &Connection) -> Result<()> {
    drop_sqlite_clear_triggers(conn)?;
    if sqlite_memories_has_column(conn, "embedding")? {
        conn.execute_batch(MIGRATION_V96_SQLITE)
            .context("apply v96 embed_skip DDL")?;
    } else {
        conn.execute_batch(SQL_TABLE_AND_INDEX)
            .context("apply v96 embed_skip table without memories triggers")?;
    }
    Ok(())
}

/// Why a row was remembered as unembeddable. A descriptive enum, not a
/// bare bool (API-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedSkipReason {
    /// Envelope present but [`crate::encryption::open_content`] failed
    /// (key absent, wrong key, corrupt ciphertext).
    Undecryptable,
    /// Resolved plaintext exceeds [`crate::embeddings::EMBED_MAX_BYTES`].
    Oversize,
}

impl EmbedSkipReason {
    /// Wire / SQL value. Keep in lockstep with the table CHECK.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undecryptable => "undecryptable",
            Self::Oversize => "oversize",
        }
    }

    fn from_stored(raw: &str) -> Option<Self> {
        match raw {
            "undecryptable" => Some(Self::Undecryptable),
            "oversize" => Some(Self::Oversize),
            _ => None,
        }
    }
}

const SQL_INSERT_IGNORE: &str = "INSERT OR IGNORE INTO embed_skip \
    (memory_id, agent_id, key_fingerprint, reason, created_at) \
    VALUES (?1, ?2, ?3, ?4, ?5)";

const SQL_SELECT_ALL: &str = "SELECT memory_id, agent_id, key_fingerprint, reason FROM embed_skip";

const SQL_DELETE_BY_ID: &str = "DELETE FROM embed_skip WHERE memory_id = ?1";

const SQL_COUNT: &str = "SELECT COUNT(*) FROM embed_skip";

/// Minimum interval between full-table stale-marker walks (#3344
/// amendment 2). Consecutive backfill ticks with unchanged key material
/// must be O(1) — not O(n) over `embed_skip`. A key rotation on this
/// store is honoured within at most this interval (the next successful
/// walk after the interval elapses drops markers whose stored
/// fingerprint no longer matches live key material).
pub const INVALIDATE_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Per-store amortisation of the `embed_skip` stale-marker walk.
///
/// Owned by [`crate::store::sqlite::SqliteStore`] / `PostgresStore`,
/// never process-global: two stores in one process must not share a
/// timer (store B's first scan must not skip because store A walked).
/// `PostgresStore` is `Clone`; hold this behind `Arc` so clones of
/// ONE store share the timer. CONCURRENCY-18: poison recovers via
/// `into_inner`. CONCURRENCY-20: the mutex is never held across
/// `.await` — callers copy the decision out, drop the guard, then
/// await the walk.
pub struct EmbedSkipAmortisation {
    last_walk: Mutex<Option<Instant>>,
    walk_count: AtomicUsize,
}

impl Default for EmbedSkipAmortisation {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbedSkipAmortisation {
    /// Fresh amortisation: the next [`prepare_scan_sqlite`] / postgres
    /// `prepare_scan` walks. A new store instance is the reset (no
    /// process-global `reset_amortisation_for_tests`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_walk: Mutex::new(None),
            walk_count: AtomicUsize::new(0),
        }
    }

    /// True when a full-table stale walk should run. False within
    /// [`INVALIDATE_MIN_INTERVAL`] of the last successful walk on
    /// **this store**.
    fn should_walk(&self) -> bool {
        let guard = match self.last_walk.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match *guard {
            Some(t) => Instant::now().saturating_duration_since(t) >= INVALIDATE_MIN_INTERVAL,
            None => true,
        }
    }

    fn mark_walked(&self) {
        let mut guard = match self.last_walk.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(Instant::now());
    }

    fn bump_walk(&self) {
        self.walk_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Test pin: number of full-table stale-marker walks on this store.
    #[must_use]
    pub fn table_walk_count(&self) -> usize {
        self.walk_count.load(Ordering::Relaxed)
    }
}

fn fingerprint_for(agent_id: &str) -> String {
    agent_encryption_key_fingerprint(agent_id)
}

/// Persist a skip marker. Returns `true` when this was a NEW insert
/// (caller should WARN once); `false` when the id was already remembered
/// (no re-WARN). Fingerprint is taken from the live key material so a
/// later key restore cannot match this row.
///
/// Persist faults are returned to the caller; the scan path logs and
/// continues (ERRORS-19: never silently drop).
pub fn record_sqlite(
    conn: &Connection,
    memory_id: &str,
    agent_id: &str,
    reason: EmbedSkipReason,
) -> Result<bool> {
    // #3484 — derived cache or not, the store does not mutate under an
    // engaged record stop (same funnel every write-SQL fn uses).
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let fp = match reason {
        EmbedSkipReason::Undecryptable => fingerprint_for(agent_id),
        EmbedSkipReason::Oversize => EmbedSkipReason::Oversize.as_str().to_string(),
    };
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        SQL_INSERT_IGNORE,
        params![memory_id, agent_id, fp, reason.as_str(), now],
    )?;
    Ok(conn.changes() > 0)
}

/// Drop skip markers whose stored fingerprint no longer matches live key
/// material (undecryptable only — oversize is independent of keys and is
/// cleared by the content-update trigger). Returns the number of rows
/// deleted.
pub fn invalidate_stale_sqlite(conn: &Connection) -> Result<usize> {
    // #3484 — DELETE FROM embed_skip is a write; gate it like every other.
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let mut stmt = conn.prepare(SQL_SELECT_ALL)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut fp_by_agent: HashMap<String, String> = HashMap::new();
    let mut stale: Vec<String> = Vec::new();
    for row in rows {
        let (id, agent_id, stored_fp, reason) = row?;
        let Some(reason) = EmbedSkipReason::from_stored(&reason) else {
            stale.push(id);
            continue;
        };
        if reason != EmbedSkipReason::Undecryptable {
            continue;
        }
        let live = fp_by_agent
            .entry(agent_id.clone())
            .or_insert_with(|| fingerprint_for(&agent_id));
        if stored_fp != *live {
            stale.push(id);
        }
    }
    let n = stale.len();
    for id in stale {
        conn.execute(SQL_DELETE_BY_ID, params![id])?;
    }
    Ok(n)
}

/// Count remembered skip rows (boot summary).
pub fn count_sqlite(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(SQL_COUNT, [], |row| row.get(0))?)
}

/// Log the remembered-skip count ONCE per process (INFO, not per-row WARN).
pub fn log_remembered_once(count: i64) {
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if count <= 0 {
        return;
    }
    if LOGGED.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::info!(
        skipped = count,
        "embedding backfill: {count} row(s) remembered as unembeddable under \
         current key material (#3344); skipped without re-scan. Restore the \
         decryption key to heal."
    );
}

/// Invalidate stale markers (amortised: at most once per
/// [`INVALIDATE_MIN_INTERVAL`] **on this store**), then emit the
/// once-per-process boot summary. Best-effort: a skip-cache fault is
/// logged and never fails the scan.
pub fn prepare_scan_sqlite(conn: &Connection, amort: &EmbedSkipAmortisation) {
    if amort.should_walk() {
        match invalidate_stale_sqlite(conn) {
            Ok(_) => {
                amort.bump_walk();
                amort.mark_walked();
            }
            Err(e) => tracing::warn!(error = %e, "embed skip stale-invalidate failed (#3344)"),
        }
    }
    match count_sqlite(conn) {
        Ok(n) => log_remembered_once(n),
        Err(e) => tracing::warn!(error = %e, "embed skip count failed (#3344)"),
    }
}

/// Best-effort persist used by the scan path. Returns whether this was a
/// newly recorded skip (caller WARNs once).
pub fn record_sqlite_best_effort(
    conn: &Connection,
    memory_id: &str,
    agent_id: &str,
    reason: EmbedSkipReason,
) -> bool {
    match record_sqlite(conn, memory_id, agent_id, reason) {
        Ok(fresh) => fresh,
        Err(e) => {
            tracing::warn!(
                error = %e,
                memory_id,
                "embed skip persist failed (#3344)"
            );
            true
        }
    }
}

/// Pull `metadata.agent_id` from the JSON blob the unembedded scan already
/// fetched. Empty string when the key is absent (open_content then fails
/// closed the same way).
#[must_use]
pub fn agent_id_from_metadata_json(metadata_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(metadata_json)
        .ok()
        .as_ref()
        .and_then(|m| m.get("agent_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
}

#[cfg(feature = "sal-postgres")]
pub mod postgres {
    //! Postgres twins of the sqlite skip-cache helpers. Gated with the
    //! adapter so default builds do not pull sqlx.

    use super::{
        EmbedSkipAmortisation, EmbedSkipReason, TABLE, fingerprint_for, log_remembered_once,
    };
    use sqlx::{PgPool, Row};
    use std::collections::HashMap;

    const SQL_INSERT_IGNORE: &str = "INSERT INTO embed_skip \
        (memory_id, agent_id, key_fingerprint, reason, created_at) \
        VALUES ($1, $2, $3, $4, now()) \
        ON CONFLICT (memory_id) DO NOTHING";

    const SQL_SELECT_ALL: &str =
        "SELECT memory_id, agent_id, key_fingerprint, reason FROM embed_skip";

    const SQL_DELETE_BY_ID: &str = "DELETE FROM embed_skip WHERE memory_id = $1";

    const SQL_COUNT: &str = "SELECT COUNT(*) FROM embed_skip";

    /// See [`super::prepare_scan_sqlite`]. The walk decision is taken
    /// (and the mutex dropped) before the `.await` (CONCURRENCY-20).
    pub async fn prepare_scan(pool: &PgPool, amort: &EmbedSkipAmortisation) {
        if amort.should_walk() {
            match invalidate_stale(pool).await {
                Ok(_) => {
                    amort.bump_walk();
                    amort.mark_walked();
                }
                Err(e) => {
                    tracing::warn!(error = %e, "embed skip stale-invalidate failed (#3344)");
                }
            }
        }
        match count(pool).await {
            Ok(n) => log_remembered_once(n),
            Err(e) => tracing::warn!(error = %e, "embed skip count failed (#3344)"),
        }
    }

    async fn count(pool: &PgPool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(SQL_COUNT).fetch_one(pool).await
    }

    async fn invalidate_stale(pool: &PgPool) -> Result<usize, sqlx::Error> {
        let rows = sqlx::query(SQL_SELECT_ALL).fetch_all(pool).await?;
        let mut fp_by_agent: HashMap<String, String> = HashMap::new();
        let mut n = 0usize;
        for row in rows {
            let id: String = row.try_get("memory_id")?;
            let agent_id: String = row.try_get("agent_id")?;
            let stored_fp: String = row.try_get("key_fingerprint")?;
            let reason_raw: String = row.try_get("reason")?;
            let stale = match EmbedSkipReason::from_stored(&reason_raw) {
                Some(EmbedSkipReason::Undecryptable) => {
                    let live = fp_by_agent
                        .entry(agent_id.clone())
                        .or_insert_with(|| fingerprint_for(&agent_id));
                    stored_fp != *live
                }
                Some(EmbedSkipReason::Oversize) => false,
                None => true,
            };
            if stale {
                sqlx::query(SQL_DELETE_BY_ID)
                    .bind(&id)
                    .execute(pool)
                    .await?;
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Best-effort persist. Returns whether this was a new insert.
    pub async fn record_best_effort(
        pool: &PgPool,
        memory_id: &str,
        agent_id: &str,
        reason: EmbedSkipReason,
    ) -> bool {
        let fp = match reason {
            EmbedSkipReason::Undecryptable => fingerprint_for(agent_id),
            EmbedSkipReason::Oversize => EmbedSkipReason::Oversize.as_str().to_string(),
        };
        match sqlx::query(SQL_INSERT_IGNORE)
            .bind(memory_id)
            .bind(agent_id)
            .bind(&fp)
            .bind(reason.as_str())
            .execute(pool)
            .await
        {
            Ok(res) => res.rows_affected() > 0,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    memory_id,
                    table = TABLE,
                    "embed skip persist failed (#3344)"
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        // Triggers in the v96 DDL fire ON memories, so the stub table
        // must exist first (production always has `memories` before v96).
        conn.execute_batch(
            "CREATE TABLE memories (
                id TEXT PRIMARY KEY,
                content TEXT,
                encrypted_envelope BLOB,
                embedding BLOB
            );",
        )
        .expect("stub memories");
        conn.execute_batch(MIGRATION_V96_SQLITE).expect("v96 ddl");
        conn
    }

    #[test]
    fn record_is_idempotent_no_second_insert() {
        let conn = fresh_conn();
        let first =
            record_sqlite(&conn, "m1", "agent-a", EmbedSkipReason::Undecryptable).expect("first");
        let second =
            record_sqlite(&conn, "m1", "agent-a", EmbedSkipReason::Undecryptable).expect("second");
        assert!(first, "first persist is a new insert");
        assert!(!second, "second persist of the same id is a no-op");
        assert_eq!(count_sqlite(&conn).expect("count"), 1);
    }

    #[test]
    fn invalidate_stale_drops_undecryptable_when_fingerprint_changes() {
        let conn = fresh_conn();
        conn.execute(
            "INSERT INTO embed_skip (memory_id, agent_id, key_fingerprint, reason, created_at) \
             VALUES ('m1', 'agent-a', 'stale-fp', 'undecryptable', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("plant stale");
        conn.execute(
            "INSERT INTO embed_skip (memory_id, agent_id, key_fingerprint, reason, created_at) \
             VALUES ('m2', 'agent-a', 'oversize', 'oversize', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("plant oversize");
        let dropped = invalidate_stale_sqlite(&conn).expect("invalidate");
        assert_eq!(dropped, 1, "only the stale undecryptable row is dropped");
        assert_eq!(count_sqlite(&conn).expect("count"), 1);
        let remaining: String = conn
            .query_row("SELECT memory_id FROM embed_skip", [], |r| r.get(0))
            .expect("remaining");
        assert_eq!(remaining, "m2");
    }

    #[test]
    fn reason_as_str_matches_sql_check() {
        assert_eq!(EmbedSkipReason::Undecryptable.as_str(), "undecryptable");
        assert_eq!(EmbedSkipReason::Oversize.as_str(), "oversize");
        assert_eq!(
            EmbedSkipReason::from_stored("undecryptable"),
            Some(EmbedSkipReason::Undecryptable)
        );
        assert_eq!(EmbedSkipReason::from_stored("nope"), None);
    }

    #[test]
    fn consecutive_prepare_scan_does_not_rewalk_when_keys_unchanged() {
        // #3344 amendment 2 — two consecutive scans with unchanged key
        // material must not re-SELECT the whole skip table (O(1) tick).
        // Per-store amort: a second store's first scan still walks.
        let amort = EmbedSkipAmortisation::new();
        let conn = fresh_conn();
        record_sqlite(&conn, "m1", "agent-a", EmbedSkipReason::Undecryptable).expect("record");
        prepare_scan_sqlite(&conn, &amort);
        let walks_after_first = amort.table_walk_count();
        assert!(
            walks_after_first >= 1,
            "first prepare_scan must walk, got {walks_after_first}"
        );
        prepare_scan_sqlite(&conn, &amort);
        prepare_scan_sqlite(&conn, &amort);
        assert_eq!(
            amort.table_walk_count(),
            walks_after_first,
            "subsequent scans within 60s must not re-walk embed_skip"
        );
        let other = EmbedSkipAmortisation::new();
        prepare_scan_sqlite(&conn, &other);
        assert!(
            other.table_walk_count() >= 1,
            "a different store instance must not inherit the first store's timer"
        );
    }

    #[test]
    fn sql_predicate_names_the_table_const() {
        assert!(
            SQL_AND_NOT_SKIPPED.contains(TABLE),
            "scan predicate must name {TABLE}"
        );
        assert!(
            MIGRATION_V96_SQLITE.contains("CREATE TABLE IF NOT EXISTS embed_skip"),
            "sqlite DDL twin must ship the table"
        );
        assert!(
            MIGRATION_V96_POSTGRES.contains("CREATE TABLE IF NOT EXISTS embed_skip"),
            "postgres DDL twin must ship the table"
        );
        assert!(
            MIGRATION_V96_POSTGRES.contains(POSTGRES_DROP_CLEAR_TRIGGER),
            "postgres DDL twin must match the conversion-time trigger drop"
        );
        assert!(
            MIGRATION_V96_POSTGRES.contains(POSTGRES_CREATE_CLEAR_TRIGGER),
            "postgres DDL twin must match the conversion-time trigger recreation"
        );
        assert!(
            MIGRATION_V96_SQLITE.contains(TRIGGER_CLEAR_ON_EMBED),
            "sqlite DDL twin must ship the embedding-clear trigger"
        );
        assert!(
            MIGRATION_V96_SQLITE.contains(TRIGGER_CLEAR_ON_CONTENT),
            "sqlite DDL twin must ship the content-clear trigger"
        );
    }

    #[test]
    fn apply_sqlite_v96_skips_embed_trigger_when_embedding_column_absent_3344() {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(
            "CREATE TABLE memories (
                id TEXT PRIMARY KEY,
                content TEXT,
                encrypted_envelope BLOB
            );",
        )
        .expect("stub memories without embedding");
        apply_sqlite_v96(&conn).expect("v96 table-only apply");
        let trigger_present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'trigger' AND name = ?1",
                params![TRIGGER_CLEAR_ON_EMBED],
                |r| r.get(0),
            )
            .expect("probe trigger");
        assert_eq!(
            trigger_present, 0,
            "must not CREATE memories_embed_skip_clear_on_embed without embedding"
        );
        let table_present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name = ?1",
                params![TABLE],
                |r| r.get(0),
            )
            .expect("probe table");
        assert_eq!(table_present, 1, "embed_skip table is still created");
    }

    #[test]
    fn drop_sqlite_clear_triggers_is_idempotent_3344() {
        let conn = fresh_conn();
        drop_sqlite_clear_triggers(&conn).expect("first drop");
        drop_sqlite_clear_triggers(&conn).expect("second drop");
        apply_sqlite_v96(&conn).expect("recreate");
        let trigger_present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'trigger' AND name = ?1",
                params![TRIGGER_CLEAR_ON_EMBED],
                |r| r.get(0),
            )
            .expect("probe trigger");
        assert_eq!(trigger_present, 1, "recreate after drop must reinstall");
    }
}
