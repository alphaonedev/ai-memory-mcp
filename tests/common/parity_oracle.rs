// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7030 campaign X — the cross-backend state oracle.
//!
//! [`state_digest`] reads the durable state a single SAL call may have touched
//! and renders it as backend-neutral text sections, so a sqlite store and a
//! postgres store that were driven identically compare with `==` and a diff
//! names the diverging section. [`err_variant`] reduces a `StoreError` to its
//! variant plus a sanitized message for the same purpose.
//!
//! No `MemoryStore` trait method is added (a T1 public-contract change): the
//! oracle reads through raw SQL against an explicit [`RawDb`] locator, because
//! a `&dyn MemoryStore` cannot be downcast to its connection.
//! Timestamps are excluded on purpose (formats legitimately differ).

#![allow(dead_code)]
#![cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ai_memory::store::StoreError;

/// Where the raw state of one backend lives.
pub enum RawDb {
    /// Path of the sqlite database file behind a `SqliteStore`.
    Sqlite(PathBuf),
    /// Pool of the `PostgresStore` (its `search_path` already scopes the schema).
    #[cfg(feature = "sal-postgres")]
    Pg(sqlx::PgPool),
}

/// Backend-neutral state: section name -> sorted text rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateDigest(pub BTreeMap<String, Vec<Vec<String>>>);

impl StateDigest {
    /// Rows of one section (empty when absent).
    #[must_use]
    pub fn section(&self, name: &str) -> &[Vec<String>] {
        self.0.get(name).map_or(&[], Vec::as_slice)
    }

    /// A copy without the named sections (for per-assertion narrowing).
    #[must_use]
    pub fn without(&self, names: &[&str]) -> Self {
        let mut d = self.clone();
        for n in names {
            d.0.remove(*n);
        }
        d
    }
}

/// `(section, SQL)`; every column is `CAST(.. AS TEXT)` so one statement is
/// valid on both engines.
const SECTIONS: &[(&str, &str)] = &[
    (
        "memories",
        "SELECT CAST(id AS TEXT), CAST(title AS TEXT), CAST(namespace AS TEXT), \
         CAST(tier AS TEXT), CAST(lifecycle_state AS TEXT), CAST(version AS TEXT), \
         CAST(metadata ->> 'agent_id' AS TEXT) FROM memories ORDER BY id",
    ),
    (
        "links",
        "SELECT CAST(source_id AS TEXT), CAST(target_id AS TEXT), CAST(relation AS TEXT) \
         FROM memory_links ORDER BY source_id, target_id, relation",
    ),
    (
        "archived",
        "SELECT CAST(id AS TEXT) FROM archived_memories ORDER BY id",
    ),
    (
        "forget_tombstones",
        "SELECT CAST(memory_id AS TEXT), CAST(namespace AS TEXT) FROM forget_tombstones \
         ORDER BY memory_id",
    ),
    (
        "signed_events",
        "SELECT CAST(event_type AS TEXT), CAST(COUNT(*) AS TEXT) FROM signed_events \
         GROUP BY event_type ORDER BY event_type",
    ),
    (
        "revisions",
        "SELECT CAST(memory_id AS TEXT), CAST(kind AS TEXT), CAST(prior_version AS TEXT) \
         FROM memory_revisions ORDER BY memory_id, kind, prior_version",
    ),
    (
        "leases",
        "SELECT CAST(action_id AS TEXT), CAST(holder AS TEXT) FROM leases ORDER BY action_id, holder",
    ),
    (
        "actions",
        "SELECT CAST(id AS TEXT), CAST(state AS TEXT), CAST(claimed_by AS TEXT) FROM actions ORDER BY id",
    ),
    (
        "quota",
        "SELECT CAST(agent_id AS TEXT), CAST(current_memories_today AS TEXT), \
         CAST(current_storage_bytes AS TEXT), CAST(current_links_today AS TEXT) \
         FROM agent_quotas ORDER BY agent_id",
    ),
];

async fn fetch(db: &RawDb, sql: &str) -> Vec<Vec<String>> {
    match db {
        RawDb::Sqlite(path) => {
            let conn = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap_or_else(|e| panic!("oracle: open sqlite {}: {e}", path.display()));
            let mut stmt = conn
                .prepare(sql)
                .unwrap_or_else(|e| panic!("oracle: prepare `{sql}`: {e}"));
            let cols = stmt.column_count();
            stmt.query_map([], |row| {
                (0..cols)
                    .map(|i| {
                        row.get::<_, Option<String>>(i)
                            .map(Option::unwrap_or_default)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(Iterator::collect)
            .unwrap_or_else(|e| panic!("oracle: query `{sql}`: {e}"))
        }
        #[cfg(feature = "sal-postgres")]
        RawDb::Pg(pool) => {
            use sqlx::Row;
            let rows = sqlx::query(sql)
                .fetch_all(pool)
                .await
                .unwrap_or_else(|e| panic!("oracle: pg query `{sql}`: {e}"));
            rows.iter()
                .map(|r| {
                    (0..r.columns().len())
                        .map(|i| {
                            r.try_get::<Option<String>, _>(i)
                                .unwrap_or_else(|e| panic!("oracle: pg column {i}: {e}"))
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .collect()
        }
    }
}

/// Run one raw statement on `db` (system-only state such as quarantine has no
/// SAL setter, so cells arm it with SQL).
pub async fn exec(db: &RawDb, sql: &str) {
    match db {
        RawDb::Sqlite(path) => {
            let conn = rusqlite::Connection::open(path)
                .unwrap_or_else(|e| panic!("oracle: open sqlite {}: {e}", path.display()));
            conn.execute_batch(sql)
                .unwrap_or_else(|e| panic!("oracle: exec `{sql}`: {e}"));
        }
        #[cfg(feature = "sal-postgres")]
        RawDb::Pg(pool) => {
            sqlx::query(sql)
                .execute(pool)
                .await
                .unwrap_or_else(|e| panic!("oracle: pg exec `{sql}`: {e}"));
        }
    }
}

/// Read every campaign-X section from `db`.
pub async fn state_digest(db: &RawDb) -> StateDigest {
    let mut out = BTreeMap::new();
    for (name, sql) in SECTIONS {
        out.insert((*name).to_string(), fetch(db, sql).await);
    }
    StateDigest(out)
}

/// A `StoreError` as `(variant name, sanitized message)`: digits are masked so
/// ids and counts never create a false divergence, text is lowercased.
/// Only the typed backend label is removed; operation-specific detail remains
/// observable. Unknown driver wording is not collapsed to a generic success.
#[must_use]
pub fn err_variant(e: &StoreError) -> (String, String) {
    let dbg = format!("{e:?}");
    let variant = dbg
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or_default()
        .to_string();
    let text = match e {
        StoreError::BackendUnavailable { detail, .. } => format!("backend unavailable: {detail}"),
        _ => e.to_string(),
    };
    let msg = text
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                '#'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    (variant, msg)
}

/// Allocate one SQLite database; keep the directory guard until the store drops.
#[must_use]
pub fn sqlite_scratch() -> (
    tempfile::TempDir,
    ai_memory::store::sqlite::SqliteStore,
    RawDb,
) {
    let root = std::env::var_os("TMPDIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".local-runs"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&root).expect("parity scratch root");
    let dir = tempfile::Builder::new()
        .prefix("parity-")
        .tempdir_in(root)
        .expect("parity scratch directory");
    let path = dir.path().join("parity.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("parity sqlite");
    (dir, store, RawDb::Sqlite(path))
}

/// Allocate a database per run, including when nextest uses a process per test.
/// A missing URL is an explicit skip; provisioning errors are failures.
/// Keep the `ScratchDb` guard alive and close the store pool before normal return.
#[cfg(feature = "sal-postgres")]
pub async fn pg_scratch(
    tag: &str,
) -> Option<(
    crate::common::pg_barrier::ScratchDb,
    ai_memory::store::postgres::PostgresStore,
    RawDb,
)> {
    const URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
    let base = match std::env::var(URL_ENV) {
        Ok(base) => base,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("skip: {tag}: {URL_ENV} unset (live postgres required)");
            return None;
        }
        Err(std::env::VarError::NotUnicode(_)) => panic!("{URL_ENV} must be valid Unicode"),
    };
    // Guard before pg_isolate can provision, then guard its resolved URL too.
    crate::common::lane_db::assert_lane_database(&base);
    let url = crate::common::pg_isolate::isolated_url().expect("configured postgres URL");
    Some(pg_scratch_from_url(&url, tag).await)
}

/// Explicit-URL entry for isolation controls. Reject unsafe lanes BEFORE any IO.
#[cfg(feature = "sal-postgres")]
pub async fn pg_scratch_from_url(
    url: &str,
    tag: &str,
) -> (
    crate::common::pg_barrier::ScratchDb,
    ai_memory::store::postgres::PostgresStore,
    RawDb,
) {
    use std::hash::{Hash, Hasher};

    use crate::common::pg_barrier::ScratchDb;
    use ai_memory::store::postgres::PostgresStore;
    const MAX_TAG_LEN: usize = 8;
    const EXTENSIONS: &[&str] = &[
        "CREATE EXTENSION IF NOT EXISTS age",
        "CREATE EXTENSION IF NOT EXISTS vector",
    ];
    crate::common::lane_db::assert_lane_database(url);
    assert!(
        !tag.is_empty()
            && tag.len() <= MAX_TAG_LEN
            && tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "parity scratch tag must be short lowercase ASCII"
    );
    // Scope stale cleanup to this provisioning lane and cell, including killed
    // prior processes. Keep the full hash and room for ScratchDb's unique suffix
    // within PostgreSQL's identifier limit; concurrent runs remain distinct.
    let mut lane = std::collections::hash_map::DefaultHasher::new();
    crate::common::lane_db::database_name(url).hash(&mut lane);
    let prefix = format!("ai_memory_parity_{:016x}_{tag}", lane.finish());
    let scratch = ScratchDb::create(url, &prefix)
        .await
        .expect("parity ScratchDb");
    let bootstrap = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&scratch.url())
        .await
        .expect("parity extension connection");
    for sql in EXTENSIONS {
        sqlx::query(sql)
            .execute(&bootstrap)
            .await
            .expect("parity extension");
    }
    bootstrap.close().await;
    let store = PostgresStore::connect(&scratch.url())
        .await
        .expect("parity postgres");
    let raw = RawDb::Pg(store.pool().clone());
    (scratch, store, raw)
}

/// All tests touching lineage flags in a binary share this async lock.
pub static LINEAGE_FLAGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reset both flags before releasing the lock, including during panic unwind.
/// OWNERSHIP-24/25: Drop performs only nonpanicking atomic stores.
#[must_use = "hold the guard until the lineage operation completes"]
pub struct LineageGuard {
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl LineageGuard {
    pub async fn enable() -> Self {
        let lock = LINEAGE_FLAGS.lock().await;
        ai_memory::config::set_lineage_dag(true);
        ai_memory::config::set_consolidate_tombstone_sources(true);
        Self { _lock: lock }
    }
}

impl Drop for LineageGuard {
    fn drop(&mut self) {
        ai_memory::config::set_consolidate_tombstone_sources(false);
        ai_memory::config::set_lineage_dag(false);
    }
}

/// Compare complete (or explicitly narrowed) digests with cell context.
pub fn assert_digest_parity(cell: &str, sq: &StateDigest, pg: &StateDigest) {
    assert_eq!(sq, pg, "{cell}: state digest parity (sqlite vs postgres)");
}

/// Compare BOTH the variant and sanitized message; no implicit message waiver.
pub fn assert_err_parity(cell: &str, sq: &StoreError, pg: &StoreError) {
    assert_eq!(
        err_variant(sq),
        err_variant(pg),
        "{cell}: error parity (variant and sanitized message)"
    );
}
