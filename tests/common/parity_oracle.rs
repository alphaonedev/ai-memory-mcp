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
         CAST(lifecycle_state AS TEXT), CAST(version AS TEXT) FROM memories ORDER BY id",
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
    ("leases", "SELECT CAST(COUNT(*) AS TEXT) FROM leases"),
    ("actions", "SELECT CAST(COUNT(*) AS TEXT) FROM actions"),
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
#[must_use]
pub fn err_variant(e: &StoreError) -> (String, String) {
    let dbg = format!("{e:?}");
    let variant = dbg
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or_default()
        .to_string();
    let msg = e
        .to_string()
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
