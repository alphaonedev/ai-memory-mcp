// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v103 (#10108, signed writes) — the persisted places of two agent
//! signatures and the agent-attribution cutover marker. `3-agent vote
//! (71472661)` V1-AGENT-SIG-SCHEMA, decision A (conditions S-1, S-3).
//!
//! Strictly additive: two NULL-able columns on `transcript_line_dedup`, the
//! new `atomisation_receipts` table and ONE appended `signed_events` row. No
//! existing row is rewritten, relabelled or deleted. Every step is guarded, so
//! the arm is idempotent, and it runs inside the ladder's one migrate
//! transaction, so a crash before COMMIT leaves the database at v102 with
//! nothing written. There is no down migration: a downgrade is a restore of
//! the pre-v103 backup the ladder writes (docs/MIGRATION.md).

use anyhow::Result;
use rusqlite::Connection;

/// The `atomisation_receipts` DDL (the columns are added in Rust below,
/// because sqlite `ALTER TABLE ADD COLUMN` has no `IF NOT EXISTS` form).
const MIGRATION_V103_SQLITE: &str =
    include_str!("../../migrations/sqlite/0087_v103_agent_signature_places.sql");

/// #10108 (S-2) — the two `transcript_line_dedup` columns and their column
/// CHECKs: 64-byte signature, 32-byte key, both set or both NULL.
const DEDUP_COLUMNS: [(&str, &str); 2] = [
    (
        "host_signature",
        "ALTER TABLE transcript_line_dedup ADD COLUMN host_signature BLOB NULL \
         CHECK (host_signature IS NULL OR (typeof(host_signature) = 'blob' \
         AND length(host_signature) = 64))",
    ),
    (
        "host_pubkey",
        "ALTER TABLE transcript_line_dedup ADD COLUMN host_pubkey BLOB NULL \
         CHECK (host_pubkey IS NULL OR (typeof(host_pubkey) = 'blob' \
         AND length(host_pubkey) = 32))",
    ),
];

/// #10108 (S-2) — the both-or-neither rule. A column CHECK may name only its
/// own column, so the pair rule is two triggers (insert and update).
const DEDUP_PAIR_TRIGGERS: &str = "
CREATE TRIGGER IF NOT EXISTS transcript_line_dedup_host_sig_pair_insert_v103
BEFORE INSERT ON transcript_line_dedup
WHEN (NEW.host_signature IS NULL) <> (NEW.host_pubkey IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'transcript_line_dedup: host_signature and host_pubkey are both set or both NULL');
END;
CREATE TRIGGER IF NOT EXISTS transcript_line_dedup_host_sig_pair_update_v103
BEFORE UPDATE OF host_signature, host_pubkey ON transcript_line_dedup
WHEN (NEW.host_signature IS NULL) <> (NEW.host_pubkey IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'transcript_line_dedup: host_signature and host_pubkey are both set or both NULL');
END;
";

/// The table the v103 columns land on (pm-v3.1: one named constant).
const DEDUP_TABLE: &str = "transcript_line_dedup";

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )?)
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        [table, column],
        |r| r.get(0),
    )?)
}

pub(super) fn migrate_v103(conn: &Connection) -> Result<()> {
    conn.execute_batch(MIGRATION_V103_SQLITE)?;
    // Same gate as the v102 arm: every deployed path creates the table before
    // `migrate`; only fixtures that stamp a version without it lack it.
    if table_exists(conn, DEDUP_TABLE)? {
        for (column, ddl) in DEDUP_COLUMNS {
            if !column_exists(conn, DEDUP_TABLE, column)? {
                conn.execute(ddl, [])?;
            }
        }
        conn.execute_batch(DEDUP_PAIR_TRIGGERS)?;
    }
    // #10108 (S-3) — the marker is written in the same transaction as the
    // stamp below: no committed state has the schema at v103 and no marker.
    if table_exists(conn, super::schema_integrity::TABLE_SIGNED_EVENTS)? {
        crate::signed_events::agent_cutover::write_sqlite_agent_cutover(conn)?;
    }
    conn.execute(super::migrations::SQL_CLEAR_SCHEMA_VERSION, [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (103)", [])?;
    Ok(())
}
