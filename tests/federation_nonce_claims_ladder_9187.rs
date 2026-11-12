// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9187 C1 — the sqlite ladder cell for `federation_nonce_claims`.
//!
//! The postgres cell lives in `tests/postgres_ladder_replay.rs`. This file
//! holds the sqlite twin: a database stamped at a rung below v103 WITHOUT the
//! claim table ladders to EXACTLY v103 with the table, its column shape and its
//! `(key_fp, nonce_fp)` PRIMARY KEY present, and re-running the v103 rung over
//! a populated table changes no schema object and no row. The legacy v51
//! `federation_nonce_cache` table is left untouched by the rung.

use rusqlite::Connection;

/// The #9187 federation nonce claim table, keyed `(key_fp, nonce_fp)`.
const NONCE_TABLE: &str = "federation_nonce_claims";
/// The legacy v51 table the v103 rung must leave in place.
const LEGACY_NONCE_TABLE: &str = "federation_nonce_cache";
/// The ladder rung that owns `federation_nonce_claims` on sqlite.
const NONCE_LADDER_VERSION: i64 = 103;
/// Rungs below v103 a database may be stamped at when the rung first runs.
const NONCE_PRE_VERSIONS: &[i64] = &[101, 102];
/// The column shape v103 must create: `name:type:notnull:pk position`.
const NONCE_COLUMNS: &[&str] = &[
    "key_fp:BLOB:1:1",
    "nonce_fp:BLOB:1:2",
    "accepted_at:INTEGER:1:0",
];
/// Rows planted before the idempotency re-run: `(key_fp, nonce_fp, accepted_at)`.
const NONCE_PLANTED: &[(&[u8], &[u8], i64)] = &[
    (
        &[0x91, 0x87, 0xaa, 0x00],
        &[0x00, 0xff, 0x10, 0x20],
        1_700_000_000,
    ),
    (
        &[0x91, 0x87, 0xbb, 0x01],
        &[0xde, 0xad, 0xbe, 0xef],
        1_700_000_001,
    ),
];

/// Every observable byte of the claim table: column shape, every schema
/// object on it (`sqlite_master`, the PK autoindex included), every row.
#[derive(Debug, PartialEq, Eq)]
struct NonceSnapshot {
    columns: Vec<String>,
    objects: Vec<String>,
    rows: Vec<String>,
}

fn strings(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Vec<String> {
    let mut stmt = conn.prepare(sql).expect("prepare snapshot query");
    stmt.query_map(params, |r| r.get::<_, String>(0))
        .expect("run snapshot query")
        .collect::<Result<Vec<_>, _>>()
        .expect("read snapshot rows")
}

fn nonce_snapshot(conn: &Connection) -> NonceSnapshot {
    NonceSnapshot {
        columns: strings(
            conn,
            "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk \
             FROM pragma_table_info(?1) ORDER BY cid",
            [NONCE_TABLE],
        ),
        objects: strings(
            conn,
            "SELECT type || ':' || name || ':' || COALESCE(sql, '<auto>') \
             FROM sqlite_master WHERE tbl_name = ?1 ORDER BY type, name",
            [NONCE_TABLE],
        ),
        rows: strings(
            conn,
            "SELECT hex(key_fp) || '|' || hex(nonce_fp) || '|' || accepted_at \
             FROM federation_nonce_claims ORDER BY key_fp, nonce_fp",
            [],
        ),
    }
}

fn table_present(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get::<_, i64>(0),
    )
    .expect("probe sqlite_master")
        == 1
}

fn schema_version(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .expect("read schema_version")
}

fn stamp_version(conn: &Connection, version: i64) {
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear schema_version");
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [version],
    )
    .expect("stamp schema_version");
}

fn reopen(path: &std::path::Path, why: &str) -> Connection {
    ai_memory::db::open(path).unwrap_or_else(|e| panic!("#9187: open ({why}) must succeed: {e:#}"))
}

/// #9187 C1 (sqlite cell): from every rung below v103, a database WITHOUT the
/// claim table ladders to exactly v103 with the table, its column shape and
/// its `(key_fp, nonce_fp)` PRIMARY KEY; a plain reopen and a forced re-run of
/// the v103 rung over a populated table change nothing.
#[test]
fn federation_nonce_claims_ladders_below_v103_and_rerun_is_idempotent() {
    for &pre in NONCE_PRE_VERSIONS {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("m.db");

        // 1. A tip database, then rewound to "v<pre> without the table".
        let conn = reopen(&path, "seed");
        conn.execute_batch(&format!("DROP TABLE IF EXISTS {NONCE_TABLE}"))
            .expect("drop the claim table to synthesise the pre-v103 shape");
        stamp_version(&conn, pre);
        // Non-vacuity: the synthesised database really lacks the table.
        assert!(
            !table_present(&conn, NONCE_TABLE),
            "#9187: drop did not take"
        );
        assert_eq!(schema_version(&conn), pre);
        drop(conn);

        // 2. Ladder it: exact stamp, table, columns and PRIMARY KEY present.
        let conn = reopen(&path, "pre -> tip");
        assert_eq!(
            schema_version(&conn),
            NONCE_LADDER_VERSION,
            "#9187 C1: a v{pre} sqlite database did not ladder to exactly v{NONCE_LADDER_VERSION}",
        );
        assert!(
            table_present(&conn, NONCE_TABLE),
            "#9187 C1: `{NONCE_TABLE}` absent after laddering from v{pre}",
        );
        assert!(
            table_present(&conn, LEGACY_NONCE_TABLE),
            "#9187 C1: the v103 rung must leave the legacy `{LEGACY_NONCE_TABLE}` in place",
        );
        assert_eq!(
            nonce_snapshot(&conn).columns,
            NONCE_COLUMNS,
            "#9187 C1: `{NONCE_TABLE}` has the wrong columns or PRIMARY KEY",
        );

        // 3. Populate, snapshot, then re-run twice; nothing may move.
        for (key_fp, nonce_fp, accepted_at) in NONCE_PLANTED {
            conn.execute(
                "INSERT INTO federation_nonce_claims (key_fp, nonce_fp, accepted_at) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![key_fp, nonce_fp, accepted_at],
            )
            .expect("plant a claim row");
        }
        // The PRIMARY KEY is the atomic arbiter: a second claim of the same
        // (key_fp, nonce_fp) is refused.
        let (key_fp, nonce_fp, accepted_at) = NONCE_PLANTED[0];
        let dup = conn.execute(
            "INSERT INTO federation_nonce_claims (key_fp, nonce_fp, accepted_at) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![key_fp, nonce_fp, accepted_at],
        );
        let err = dup.expect_err("#9187 C1: a duplicate (key_fp, nonce_fp) claim must be refused");
        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "#9187 C1: duplicate claim refused for the wrong reason: {err}",
        );
        let before = nonce_snapshot(&conn);
        assert_eq!(
            before.rows.len(),
            NONCE_PLANTED.len(),
            "#9187: planting failed"
        );
        drop(conn);

        let conn = reopen(&path, "second run at tip");
        assert_eq!(schema_version(&conn), NONCE_LADDER_VERSION);
        assert_eq!(
            nonce_snapshot(&conn),
            before,
            "#9187 C1: a second migration run at the tip changed the claim table",
        );
        stamp_version(&conn, pre);
        drop(conn);

        let conn = reopen(&path, "forced v103 re-run over a populated table");
        assert_eq!(schema_version(&conn), NONCE_LADDER_VERSION);
        assert_eq!(
            nonce_snapshot(&conn),
            before,
            "#9187 C1: re-running the v103 rung from v{pre} over a populated table changed it",
        );
    }
}

/// #9187 C1 (sqlite cell, fresh database): a database created from nothing
/// carries the claim table at v103 too.
#[test]
fn fresh_sqlite_database_carries_federation_nonce_claims_at_v103() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = reopen(&dir.path().join("m.db"), "fresh");
    assert_eq!(
        schema_version(&conn),
        NONCE_LADDER_VERSION,
        "#9187 C1: a fresh sqlite database is not stamped v{NONCE_LADDER_VERSION}",
    );
    assert!(
        table_present(&conn, NONCE_TABLE),
        "#9187 C1: a fresh sqlite database lacks `{NONCE_TABLE}`",
    );
}
