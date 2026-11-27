// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap fixture for the stamped-version ladder tests (#10040).
//!
//! The ladder tests in `migrations::tests` apply the bootstrap `SCHEMA`,
//! stamp a historical version `N` and run `migrate` to the tip. The bootstrap
//! `SCHEMA` carries `memories` but not the 13 side tables the ladder creates
//! in arms v5 to v62. A real store always walks the whole ladder from v0, so a
//! store stamped at `N >= 26` always holds every one of them; the hand-stamped
//! fixture did not. Since 7213084c3 the v103 arm reads every attested table
//! (`row_attest::TABLES`) and refuses a missing one ("row attestation read
//! of <table>"), which is the fail-closed contract, so the fixture is
//! completed here instead of teaching v103 to skip a missing table.
//!
//! [`apply_schema`] applies `SCHEMA` and then creates each attested table that
//! is still absent with the exact `CREATE TABLE` text a full v0-to-tip ladder
//! run produces, so the fixture shape cannot drift from the ladder. Every
//! ALTER the ladder runs on these tables after v25 is guarded by a column
//! probe, so pre-creating the final shape is safe for stamps of v26 and up;
//! tests that hand-roll an older shape of one table drop and recreate it after
//! this call, as before.

use std::sync::OnceLock;

use rusqlite::Connection;

use super::migrations::SCHEMA;
use super::row_attest::TABLES;

/// `(table, CREATE TABLE text)` for every attested table, read once from a
/// database migrated from v0 to the tip.
fn reference_ddl() -> &'static [(String, String)] {
    static DDL: OnceLock<Vec<(String, String)>> = OnceLock::new();
    DDL.get_or_init(|| {
        let conn = Connection::open_in_memory().expect("in-memory reference db");
        conn.execute_batch(SCHEMA).expect("apply SCHEMA");
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear schema_version");
        conn.execute("INSERT INTO schema_version (version) VALUES (0)", [])
            .expect("seed v0");
        super::migrations::migrate(&conn).expect("reference migrate from v0");
        TABLES
            .iter()
            .map(|spec| {
                let ddl: String = conn
                    .query_row(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        [spec.table],
                        |r| r.get(0),
                    )
                    .unwrap_or_else(|e| panic!("reference DDL of {}: {e}", spec.table));
                (spec.table.to_string(), ddl)
            })
            .collect()
    })
}

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )
    .expect("sqlite_master probe")
}

/// Apply the bootstrap `SCHEMA`, then create every attested table that is
/// still absent in its ladder-produced shape. Existing tables are untouched.
pub(super) fn apply_schema(conn: &Connection) {
    conn.execute_batch(SCHEMA).expect("apply SCHEMA");
    for (table, ddl) in reference_ddl() {
        if !table_exists(conn, table) {
            conn.execute_batch(ddl)
                .unwrap_or_else(|e| panic!("create attested table {table}: {e}"));
        }
    }
}

/// The fixture leaves no attested table absent, and it never replaces a table
/// the bootstrap `SCHEMA` already created.
#[test]
fn apply_schema_creates_every_attested_table_and_keeps_existing_ones_10040() {
    let conn = Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(SCHEMA).expect("apply SCHEMA");
    let before: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'memories'",
            [],
            |r| r.get(0),
        )
        .expect("memories DDL");
    let absent_before = TABLES
        .iter()
        .filter(|spec| !table_exists(&conn, spec.table))
        .count();
    assert!(absent_before > 0, "SCHEMA alone must lack side tables");
    let fresh = Connection::open_in_memory().expect("in-memory db");
    apply_schema(&fresh);
    for spec in TABLES {
        assert!(table_exists(&fresh, spec.table), "{} absent", spec.table);
    }
    let after: String = fresh
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'memories'",
            [],
            |r| r.get(0),
        )
        .expect("memories DDL");
    assert_eq!(before, after, "memories must keep the SCHEMA shape");
}
