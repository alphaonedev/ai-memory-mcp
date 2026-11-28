// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The v66 `governance_rules` rebuild test, moved out of `migrations.rs`
//! unchanged so that module stays under its QUAL-10 ceiling (#10145).

use super::{CURRENT_SCHEMA_VERSION, SCHEMA, migrate};
use rusqlite::{Connection, params};

fn current_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap_or(0)
}

#[test]
fn v66_rebuild_preserves_governance_rules_and_accepts_escalate_severity() {
    // §22 PE-5 (#697) — the load-bearing risk: the v66 full-table
    // rebuild of `governance_rules` must preserve every
    // pre-existing row + every column (including the OPERATOR-SIGNED
    // signature + attest_level data — a dropped signed-rule row or
    // column is a security regression), recreate BOTH indexes, AND
    // begin accepting the new `escalate` severity. We build a
    // pre-v66 (3-value severity CHECK) governance_rules table with
    // its two indexes, seed a signed rule, stamp the DB at v65, run
    // the migrate ladder, and assert:
    //   (a) the seeded row survives the rebuild verbatim (all
    //       columns, incl. signature + attest_level),
    //   (b) the pre-v66 CHECK would have REJECTED 'escalate',
    //   (c) post-v66 an 'escalate' row inserts cleanly,
    //   (d) both indexes were recreated.
    let conn = Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(SCHEMA).expect("apply SCHEMA");

    // The pre-v66 governance_rules shape (3-value severity CHECK).
    conn.execute_batch(
        "CREATE TABLE governance_rules (
             id            TEXT PRIMARY KEY,
             kind          TEXT NOT NULL,
             matcher       TEXT NOT NULL,
             severity      TEXT NOT NULL CHECK (severity IN ('refuse', 'warn', 'log')),
             reason        TEXT NOT NULL,
             namespace     TEXT NOT NULL DEFAULT '_global',
             created_by    TEXT NOT NULL,
             created_at    INTEGER NOT NULL,
             enabled       INTEGER NOT NULL DEFAULT 1,
             signature     BLOB,
             attest_level  TEXT NOT NULL DEFAULT 'unsigned'
         );
         CREATE INDEX idx_governance_rules_kind_enabled
             ON governance_rules (kind, enabled);
         CREATE INDEX idx_governance_rules_namespace
             ON governance_rules (namespace);",
    )
    .expect("recreate pre-v66 governance_rules");

    // (b) pre-v66 the CHECK must REJECT 'escalate'.
    let pre_escalate = conn.execute(
        "INSERT INTO governance_rules \
         (id, kind, matcher, severity, reason, created_by, created_at) \
         VALUES ('E0', 'bash', '{}', 'escalate', 'x', 'test', 0)",
        [],
    );
    assert!(
        pre_escalate.is_err(),
        "pre-v66 CHECK must reject the 'escalate' severity"
    );

    // Seed a signed operator rule (refuse severity + a 64-byte
    // signature + operator_signed attest_level) to prove the
    // rebuild preserves signed-rule security columns.
    let sig = vec![0xABu8; 64];
    conn.execute(
        "INSERT INTO governance_rules \
         (id, kind, matcher, severity, reason, namespace, created_by, created_at, \
          enabled, signature, attest_level) \
         VALUES ('R001', 'filesystem_write', '{\"glob\":\"/tmp/**\"}', 'refuse', \
                 'no /tmp', 'secure', 'operator', 42, 1, ?1, 'operator_signed')",
        params![sig],
    )
    .expect("seed signed pre-v66 rule");

    // Stamp at v65 so the migrate ladder runs the v66 arm.
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear schema_version");
    conn.execute("INSERT INTO schema_version (version) VALUES (65)", [])
        .expect("stamp v65");

    migrate(&conn).expect("migrate to v66 succeeds");
    assert_eq!(current_version(&conn), CURRENT_SCHEMA_VERSION);

    // (a) the signed row survived verbatim — every column intact.
    let (kind, matcher, severity, reason, namespace, created_by, created_at, enabled, attest): (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = conn
        .query_row(
            "SELECT kind, matcher, severity, reason, namespace, created_by, created_at, \
                    enabled, attest_level FROM governance_rules WHERE id = 'R001'",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )
        .expect("signed rule must survive the v66 rebuild");
    assert_eq!(kind, "filesystem_write");
    assert_eq!(matcher, "{\"glob\":\"/tmp/**\"}");
    assert_eq!(severity, "refuse");
    assert_eq!(reason, "no /tmp");
    assert_eq!(namespace, "secure");
    assert_eq!(created_by, "operator");
    assert_eq!(created_at, 42);
    assert_eq!(enabled, 1);
    assert_eq!(attest, "operator_signed");

    // The signature BLOB survived byte-for-byte.
    let surviving_sig: Vec<u8> = conn
        .query_row(
            "SELECT signature FROM governance_rules WHERE id = 'R001'",
            [],
            |r| r.get(0),
        )
        .expect("signature column must survive");
    assert_eq!(
        surviving_sig, sig,
        "signed-rule signature must be preserved"
    );

    // (c) post-v66 an 'escalate' row inserts cleanly.
    conn.execute(
        "INSERT INTO governance_rules \
         (id, kind, matcher, severity, reason, created_by, created_at) \
         VALUES ('E001', 'bash', '{\"command_substring\":\"sudo\"}', 'escalate', \
                 'human review', 'operator', 7)",
        [],
    )
    .expect("'escalate' severity must insert cleanly post-v66");

    // (d) both indexes were recreated by the rebuild.
    for idx in [
        "idx_governance_rules_kind_enabled",
        "idx_governance_rules_namespace",
    ] {
        let present: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type = 'index' AND name = ?1)",
                params![idx],
                |r| r.get(0),
            )
            .expect("probe index");
        assert!(present, "v66 rebuild must recreate {idx}");
    }
}
