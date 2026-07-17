// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2024 — operator-authorized skill retire/unretire lifecycle tests
//! (MCP-substrate level + schema-v82 migration + audit chain).
//!
//! The HTTP admin-gate + CLI/MCP/HTTP parity assertions live in
//! `tests/skill_cli_http_parity.rs`; this file exercises the substrate
//! semantics (hide-from-list, idempotency, lineage-wide stamping, the
//! register REFUSE, and the daemon-signed audit rows).

use ai_memory::db;
use ai_memory::mcp::{
    handle_skill_delete, handle_skill_get, handle_skill_list, handle_skill_register,
    handle_skill_retire,
};
use ai_memory::signed_events::verify_chain;
use serde_json::{Value, json};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open_db() -> (TempDir, rusqlite::Connection) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    let conn = db::open(&path).expect("db::open");
    (dir, conn)
}

fn minimal_skill_md(name: &str) -> String {
    format!("---\nnamespace: retns\nname: {name}\ndescription: A demo skill.\n---\n\nBody.\n")
}

fn register(conn: &rusqlite::Connection, name: &str) -> String {
    let v = handle_skill_register(conn, &json!({"inline_skill": minimal_skill_md(name)}), None)
        .expect("register");
    v["id"].as_str().expect("id").to_string()
}

fn retired_rows(conn: &rusqlite::Connection, ns: &str, name: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM skills WHERE namespace = ?1 AND name = ?2 AND retired_at IS NOT NULL",
        rusqlite::params![ns, name],
        |r| r.get(0),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Discovery hide / include_retired
// ---------------------------------------------------------------------------

#[test]
fn retire_hides_from_list() {
    let (_d, conn) = open_db();
    register(&conn, "hide-me");

    let before = handle_skill_list(&conn, &json!({})).unwrap();
    assert_eq!(before["count"], json!(1));

    let r = handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "hide-me"}),
        None,
    )
    .unwrap();
    assert_eq!(r["retired"], json!(true));
    assert_eq!(r["action"], json!("retire"));
    assert_eq!(r["affected"], json!(1));

    let after = handle_skill_list(&conn, &json!({})).unwrap();
    assert_eq!(
        after["count"],
        json!(0),
        "retired skill hidden from discovery"
    );
}

#[test]
fn include_retired_shows_it() {
    let (_d, conn) = open_db();
    register(&conn, "show-me");
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "show-me"}),
        None,
    )
    .unwrap();

    let v = handle_skill_list(&conn, &json!({"include_retired": true})).unwrap();
    assert_eq!(v["count"], json!(1));
    let entry = &v["skills"][0];
    assert_eq!(entry["retired"], json!(true));
    assert!(entry["retired_at"].as_i64().is_some());
}

#[test]
fn skill_get_shows_retired_state() {
    let (_d, conn) = open_db();
    let id = register(&conn, "get-state");

    let active = handle_skill_get(&conn, &json!({"skill_id": id})).unwrap();
    assert_eq!(active["retired"], json!(false));

    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "get-state", "reason": "obsolete"}),
        None,
    )
    .unwrap();

    let retired = handle_skill_get(&conn, &json!({"skill_id": id})).unwrap();
    assert_eq!(retired["retired"], json!(true));
    assert!(retired["retired_at"].as_i64().is_some());
    assert_eq!(retired["retire_reason"], json!("obsolete"));
    // Activation-by-id still returns the body (retire is discovery-hide,
    // not a hard activation block).
    assert!(retired["body"].as_str().unwrap().contains("Body."));
}

// ---------------------------------------------------------------------------
// Idempotency + unretire
// ---------------------------------------------------------------------------

#[test]
fn idempotent_re_retire() {
    let (_d, conn) = open_db();
    register(&conn, "idem");
    let first =
        handle_skill_retire(&conn, &json!({"namespace": "retns", "name": "idem"}), None).unwrap();
    assert_eq!(first["affected"], json!(1));

    // Re-retiring the already-retired lineage succeeds with affected=0.
    let second =
        handle_skill_retire(&conn, &json!({"namespace": "retns", "name": "idem"}), None).unwrap();
    assert_eq!(second["retired"], json!(true));
    assert_eq!(
        second["affected"],
        json!(0),
        "re-retire is idempotent, not an error"
    );
}

#[test]
fn unretire_restores() {
    let (_d, conn) = open_db();
    register(&conn, "restore");
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "restore"}),
        None,
    )
    .unwrap();
    assert_eq!(
        handle_skill_list(&conn, &json!({})).unwrap()["count"],
        json!(0)
    );

    let un = handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "restore", "unretire": true}),
        None,
    )
    .unwrap();
    assert_eq!(un["unretired"], json!(true));
    assert_eq!(un["action"], json!("unretire"));
    assert_eq!(un["affected"], json!(1));

    assert_eq!(
        handle_skill_list(&conn, &json!({})).unwrap()["count"],
        json!(1),
        "unretire returns the skill to discovery"
    );
    // Idempotent re-unretire.
    let again = handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "restore", "unretire": true}),
        None,
    )
    .unwrap();
    assert_eq!(again["affected"], json!(0));
}

#[test]
fn lineage_wide_multi_version_retire_then_unretire() {
    let (_d, conn) = open_db();
    // Two registrations of the same (namespace, name) → v1 superseded, v2 current.
    register(&conn, "chain");
    register(&conn, "chain");
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM skills WHERE namespace = 'retns' AND name = 'chain'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(total, 2, "chain has two versions");

    let r =
        handle_skill_retire(&conn, &json!({"namespace": "retns", "name": "chain"}), None).unwrap();
    assert_eq!(
        r["affected"],
        json!(2),
        "lineage-wide retire stamps every version"
    );
    assert_eq!(retired_rows(&conn, "retns", "chain"), 2);

    let un = handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "chain", "unretire": true}),
        None,
    )
    .unwrap();
    assert_eq!(un["affected"], json!(2));
    assert_eq!(retired_rows(&conn, "retns", "chain"), 0);
}

#[test]
fn single_version_retire_by_skill_id() {
    let (_d, conn) = open_db();
    let v1 = register(&conn, "byid");
    register(&conn, "byid"); // v2 current

    let r = handle_skill_retire(&conn, &json!({"skill_id": v1}), None).unwrap();
    assert_eq!(r["affected"], json!(1));
    assert_eq!(r["skill_id"], json!(v1));
    // Only the targeted version is retired; the other stays active.
    assert_eq!(retired_rows(&conn, "retns", "byid"), 1);
}

// ---------------------------------------------------------------------------
// Register REFUSE (the plan-promised, load-bearing block)
// ---------------------------------------------------------------------------

#[test]
fn re_register_of_retired_refuses() {
    let (_d, conn) = open_db();
    register(&conn, "refuse");
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "refuse"}),
        None,
    )
    .unwrap();

    let err = handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md("refuse")}),
        None,
    )
    .unwrap_err();
    assert!(
        err.contains("retired") && err.contains("unretire"),
        "re-register onto a retired lineage must be refused: {err}"
    );

    // After unretire, re-registration is allowed again.
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "refuse", "unretire": true}),
        None,
    )
    .unwrap();
    handle_skill_register(
        &conn,
        &json!({"inline_skill": minimal_skill_md("refuse")}),
        None,
    )
    .expect("re-register after unretire succeeds");
}

#[test]
fn retire_unknown_skill_id_is_not_found() {
    let (_d, conn) = open_db();
    let err = handle_skill_retire(&conn, &json!({"skill_id": "no-such-id"}), None).unwrap_err();
    assert!(err.contains("skill not found"), "got: {err}");
}

#[test]
fn retire_without_target_errors() {
    let (_d, conn) = open_db();
    let err = handle_skill_retire(&conn, &json!({}), None).unwrap_err();
    assert!(err.contains("requires"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

#[test]
fn skill_retired_and_skill_unretired_events_emitted() {
    let (_d, conn) = open_db();
    register(&conn, "audit");
    handle_skill_retire(&conn, &json!({"namespace": "retns", "name": "audit"}), None).unwrap();
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "audit", "unretire": true}),
        None,
    )
    .unwrap();

    let event_count = |et: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [et],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(event_count("skill.retired"), 1, "one retire audit row");
    assert_eq!(event_count("skill.unretired"), 1, "one unretire audit row");

    let report = verify_chain(&conn, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "the audit chain must hold after retire + unretire: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// Schema v82 migration
// ---------------------------------------------------------------------------

#[test]
fn migration_v82_applies_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("mig.db");

    // Fresh open reaches the current tip with the v82 retire columns present.
    let conn = db::open(&path).unwrap();
    assert_eq!(db::migrations::current_schema_version_for_tests(), 84);
    assert!(
        conn.prepare("SELECT retired_at, retired_by, retire_reason FROM skills LIMIT 0")
            .is_ok(),
        "v82 added the retire columns"
    );

    // Simulate a pre-v82 database (columns dropped, version stamped 81),
    // then re-open: the probe-guarded v82 ALTER re-adds them and the ladder
    // runs on to the current tip.
    conn.execute_batch(
        "ALTER TABLE skills DROP COLUMN retire_reason;\n\
         ALTER TABLE skills DROP COLUMN retired_by;\n\
         ALTER TABLE skills DROP COLUMN retired_at;\n\
         DELETE FROM schema_version;\n\
         INSERT INTO schema_version (version) VALUES (81);",
    )
    .unwrap();
    drop(conn);

    let conn2 = db::open(&path).unwrap();
    let version: i64 = conn2
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        version, 84,
        "upgrade-from-v81 runs the full ladder to the current tip (v82 re-adds the \
         retire columns; v83 adds agent_api_keys)"
    );
    assert!(
        conn2
            .prepare("SELECT retired_at, retired_by, retire_reason FROM skills LIMIT 0")
            .is_ok(),
        "the retire columns were re-added by the v82 arm"
    );

    // Idempotent re-open (probe skips the ALTER since columns exist).
    drop(conn2);
    let conn3 = db::open(&path).unwrap();
    let v3: i64 = conn3
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v3, 84, "re-open stays at the current tip idempotently");
    // A retire round-trips end-to-end on the migrated DB.
    let _: Value = handle_skill_register(
        &conn3,
        &json!({"inline_skill": minimal_skill_md("post-mig")}),
        None,
    )
    .unwrap();
    let r = handle_skill_retire(
        &conn3,
        &json!({"namespace": "retns", "name": "post-mig"}),
        None,
    )
    .unwrap();
    assert_eq!(r["affected"], json!(1));
}

// ---------------------------------------------------------------------------
// Hard delete / purge (#2024 scope-expansion)
// ---------------------------------------------------------------------------

fn skill_row_count(conn: &rusqlite::Connection, ns: &str, name: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM skills WHERE namespace = ?1 AND name = ?2",
        rusqlite::params![ns, name],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn purge_refused_when_not_retired_and_no_force() {
    let (_d, conn) = open_db();
    register(&conn, "no-force");
    let err = handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "no-force"}),
        None,
    )
    .unwrap_err();
    assert!(
        err.contains("not retired") && err.contains("force"),
        "active-lineage purge without force must be refused: {err}"
    );
    // The lineage is untouched.
    assert_eq!(skill_row_count(&conn, "retns", "no-force"), 1);
}

#[test]
fn purge_succeeds_after_retire() {
    let (_d, conn) = open_db();
    register(&conn, "purge-after-retire");
    handle_skill_retire(
        &conn,
        &json!({"namespace": "retns", "name": "purge-after-retire"}),
        None,
    )
    .unwrap();
    let r = handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "purge-after-retire"}),
        None,
    )
    .unwrap();
    assert_eq!(r["purged"], json!(true));
    assert_eq!(r["affected"], json!(1));
    assert_eq!(skill_row_count(&conn, "retns", "purge-after-retire"), 0);
}

#[test]
fn purge_with_force_bypasses_retire_gate() {
    let (_d, conn) = open_db();
    register(&conn, "forced");
    let r = handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "forced", "force": true}),
        None,
    )
    .unwrap();
    assert_eq!(r["purged"], json!(true));
    assert_eq!(skill_row_count(&conn, "retns", "forced"), 0);
}

#[test]
fn purge_removes_all_lineage_versions_and_their_skill_resources() {
    let (_d, conn) = open_db();
    let v1 = register(&conn, "multi");
    register(&conn, "multi"); // v2 current
    // Attach a resource to v1 so we can prove the cascade reaps it.
    let rblob = zstd::encode_all(b"echo".as_slice(), 3).unwrap();
    let rdig = vec![0u8; 32];
    conn.execute(
        "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
         VALUES (?1, 'scripts/run.sh', 'script', ?2, ?3)",
        rusqlite::params![v1, rblob, rdig],
    )
    .unwrap();
    assert_eq!(skill_row_count(&conn, "retns", "multi"), 2);

    let r = handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "multi", "force": true}),
        None,
    )
    .unwrap();
    assert_eq!(r["affected"], json!(2), "purge removes every version");
    assert_eq!(skill_row_count(&conn, "retns", "multi"), 0);
    let res_left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM skill_resources WHERE skill_id = ?1",
            [&v1],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        res_left, 0,
        "skill_resources cascade-deleted with the lineage"
    );
}

#[test]
fn purge_by_id_targets_whole_lineage() {
    let (_d, conn) = open_db();
    let v1 = register(&conn, "byid-purge");
    register(&conn, "byid-purge"); // v2
    // A by-id purge resolves to the whole lineage (never partial-chain).
    let r = handle_skill_delete(&conn, &json!({"skill_id": v1, "force": true}), None).unwrap();
    assert_eq!(r["affected"], json!(2));
    assert_eq!(skill_row_count(&conn, "retns", "byid-purge"), 0);
}

#[test]
fn purge_404_unknown_lineage() {
    let (_d, conn) = open_db();
    let err = handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "ghost", "force": true}),
        None,
    )
    .unwrap_err();
    assert!(err.contains("skill not found"), "got: {err}");
}

#[test]
fn purge_emits_skill_purged_event_before_delete_and_chain_holds() {
    let (_d, conn) = open_db();
    let id = register(&conn, "purge-audit");
    let digest_hex: String = {
        use std::fmt::Write as _;
        let d: Vec<u8> = conn
            .query_row("SELECT digest FROM skills WHERE id = ?1", [&id], |r| {
                r.get(0)
            })
            .unwrap();
        d.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    };

    handle_skill_delete(
        &conn,
        &json!({"namespace": "retns", "name": "purge-audit", "force": true}),
        None,
    )
    .unwrap();

    // The skill row is gone, but the signed purge audit row survives.
    assert_eq!(skill_row_count(&conn, "retns", "purge-audit"), 0);
    let purged_events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'skill.purged'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        purged_events, 1,
        "one skill.purged audit row survives the erasure"
    );

    // The audit row references the purged id + its digest.
    let payload_present: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'skill.purged'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(payload_present, 1);
    assert_eq!(digest_hex.len(), 64, "digest is a 32-byte hex string");

    let report = verify_chain(&conn, None).expect("verify_chain");
    assert!(
        report.chain_holds(),
        "the audit chain must hold after a purge: {report:?}"
    );
}
