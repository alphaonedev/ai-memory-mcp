// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4982 — `doctor_oldest_pending_age_secs` turns a read FAULT, and a pending
//! row whose `requested_at` does not parse, into an error — never into
//! `Ok(None)` ("queue empty"). `ai-memory doctor` renders either as
//! `oldest_pending_age_secs = unreadable` (Critical, exit 2) beside the
//! `pending_query_error` fact.
//!
//! The helper `.ok()`'d its `query_row`, so every error (not only
//! `QueryReturnedNoRows`) was `Ok(None)`, and an unparseable timestamp was
//! `Ok(None)` too; the doctor printed `queue_empty` and hid the 24h-backlog
//! Critical (swallowed Result, rust-1.98 ERRORS-19 / ERRORS-02).

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let keys = db.parent().expect("db in a tempdir").join("keys-4982");
    std::fs::create_dir_all(&keys).expect("key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .args(["--db", db.to_str().expect("utf8 path")]);
    cmd
}

fn fresh_db() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("ai-memory.db");
    ai_memory(&db).args(["stats"]).assert().success();
    (tmp, db)
}

fn doctor_json(db: &std::path::Path) -> (Value, i32) {
    let out = ai_memory(db)
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse: {e}\n{stdout}"));
    (v, out.status.code().unwrap_or(-1))
}

fn section<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no {name} section in {report}"))
}

fn fact<'a>(section: &'a Value, key: &str) -> Option<&'a str> {
    section["facts"]
        .as_array()?
        .iter()
        .find(|f| f[0].as_str() == Some(key))
        .and_then(|f| f[1].as_str())
}

/// A `pending` row whose `requested_at` is `ts` (the writer stamps RFC 3339;
/// a raw row can carry anything).
fn plant_pending(conn: &rusqlite::Connection, id: &str, ts: &str) {
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by, \
         requested_at, status) VALUES (?1, 'insert', 'ns4982', '{}', 'ai:test-4982', ?2, 'pending')",
        rusqlite::params![id, ts],
    )
    .expect("plant pending row");
}

#[test]
fn oldest_pending_age_errors_when_the_table_is_missing_4982() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    conn.execute_batch("ALTER TABLE pending_actions RENAME TO pending_actions_gone")
        .expect("rename away");
    assert!(
        ai_memory::db::doctor_oldest_pending_age_secs(&conn).is_err(),
        "a missing pending_actions table must be a read fault, not an empty queue"
    );
}

#[test]
fn oldest_pending_age_errors_on_an_unparseable_timestamp_4982() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    plant_pending(&conn, "p4982-garbage", "garbage");
    let err = ai_memory::db::doctor_oldest_pending_age_secs(&conn)
        .expect_err("an unparseable requested_at must be a read fault, not an empty queue");
    assert!(
        format!("{err:#}").contains("garbage"),
        "the error names the row's text: {err:#}"
    );
}

/// The healthy paths are unchanged: an empty queue is `Ok(None)`, a parseable
/// row is its age.
#[test]
fn oldest_pending_age_reports_empty_and_aged_queues_4982() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    assert_eq!(
        ai_memory::db::doctor_oldest_pending_age_secs(&conn).expect("empty queue"),
        None
    );
    plant_pending(&conn, "p4982-old", "2026-01-01T00:00:00Z");
    let age = ai_memory::db::doctor_oldest_pending_age_secs(&conn)
        .expect("aged queue")
        .expect("one pending row");
    assert!(age > ai_memory::SECS_PER_DAY, "age {age}s");
}

#[test]
fn doctor_cli_reports_an_unparseable_pending_timestamp_critical_4982() {
    let (_t, db) = fresh_db();
    {
        let conn = ai_memory::db::open(&db).expect("open");
        plant_pending(&conn, "p4982-garbage", "garbage");
    }
    let (report, code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert_eq!(gov["severity"].as_str(), Some("critical"), "{gov}");
    assert_eq!(
        fact(gov, "oldest_pending_age_secs"),
        Some("unreadable"),
        "a read fault must not print queue_empty: {gov}"
    );
    assert!(
        fact(gov, "pending_query_error").is_some_and(|e| e.contains("garbage")),
        "the fault names the row's text: {gov}"
    );
    assert_eq!(code, 2, "a Critical section exits 2");
}

#[test]
fn doctor_cli_reports_a_missing_pending_table_unreadable_4982() {
    let (_t, db) = fresh_db();
    {
        let conn = ai_memory::db::open(&db).expect("open");
        conn.execute_batch("ALTER TABLE pending_actions RENAME TO pending_actions_gone")
            .expect("rename away");
    }
    let (report, code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert_eq!(gov["severity"].as_str(), Some("critical"), "{gov}");
    assert_eq!(
        fact(gov, "oldest_pending_age_secs"),
        Some("unreadable"),
        "{gov}"
    );
    assert!(fact(gov, "pending_query_error").is_some(), "{gov}");
    assert_eq!(code, 2);
}
