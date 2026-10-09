// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4780 — the `ai-memory doctor` Reflection Health section reports a store
//! read FAULT as a Critical finding with the error text, never as an empty
//! histogram / zero refusals, and the storage helper
//! `doctor_reflection_depth_exceeded_count` is an error when `signed_events`
//! cannot be read (it ended in `.unwrap_or(0)`).
//!
//! Four reads built the section and each turned a fault into a healthy value
//! (`.unwrap_or_default()` / `.unwrap_or(0)`): an operator got a clean report
//! from a store the doctor could not read (fail-open diagnostic, rust-1.98
//! ERRORS-19). #4715 fixed the same class in the Governance section; this is
//! the same shape: `<fact>_error` with the error text, the value fact set to
//! `unreadable`, Critical, exit 2.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const SECTION: &str = "Reflection Health";
const EPOCH: &str = "1970-01-01T00:00:00Z";

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let keys = db.parent().expect("db in a tempdir").join("keys-4780");
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

fn is_critical(s: &Value) -> bool {
    s["severity"].as_str() == Some("critical")
}

/// A reflected row (`reflection_depth = 1`) whose `namespace` is a BLOB: the
/// text column read refuses it, so the depth distribution and the
/// per-namespace totals both fault while every other table is intact.
fn plant_unreadable_reflection(conn: &rusqlite::Connection) {
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at, \
         reflection_depth) VALUES ('r4780', 'long', X'DEADBEEF', 'reflection', 'reflection', \
         '2026-10-03T00:00:00Z', '2026-10-03T00:00:00Z', 1)",
        [],
    )
    .expect("plant unreadable reflection row");
}

#[test]
fn depth_exceeded_count_errors_when_signed_events_is_missing_4780() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    conn.execute_batch("ALTER TABLE signed_events RENAME TO signed_events_gone")
        .expect("rename away");
    assert!(
        ai_memory::db::doctor_reflection_depth_exceeded_count(&conn, EPOCH).is_err(),
        "a missing signed_events table must be a read fault, not 0 refusals"
    );
}

#[test]
fn reflection_probes_error_on_an_unreadable_row_4780() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    plant_unreadable_reflection(&conn);
    assert!(
        ai_memory::db::doctor_reflection_depth_distribution(&conn).is_err(),
        "an unreadable row must be an error, not an empty histogram"
    );
    assert!(
        ai_memory::db::doctor_reflection_totals_by_namespace(&conn).is_err(),
        "an unreadable row must be an error, not empty totals"
    );
}

#[test]
fn doctor_cli_reports_missing_signed_events_critical_not_zero_4780() {
    let (_t, db) = fresh_db();
    {
        let conn = ai_memory::db::open(&db).expect("open");
        conn.execute_batch("ALTER TABLE signed_events RENAME TO signed_events_gone")
            .expect("rename away");
    }
    let (report, code) = doctor_json(&db);
    let sec = section(&report, SECTION);
    assert!(is_critical(sec), "a read fault is Critical: {sec}");
    assert_eq!(
        fact(sec, "depth_limit_refusals_24h"),
        Some("unreadable"),
        "a read fault must not print a healthy-looking 0: {sec}"
    );
    assert!(
        fact(sec, "depth_limit_refusals_24h_error").is_some(),
        "{sec}"
    );
    assert_eq!(
        fact(sec, "depth_limit_refusals_all_time"),
        Some("unreadable"),
        "{sec}"
    );
    assert!(
        fact(sec, "depth_limit_refusals_all_time_error").is_some(),
        "{sec}"
    );
    assert_eq!(code, 2, "a Critical section exits 2");
}

#[test]
fn doctor_cli_reports_an_unreadable_reflection_row_critical_not_empty_4780() {
    let (_t, db) = fresh_db();
    {
        let conn = ai_memory::db::open(&db).expect("open");
        plant_unreadable_reflection(&conn);
    }
    let (report, code) = doctor_json(&db);
    let sec = section(&report, SECTION);
    assert!(is_critical(sec), "a read fault is Critical: {sec}");
    assert_eq!(
        fact(sec, "reflections_observed"),
        Some("unreadable"),
        "a read fault must not print `none`: {sec}"
    );
    assert!(
        fact(sec, "reflection_depth_distribution_error").is_some(),
        "{sec}"
    );
    assert_eq!(fact(sec, "reflection_totals"), Some("unreadable"), "{sec}");
    assert!(fact(sec, "reflection_totals_error").is_some(), "{sec}");
    let note = sec["note"].as_str().unwrap_or_default();
    assert!(note.contains("could not be read"), "{note}");
    assert_eq!(code, 2);
}

/// The healthy path is unchanged: a fresh store reports no reflections and
/// zero refusals at INFO.
#[test]
fn doctor_cli_reports_a_fresh_store_clean_4780() {
    let (_t, db) = fresh_db();
    let (report, _code) = doctor_json(&db);
    let sec = section(&report, SECTION);
    assert_eq!(sec["severity"].as_str(), Some("info"), "{sec}");
    assert_eq!(fact(sec, "reflections_observed"), Some("none"), "{sec}");
    assert_eq!(fact(sec, "depth_limit_refusals_24h"), Some("0"), "{sec}");
    assert_eq!(
        fact(sec, "depth_limit_refusals_all_time"),
        Some("0"),
        "{sec}"
    );
}
