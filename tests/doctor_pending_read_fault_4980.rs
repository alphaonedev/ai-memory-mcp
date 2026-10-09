// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4980 — `count_pending_actions_by_status` reports a read FAULT as an
//! error, never as `0` pending actions; `ai-memory doctor` renders that fault
//! as `pending_actions_total = unreadable` (Critical, exit 2) and
//! `memory_capabilities` fails instead of advertising
//! `approval.pending_requests = 0` over a store it could not read.
//!
//! The helper ended in `.unwrap_or(0)`: with `pending_actions` renamed away
//! the doctor printed `pending_actions_total 0` and capabilities printed
//! `pending_requests 0`, with no error anywhere (swallowed Result, rust-1.98
//! ERRORS-19 / ERRORS-02; never fail open).

use ai_memory::config::{FeatureTier, ResolvedModels};
use ai_memory::mcp::{CapabilitiesAccept, handle_capabilities_with_conn};
use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let keys = db.parent().expect("db in a tempdir").join("keys-4980");
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

fn rename_pending_actions_away(db: &std::path::Path) {
    let conn = ai_memory::db::open(db).expect("open");
    conn.execute_batch("ALTER TABLE pending_actions RENAME TO pending_actions_gone")
        .expect("rename away");
}

#[test]
fn count_pending_by_status_errors_when_the_table_is_missing_4980() {
    let (_t, db) = fresh_db();
    rename_pending_actions_away(&db);
    let conn = ai_memory::db::open(&db).expect("open");
    assert!(
        ai_memory::db::count_pending_actions_by_status(&conn, "pending").is_err(),
        "a missing pending_actions table must be a read fault, not 0"
    );
}

#[test]
fn doctor_cli_reports_an_unreadable_pending_count_critical_4980() {
    let (_t, db) = fresh_db();
    rename_pending_actions_away(&db);
    let (report, code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert_eq!(gov["severity"].as_str(), Some("critical"), "{gov}");
    assert_eq!(
        fact(gov, "pending_actions_total"),
        Some("unreadable"),
        "a read fault must not print a healthy-looking 0: {gov}"
    );
    assert!(
        fact(gov, "pending_actions_total_error").is_some(),
        "the fault is surfaced: {gov}"
    );
    assert_eq!(code, 2, "a Critical section exits 2");
}

/// The healthy path is unchanged: an empty queue prints `0`.
#[test]
fn doctor_cli_prints_zero_for_an_empty_readable_queue_4980() {
    let (_t, db) = fresh_db();
    let (report, _code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert_eq!(fact(gov, "pending_actions_total"), Some("0"), "{gov}");
    assert!(fact(gov, "pending_actions_total_error").is_none(), "{gov}");
}

/// `memory_capabilities` must not advertise `pending_requests = 0` over a
/// store whose queue depth could not be read.
#[test]
fn capabilities_fail_when_the_pending_count_cannot_be_read_4980() {
    let (_t, db) = fresh_db();
    rename_pending_actions_away(&db);
    let conn = ai_memory::db::open(&db).expect("open");
    let tier = FeatureTier::Keyword.config();
    let res = handle_capabilities_with_conn(
        &tier,
        &ResolvedModels::from_tier_preset(&tier),
        None,
        false,
        Some(&conn),
        CapabilitiesAccept::V2,
    );
    let err = res.expect_err("a pending-count read fault must fail the capabilities call");
    assert!(
        err.contains("pending"),
        "the error names what could not be read: {err}"
    );
}
