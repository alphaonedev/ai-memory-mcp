// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5009 — with the strict-admission posture engaged
//! (`AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE`) under `mode=enforce`,
//! `ai-memory doctor` keeps the blast-radius note when the governance-coverage
//! read FAULTS: the refusal posture is live and its blast radius is UNKNOWN,
//! which is exactly the state the note exists for.
//!
//! The Governance section collapsed a coverage fault (`None`) and a coverage
//! of zero into the same `without = 0`, so the note that says "writes into
//! them are refused" was silent on the fault path. Severity is Critical from
//! the fault either way, so these cells assert on the NOTE TEXT, not severity.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const STRICT_ENV: &str = ai_memory::governance::ENV_REQUIRE_GOVERNED_NAMESPACE;

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let keys = db.parent().expect("db in a tempdir").join("keys-5009");
    std::fs::create_dir_all(&keys).expect("key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_PERMISSIONS_MODE", "enforce")
        .args(["--db", db.to_str().expect("utf8 path")]);
    cmd
}

fn fresh_db() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("ai-memory.db");
    ai_memory(&db).args(["stats"]).assert().success();
    (tmp, db)
}

/// `doctor --json` with the strict-admission posture on or off.
fn doctor_json(db: &std::path::Path, strict: bool) -> Value {
    let mut cmd = ai_memory(db);
    if strict {
        cmd.env(STRICT_ENV, "1");
    } else {
        cmd.env_remove(STRICT_ENV);
    }
    let out = cmd.args(["doctor", "--json"]).output().expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse: {e}\n{stdout}"))
}

fn governance_note(report: &Value) -> String {
    report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"].as_str() == Some("Governance"))
        .unwrap_or_else(|| panic!("no Governance section in {report}"))["note"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Plants a namespace standard whose memory carries `metadata` verbatim.
fn plant_standard_with_metadata(db: &std::path::Path, metadata: &str) {
    let conn = ai_memory::db::open(db).expect("open");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at, metadata) \
         VALUES ('std5009', 'long', 'ns5009', 'standard', 'standard', \
                 '2026-10-03T00:00:00Z', '2026-10-03T00:00:00Z', ?1)",
        rusqlite::params![metadata],
    )
    .expect("plant standard memory");
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at) \
         VALUES ('ns5009', 'std5009', '2026-10-03T00:00:00Z')",
        [],
    )
    .expect("bind the standard");
}

const STRICT_NOTE: &str = "strict admission posture is engaged";

/// The defect: a coverage FAULT under the engaged posture must still carry
/// the blast-radius note, saying the affected count could not be read.
#[test]
fn doctor_keeps_the_strict_admission_note_when_coverage_is_unreadable_5009() {
    let (_t, db) = fresh_db();
    plant_standard_with_metadata(&db, "{not json");
    let note = governance_note(&doctor_json(&db, true));
    assert!(
        note.contains(STRICT_NOTE),
        "the engaged posture must be named on the fault path: {note}"
    );
    assert!(
        note.contains("could not be read"),
        "the note says the blast radius cannot be sized: {note}"
    );
    assert!(
        note.contains("refused"),
        "the note names the consequence (writes are refused): {note}"
    );
}

/// A coverage fault with the posture OFF leaves the note free of the
/// strict-admission sentence (the new arm cannot fire on a posture that is
/// not engaged).
#[test]
fn doctor_stays_silent_on_a_coverage_fault_when_strict_admission_is_off_5009() {
    let (_t, db) = fresh_db();
    plant_standard_with_metadata(&db, "{not json");
    let note = governance_note(&doctor_json(&db, false));
    assert!(
        !note.contains(STRICT_NOTE),
        "the posture is off, so the strict-admission note must not fire: {note}"
    );
}

/// The readable-and-nonzero path is unchanged, text included.
#[test]
fn doctor_sizes_the_strict_admission_note_when_coverage_is_readable_5009() {
    let (_t, db) = fresh_db();
    plant_standard_with_metadata(&db, "{}");
    let note = governance_note(&doctor_json(&db, true));
    assert!(
        note.contains(
            "strict admission posture is engaged under mode=enforce and 1 namespace(s) \
                       resolve no governance policy — writes into them are refused"
        ),
        "the sized note is byte-identical: {note}"
    );
}

/// Readable coverage of zero stays silent.
#[test]
fn doctor_stays_silent_when_every_namespace_is_governed_5009() {
    let (_t, db) = fresh_db();
    plant_standard_with_metadata(&db, r#"{"governance": {"write": "any"}}"#);
    let note = governance_note(&doctor_json(&db, true));
    assert!(!note.contains(STRICT_NOTE), "{note}");
}
