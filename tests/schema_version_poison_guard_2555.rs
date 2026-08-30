// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2555 — the `schema_version` POISON guard + in-product repair.
//!
//! `schema_version` was an unconstrained integer, so
//! `INSERT INTO schema_version VALUES (2147483647)` was a permanent, fleet-wide
//! kill-switch: it read back through `COALESCE(MAX(version), 0)`, tripped the
//! #2445 schema-ahead DENY on every daemon, and had NO in-product recovery (the
//! DENY's remediations cannot recover a fabricated version). This suite pins:
//!
//! * a POISONED far-ahead stamp yields the NEW typed error (not the plain
//!   downgrade DENY) and names the repair verb;
//! * the bounding CHECK rejects an out-of-band INSERT;
//! * the repair verb restamps SNAPSHOT-FIRST and restores boot;
//! * a normal one-ahead downgrade still yields the existing downgrade DENY
//!   (no regression).

use ai_memory::storage::schema_guard::{schema_ahead_of, schema_version_poisoned};
use std::path::{Path, PathBuf};

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

fn max_ceiling() -> i64 {
    ai_memory::storage::migrations::max_schema_version()
}

/// A real, fully-migrated database with one durable row.
fn fresh_db_with_row(dir: &Path) -> PathBuf {
    let path = dir.join("ai-memory.db");
    let conn = ai_memory::db::open(&path).expect("fresh open must succeed");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
         confidence, source, metadata, access_count, created_at, updated_at) \
         VALUES ('m-2555', 'long', 'ns', 't', 'durable text', '[]', 5, 1.0, 'api', \
         '{}', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        [],
    )
    .expect("seed row");
    path
}

/// Simulate a LEGACY (pre-CHECK) database whose `schema_version` ledger was
/// POISONED to `value`. The migrated table now carries the bounding CHECK, so a
/// poison INSERT would be refused — which is exactly the point — so the poison
/// is planted by first replacing the table with the historical CHECK-less
/// shape, then writing the out-of-band stamp.
fn db_poisoned_at(dir: &Path, value: i64) -> PathBuf {
    let path = fresh_db_with_row(dir);
    let conn = ai_memory::db::open_unmigrated(&path).expect("unmigrated open");
    conn.execute_batch(
        "DROP TABLE schema_version; \
         CREATE TABLE schema_version (version INTEGER NOT NULL);",
    )
    .expect("recreate legacy check-less schema_version");
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![value],
    )
    .expect("plant the poison stamp");
    path
}

fn memory_count(path: &Path) -> i64 {
    let conn = ai_memory::db::open_unmigrated(path).expect("count open");
    conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count memories")
}

/// A poisoned far-ahead stamp yields the NEW typed poison error (NOT the plain
/// #2445 downgrade DENY) and its message names the repair verb.
#[test]
fn poisoned_stamp_yields_poison_error_that_names_the_repair_verb_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_poisoned_at(dir.path(), 2_147_483_647); // i32::MAX

    let err = ai_memory::db::open(&path).expect_err("a poisoned ledger must refuse to open");

    let poisoned = schema_version_poisoned(&err)
        .unwrap_or_else(|| panic!("must be the typed SchemaVersionPoisoned verdict, got: {err:#}"));
    assert_eq!(poisoned.observed, 2_147_483_647);
    assert_eq!(poisoned.max, max_ceiling());

    // It is NOT the plain downgrade DENY (whose remedy — "run a newer binary" —
    // cannot recover a fabricated version).
    assert!(
        schema_ahead_of(&err).is_none(),
        "a poisoned stamp must not classify as an ordinary schema-ahead downgrade"
    );

    // The remediation names the repair verb the DENY path lacks.
    let msg = err.to_string();
    assert!(
        msg.contains("--repair-schema-version"),
        "must name the repair verb: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("poison"),
        "must name the poison state: {msg}"
    );
}

/// `doctor` reports a poisoned ledger BY NAME (Storage section critical, naming
/// the repair verb) rather than flattening it into "could not open database".
#[test]
fn doctor_reports_poisoned_ledger_by_name_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_poisoned_at(dir.path(), 2_147_483_647);

    let mut so: Vec<u8> = Vec::new();
    let mut se: Vec<u8> = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let args = ai_memory::cli::doctor::DoctorArgs {
        json: true,
        ..Default::default()
    };
    // A poisoned database yields a Critical report (exit 2), not a panic.
    let code = ai_memory::cli::doctor::run(&path, &args, &mut out).expect("doctor runs");
    assert_eq!(code, 2, "a poisoned ledger is a Critical finding");
    let report = String::from_utf8_lossy(&so);
    assert!(
        report.contains("poisoned"),
        "doctor names the poison state: {report}"
    );
    assert!(
        report.contains("--repair-schema-version"),
        "doctor names the repair verb: {report}"
    );
}

/// The bounding CHECK rejects an out-of-band INSERT on a migrated database.
#[test]
fn check_rejects_out_of_band_insert_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fresh_db_with_row(dir.path());

    let conn = ai_memory::db::open_unmigrated(&path).expect("unmigrated open");
    let err = conn
        .execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![max_ceiling() + 1],
        )
        .expect_err("an out-of-band stamp must be rejected by the CHECK");
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "expected a CHECK-constraint failure, got: {err}"
    );

    // A value AT the ceiling and a normal in-band value are both accepted.
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![max_ceiling()],
    )
    .expect("a value at the ceiling is in band");
}

/// The repair verb restamps SNAPSHOT-FIRST and restores boot, preserving the
/// durable rows.
#[test]
fn repair_verb_restamps_snapshot_first_and_restores_boot_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_poisoned_at(dir.path(), 2_147_483_647);

    // Precondition: the poisoned database refuses to open.
    assert!(
        ai_memory::db::open(&path).is_err(),
        "the poisoned database must refuse before repair"
    );

    // Repair: restamp to the tip this binary understands.
    let mut so: Vec<u8> = Vec::new();
    let mut se: Vec<u8> = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let code = ai_memory::cli::doctor::run_repair_schema_version(&path, tip(), &mut out)
        .expect("repair verb runs");
    assert_eq!(
        code,
        0,
        "repair must succeed; stderr={}",
        String::from_utf8_lossy(&se)
    );

    // SNAPSHOT-FIRST: a sibling backup was written before the restamp.
    let snapshots: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .contains(".pre-repair-schema-version-")
        })
        .collect();
    assert_eq!(
        snapshots.len(),
        1,
        "exactly one snapshot-first backup must exist"
    );

    // Boot is restored and the durable row survived.
    let reopened = ai_memory::db::open(&path).expect("repaired database must open");
    let stamp: i64 = reopened
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .expect("read stamp");
    assert_eq!(stamp, tip(), "the stamp is repaired to the tip");
    assert_eq!(
        memory_count(&path),
        1,
        "the durable row survived the repair"
    );
}

/// The repair verb refuses an out-of-range target rather than write a fresh bad
/// stamp (fail closed).
#[test]
fn repair_verb_refuses_out_of_range_target_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = db_poisoned_at(dir.path(), 2_147_483_647);

    for bad in [0, -1, tip() + 1, max_ceiling() + 1] {
        let mut so: Vec<u8> = Vec::new();
        let mut se: Vec<u8> = Vec::new();
        let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
        let code = ai_memory::cli::doctor::run_repair_schema_version(&path, bad, &mut out)
            .expect("repair verb runs");
        assert_eq!(code, 2, "target {bad} must be refused as out of range");
    }
    // The poison is untouched — still refuses to open.
    assert!(
        ai_memory::db::open(&path).is_err(),
        "a refused repair must leave the ledger exactly as found"
    );
}

/// A normal one-ahead downgrade still yields the existing downgrade DENY (NOT
/// the poison error) — no regression.
#[test]
fn normal_one_ahead_downgrade_still_yields_downgrade_deny_2555() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fresh_db_with_row(dir.path());
    // Stamp exactly one ahead of this binary — a legitimate downgrade, well
    // inside the ceiling.
    {
        let conn = ai_memory::db::open_unmigrated(&path).expect("stamp open");
        conn.execute("DELETE FROM schema_version", []).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![tip() + 1],
        )
        .expect("stamp one ahead (in band)");
    }

    let err = ai_memory::db::open(&path).expect_err("a newer database must refuse");
    assert!(
        schema_ahead_of(&err).is_some(),
        "one-ahead must classify as the ordinary schema-ahead downgrade: {err:#}"
    );
    assert!(
        schema_version_poisoned(&err).is_none(),
        "one-ahead must NOT classify as poison"
    );
    // The downgrade DENY keeps its own guidance ("run a newer binary").
    let msg = err.to_string();
    assert!(
        msg.contains("AHEAD"),
        "downgrade DENY names the schema-ahead state: {msg}"
    );
}
