// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2444 — `ai-memory backup` must FAIL CLOSED.
//!
//! # The defect these tests pin
//!
//! Before #2444, `run_backup` took the `--db` path unconditionally and handed
//! it to `db::open`, which **creates the file when absent**
//! (`src/storage/connection.rs`) and then runs the bootstrap schema + the whole
//! migration ladder on it. So on a Postgres-backed deployment the product's own
//! backup verb:
//!
//!   1. created an EMPTY SQLite database at the placeholder `--db` path,
//!   2. `VACUUM INTO`-ed it to a timestamped snapshot,
//!   3. wrote a **valid** sha256 manifest over those bytes,
//!   4. rotated `--keep` against it, and
//!   5. **exited 0**.
//!
//! Every signal the operator had said the backup succeeded. The corpus lived in
//! Postgres and was never captured; the discovery moment was the DR restore —
//! the one moment it cannot be fixed. A data-loss control that reports success
//! is the exact class this release must not ship.
//!
//! # Why these tests drive the BINARY, not the library
//!
//! R-203 requires the regression to FAIL against the parent commit and PASS
//! after. These tests therefore reference **no** new struct field: they spawn
//! the real `ai-memory` binary and configure the store through the
//! `AI_MEMORY_STORE_URL` env channel that #1927 already shipped (and that
//! `serve` already honours). The identical source compiles and runs against the
//! parent commit `47939793`, where it fails — the pre-fix binary exits 0 and
//! leaves a snapshot + a valid manifest behind.
//!
//! Spawning a subprocess also keeps every `AI_MEMORY_*` mutation out of the
//! test process, so nothing here races the shared `config::test_env_lock()`
//! discipline (#2127 / #2146).

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// A Postgres DSN carrying a password, so the refusal path is also asserted to
/// REDACT the credential rather than echo it (#1579 A3).
const PG_STORE_URL: &str = "postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory";

/// The literal secret inside [`PG_STORE_URL`]; must never appear in output.
const PG_PASSWORD: &str = "hunter2";

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Count `ai-memory-*.db` snapshots and `*.manifest.json` sidecars under `dir`.
/// A missing directory counts as zero of each (the fail-closed path should not
/// even create the backup directory's contents).
fn artifact_counts(dir: &Path) -> (usize, usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut snapshots = 0;
    let mut manifests = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("ai-memory-") && name.ends_with(".db") {
            snapshots += 1;
        }
        if name.ends_with(".manifest.json") {
            manifests += 1;
        }
    }
    (snapshots, manifests)
}

/// THE #2444 REGRESSION. A Postgres-configured deployment running the product's
/// own `backup` verb must ERROR and leave NO artifact behind.
///
/// Against the parent commit this test fails on every assertion below: the
/// command exits 0, `placeholder.db` is created, and a snapshot + a valid
/// manifest land in the backup directory.
#[test]
fn backup_on_a_postgres_store_refuses_and_writes_no_artifact_2444() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("placeholder.db");
    let backups = tmp.path().join("backups");

    let assert = ai_memory(&db)
        .env("AI_MEMORY_STORE_URL", PG_STORE_URL)
        .args(["backup", "--to", backups.to_str().expect("utf-8")])
        .assert()
        .failure();

    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The refusal must name the supported path so the operator is not left
    // guessing what to run instead.
    assert!(
        stderr.contains("pg_dump"),
        "refusal must name the supported Postgres backup path; stderr was: {stderr}"
    );
    // #1579 A3 — a mistyped/echoed store URL must never carry the credential.
    assert!(
        !stderr.contains(PG_PASSWORD),
        "refusal leaked the DSN password; stderr was: {stderr}"
    );

    // FAIL CLOSED: no artifact, and specifically no checksum written over
    // content that was never read.
    let (snapshots, manifests) = artifact_counts(&backups);
    assert_eq!(
        snapshots, 0,
        "a Postgres-store backup must not produce a snapshot"
    );
    assert_eq!(
        manifests, 0,
        "a Postgres-store backup must not produce a manifest — a valid checksum \
         over an empty artifact is the #2444 defect"
    );

    // And the placeholder SQLite database must not have been conjured into
    // existence as a side effect of taking a backup.
    assert!(
        !db.exists(),
        "backup must not CREATE the source database it claims to capture"
    );
}

/// The same fail-closed rule with no store URL at all: `backup` pointed at a
/// path where no database exists must refuse rather than create one and
/// snapshot the empty result.
///
/// Against the parent commit this fails: the command exits 0 with a snapshot +
/// manifest, having created the database itself.
#[test]
fn backup_refuses_to_create_and_snapshot_a_missing_database_2444() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("never-created.db");
    let backups = tmp.path().join("backups");

    let assert = ai_memory(&db)
        .args(["backup", "--to", backups.to_str().expect("utf-8")])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("refusing to create"),
        "refusal must explain that it will not create the source DB; stderr was: {stderr}"
    );

    let (snapshots, manifests) = artifact_counts(&backups);
    assert_eq!(snapshots, 0, "no snapshot of a database that does not exist");
    assert_eq!(manifests, 0, "no manifest over content that was never read");
    assert!(!db.exists(), "backup must not create the source database");
}

/// The restore half of the same defect: restoring a SQLite snapshot onto a
/// Postgres-configured deployment used to copy the file to the placeholder
/// path, print `Restored`, and exit 0 while the real corpus was untouched —
/// false assurance at the exact moment of a disaster rehearsal.
///
/// Against the parent commit this fails: the restore succeeds.
#[test]
fn restore_on_a_postgres_store_refuses_2444() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("live.db");
    let backups = tmp.path().join("backups");

    // A genuine SQLite deployment with one memory, and a genuine snapshot of it.
    ai_memory(&db)
        .args(["store", "-T", "pinned-2444", "-c", "corpus content"])
        .assert()
        .success();
    ai_memory(&db)
        .args(["backup", "--to", backups.to_str().expect("utf-8")])
        .assert()
        .success();

    let before = std::fs::metadata(&db).expect("live db").len();

    // Now the operator's deployment is Postgres-backed. Restoring a SQLite
    // snapshot cannot restore that corpus, so it must refuse.
    let assert = ai_memory(&db)
        .env("AI_MEMORY_STORE_URL", PG_STORE_URL)
        .args(["restore", "--from", backups.to_str().expect("utf-8")])
        .assert()
        .failure();

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("Restored"),
        "a refused restore must never report success; stdout was: {stdout}"
    );
    assert!(
        stderr.contains("pg_dump"),
        "refusal must name the supported Postgres path; stderr was: {stderr}"
    );
    assert!(
        !stderr.contains(PG_PASSWORD),
        "refusal leaked the DSN password; stderr was: {stderr}"
    );

    // Nothing was moved aside and nothing was overwritten.
    assert_eq!(
        std::fs::metadata(&db).expect("live db still there").len(),
        before,
        "a refused restore must not touch the live database"
    );
    let moved_aside = std::fs::read_dir(tmp.path())
        .expect("tmpdir")
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("pre-restore-"));
    assert!(
        !moved_aside,
        "a refused restore must not move the live database aside"
    );
}

/// Positive control: on a real SQLite deployment `backup` still works, and the
/// manifest is now self-describing (#2444 records backend / schema_version /
/// memory_count so the artifact can be judged without opening it).
#[test]
fn backup_still_succeeds_on_a_real_sqlite_deployment_2444() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("live.db");
    let backups = tmp.path().join("backups");

    ai_memory(&db)
        .args(["store", "-T", "positive-control", "-c", "real content"])
        .assert()
        .success();

    let assert = ai_memory(&db)
        .args([
            "--json",
            "backup",
            "--to",
            backups.to_str().expect("utf-8"),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    let manifest: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("manifest JSON on stdout");
    assert_eq!(manifest["backend"].as_str(), Some("sqlite"));
    assert!(
        manifest["schema_version"].as_i64().unwrap_or(0) > 0,
        "manifest must record the captured schema version: {manifest}"
    );
    assert_eq!(
        manifest["memory_count"].as_i64(),
        Some(1),
        "manifest must record what was actually captured: {manifest}"
    );

    let (snapshots, manifests) = artifact_counts(&backups);
    assert_eq!(snapshots, 1);
    assert_eq!(manifests, 1);
}
