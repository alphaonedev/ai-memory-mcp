// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4323 — `ai-memory backup` must still produce a snapshot when the
//! `schema_version` relation is ABSENT on a populated store.
//!
//! The #2564 zeroed-stamp refusal tells the operator that `backup` continues
//! to operate and to snapshot first. The `DELETE FROM schema_version` shape
//! always honoured that; the `DROP TABLE schema_version` shape did not,
//! because the manifest's schema version was read with a bare
//! `SELECT COALESCE(MAX(version), 0) FROM schema_version`, which fails with
//! `no such table` when the relation itself is gone. Both shapes are pinned
//! here: each must exit 0, write exactly one snapshot + one manifest, and
//! record the destroyed stamp as an explicit `schema_version: 0`.

use std::path::Path;

use assert_cmd::Command;

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Snapshot `.db` files and manifest sidecars under `dir`.
fn artifacts(dir: &Path) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let mut snaps = Vec::new();
    let mut manifests = Vec::new();
    for e in std::fs::read_dir(dir).expect("read backup dir") {
        let p = e.expect("dir entry").path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if name.ends_with(".manifest.json") {
            manifests.push(p);
        } else if name.starts_with("ai-memory-")
            && p.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
        {
            snaps.push(p);
        }
    }
    (snaps, manifests)
}

/// Build a populated store at the current schema, then destroy its stamp
/// with `destroy` (run on a raw connection, bypassing every funnel).
fn populated_store_with_destroyed_stamp(dir: &Path, destroy: &str) -> std::path::PathBuf {
    let db = dir.join("memories.db");
    ai_memory(&db)
        .args(["store", "-T", "durable-4323", "-c", "durable text 4323"])
        .assert()
        .success();
    let conn = rusqlite::Connection::open(&db).expect("raw open");
    conn.execute_batch(destroy).expect("destroy the stamp");
    drop(conn);
    db
}

fn assert_backup_survives_destroyed_stamp(destroy: &str) {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-4323-")
        .tempdir()
        .expect("scratch dir");
    let db = populated_store_with_destroyed_stamp(dir.path(), destroy);
    let backups = dir.path().join("backups");

    let output = ai_memory(&db)
        .args(["backup", "--to", backups.to_str().expect("utf-8")])
        .output()
        .expect("run backup");
    assert!(
        output.status.success(),
        "backup must succeed after `{destroy}` (the #2564 refusal promises it); \
         status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let (snaps, manifests) = artifacts(&backups);
    assert_eq!(snaps.len(), 1, "exactly one snapshot after `{destroy}`");
    assert_eq!(manifests.len(), 1, "exactly one manifest after `{destroy}`");

    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifests[0]).expect("read manifest"))
            .expect("manifest json");
    assert_eq!(
        manifest["schema_version"],
        serde_json::json!(0),
        "a destroyed stamp is recorded as an explicit zeroed schema version"
    );
    assert_eq!(manifest["memory_count"], serde_json::json!(1));

    // The snapshot carries the durable text.
    let snap = rusqlite::Connection::open(&snaps[0]).expect("open snapshot");
    let content: String = snap
        .query_row(
            "SELECT content FROM memories WHERE title = 'durable-4323'",
            [],
            |r| r.get(0),
        )
        .expect("durable row in snapshot");
    assert_eq!(content, "durable text 4323");
}

/// The shape #4323 reports: the relation itself is gone.
#[test]
fn backup_succeeds_when_schema_version_relation_is_dropped_4323() {
    assert_backup_survives_destroyed_stamp("DROP TABLE schema_version;");
}

/// The sibling shape that already worked; pinned so the two cannot diverge.
#[test]
fn backup_succeeds_when_schema_version_rows_are_deleted_4323() {
    assert_backup_survives_destroyed_stamp("DELETE FROM schema_version;");
}
