// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2565 — the pre-migration snapshot must be restorable through the VERIFIED
//! `restore` path, and `--skip-verify` must waive the sha256, not the
//! cross-backend compatibility refusal.
//!
//! `snapshot_before_migration` wrote a bare `VACUUM INTO` file with no
//! manifest, so the rollback `docs/production-deployment.md` documents was
//! executable only via `restore --skip-verify` — and the #2444 cross-backend
//! refusal lived inside the skipped block, so that flag silently waived it.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use sha2::Digest;

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

fn ai_memory(db: &Path, key_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("AI_MEMORY_KEY_DIR", key_dir)
        .env_remove("AI_MEMORY_OPERATOR_PUBKEY")
        .env_remove("AI_MEMORY_SECURITY_PROFILE")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// A populated database one rung behind the tip, then opened by this binary
/// so the ladder writes its pre-migration snapshot. Returns the snapshot.
fn upgrade_with_snapshot(dir: &Path) -> PathBuf {
    let path = dir.join("ai-memory.db");
    {
        let conn = ai_memory::db::open(&path).expect("fresh open");
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, metadata, access_count, created_at, updated_at) \
             VALUES ('m-2565', 'long', 'ns', 't', 'durable text', '[]', 5, 1.0, 'api', \
             '{}', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("seed row");
    }
    {
        let conn = ai_memory::db::open_unmigrated(&path).expect("stamp open");
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear stamp");
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![tip() - 1],
        )
        .expect("rewind stamp");
    }
    drop(ai_memory::db::open(&path).expect("upgrade open"));
    let infix = ai_memory::storage::pre_migration_backup_infix_for_tests();
    let snaps: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(infix) && !n.ends_with(".manifest.json"))
        })
        .collect();
    match snaps.as_slice() {
        [snap] => snap.clone(),
        other => panic!("expected exactly one pre-migration snapshot, found {other:?}"),
    }
}

fn manifest_beside(snapshot: &Path) -> PathBuf {
    let stem = snapshot
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("snapshot stem");
    snapshot.with_file_name(format!("{stem}.manifest.json"))
}

#[test]
fn pre_migration_snapshot_carries_a_sibling_manifest_2565() {
    let dir = tempfile::tempdir().expect("tempdir");
    let snap = upgrade_with_snapshot(dir.path());
    let manifest_path = manifest_beside(&snap);
    let text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("manifest {} must exist: {e}", manifest_path.display()));
    let m: serde_json::Value = serde_json::from_str(&text).expect("manifest is JSON");
    let bytes = std::fs::read(&snap).expect("read snapshot");
    let file_name = snap.file_name().and_then(|n| n.to_str()).expect("name");
    assert_eq!(m["snapshot"], file_name);
    assert_eq!(m["sha256"], format!("{:x}", sha2::Sha256::digest(&bytes)));
    assert_eq!(
        m["bytes"],
        u64::try_from(bytes.len()).expect("len fits u64")
    );
    assert_eq!(m["backend"], "sqlite");
    assert_eq!(m["schema_version"], tip() - 1);
}

#[test]
fn pre_migration_snapshot_restores_through_the_verified_path_2565() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = tempfile::tempdir().expect("key dir");
    let snap = upgrade_with_snapshot(dir.path());
    let target = dir.path().join("restored.db");
    drop(ai_memory::db::open(&target).expect("target db"));
    // No --skip-verify: the sha256 in the sibling manifest is checked.
    ai_memory(&target, keys.path())
        .args(["restore", "--from"])
        .arg(&snap)
        .args(["--allow-unsigned-manifest", "--yes"])
        .assert()
        .success();
    let conn = rusqlite::Connection::open(&target).expect("open restored");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = 'm-2565'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 1, "the snapshot's row is restored");
}

#[test]
fn skip_verify_still_refuses_a_cross_backend_manifest_2565() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = tempfile::tempdir().expect("key dir");
    let snap = upgrade_with_snapshot(dir.path());
    std::fs::write(
        manifest_beside(&snap),
        r#"{"snapshot":"x","sha256":"0","bytes":0,"source_db":"pg-placeholder",
            "version":"0","created_at":"2026-01-01T00:00:00Z","backend":"postgres"}"#,
    )
    .expect("write foreign manifest");
    let target = dir.path().join("restored.db");
    drop(ai_memory::db::open(&target).expect("target db"));
    let out = ai_memory(&target, keys.path())
        .args(["restore", "--from"])
        .arg(&snap)
        .args(["--skip-verify", "--yes"])
        .assert()
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cross-backend"),
        "--skip-verify must not waive the cross-backend refusal: {stderr}"
    );
}
