// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]
#![cfg(unix)]

//! v1.0.0 #8950 — the real `ai-memory backup` binary refuses a symlink planted
//! at the predictable snapshot name: non-zero exit, the exact error on stderr,
//! no JSON envelope (no `durable` field) on stdout, and the link's target left
//! untouched. Each cell runs the binary with an explicit `--db` in its own
//! scratch directory and a scratch `HOME`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Seconds of future snapshot names each cell plants.
const PLANT_WINDOW_SECS: i64 = 12;
/// `backup.rs` `BACKUP_TS_FMT`.
const BACKUP_TS_FMT: &str = "%Y-%m-%dT%H%M%SZ";

fn ai_memory(home: &Path, db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Plant links at the next [`PLANT_WINDOW_SECS`] snapshot names, each to its
/// own target made by `make_target`. Returns `(link, target)` pairs.
fn plant(backups: &Path, make_target: impl Fn(i64) -> PathBuf) -> Vec<(PathBuf, PathBuf)> {
    let now = chrono::Utc::now();
    (0..PLANT_WINDOW_SECS)
        .map(|offset| {
            let ts = (now + chrono::Duration::seconds(offset))
                .format(BACKUP_TS_FMT)
                .to_string();
            let link = backups.join(format!("ai-memory-{ts}.db"));
            let target = make_target(offset);
            std::os::unix::fs::symlink(&target, &link).expect("plant symlink");
            (link, target)
        })
        .collect()
}

/// Run `backup --json` and assert the refusal: non-zero exit, one of the
/// exact refusals on stderr, nothing on stdout.
fn assert_refused(tmp: &TempDir, db: &Path, backups: &Path, planted: &[(PathBuf, PathBuf)]) {
    let output = ai_memory(tmp.path(), db)
        .args(["backup", "--to", backups.to_str().expect("utf-8"), "--json"])
        .output()
        .expect("run backup");
    assert!(
        !output.status.success(),
        "a planted symlink must fail the backup"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let refused = planted.iter().any(|(link, _)| {
        stderr.contains(&format!(
            "refusing to write {}: a symlink sits at that path and would be followed (#8950)",
            link.display()
        ))
    });
    assert!(refused, "exact refusal expected on stderr, got: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "a refused backup printed an envelope: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn seeded(tmp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let db = tmp.path().join("ai-memory.db");
    drop(ai_memory::db::open(&db).expect("create db"));
    let backups = tmp.path().join("backups");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&backups).expect("backups dir");
    std::fs::create_dir_all(&outside).expect("outside dir");
    (db, backups, outside)
}

/// CLI row: dangling link at the snapshot name. The old binary created the
/// target through it and printed `"durable":true`.
#[test]
fn cli_backup_refuses_dangling_snapshot_symlink_8950() {
    let tmp = TempDir::new().expect("tempdir");
    let (db, backups, outside) = seeded(&tmp);
    let planted = plant(&backups, |i| outside.join(format!("gone-{i}")));
    assert_refused(&tmp, &db, &backups, &planted);
    for (_, target) in &planted {
        assert!(
            std::fs::symlink_metadata(target).is_err(),
            "the dangling target {} was created",
            target.display()
        );
    }
}

/// CLI row: link to a regular file outside the backup directory; the file is
/// byte-unchanged.
#[test]
fn cli_backup_refuses_outside_file_snapshot_symlink_8950() {
    let tmp = TempDir::new().expect("tempdir");
    let (db, backups, outside) = seeded(&tmp);
    let planted = plant(&backups, |i| {
        let file = outside.join(format!("victim-{i}"));
        std::fs::write(&file, b"victim-bytes").expect("victim file");
        file
    });
    assert_refused(&tmp, &db, &backups, &planted);
    for (_, target) in &planted {
        assert_eq!(std::fs::read(target).expect("victim"), b"victim-bytes");
    }
}

/// CLI row: link to a directory; nothing is written into it.
#[test]
fn cli_backup_refuses_directory_snapshot_symlink_8950() {
    let tmp = TempDir::new().expect("tempdir");
    let (db, backups, outside) = seeded(&tmp);
    let planted = plant(&backups, |i| {
        let dir = outside.join(format!("dir-{i}"));
        std::fs::create_dir(&dir).expect("victim dir");
        dir
    });
    assert_refused(&tmp, &db, &backups, &planted);
    for (_, target) in &planted {
        assert_eq!(std::fs::read_dir(target).expect("dir").count(), 0);
    }
}
