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
use std::process::Stdio;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Seconds of future snapshot names each cell plants.
const PLANT_WINDOW_SECS: i64 = 12;
/// `backup.rs` `BACKUP_TS_FMT`.
const BACKUP_TS_FMT: &str = "%Y-%m-%dT%H%M%SZ";
/// `snapshot_file::SYMLINK_REFUSAL_TAIL`.
const TAIL: &str = "a symlink sits at that path and would be followed (#8950)";

fn ai_memory(home: &Path, db: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("ai-memory"));
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

/// Filler rows and bytes each: the repair `VACUUM INTO` outlasts the planter.
const FILLER: (u32, u32) = (64, 512 * 1024);
const STAGE_MARK: &str = ".stage-";
/// Wall-clock ceiling for the planter's watch.
const PLANT_DEADLINE: Duration = Duration::from_secs(60);

/// The snapshot name off a staging entry `.{snapshot}{STAGE_MARK}{pid}-{nonce}`.
fn staged_snapshot(entry: &std::fs::DirEntry) -> Option<String> {
    let name = entry.file_name().into_string().ok()?;
    let (snapshot, _) = name.strip_prefix('.')?.rsplit_once(STAGE_MARK)?;
    Some(snapshot.to_owned())
}

/// CLI row (S-3): a symlink planted at the `doctor --repair-schema-version`
/// snapshot name while it is staged is refused with the exact error, and its
/// target is byte-unchanged. A raw write at the name never stages: red.
#[test]
fn cli_doctor_repair_snapshot_refuses_planted_symlink_8950() {
    let tmp = TempDir::new().expect("tempdir");
    let (db, _, outside) = seeded(&tmp);
    let filler = format!(
        "CREATE TABLE filler (b BLOB); WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL \
         SELECT i + 1 FROM n WHERE i < {}) INSERT INTO filler SELECT zeroblob({}) FROM n;",
        FILLER.0, FILLER.1
    );
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute_batch(&filler).expect("filler");
    let victim = outside.join("victim");
    std::fs::write(&victim, b"victim-bytes").expect("victim file");
    let tip = ai_memory::storage::migrations::current_schema_version().to_string();
    let mut doctor = ai_memory(tmp.path(), &db);
    doctor.args(["doctor", "--repair-schema-version", &tip]);
    let mut child = doctor.stderr(Stdio::piped()).spawn().expect("spawn");
    let deadline = Instant::now() + PLANT_DEADLINE;
    let link = loop {
        let mut entries = std::fs::read_dir(tmp.path()).expect("dir").flatten();
        if let Some(snapshot) = entries.find_map(|e| staged_snapshot(&e)) {
            let link = tmp.path().join(snapshot);
            std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");
            break link;
        }
        let running = child.try_wait().expect("poll").is_none();
        assert!(running && Instant::now() < deadline, "never staged");
    };
    let output = child.wait_with_output().expect("doctor output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "a planted symlink must fail");
    let refusal = format!("refusing to write {}: {TAIL}", link.display());
    assert!(stderr.contains(&refusal), "{stderr}");
    assert_eq!(std::fs::read(&victim).expect("victim"), b"victim-bytes");
}
