// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8950 — `backup` never writes through a symlink planted at the
//! snapshot or manifest name, and never reports a backup it did not make.
//!
//! The snapshot name is predictable to the second (`ai-memory-<UTC ts>.db`), so
//! anyone who can write into the backup directory can plant a link there before
//! the hourly timer fires. `Path::exists` follows links and answers `false` for
//! a dangling one, and `VACUUM INTO` creates its output through the link, so the
//! old code wrote the whole corpus to wherever the link pointed and then
//! printed `durable: true`.
//!
//! A child of `cli::backup::tests`, so the fixtures there are in scope through
//! `super::*`. Each row plants links for the next few seconds of names, so the
//! name the run picks is always planted.

#![cfg(all(test, unix))]

use super::*;

/// How many seconds of future snapshot names each row plants.
const PLANT_WINDOW_SECS: i64 = 12;

/// The exact refusal for a symlink at a destination (`#8950`).
fn symlink_refusal(dest: &Path) -> String {
    format!(
        "refusing to write {}: a symlink sits at that path and would be followed (#8950)",
        dest.display()
    )
}

/// What sits at the planted names.
#[derive(Debug, Clone, Copy)]
enum Plant {
    /// A link to a path that does not exist yet (`Path::exists` says absent).
    Dangling,
    /// A link to a regular file OUTSIDE the backup directory.
    OutsideFile,
    /// A link to a directory.
    Directory,
}

/// Which name the row plants at.
#[derive(Debug, Clone, Copy)]
enum At {
    Snapshot,
    Manifest,
}

/// The snapshot and manifest names a run started at `ts` would pick.
fn names_at(ts: &str) -> (String, String) {
    let id = format!("{SNAPSHOT_FILE_PREFIX}{ts}");
    (format!("{id}.{SNAPSHOT_FILE_EXT}"), manifest_file_name(&id))
}

/// Plant `plant` at every `at` name for the next [`PLANT_WINDOW_SECS`].
/// Returns `(link, target)` pairs.
fn plant_window(backups: &Path, outside: &Path, plant: Plant, at: At) -> Vec<(PathBuf, PathBuf)> {
    let now = chrono::Utc::now();
    let mut planted = Vec::new();
    for offset in 0..PLANT_WINDOW_SECS {
        let ts = (now + chrono::Duration::seconds(offset))
            .format(BACKUP_TS_FMT)
            .to_string();
        let (snapshot, manifest) = names_at(&ts);
        let name = match at {
            At::Snapshot => snapshot,
            At::Manifest => manifest,
        };
        let target = match plant {
            Plant::Dangling => outside.join(format!("dangling-{offset}")),
            Plant::OutsideFile => {
                let file = outside.join(format!("outside-{offset}"));
                std::fs::write(&file, b"outside-sentinel").expect("plant outside file");
                file
            }
            Plant::Directory => {
                let dir = outside.join(format!("dir-{offset}"));
                std::fs::create_dir(&dir).expect("plant outside dir");
                dir
            }
        };
        let link = backups.join(name);
        std::os::unix::fs::symlink(&target, &link).expect("plant symlink");
        planted.push((link, target));
    }
    planted
}

/// Every name in `dir` that is not one of the planted links.
fn non_link_entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read backups dir")
        .flatten()
        .filter(|e| !e.file_type().expect("file type").is_symlink())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

/// THE #8950 TABLE. Every planted shape at either name is refused with the
/// exact error, nothing reaches the link's target, nothing is left in the
/// backup directory, and no envelope (no `durable` field) is printed.
#[test]
fn backup_refuses_planted_symlink_rows_8950() {
    let rows = [
        (Plant::Dangling, At::Snapshot),
        (Plant::OutsideFile, At::Snapshot),
        (Plant::Directory, At::Snapshot),
        (Plant::Dangling, At::Manifest),
        (Plant::OutsideFile, At::Manifest),
        (Plant::Directory, At::Manifest),
    ];
    for (plant, at) in rows {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let root = db.parent().expect("db dir").to_path_buf();
        let backups = root.join("backups-8950");
        let outside = root.join("outside-8950");
        std::fs::create_dir_all(&backups).expect("backups dir");
        std::fs::create_dir_all(&outside).expect("outside dir");
        let planted = plant_window(&backups, &outside, plant, at);
        let args = BackupArgs {
            to: backups.clone(),
            keep: 48,
            store_url: None,
        };
        let result = {
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out)
        };
        let row = format!("{plant:?} at {at:?}");
        let err = result.expect_err(&format!("{row}: a planted symlink must refuse the backup"));
        let msg = err.to_string();
        let expected: Vec<String> = planted.iter().map(|(l, _)| symlink_refusal(l)).collect();
        assert!(
            expected.contains(&msg),
            "{row}: exact refusal expected, got: {msg}"
        );
        for (link, target) in &planted {
            match plant {
                Plant::Dangling => assert!(
                    std::fs::symlink_metadata(target).is_err(),
                    "{row}: the dangling target {} was created",
                    target.display()
                ),
                Plant::OutsideFile => assert_eq!(
                    std::fs::read(target).expect("outside file"),
                    b"outside-sentinel",
                    "{row}: the outside file was changed"
                ),
                Plant::Directory => assert_eq!(
                    std::fs::read_dir(target).expect("outside dir").count(),
                    0,
                    "{row}: something was written into the linked directory"
                ),
            }
            assert!(
                std::fs::symlink_metadata(link)
                    .expect("link still there")
                    .file_type()
                    .is_symlink(),
                "{row}: the planted link was replaced"
            );
        }
        assert_eq!(
            non_link_entries(&backups),
            Vec::<String>::new(),
            "{row}: a refused backup left files in the backup directory"
        );
        assert!(
            env.stdout.is_empty(),
            "{row}: a refused backup printed an envelope: {}",
            String::from_utf8_lossy(&env.stdout)
        );
    }
}

/// A regular file already at the snapshot name keeps its own exact refusal
/// and is not touched.
#[test]
fn backup_refuses_existing_regular_snapshot_8950() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let backups = db.parent().expect("db dir").join("backups-8950-regular");
    std::fs::create_dir_all(&backups).expect("backups dir");
    let now = chrono::Utc::now();
    let mut squatted = Vec::new();
    for offset in 0..PLANT_WINDOW_SECS {
        let ts = (now + chrono::Duration::seconds(offset))
            .format(BACKUP_TS_FMT)
            .to_string();
        let path = backups.join(names_at(&ts).0);
        std::fs::write(&path, b"squatter").expect("plant regular file");
        squatted.push(path);
    }
    let args = BackupArgs {
        to: backups.clone(),
        keep: 48,
        store_url: None,
    };
    let err = {
        let mut out = env.output();
        run_backup(&db, &args, true, &mut out).expect_err("an existing snapshot must refuse")
    };
    let msg = err.to_string();
    assert!(
        squatted
            .iter()
            .any(|p| msg == format!("refusing to overwrite existing snapshot {}", p.display())),
        "exact refusal expected, got: {msg}"
    );
    for path in &squatted {
        assert_eq!(std::fs::read(path).expect("squatter"), b"squatter");
    }
    assert!(
        env.stdout.is_empty(),
        "a refused backup printed an envelope"
    );
}

/// RULING ROW — symlinked parent. The defect class covers the FINAL path
/// component only: `--to` may itself be a link an operator made (a backup
/// volume mounted elsewhere), and the backup lands as a regular file in the
/// directory it resolves to, reported durable.
#[test]
fn backup_through_symlinked_parent_dir_writes_regular_files_8950() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let root = db.parent().expect("db dir").to_path_buf();
    let real = root.join("real-backups-8950");
    std::fs::create_dir_all(&real).expect("real dir");
    let linked = root.join("linked-backups-8950");
    std::os::unix::fs::symlink(&real, &linked).expect("link the backup dir");
    let args = BackupArgs {
        to: linked,
        keep: 48,
        store_url: None,
    };
    {
        let mut out = env.output();
        run_backup(&db, &args, true, &mut out).expect("a symlinked --to is followed");
    }
    let envelope: serde_json::Value =
        serde_json::from_slice(&env.stdout).expect("one JSON envelope");
    assert_eq!(envelope["durable"], serde_json::Value::Bool(true));
    let snapshot = real.join(envelope["snapshot"].as_str().expect("snapshot name"));
    let meta = std::fs::symlink_metadata(&snapshot).expect("snapshot in the real dir");
    assert!(meta.file_type().is_file(), "the snapshot is a regular file");
    assert_eq!(
        meta.len(),
        envelope["bytes"].as_u64().expect("bytes"),
        "the reported size is the file's"
    );
    let entries = non_link_entries(&real);
    assert_eq!(
        entries.len(),
        2,
        "exactly the pair, no staging left: {entries:?}"
    );
}
