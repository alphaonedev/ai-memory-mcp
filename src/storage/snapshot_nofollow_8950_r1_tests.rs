// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8950 round 1 (NOTICE-FIX-9281-r1): the pre-migration snapshot
//! through the stage (X-1, X-4), the no-replace publish for every errno of the
//! link call (X-2), one link call per backup name (X-3) and the deterministic
//! doctor plant (X-6). Every plant runs at a named point of the write through
//! the `cfg(test)` seam, so no row races the writer.

use super::snapshot_file::seam::{self, Point};
use super::snapshot_file::{stage_beside, symlink_refusal, write_new_private_unique};
use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// The mode a victim file carries before a row runs.
const VICTIM_MODE: u32 = 0o644;
/// The mode of the source database in the snapshot rows.
const SOURCE_MODE: u32 = 0o600;
/// Bytes a planted victim holds.
const VICTIM_BYTES: &[u8] = b"victim-bytes";

/// Scratch directory for one test (under `TMPDIR`, removed on drop).
fn scratch() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("scratch dir")
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("mode")
        .permissions()
        .mode()
        & 0o777
}

/// A victim regular file with `bytes` and [`VICTIM_MODE`].
fn victim_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("victim");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(VICTIM_MODE)).expect("mode");
}

/// What a snapshot row puts at the final snapshot name, and when.
#[derive(Debug, Clone, Copy)]
enum Swap {
    /// A dangling symlink, before the fill.
    Dangling,
    /// A symlink to an empty victim file, before the fill.
    LiveLink,
    /// A hard link to an empty victim file, before the fill.
    HardLink,
    /// A regular victim file in place of the filled snapshot, after the fill.
    Regular,
}

const SWAPS: [Swap; 4] = [
    Swap::Dangling,
    Swap::LiveLink,
    Swap::HardLink,
    Swap::Regular,
];

/// A file-backed source database (mode [`SOURCE_MODE`]) with one row.
fn source_db(dir: &Path) -> (rusqlite::Connection, PathBuf) {
    let db = dir.join("source.db");
    let conn = rusqlite::Connection::open(&db).expect("open");
    conn.execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('row');")
        .expect("seed");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(SOURCE_MODE)).expect("mode");
    (conn, db)
}

/// Arm the hook: at the swap's point, put the swap at the final name.
/// Returns the cell that receives the final name.
fn arm(swap: Swap, victim: PathBuf) -> Rc<RefCell<Option<PathBuf>>> {
    let seen = Rc::new(RefCell::new(None));
    let cell = Rc::clone(&seen);
    seam::set_hook(move |point, dest| {
        let due = match swap {
            Swap::Regular => Point::Filled,
            _ => Point::Fill,
        };
        if point != due {
            return;
        }
        *cell.borrow_mut() = Some(dest.to_path_buf());
        // The pre-fix code has already created the name; the staged code has not.
        let _ = std::fs::remove_file(dest);
        match swap {
            Swap::Dangling => std::os::unix::fs::symlink(&victim, dest).expect("dangling"),
            Swap::LiveLink => {
                victim_file(&victim, b"");
                std::os::unix::fs::symlink(&victim, dest).expect("live link");
            }
            Swap::HardLink => {
                victim_file(&victim, b"");
                std::fs::hard_link(&victim, dest).expect("hard link");
            }
            Swap::Regular => victim_file(dest, VICTIM_BYTES),
        }
    });
    seen
}

/// X-1 / X-4: whatever is swapped in at the pre-migration snapshot name
/// between its create and its publish is never written through, never
/// chmod-ed and never replaced; the snapshot is refused with the exact error.
#[test]
fn migration_snapshot_refuses_swapped_name_rows_8950() {
    for swap in SWAPS {
        let dir = scratch();
        let (conn, _db) = source_db(dir.path());
        let victim = dir.path().join("victim");
        let seen = arm(swap, victim.clone());
        let result = super::migrations::snapshot_before_migration(&conn, 1, 2);
        seam::reset();
        let dest = seen
            .borrow()
            .clone()
            .unwrap_or_else(|| panic!("{swap:?}: hook never ran"));
        let err = result.expect_err(&format!("{swap:?}: a swapped name must be refused"));
        let cause = match swap {
            Swap::Dangling | Swap::LiveLink => symlink_refusal(&dest),
            Swap::HardLink | Swap::Regular => format!(
                "refusing to overwrite existing pre-migration snapshot {}",
                dest.display()
            ),
        };
        let want = format!(
            "pre-migration snapshot (v1→v2) failed; refusing to mutate schema without a \
             recoverable backup: {cause}"
        );
        assert_eq!(format!("{err:#}"), want, "{swap:?}");
        match swap {
            Swap::Dangling => {
                assert!(
                    std::fs::symlink_metadata(&victim).is_err(),
                    "{swap:?}: victim made"
                );
            }
            Swap::LiveLink | Swap::HardLink => {
                assert_eq!(std::fs::read(&victim).expect("victim"), b"", "{swap:?}");
                assert_eq!(mode_of(&victim), VICTIM_MODE, "{swap:?}");
            }
            Swap::Regular => {
                assert_eq!(
                    std::fs::read(&dest).expect("victim"),
                    VICTIM_BYTES,
                    "{swap:?}"
                );
                assert_eq!(mode_of(&dest), VICTIM_MODE, "{swap:?}");
            }
        }
    }
}

/// X-1: with nothing swapped in, the snapshot is a published regular file
/// with the source's mode and no staging entry is left.
#[test]
fn migration_snapshot_publishes_with_source_mode_8950() {
    let dir = scratch();
    let (conn, db) = source_db(dir.path());
    let snapshot = super::migrations::snapshot_before_migration(&conn, 1, 2)
        .expect("snapshot")
        .expect("file-backed");
    let meta = std::fs::symlink_metadata(&snapshot).expect("published");
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, SOURCE_MODE);
    let mut names: Vec<_> = std::fs::read_dir(dir.path())
        .expect("dir")
        .flatten()
        .map(|e| PathBuf::from(e.file_name()))
        .collect();
    names.sort();
    let want = [
        db.file_name().map(PathBuf::from),
        snapshot.file_name().map(PathBuf::from),
    ];
    let mut want: Vec<PathBuf> = want.into_iter().flatten().collect();
    want.sort();
    assert_eq!(names, want);
}

/// An `io::Error` display for `errno`, as the refusal shows it.
fn os_error(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// The errnos of a filesystem without hard links: the only ones that may
/// fall back (to an atomic no-replace rename).
const NO_HARD_LINK_ERRNOS: [i32; 3] = [libc::EPERM, libc::EOPNOTSUPP, libc::ENOSYS];
/// Every other link failure is refused, never followed by a fallback.
const REFUSED_ERRNOS: [i32; 6] = [
    libc::EIO,
    libc::EMLINK,
    libc::ENOSPC,
    libc::EACCES,
    libc::EXDEV,
    libc::EROFS,
];

/// X-2: the link fails with an errno of no-hard-link class and an entry sits
/// at the destination (regular file or symlink): refused exactly, entry and
/// its target untouched.
#[test]
fn publish_fallback_never_replaces_an_entry_rows_8950() {
    for errno in NO_HARD_LINK_ERRNOS {
        for symlink in [false, true] {
            let dir = scratch();
            let dest = dir.path().join("snap.db");
            let victim = dir.path().join("victim");
            victim_file(&victim, VICTIM_BYTES);
            let mut stage = stage_beside(&dest, "repair snapshot").expect("stage");
            stage.write_all(b"staged").expect("write");
            if symlink {
                std::os::unix::fs::symlink(&victim, &dest).expect("plant");
            } else {
                victim_file(&dest, VICTIM_BYTES);
            }
            seam::inject_link_errno(Some(errno));
            let err = stage
                .publish()
                .expect_err("an entry at dest must be refused");
            seam::reset();
            let want = if symlink {
                symlink_refusal(&dest)
            } else {
                format!(
                    "refusing to overwrite existing repair snapshot {}",
                    dest.display()
                )
            };
            assert_eq!(format!("{err:#}"), want, "errno {errno} symlink {symlink}");
            assert_eq!(std::fs::read(&victim).expect("victim"), VICTIM_BYTES);
            let at_dest = std::fs::symlink_metadata(&dest).expect("entry kept");
            assert_eq!(at_dest.file_type().is_symlink(), symlink, "errno {errno}");
            assert_eq!(std::fs::read(&dest).expect("entry"), VICTIM_BYTES);
        }
    }
}

/// X-2: no-hard-link errno, nothing at the destination: published by the
/// no-replace rename, owner-only, staged bytes, no staging entry left.
#[test]
fn publish_fallback_renames_onto_a_free_name_rows_8950() {
    for errno in NO_HARD_LINK_ERRNOS {
        let dir = scratch();
        let dest = dir.path().join("snap.db");
        let mut stage = stage_beside(&dest, "repair snapshot").expect("stage");
        stage.write_all(b"staged").expect("write");
        seam::inject_link_errno(Some(errno));
        let published = stage.publish();
        seam::reset();
        let (file, durability) = published.unwrap_or_else(|e| panic!("errno {errno}: {e:#}"));
        drop(file);
        super::snapshot_file::require_durable(durability)
            .unwrap_or_else(|e| panic!("errno {errno}: {e:#}"));
        assert_eq!(std::fs::read(&dest).expect("published"), b"staged");
        assert_eq!(mode_of(&dest), 0o600);
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("dir").count(),
            1,
            "errno {errno}"
        );
    }
}

/// X-2: any other errno of the link call is refused with the link error kept
/// as context; nothing is created at the destination.
#[test]
fn publish_refuses_other_link_errnos_rows_8950() {
    for errno in REFUSED_ERRNOS {
        let dir = scratch();
        let dest = dir.path().join("snap.db");
        let mut stage = stage_beside(&dest, "repair snapshot").expect("stage");
        stage.write_all(b"staged").expect("write");
        seam::inject_link_errno(Some(errno));
        let err = stage
            .publish()
            .expect_err("an unknown link failure must be refused");
        seam::reset();
        let want = format!(
            "refusing to publish repair snapshot {}: the link failed and no fallback \
             applies (#8950): {}",
            dest.display(),
            os_error(errno)
        );
        assert_eq!(format!("{err:#}"), want, "errno {errno}");
        assert!(
            std::fs::symlink_metadata(&dest).is_err(),
            "errno {errno}: dest made"
        );
    }
}

/// X-2: `EEXIST` from the link call is "name taken": the publish refuses and
/// the entry is untouched.
#[test]
fn publish_eexist_is_name_taken_8950() {
    let dir = scratch();
    let dest = dir.path().join("snap.db");
    let mut stage = stage_beside(&dest, "repair snapshot").expect("stage");
    stage.write_all(b"staged").expect("write");
    victim_file(&dest, VICTIM_BYTES);
    seam::inject_link_errno(Some(libc::EEXIST));
    let err = stage.publish().expect_err("taken");
    seam::reset();
    let want = format!(
        "refusing to overwrite existing repair snapshot {}",
        dest.display()
    );
    assert_eq!(format!("{err:#}"), want);
    assert_eq!(std::fs::read(&dest).expect("entry"), VICTIM_BYTES);
}

/// X-5: the link succeeded, so a staging name that cannot be removed (a
/// non-empty directory now sits there) does not fail the publish.
#[test]
fn publish_survives_a_failing_staging_unlink_8950() {
    let dir = scratch();
    let dest = dir.path().join("snap.db");
    let mut stage = stage_beside(&dest, "repair snapshot").expect("stage");
    stage.write_all(b"staged").expect("write");
    seam::set_hook(|point, staged| {
        if point == seam::Point::Linked {
            std::fs::remove_file(staged).expect("unlink staged");
            std::fs::create_dir(staged).expect("dir at the staging name");
            std::fs::write(staged.join("keep"), b"x").expect("non-empty");
        }
    });
    let published = stage.publish();
    seam::reset();
    let (handle, durability) =
        published.expect("a published file must not fail on the staging unlink");
    drop(handle);
    super::snapshot_file::require_durable(durability).expect("durable publish");
    assert_eq!(std::fs::read(&dest).expect("published"), b"staged");
}

fn backup_names(dest: &Path, upto: u32) -> Vec<PathBuf> {
    let mut names = vec![dest.to_path_buf()];
    names.extend((1..=upto).map(|n| PathBuf::from(format!("{}.{n}", dest.display()))));
    names
}

/// X-3: ONE create-new link call per candidate name, in order, and the
/// first free name is the one written.
#[test]
fn unique_backup_one_link_call_per_name_8950() {
    let dir = scratch();
    let dest = dir.path().join("config.toml.bak");
    let taken = backup_names(&dest, 2);
    for name in &taken {
        std::fs::write(name, b"taken").expect("taken");
    }
    seam::reset();
    let (written, durability) =
        write_new_private_unique(&dest, "install backup", b"new").expect("written");
    super::snapshot_file::require_durable(durability).expect("durable");
    let calls = seam::take_link_calls();
    assert_eq!(written, PathBuf::from(format!("{}.3", dest.display())));
    assert_eq!(calls, backup_names(&dest, 3));
    assert_eq!(std::fs::read(&written).expect("written"), b"new");
    for name in &taken {
        assert_eq!(std::fs::read(name).expect("taken"), b"taken");
    }
}

/// X-3: the numbered names run to `.1000` exactly: `.1000` is still taken,
/// `.1001` is never tried, and the refusal names the literal 1000.
#[test]
fn unique_backup_bound_is_literal_1000_8950() {
    let dir = scratch();
    let dest = dir.path().join("config.toml.bak");
    for name in backup_names(&dest, 999) {
        std::fs::write(name, b"taken").expect("taken");
    }
    seam::reset();
    let (written, durability) =
        write_new_private_unique(&dest, "install backup", b"new").expect("1000 free");
    super::snapshot_file::require_durable(durability).expect("durable");
    assert_eq!(written, PathBuf::from(format!("{}.1000", dest.display())));
    assert_eq!(seam::take_link_calls(), backup_names(&dest, 1000));
    let err = write_new_private_unique(&dest, "install backup", b"new").expect_err("all taken");
    let want = format!(
        "refusing to write install backup {}: it and 1000 numbered names beside it are taken",
        dest.display()
    );
    assert_eq!(format!("{err:#}"), want);
    assert_eq!(seam::take_link_calls(), backup_names(&dest, 1000));
    let past = PathBuf::from(format!("{}.1001", dest.display()));
    assert!(
        std::fs::symlink_metadata(&past).is_err(),
        ".1001 must never be written"
    );
}

/// X-3: a symlink planted at `.2` mid-sequence is refused (not skipped),
/// never written through, and no later name is tried.
#[test]
fn unique_backup_refuses_symlink_mid_sequence_8950() {
    let dir = scratch();
    let dest = dir.path().join("config.toml.bak");
    let names = backup_names(&dest, 3);
    std::fs::write(&names[0], b"taken").expect("taken");
    std::fs::write(&names[1], b"taken").expect("taken");
    let victim = dir.path().join("victim");
    victim_file(&victim, VICTIM_BYTES);
    std::os::unix::fs::symlink(&victim, &names[2]).expect("plant");
    seam::reset();
    let err = write_new_private_unique(&dest, "install backup", b"new").expect_err("symlink");
    assert_eq!(format!("{err:#}"), symlink_refusal(&names[2]));
    assert_eq!(seam::take_link_calls(), names[..3].to_vec());
    assert_eq!(std::fs::read(&victim).expect("victim"), VICTIM_BYTES);
    assert_eq!(mode_of(&victim), VICTIM_MODE);
    assert!(
        std::fs::symlink_metadata(&names[3]).is_err(),
        ".3 must not be tried"
    );
}

/// X-6: a symlink planted at the doctor repair snapshot name while the
/// snapshot is staged (the seam runs the plant before the fill, no race) is
/// refused with the exact error; its target is byte-unchanged.
#[test]
fn doctor_repair_snapshot_refuses_planted_symlink_8950() {
    let dir = scratch();
    let (conn, db) = source_db(dir.path());
    let victim = dir.path().join("victim");
    let seen = Rc::new(RefCell::new(None));
    let cell = Rc::clone(&seen);
    let target = victim.clone();
    seam::set_hook(move |point, dest| {
        if point == Point::Fill {
            victim_file(&target, VICTIM_BYTES);
            std::os::unix::fs::symlink(&target, dest).expect("plant");
            *cell.borrow_mut() = Some(dest.to_path_buf());
        }
    });
    let result = crate::cli::doctor::snapshot_before_repair(&conn, &db, 1, 2);
    seam::reset();
    let link = seen.borrow().clone().expect("hook ran");
    let err = result.expect_err("a planted symlink must be refused");
    assert_eq!(format!("{err:#}"), symlink_refusal(&link));
    assert_eq!(std::fs::read(&victim).expect("victim"), VICTIM_BYTES);
}

/// v1.0.0 #10214 — a repair snapshot whose directory fsync fails after the
/// link IS written: it stays on disk, and the restamp is refused with the
/// typed "written, not confirmed durable" error (never "could not write").
#[test]
fn doctor_repair_snapshot_dir_sync_failure_refuses_restamp_10214() {
    let dir = scratch();
    let (conn, db) = source_db(dir.path());
    seam::reset();
    seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, 1);
    let result = crate::cli::doctor::snapshot_before_repair(&conn, &db, 1, 2);
    seam::reset();
    let err = result.expect_err("a snapshot not confirmed durable refuses the restamp");
    let not_durable = err
        .downcast_ref::<super::snapshot_file::NotDurable>()
        .expect("the typed not-durable error");
    assert_eq!(not_durable.raw_os_error(), Some(libc::EIO));
    let snapshot = not_durable.dest().to_path_buf();
    assert!(
        err.to_string()
            .contains("is written but not confirmed durable"),
        "got {err:#}"
    );
    assert!(
        std::fs::symlink_metadata(&snapshot).is_ok_and(|m| m.is_file()),
        "the written snapshot {} stays",
        snapshot.display()
    );
}
