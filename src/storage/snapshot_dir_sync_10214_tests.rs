// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10214 — every durable replace and publish of the `snapshot_file`
//! funnel runs: stage, fsync the staged file, rename (or link) it over the
//! destination, fsync the destination's DIRECTORY. A crash after a rename
//! whose directory was never synced can bring the old file back (or none),
//! which for the row-attestation seal is a rolled-back high-water mark.
//!
//! Each step fails through the test seam (no sleeps, no real I/O fault) and
//! every row asserts the exact error and that the destination holds exactly
//! the before or the after bytes, never a partial file, with no staging
//! leftovers beside it.

use super::snapshot_file::{seam, write_new_private_unique, write_replacing};
use std::path::{Path, PathBuf};

const WHAT: &str = "dir-sync probe";
const DEST_NAME: &str = "dest-10214";
const BEFORE: &[u8] = b"before-10214";
const AFTER: &[u8] = b"after-10214";
const INJECTED_ERRNO: i32 = libc::EIO;

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

fn armed() -> SeamReset {
    seam::reset();
    SeamReset
}

/// Scratch directory for one test (under `TMPDIR`, removed on drop).
fn scratch() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("scratch dir")
}

/// The names in `dir`, sorted: proves no staging file or directory is left.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The OS errno at the root of an error chain.
fn root_errno(err: &anyhow::Error) -> Option<i32> {
    err.root_cause()
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
}

/// The bytes at `dest`, `None` when nothing is there.
fn bytes_at(dest: &Path) -> Option<Vec<u8>> {
    match std::fs::read(dest) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("reading {}: {e}", dest.display()),
    }
}

fn file_sync_refusal(dest: &Path) -> String {
    format!("fsync the staged {WHAT} for {} (#10214)", dest.display())
}

fn rename_refusal(dest: &Path) -> String {
    format!("replacing {WHAT} {} (#10214)", dest.display())
}

fn dir_sync_refusal(dir: &Path, dest: &Path) -> String {
    dir_sync_refusal_for(dir, WHAT, dest)
}

fn dir_sync_refusal_for(dir: &Path, what: &str, dest: &Path) -> String {
    format!(
        "fsync the directory {} after publishing {what} {}: the new file is in place but may \
         not survive a crash (#10214)",
        dir.display(),
        dest.display()
    )
}

#[test]
fn write_replacing_fsyncs_the_destination_directory_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    std::fs::write(&dest, BEFORE).expect("plant before");

    write_replacing(&dest, WHAT, AFTER).expect("replace");

    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}

#[test]
fn write_replacing_creating_fsyncs_the_destination_directory_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);

    write_replacing(&dest, WHAT, AFTER).expect("create");

    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
}

/// One row per (failing step, destination present before): the exact error,
/// the exact bytes left at the destination, and the directory syncs made.
#[test]
fn write_replacing_failure_at_each_step_is_typed_and_never_partial_10214() {
    #[derive(Debug, Clone, Copy)]
    enum Left {
        Before,
        After,
    }
    let rows: [(seam::Step, bool, Left); 6] = [
        (seam::Step::FileSync, true, Left::Before),
        (seam::Step::FileSync, false, Left::Before),
        (seam::Step::Rename, true, Left::Before),
        (seam::Step::Rename, false, Left::Before),
        (seam::Step::DirSync, true, Left::After),
        (seam::Step::DirSync, false, Left::After),
    ];
    for (step, present, left) in rows {
        let _reset = armed();
        let dir = scratch();
        let dest = dir.path().join(DEST_NAME);
        if present {
            std::fs::write(&dest, BEFORE).expect("plant before");
        }
        seam::inject_step_errno(step, INJECTED_ERRNO);

        let err = write_replacing(&dest, WHAT, AFTER)
            .expect_err(&format!("row {step:?} present={present} must fail"));

        let expected = match step {
            seam::Step::FileSync => file_sync_refusal(&dest),
            seam::Step::Rename => rename_refusal(&dest),
            seam::Step::DirSync => dir_sync_refusal(dir.path(), &dest),
        };
        assert_eq!(err.to_string(), expected, "row {step:?} present={present}");
        assert_eq!(root_errno(&err), Some(INJECTED_ERRNO), "row {step:?}");
        let (want, names, syncs): (Option<&[u8]>, Vec<String>, Vec<PathBuf>) = match left {
            Left::Before if present => (Some(BEFORE), vec![DEST_NAME.to_owned()], vec![]),
            Left::Before => (None, vec![], vec![]),
            Left::After => (
                Some(AFTER),
                vec![DEST_NAME.to_owned()],
                vec![dir.path().to_path_buf()],
            ),
        };
        assert_eq!(
            bytes_at(&dest).as_deref(),
            want,
            "row {step:?} present={present}"
        );
        assert_eq!(entries(dir.path()), names, "row {step:?} present={present}");
        assert_eq!(
            seam::take_dir_syncs(),
            syncs,
            "row {step:?} present={present}"
        );
    }
}

#[test]
fn write_new_private_unique_fsyncs_the_destination_directory_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);

    let published = write_new_private_unique(&dest, WHAT, AFTER).expect("publish");

    assert_eq!(published, dest);
    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}

#[test]
fn write_new_private_unique_dir_sync_failure_keeps_the_complete_file_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    seam::inject_step_errno(seam::Step::DirSync, INJECTED_ERRNO);

    let err = write_new_private_unique(&dest, WHAT, AFTER).expect_err("dir sync fails");

    assert_eq!(err.to_string(), dir_sync_refusal(dir.path(), &dest));
    assert_eq!(root_errno(&err), Some(INJECTED_ERRNO));
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}

#[test]
fn write_new_private_unique_file_sync_failure_publishes_nothing_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    seam::inject_step_errno(seam::Step::FileSync, INJECTED_ERRNO);

    let err = write_new_private_unique(&dest, WHAT, AFTER).expect_err("file sync fails");

    assert_eq!(err.to_string(), file_sync_refusal(&dest));
    assert_eq!(root_errno(&err), Some(INJECTED_ERRNO));
    assert_eq!(bytes_at(&dest), None);
    assert_eq!(entries(dir.path()), Vec::<String>::new());
    assert_eq!(seam::take_dir_syncs(), Vec::<PathBuf>::new());
}

/// Sibling: the identity key writer replaces by rename and now syncs the
/// directory through the same funnel, propagating a failure (it used to
/// swallow it with `let _ =`).
#[test]
fn keypair_write_with_mode_fsyncs_the_directory_through_the_funnel_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    std::fs::write(&dest, BEFORE).expect("plant before");

    crate::identity::keypair::write_with_mode(&dest, AFTER, 0o600).expect("write key");

    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
}

#[test]
fn keypair_write_with_mode_dir_sync_failure_is_returned_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    std::fs::write(&dest, BEFORE).expect("plant before");
    seam::inject_step_errno(seam::Step::DirSync, INJECTED_ERRNO);

    let err =
        crate::identity::keypair::write_with_mode(&dest, AFTER, 0o600).expect_err("dir sync fails");

    assert_eq!(err.raw_os_error(), Some(INJECTED_ERRNO));
    assert_eq!(bytes_at(&dest).as_deref(), Some(AFTER));
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}

fn empty_allowlist() -> crate::wake_hub::delegation_verifier::AllowlistFile {
    crate::wake_hub::delegation_verifier::AllowlistFile {
        version: 1,
        refreshed_at: None,
        agents: Vec::new(),
    }
}

/// Sibling: the hub allowlist snapshot is published by a tempfile rename and
/// now syncs the directory through the same funnel (it never synced it).
#[test]
fn hub_cache_publish_fsyncs_the_directory_through_the_funnel_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);

    crate::identity::hub_cache::publish(&dest, &empty_allowlist()).expect("publish");

    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}

#[test]
fn hub_cache_publish_dir_sync_failure_is_returned_10214() {
    let _reset = armed();
    let dir = scratch();
    let dest = dir.path().join(DEST_NAME);
    seam::inject_step_errno(seam::Step::DirSync, INJECTED_ERRNO);

    let err =
        crate::identity::hub_cache::publish(&dest, &empty_allowlist()).expect_err("dir sync fails");

    assert_eq!(
        err.to_string(),
        dir_sync_refusal_for(dir.path(), "hub allowlist snapshot", &dest)
    );
    assert_eq!(root_errno(&err), Some(INJECTED_ERRNO));
    assert!(
        bytes_at(&dest).is_some(),
        "the snapshot is in place (after state)"
    );
}

/// #8950 census guard: `sync_dir` opens READ-only and creates or replaces
/// nothing. A missing path stays missing (no create flag), a regular file is
/// refused with `ENOTDIR` and keeps its bytes (no write or truncate flag),
/// and a real directory keeps exactly its entries.
#[cfg(unix)]
#[test]
fn sync_dir_opens_read_only_and_creates_nothing_10214() {
    let _reset = armed();
    let dir = scratch();
    let missing = dir.path().join("missing-10214");
    let err = super::snapshot_file::sync_dir(&missing).expect_err("missing dir");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(bytes_at(&missing), None);

    let file = dir.path().join(DEST_NAME);
    std::fs::write(&file, BEFORE).expect("plant file");
    let err = super::snapshot_file::sync_dir(&file).expect_err("not a directory");
    assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
    assert_eq!(bytes_at(&file).as_deref(), Some(BEFORE));

    super::snapshot_file::sync_dir(dir.path()).expect("real directory");
    assert_eq!(entries(dir.path()), vec![DEST_NAME.to_owned()]);
}
