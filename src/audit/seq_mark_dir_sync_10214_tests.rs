// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10214 — the audit sequence high-water mark is replaced by a
//! rename and its directory is fsynced through the `snapshot_file` funnel.
//! The old body made the directory fsync best-effort (`let _ =`), so a lost
//! rename could bring back an older high-water mark after a crash.

use super::{create_seq_mark, seq_mark_record};
use crate::storage::snapshot_file::seam;

const MARK_NAME: &str = "audit.seq";
const VALUE: u64 = 10_214;

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

#[test]
fn create_seq_mark_fsyncs_its_directory_through_the_funnel_10214() {
    let _reset = armed();
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let mark = dir.path().join(MARK_NAME);

    let created = create_seq_mark(&mark, VALUE).expect("create mark");

    assert_eq!(created.recorded, VALUE);
    assert_eq!(seam::take_dir_syncs(), vec![dir.path().to_path_buf()]);
    assert_eq!(
        std::fs::read_to_string(&mark).expect("read mark"),
        seq_mark_record(VALUE)
    );
}

#[test]
fn create_seq_mark_dir_sync_failure_is_returned_not_swallowed_10214() {
    let _reset = armed();
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let mark = dir.path().join(MARK_NAME);
    seam::inject_step_errno(seam::Step::DirSync, libc::EIO);

    let err = create_seq_mark(&mark, VALUE)
        .err()
        .expect("a failed directory fsync fails the mark write");

    assert_eq!(
        err.to_string(),
        format!(
            "audit sequence high-water {} is written but not confirmed durable: the fsync of \
             its directory {} failed ({}), so it may not survive a crash (#10214)",
            mark.display(),
            dir.path().display(),
            std::io::Error::from_raw_os_error(libc::EIO)
        )
    );
    assert_eq!(
        err.downcast_ref::<crate::storage::snapshot_file::NotDurable>()
            .and_then(crate::storage::snapshot_file::NotDurable::raw_os_error),
        Some(libc::EIO)
    );
    // After state: the complete new record, never a partial file.
    assert_eq!(
        std::fs::read_to_string(&mark).expect("read mark"),
        seq_mark_record(VALUE)
    );
}
