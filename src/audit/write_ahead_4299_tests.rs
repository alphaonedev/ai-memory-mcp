// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4299 — a number is in the high-water mark BEFORE its event is appended.
//!
//! #4086 wrote the mark only after a write failed. An event whose write failed
//! on the FIRST byte, with the process dying before that mark write, left no
//! evidence: nothing in the trail, nothing in the mark, and `verify` read
//! clean. The mark is now written ahead of every append (in place, no fsync:
//! as durable as the trail lines it guards), so any process death after
//! numbering an event and before writing it leaves the number on disk.
//! Decided by a 5-agent vote (4d3ea1c5): option a', 3-2.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::tail_loss_4086_tests::{Enospc, one, reopen_real_file, sequences, swap_writer};
use super::*;

/// Sets the crash-snapshot directory for one cell and always clears it.
struct Snapshots(PathBuf);

impl Snapshots {
    fn at(dir: PathBuf) -> Self {
        *CRASH_SNAPSHOT_DIR.lock().expect("snapshot seam") = Some(dir.clone());
        Self(dir)
    }
    fn trail(&self, point: &str) -> PathBuf {
        self.0.join(point).join("audit.log")
    }
}

impl Drop for Snapshots {
    fn drop(&mut self) {
        if let Ok(mut g) = CRASH_SNAPSHOT_DIR.lock() {
            *g = None;
        }
    }
}

/// Sets the refuse-write-ahead seam for one cell and always clears it.
struct RefuseWriteAhead;

impl RefuseWriteAhead {
    fn on() -> Self {
        REFUSE_WRITE_AHEAD_FOR_TEST.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for RefuseWriteAhead {
    fn drop(&mut self) {
        REFUSE_WRITE_AHEAD_FOR_TEST.store(false, Ordering::SeqCst);
    }
}

fn mark_value(trail: &Path) -> Option<u64> {
    read_seq_mark(&seq_mark_path(trail)).expect("mark readable")
}

/// The issue's cell: event 3's write fails on the FIRST byte and the process
/// dies before the failure path records the loss (the before-mark crash
/// point). Red on ecb799000: no bytes reached the trail and the mark still
/// read 0, so the disk verified CLEAN.
#[test]
fn a_first_byte_failure_then_a_crash_is_a_gap_4299() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    let snaps = Snapshots::at(tmp.path().join("crash"));
    init(&path, true, false).expect("init");
    one();
    one();
    swap_writer(Box::new(Enospc));
    one();
    reopen_real_file(&path);
    shutdown_for_test();
    let disk = snaps.trail(CRASH_BEFORE_MARK);
    drop(snaps);

    let report = verify_chain(&disk).expect("verify");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert_eq!(
        report.gaps,
        vec![SequenceGap { from: 3, to: 3 }],
        "a lost first-byte write must never verify clean"
    );

    assert_eq!(
        sequences(&disk),
        vec![1, 2],
        "no byte of event 3 reached the trail"
    );
    assert_eq!(
        mark_value(&disk),
        Some(3),
        "the write-ahead named 3 before the append"
    );

    // A restart resumes after the lost number and never reuses it.
    init(&disk, true, false).expect("restart on the crash disk");
    one();
    shutdown_for_test();
    assert_eq!(sequences(&disk), vec![1, 2, 4]);
}

/// A process killed between the write-ahead and the append of an event that
/// would have succeeded DID lose that event: verify says so, and a restart
/// resumes after it.
#[test]
fn a_crash_between_write_ahead_and_append_is_a_gap_4299() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    let snaps = Snapshots::at(tmp.path().join("crash"));
    one();
    let disk = snaps.trail(CRASH_BEFORE_APPEND);
    drop(snaps);
    shutdown_for_test();

    assert_eq!(sequences(&disk), vec![1, 2]);
    assert_eq!(mark_value(&disk), Some(3));
    let report = verify_chain(&disk).expect("verify");
    assert_eq!(report.gaps, vec![SequenceGap { from: 3, to: 3 }]);
    init(&disk, true, false).expect("restart");
    one();
    shutdown_for_test();
    assert_eq!(sequences(&disk), vec![1, 2, 4]);
}

/// No false alarm: after ordinary writes the mark equals the last line, so
/// verify is clean before and after a restart.
#[test]
fn ordinary_writes_leave_no_false_gap_4299() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    one();
    shutdown_for_test();
    assert_eq!(
        mark_value(&path),
        Some(3),
        "the mark tracks the last written number"
    );
    let report = verify_chain(&path).expect("verify");
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report.into_result().is_ok());

    init(&path, true, false).expect("restart");
    one();
    shutdown_for_test();
    assert_eq!(sequences(&path), vec![1, 2, 3, 4]);
    assert!(verify_chain(&path).expect("verify").into_result().is_ok());
}

/// A failed write-ahead never costs the event: it is still appended and the
/// trail verifies clean (the durable record matters more than its index).
#[test]
fn a_refused_write_ahead_still_writes_the_event_4299() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    {
        let _refuse = RefuseWriteAhead::on();
        one();
    }
    one();
    shutdown_for_test();
    assert_eq!(sequences(&path), vec![1, 2, 3]);
    assert!(verify_chain(&path).expect("verify").into_result().is_ok());
}

/// A writer holds the EXCLUSIVE trail lock across its write-ahead and its
/// append, so for that moment the mark leads the trail. verify takes a SHARED
/// lock and waits that moment out rather than reporting a false gap.
#[test]
fn verify_waits_for_a_writer_holding_the_trail_lock_4299() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    shutdown_for_test();

    // Stand in for a writer mid-append: the lock is held and the mark already
    // names 3, whose line is not written yet.
    let writer = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .expect("open");
    writer.lock().expect("exclusive lock");
    let mark = seq_mark_path(&path);
    let before = std::fs::read(&mark).expect("mark");
    std::fs::write(&mark, seq_mark_record(3)).expect("write ahead 3");

    let verify_path = path.clone();
    let verifier = std::thread::spawn(move || verify_chain(&verify_path));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !verifier.is_finished(),
        "verify read the trail while a writer held the lock"
    );

    // The "writer" finishes as a successful append would leave it: the mark
    // back at the last written number (here: restored), then the unlock.
    std::fs::write(&mark, before).expect("restore mark");
    writer.unlock().expect("unlock");
    let report = verifier.join().expect("verify thread").expect("verify");
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
}
