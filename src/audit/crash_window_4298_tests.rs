// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4298 — no crash on the failed-append path may leave a false "no gap".
//!
//! #4211 truncates a failed append's own bytes; #4086 records the lost
//! sequence in the high-water mark. The mark must be durable BEFORE the
//! truncation: in the reverse order a crash in between left a clean trail and
//! a mark that did not cover the lost number, so `verify` read clean and a
//! restart reused the number.
//!
//! The crash-snapshot seam copies the trail and its mark at every crash point
//! on that path, i.e. exactly the disk a process killed there leaves behind.
//! Every such disk must fail `verify` (or refuse the restart) or report the
//! lost event as a gap.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use super::tail_loss_4086_tests::{one, reopen_real_file, sequences, swap_writer};
use super::*;

/// First write call lands `n` bytes on the real trail, then fails like a full
/// disk.
struct ShortThenFail {
    file: std::fs::File,
    n: usize,
    done: bool,
}

impl Write for ShortThenFail {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.done {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        self.done = true;
        let k = self.n.min(buf.len());
        self.file.write_all(&buf[..k])?;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn short_then_fail(path: &Path, n: usize) -> Box<ShortThenFail> {
    let file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open trail");
    Box::new(ShortThenFail {
        file,
        n,
        done: false,
    })
}

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

/// Sets the refuse-mark-write seam for one cell and always clears it.
struct RefuseMark;

impl RefuseMark {
    fn on() -> Self {
        REFUSE_MARK_WRITE_FOR_TEST.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for RefuseMark {
    fn drop(&mut self) {
        REFUSE_MARK_WRITE_FOR_TEST.store(false, Ordering::SeqCst);
    }
}

/// Events 1 and 2 written, event 3 short-written (17 bytes) then ENOSPC.
fn lose_event_three(path: &Path) {
    init(path, true, false).expect("init");
    one();
    one();
    swap_writer(short_then_fail(path, 17));
    one();
    reopen_real_file(path);
    shutdown_for_test();
}

/// "Clean" = verify found no failure and no gap: the false "no gap".
fn reads_clean(path: &Path) -> bool {
    verify_chain(path).is_ok_and(|r| r.first_failure.is_none() && r.gaps.is_empty())
}

/// The restart path on a crash disk: init refuses (fail closed), or it
/// continues and the loss is still visible after one more event.
fn restart_keeps_the_loss_visible(path: &Path) -> bool {
    match init(path, true, false) {
        Err(_) => true,
        Ok(()) => {
            one();
            shutdown_for_test();
            !reads_clean(path)
        }
    }
}

/// The issue's cells: a crash at every point of the failed-append path. Red on
/// 5a7e0998b: its order was append, truncate, mark, and a crash between the
/// last two read clean (reviewer ai:code_reviewer-r2's cell,
/// crash_after_a_partial_append_before_the_mark_is_not_a_false_no_gap_r2).
#[test]
fn no_crash_point_on_a_failed_append_reads_clean_4298() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    let snaps = Snapshots::at(tmp.path().join("crash"));
    lose_event_three(&path);
    drop(snaps);
    let snaps = Snapshots(tmp.path().join("crash"));

    for point in [CRASH_BEFORE_MARK, CRASH_AFTER_MARK, CRASH_AFTER_TRUNCATE] {
        let disk = snaps.trail(point);
        assert!(
            disk.exists(),
            "no snapshot at {point}: the seam did not fire"
        );
        assert!(
            !reads_clean(&disk),
            "a crash {point} leaves a disk that verifies CLEAN although event 3 was lost"
        );
    }
    // Before the truncation the partial bytes are still the evidence: a
    // restart refuses the torn last line (#4190) or keeps the loss visible.
    for point in [CRASH_BEFORE_MARK, CRASH_AFTER_MARK] {
        assert!(
            restart_keeps_the_loss_visible(&snaps.trail(point)),
            "restart after a crash {point} hid the loss"
        );
    }
    // After the truncation the trail is as it was, and the mark names the loss.
    let after = verify_chain(&snaps.trail(CRASH_AFTER_TRUNCATE)).expect("verify");
    assert!(after.first_failure.is_none(), "{:?}", after.first_failure);
    assert_eq!(after.gaps, vec![SequenceGap { from: 3, to: 3 }]);
}

/// The ordering itself: by the time the partial record is truncated, the mark
/// on disk already covers the lost sequence. Moving the mark write after the
/// truncation fails this cell.
#[test]
fn the_mark_is_durable_before_the_truncation_4298() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    let snaps = Snapshots::at(tmp.path().join("crash"));
    lose_event_three(&path);

    let at_truncate = snaps.trail(CRASH_AFTER_TRUNCATE);
    assert_eq!(
        read_seq_mark(&seq_mark_path(&at_truncate)).expect("mark readable"),
        Some(3),
        "the truncation ran before the loss of sequence 3 was durable"
    );
    let at_mark = std::fs::metadata(snaps.trail(CRASH_AFTER_MARK))
        .expect("meta")
        .len();
    let at_append = std::fs::metadata(snaps.trail(CRASH_BEFORE_MARK))
        .expect("meta")
        .len();
    assert_eq!(
        at_mark, at_append,
        "nothing may be removed before the mark is durable"
    );
    drop(snaps);
}

/// When the mark cannot be written the loss is not durable, so the partial
/// bytes are never truncated: they stay as the evidence (the #4211 Torn path),
/// and the trail does not verify clean.
#[test]
fn a_failed_mark_write_keeps_the_fragment_4298() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    {
        let _refuse = RefuseMark::on();
        swap_writer(short_then_fail(&path, 17));
        one();
    }
    reopen_real_file(&path);
    one();
    shutdown_for_test();

    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        4,
        "events 1, 2, the kept fragment, event 4: {text}"
    );
    let report = verify_chain(&path).expect("verify");
    let failure = report.first_failure.clone().expect("never clean");
    assert_eq!(failure.kind, VerifyFailureKind::TornRecord);
    assert_eq!(failure.line_number, 3);
    assert_eq!(report.gaps, vec![SequenceGap { from: 3, to: 3 }]);
}

/// Control: without a crash the same loss is removed from the trail and is an
/// exact gap, so the seams above are what make the difference.
#[test]
fn control_no_crash_the_loss_is_an_exact_gap_4298() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    lose_event_three(&path);
    assert_eq!(sequences(&path), vec![1, 2]);
    let report = verify_chain(&path).expect("verify");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert_eq!(report.gaps, vec![SequenceGap { from: 3, to: 3 }]);
}

/// ai:code_reviewer-r2's cell (#4298), adapted to a seam that means the same
/// thing on either ordering: the BEFORE-MARK crash point, the last instant
/// before the lost number reaches the high-water. (The original simulated the
/// crash by restoring the pre-failure mark after the WHOLE failed emit, i.e.
/// it assumed the mark was the last write, a disk the fix makes unreachable.)
/// On 5a7e0998b the before-mark point comes AFTER the truncation, so the disk
/// there is a clean trail with an old mark and this cell is RED (shown with a
/// seam-only patch). On the fix it comes before anything is removed: GREEN.
/// Its question stands: verify must not read clean, before a restart or after
/// a restart and one more write.
#[test]
fn crash_after_a_partial_append_before_the_mark_is_not_a_false_no_gap_r2_4298() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    let snaps = Snapshots::at(tmp.path().join("crash"));
    lose_event_three(&path);
    let disk = snaps.trail(CRASH_BEFORE_MARK);
    drop(snaps);

    // Since #4299 the write-ahead has already put 3 in the mark (unsynced)
    // by this point; the question is unchanged: the disk must not read clean.
    assert_eq!(
        read_seq_mark(&seq_mark_path(&disk)).expect("mark readable"),
        Some(3),
        "the #4299 write-ahead names sequence 3 before the append"
    );
    assert!(
        !reads_clean(&disk),
        "after the crash (no restart) verify read CLEAN although event 3 was lost"
    );
    assert!(
        restart_keeps_the_loss_visible(&disk),
        "after a restart verify read CLEAN although event 3 was lost"
    );
}
