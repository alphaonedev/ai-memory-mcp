// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4086 — events lost at the TAIL of the flat audit trail just before a
//! restart must not be invisible.
//!
//! An event is numbered before it is written. Pre-#4086 a restart resumed
//! numbering from the last event WRITTEN, so the numbers of events lost after
//! that write were reused and no gap ever appeared: the #4021 gap check and
//! the #3975 counter (which dies with the process) both missed the loss. The
//! fix persists a sequence high-water mark next to the trail and resumes from
//! `max(tail, high-water)`, so the loss is a gap `verify` reports.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::*;

/// A writer that fails like a full disk.
struct Enospc;

impl Write for Enospc {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(28))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(28))
    }
}

/// Swap the live sink's writer (the file stays the sink's configured path).
fn swap_writer(w: Box<dyn Write + Send>) {
    let audit = &RuntimeContext::global().audit;
    let guard = audit.sink.read().expect("sink lock");
    let sink = guard.as_ref().expect("an installed sink");
    sink.inner.lock().expect("sink inner").writer = w;
}

fn reopen_real_file(path: &Path) {
    let f = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("reopen audit log");
    swap_writer(Box::new(f));
}

fn one() {
    emit(EventBuilder::new(
        AuditAction::Store,
        actor("ai:tail-4086", "explicit", None),
        target_memory("m", "ns", None, None, None),
    ));
}

fn sequences(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .expect("read trail")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<AuditEvent>(l)
                .expect("event")
                .sequence
        })
        .collect()
}

fn mark_file(path: &Path) -> PathBuf {
    let mut name = path.file_name().expect("file name").to_os_string();
    name.push(".seq");
    path.with_file_name(name)
}

/// Emit 1 and 2, lose 3 and 4 to a full disk, then "restart".
fn lose_the_tail(path: &Path) {
    init(path, true, false).expect("init");
    one();
    one();
    swap_writer(Box::new(Enospc));
    one();
    one();
    shutdown_for_test();
}

/// The issue's own test shape: after the restart one more event is written;
/// verify must report the lost 3-4 as a gap (red pre-#4086: the new process
/// reused 3 and the trail read 1,2,3 with no gap).
#[test]
fn tail_loss_before_a_restart_becomes_a_detected_gap_4086() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    lose_the_tail(&path);

    init(&path, true, false).expect("re-init after the restart");
    one();
    shutdown_for_test();

    assert_eq!(
        sequences(&path),
        vec![1, 2, 5],
        "the lost numbers 3-4 must never be reused"
    );
    let report = verify_chain(&path).expect("verify");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert_eq!(report.gaps, vec![SequenceGap { from: 3, to: 4 }]);
}

/// With NO write after the restart the loss is still reported: verify reads
/// the persisted high-water and names the trailing range.
#[test]
fn tail_loss_is_reported_even_before_the_next_write_4086() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    lose_the_tail(&path);

    init(&path, true, false).expect("re-init after the restart");
    shutdown_for_test();

    let report = verify_chain(&path).expect("verify");
    assert_eq!(
        report.gaps,
        vec![SequenceGap { from: 3, to: 4 }],
        "a tail loss must not wait for a later write to become visible"
    );
    assert!(
        report.into_result().is_err(),
        "an unacknowledged loss fails verify"
    );
}

/// No false alarm: a clean restart makes no gap, and neither does a flush
/// failure whose line nevertheless reached the file.
#[test]
fn a_clean_restart_or_a_durable_line_leaves_no_gap_4086() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    shutdown_for_test();
    init(&path, true, false).expect("clean restart");
    one();

    // A writer that writes the line but reports a failed flush.
    struct WriteThenFailFlush(std::fs::File);
    impl Write for WriteThenFailFlush {
        fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
            self.0.write(d)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(5))
        }
    }
    let f = OpenOptions::new().append(true).open(&path).expect("open");
    swap_writer(Box::new(WriteThenFailFlush(f)));
    one();
    reopen_real_file(&path);
    shutdown_for_test();
    init(&path, true, false).expect("restart after the flush failure");
    one();
    shutdown_for_test();

    assert_eq!(sequences(&path), vec![1, 2, 3, 4, 5]);
    let report = verify_chain(&path).expect("verify");
    assert!(
        report.gaps.is_empty(),
        "no event was lost: {:?}",
        report.gaps
    );
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
}

/// A high-water mark that cannot be read is not guessed around: the trail
/// cannot know whether events were lost, so init refuses (the binary then
/// refuses to boot, #3651) and verify fails.
#[test]
fn an_unreadable_high_water_mark_fails_closed_4086() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    shutdown_for_test();

    for bad in [&b"not-a-number\n"[..], b"", b"99999999999999999999999999\n"] {
        std::fs::write(mark_file(&path), bad).expect("corrupt the mark");
        let err = init(&path, true, false).expect_err("a corrupt mark must refuse init");
        assert!(
            format!("{err:#}").contains(".seq"),
            "the refusal must name the high-water file: {err:#}"
        );
        shutdown_for_test();
        assert!(
            verify_chain(&path).is_err(),
            "verify must not pass a trail whose high-water mark is unreadable"
        );
    }
}

/// Restores a directory's mode on drop, so a failing assertion never leaves
/// an unremovable temp dir behind.
#[cfg(unix)]
struct RestoreMode(PathBuf, u32);

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

/// f2r item 1: boot must keep working where no new file can be created (a
/// full disk). Pre-#4086 init only opened the trail for append. The mark
/// must not add a boot refusal: an EXISTING mark is updated in place (bytes
/// the file already owns), never through a new temp file.
///
/// The seam is an audit directory with no write permission, which refuses
/// the temp-file create exactly like a full disk while the existing trail and
/// mark stay writable. Red on 6d976adb9: init rewrote the mark through
/// `.seq.tmp` and failed.
#[cfg(unix)]
#[test]
fn init_with_an_existing_mark_needs_no_new_file_4086() {
    use std::os::unix::fs::PermissionsExt as _;
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("audit");
    let path = dir.join("audit.log");
    init(&path, true, false).expect("first boot creates trail + mark");
    one();
    one();
    shutdown_for_test();
    assert!(mark_file(&path).exists(), "the first boot wrote the mark");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod 0500");
    let _restore = RestoreMode(dir.clone(), 0o700);
    // The seam must actually hold (it does not under root); a vacuous pass
    // would prove nothing.
    assert!(
        std::fs::write(dir.join("probe"), b"x").is_err(),
        "seam did not hold: a new file could be created in a 0500 directory \
         (running as root?)"
    );

    init(&path, true, false).expect("a boot that cannot create a new file must still succeed");
    one();
    shutdown_for_test();

    assert_eq!(sequences(&path), vec![1, 2, 3]);
    assert_eq!(
        read_seq_mark(&mark_file(&path)).expect("mark readable"),
        Some(2),
        "the in-place update raised the mark to the trail tail"
    );
    assert!(
        !dir.join("audit.log.seq.tmp").exists(),
        "no temp file on the in-place path"
    );
    let report = verify_chain(&path).expect("verify");
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
}

/// f2r item 2: a trail whose EVERY event was lost (a disk full from the
/// first write) is an empty file with mark = N. That is evidence of
/// consumption, so verify reports 1..=N; it must not read as clean.
/// Red on 6d976adb9: the tail gap required at least one line.
#[test]
fn an_empty_trail_with_a_mark_is_a_gap_not_clean_4086() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    swap_writer(Box::new(Enospc));
    one();
    one();
    shutdown_for_test();

    assert!(sequences(&path).is_empty(), "every write failed");
    let report = verify_chain(&path).expect("verify");
    assert_eq!(report.gaps, vec![SequenceGap { from: 1, to: 2 }]);
    assert!(
        report.into_result().is_err(),
        "an empty trail with lost events must fail verify"
    );
}
