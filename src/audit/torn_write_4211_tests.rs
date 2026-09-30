// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4211 — a failed audit write must not leave a fragment the next record is
//! glued onto.
//!
//! The record and its newline go out as one buffer through one `write_all`.
//! When the write fails part-way, the bytes it left are removed (under the
//! trail lock, and only when they are provably this write's own), so the
//! trail is exactly as it was and the lost event is an ordinary gap. When
//! they cannot be removed (the append-only OS flag refuses truncation), the
//! next record starts its own line and `verify` reports a `TornRecord`: never
//! clean, but the chain is checked across it and the gap is still reported.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;

use super::tail_loss_4086_tests::{one, reopen_real_file, sequences, swap_writer};
use super::*;

/// A writer that hands the first `n` bytes of the next record to the real
/// trail (all but the last byte when `n` is `None`), then fails like a full
/// disk: the partial-write shape of ENOSPC.
struct ShortThenFail {
    file: std::fs::File,
    n: Option<usize>,
    done: bool,
}

impl Write for ShortThenFail {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.done {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        self.done = true;
        let k = self
            .n
            .unwrap_or_else(|| buf.len().saturating_sub(1))
            .min(buf.len());
        self.file.write_all(&buf[..k])?;
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn short_then_fail(path: &Path, n: Option<usize>) -> Box<ShortThenFail> {
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

/// Restores the truncation seam on drop, so a failing cell cannot leak it.
struct RefuseTruncation;

impl RefuseTruncation {
    fn on() -> Self {
        REFUSE_TRUNCATION_FOR_TEST.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for RefuseTruncation {
    fn drop(&mut self) {
        REFUSE_TRUNCATION_FOR_TEST.store(false, Ordering::SeqCst);
    }
}

/// Every non-blank line of the trail parses on its own: nothing was glued.
fn every_line_parses(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .expect("read trail")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .all(|l| serde_json::from_str::<AuditEvent>(l).is_ok())
}

/// Event 1 written, event 2 short-written then failed, event 3 written.
fn write_one_torn_between_two(path: &Path, landed: usize) {
    init(path, true, false).expect("init");
    one();
    swap_writer(short_then_fail(path, Some(landed)));
    one();
    reopen_real_file(path);
    one();
    shutdown_for_test();
}

/// The issue's cell: a short write followed by a good record. The fragment is
/// removed, the good record is verifiable, and the lost event 2 is a gap.
/// Red on 04f6fdd26: event 3 was glued onto the fragment and verify stopped
/// with Parse at line 2.
#[test]
fn a_short_write_is_removed_and_the_loss_is_a_gap_4211() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    write_one_torn_between_two(&path, 17);

    assert!(every_line_parses(&path), "no glued fragment");
    assert_eq!(sequences(&path), vec![1, 3]);
    let report = verify_chain(&path).expect("verify");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert!(report.torn_lines.is_empty());
    assert_eq!(report.gaps, vec![SequenceGap { from: 2, to: 2 }]);
}

/// When truncation is refused, the fragment stays but is its own line: the
/// next record is not glued, verify checks the chain across the fragment,
/// fails as TornRecord (never clean), and still reports the gap.
/// Red on 04f6fdd26: glued, Parse at line 2, no gap.
#[test]
fn an_unremovable_fragment_is_a_torn_record_not_a_glued_line_4211() {
    let _g = sink_test_lock();
    let _refuse = RefuseTruncation::on();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    write_one_torn_between_two(&path, 17);

    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "event 1, the fragment, event 3: {text}");
    assert!(
        serde_json::from_str::<AuditEvent>(lines[2]).is_ok(),
        "event 3 stands alone"
    );
    let report = verify_chain(&path).expect("verify");
    let failure = report.first_failure.clone().expect("never clean");
    assert_eq!(failure.kind, VerifyFailureKind::TornRecord);
    assert_eq!(failure.line_number, 2);
    assert_eq!(report.torn_lines, vec![2]);
    assert_eq!(report.gaps, vec![SequenceGap { from: 2, to: 2 }]);
    assert!(report.into_result().is_err());
}

/// The second shape: everything but the newline landed and truncation is
/// refused. Finishing the line completes the record, so it was not lost.
#[test]
fn a_record_missing_only_its_newline_is_completed_4211() {
    let _g = sink_test_lock();
    let _refuse = RefuseTruncation::on();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    swap_writer(short_then_fail(&path, None));
    one();
    reopen_real_file(&path);
    one();
    shutdown_for_test();

    assert!(every_line_parses(&path));
    assert_eq!(sequences(&path), vec![1, 2, 3]);
    let report = verify_chain(&path).expect("verify");
    assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
}

/// The verify rule on its own. A torn line needs the NEXT record to chain to
/// the record before it; otherwise the old failures stand.
#[test]
fn verify_treats_only_a_passed_around_line_as_torn_4211() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    shutdown_for_test();
    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();

    // Garbage between two chained records: torn.
    let between = format!("{}\n{{\"torn\n{}\n", lines[0], lines[1]);
    let r = verify_chain_from_reader(between.as_bytes()).expect("verify");
    assert_eq!(
        r.first_failure.expect("fails").kind,
        VerifyFailureKind::TornRecord
    );
    assert_eq!(r.torn_lines, vec![2]);

    // Garbage replacing a record: the next one does not chain, so this is the
    // Parse failure it always was, at the garbage line.
    let replacing = format!("{{\"torn\n{}\n", lines[1]);
    let r = verify_chain_from_reader(replacing.as_bytes()).expect("verify");
    let f = r.first_failure.expect("fails");
    assert_eq!(f.kind, VerifyFailureKind::Parse);
    assert_eq!(f.line_number, 1);

    // Trailing garbage: nothing passes around it, Parse.
    let trailing = format!("{}\n{}\n{{\"torn\n", lines[0], lines[1]);
    let r = verify_chain_from_reader(trailing.as_bytes()).expect("verify");
    let f = r.first_failure.expect("fails");
    assert_eq!(f.kind, VerifyFailureKind::Parse);
    assert_eq!(f.line_number, 3);
}
