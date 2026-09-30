// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4191 — `audit verify` checks the HEAD of the trail, not only the space
//! between two lines.
//!
//! Every trail verify accepts starts at the genesis anchor
//! ([`CHAIN_HEAD_PREV_HASH`]), whose sequence is 0: a first line that does
//! not chain to it already fails `ChainBreak`. So the first line is held to
//! the same rules as every later one. Events numbered and lost before the
//! first successful write leave a first line above 1, reported as the gap
//! `1..=first-1`; a first line with sequence 0 fails `Sequence`.

use std::path::Path;

use super::tail_loss_4086_tests::{Enospc, one, reopen_real_file, sequences, swap_writer};
use super::*;

/// The real mechanism: the first two writes of a fresh trail fail like a
/// full disk (each consumes its number first), the third succeeds. The trail
/// then starts at sequence 3. Red on 04f6fdd26: the head was exempt, so it
/// verified clean.
#[test]
fn events_lost_before_the_first_write_are_a_head_gap_4191() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    swap_writer(Box::new(Enospc));
    one();
    one();
    reopen_real_file(&path);
    one();
    shutdown_for_test();

    assert_eq!(
        sequences(&path),
        vec![3],
        "only the third event reached the trail"
    );
    let head_gap = vec![SequenceGap { from: 1, to: 2 }];
    // The chain alone shows it (no high-water mark consulted) ...
    let from_reader =
        verify_chain_from_reader(std::fs::File::open(&path).expect("open")).expect("verify");
    assert!(
        from_reader.first_failure.is_none(),
        "{:?}",
        from_reader.first_failure
    );
    assert_eq!(from_reader.gaps, head_gap);
    // ... and the file verifier reports it once, not twice.
    let report = verify_chain(&path).expect("verify");
    assert_eq!(report.gaps, head_gap);
    assert!(
        report.into_result().is_err(),
        "a head loss must fail verify"
    );
}

/// Re-hash `ev` after a field edit, as a forger with the file would.
fn rehash(mut ev: AuditEvent) -> AuditEvent {
    ev.self_hash = String::new();
    ev.self_hash = compute_self_hash(&ev);
    ev
}

/// Two well-formed, correctly chained lines whose first carries sequence 0.
fn trail_with_a_zero_head(path: &Path) -> String {
    let _g = sink_test_lock();
    init(path, true, false).expect("init");
    one();
    one();
    shutdown_for_test();
    let text = std::fs::read_to_string(path).expect("read");
    let mut lines = text
        .lines()
        .map(|l| serde_json::from_str::<AuditEvent>(l).expect("event"));
    let mut first = lines.next().expect("line 1");
    let mut second = lines.next().expect("line 2");
    first.sequence = 0;
    let first = rehash(first);
    second.prev_hash = first.self_hash.clone();
    second.sequence = u64::MAX;
    let second = rehash(second);
    format!(
        "{}\n{}\n",
        serde_json::to_string(&first).expect("ser"),
        serde_json::to_string(&second).expect("ser")
    )
}

/// A genesis-anchored first line with sequence 0 is refused, and it no
/// longer switches off the monotonic check for the next line. Red on
/// 04f6fdd26: sequence 0 then u64::MAX verified clean.
#[test]
fn a_zero_sequence_head_fails_verify_4191() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    let forged = trail_with_a_zero_head(&path);

    let report = verify_chain_from_reader(forged.as_bytes()).expect("verify");
    let failure = report.first_failure.expect("a zero head must not verify");
    assert_eq!(failure.kind, VerifyFailureKind::Sequence);
    assert_eq!(failure.line_number, 1);
}

/// No false alarm: a trail that starts at 1 has no head gap.
#[test]
fn a_trail_starting_at_one_has_no_head_gap_4191() {
    let _g = sink_test_lock();
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("audit.log");
    init(&path, true, false).expect("init");
    one();
    one();
    shutdown_for_test();

    assert_eq!(sequences(&path), vec![1, 2]);
    let report = verify_chain(&path).expect("verify");
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report.into_result().is_ok());
}
