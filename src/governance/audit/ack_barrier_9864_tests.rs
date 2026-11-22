// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9864 — unit cells of the acknowledgement barrier: the ledger's exact
//! refusals, recovery of a timed-out row (K-4), one sync per batch (K-6), the
//! inline-mode write-before-return and the deadline pin. None of them turns
//! on the background writer (a process latch), so none needs an isolated
//! child: the ledger and the batch writer are driven directly.

use super::ack_barrier::Ledger;
use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The exact refusal texts, written out by hand (not taken from `Display`).
const NOT_DURABLE_AT_ZERO: &str = "audit row not durable: the forensic audit writer did not \
     confirm the audit row within 0 ms, so this request is not acknowledged; the mutation may \
     have been applied and its audit row stays queued until the writer recovers (#9864)";
const ROW_NOT_WRITTEN: &str = "audit row not durable: the forensic audit writer could not write \
     an audit row for this request, so it is not acknowledged; the mutation may have been \
     applied (#9864)";

/// A wait long enough that only a missing wake-up reaches it.
const GENEROUS: Duration = Duration::from_secs(20);

fn queue(ledger: &Ledger) -> u64 {
    let mut got = 0;
    ledger
        .enqueue(|seq| {
            got = seq;
            Ok(())
        })
        .expect("enqueue");
    got
}

fn row(actor: &str) -> Box<PendingRow> {
    Box::new(PendingRow {
        now: Utc::now(),
        actor: actor.to_string(),
        decision: "allow".to_string(),
        kind: "bash",
        rule_id: "R9864".to_string(),
        payload: serde_json::json!({}),
    })
}

static REFUSALS_TIMEOUT: AtomicU64 = AtomicU64::new(0);
fn count_timeout() {
    REFUSALS_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}

/// K-1 / K-4: a row the writer has not settled refuses at the deadline with
/// the exact text and one count per refusal; once the writer settles it, the
/// same request's wait succeeds (the row was kept, not dropped).
#[test]
fn a_stalled_row_refuses_with_the_exact_text_then_recovers_9864() {
    let ledger = Ledger::new(count_timeout);
    let since = ledger.mark();
    let seq = queue(&ledger);
    assert_eq!(seq, 1);

    for n in 1..=3_u64 {
        let err = ledger.wait(since, Duration::ZERO).expect_err("not settled");
        assert_eq!(err, AckBarrierError::NotDurable { deadline_ms: 0 });
        assert_eq!(err.to_string(), NOT_DURABLE_AT_ZERO);
        assert!(err.to_string().starts_with(AUDIT_NOT_DURABLE_REASON));
        assert_eq!(
            REFUSALS_TIMEOUT.load(Ordering::Relaxed),
            n,
            "one count per refusal"
        );
    }

    ledger.settle(seq, &[]);
    let _proof: AuditDurable = ledger.wait(since, Duration::ZERO).expect("settled");
    assert_eq!(
        REFUSALS_TIMEOUT.load(Ordering::Relaxed),
        3,
        "a success is not counted"
    );
}

static REFUSALS_FAILED: AtomicU64 = AtomicU64::new(0);
fn count_failed() {
    REFUSALS_FAILED.fetch_add(1, Ordering::Relaxed);
}

/// A row the writer settled as not written refuses every wait marked before
/// it, with the exact text; a request marked after it is not refused for it.
#[test]
fn a_row_not_written_refuses_only_requests_that_queued_before_it_9864() {
    let ledger = Ledger::new(count_failed);
    let before = ledger.mark();
    let seq = queue(&ledger);
    ledger.settle(seq, &[seq]);
    let err = ledger.wait(before, GENEROUS).expect_err("failed row");
    assert_eq!(err, AckBarrierError::RowNotWritten);
    assert_eq!(err.to_string(), ROW_NOT_WRITTEN);
    assert_eq!(REFUSALS_FAILED.load(Ordering::Relaxed), 1);

    let after = ledger.mark();
    let next = queue(&ledger);
    ledger.settle(next, &[]);
    let _proof = ledger
        .wait(after, GENEROUS)
        .expect("a later request is clean");
}

fn no_count() {}

/// A row whose send failed is not counted as enqueued, so no wait waits on a
/// row that will never be settled; the error reaches the caller.
#[test]
fn a_failed_send_is_not_enqueued_and_reaches_the_caller_9864() {
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let err = ledger
        .enqueue(|_| Err(anyhow!("forensic audit writer thread has stopped")))
        .expect_err("send failed");
    assert_eq!(err.to_string(), "forensic audit writer thread has stopped");
    assert_eq!(ledger.mark(), since);
    let _proof = ledger.wait(since, Duration::ZERO).expect("nothing queued");
}

/// The wait is bounded by the deadline, not by the writer: a writer that
/// never settles costs a request the deadline and no more.
#[test]
fn the_wait_ends_at_its_deadline_9864() {
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let _seq = queue(&ledger);
    let deadline = Duration::from_millis(60);
    let started = Instant::now();
    let err = ledger.wait(since, deadline).expect_err("never settled");
    let took = started.elapsed();
    assert_eq!(err, AckBarrierError::NotDurable { deadline_ms: 60 });
    assert!(took >= deadline, "returned before the deadline: {took:?}");
    assert!(took < GENEROUS, "the wait overran its deadline: {took:?}");
}

/// K-6: concurrent waiters on one batch are all released by one settle.
#[test]
fn one_settle_releases_every_concurrent_waiter_9864() {
    const WAITERS: usize = 16;
    let ledger: &'static Ledger = Box::leak(Box::new(Ledger::new(no_count)));
    let since = ledger.mark();
    let mut last = 0;
    for _ in 0..WAITERS {
        last = queue(ledger);
    }
    let ready = Arc::new(std::sync::Barrier::new(WAITERS + 1));
    let handles: Vec<_> = (0..WAITERS)
        .map(|_| {
            let ready = Arc::clone(&ready);
            std::thread::spawn(move || {
                ready.wait();
                ledger.wait(since, GENEROUS).map(drop)
            })
        })
        .collect();
    ready.wait();
    ledger.settle(last, &[]);
    for h in handles {
        assert_eq!(h.join().expect("waiter"), Ok(()));
    }
}

/// K-6: a batch of N rows is written row by row and synced ONCE, and the
/// ledger is settled only after the sync. Red when the sync runs per row or
/// the settle runs before the sync.
#[test]
fn a_batch_is_synced_once_and_settled_after_the_sync_9864() {
    const ROWS: u64 = 32;
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let rows: Vec<_> = (0..ROWS)
        .map(|i| (queue(&ledger), row(&format!("ai:r-{i}"))))
        .collect();
    let mut writes = 0_u64;
    let mut syncs = 0_u64;
    let mut settled_before_sync = true;
    write_batch(
        rows,
        &ledger,
        |_| {
            writes += 1;
            RowOutcome::Written
        },
        || {
            syncs += 1;
            settled_before_sync = ledger.wait(since, Duration::ZERO).is_ok();
            Ok(())
        },
    );
    assert_eq!(writes, ROWS);
    assert_eq!(syncs, 1, "one sync per batch");
    assert!(
        !settled_before_sync,
        "the ledger was settled before the sync"
    );
    let _proof = ledger
        .wait(since, Duration::ZERO)
        .expect("settled after the sync");
}

/// A failed sync makes every written row of the batch not durable.
#[test]
fn a_failed_sync_fails_every_row_of_the_batch_9864() {
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let rows = vec![(queue(&ledger), row("ai:a")), (queue(&ledger), row("ai:b"))];
    write_batch(
        rows,
        &ledger,
        |_| RowOutcome::Written,
        || Err(std::io::Error::other("disk gone")),
    );
    assert_eq!(
        ledger.wait(since, Duration::ZERO).map(drop),
        Err(AckBarrierError::RowNotWritten)
    );
}

/// A batch whose rows were all not written is not synced, and each row is
/// failed; an empty batch settles nothing.
#[test]
fn unwritten_rows_skip_the_sync_and_fail_9864() {
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let seq = queue(&ledger);
    let mut syncs = 0;
    write_batch(
        vec![(seq, row("ai:a"))],
        &ledger,
        |_| RowOutcome::NotWritten,
        || {
            syncs += 1;
            Ok(())
        },
    );
    assert_eq!(syncs, 0);
    assert_eq!(
        ledger.wait(since, Duration::ZERO).map(drop),
        Err(AckBarrierError::RowNotWritten)
    );

    let mark = ledger.mark();
    let _next = queue(&ledger);
    write_batch(Vec::new(), &ledger, |_| RowOutcome::Written, || Ok(()));
    assert_eq!(
        ledger.wait(mark, Duration::ZERO).map(drop),
        Err(AckBarrierError::NotDurable { deadline_ms: 0 }),
        "an empty batch settled a row it did not hold"
    );
}

/// The failed-row window bounds memory without failing open: a mark older
/// than a forgotten failure refuses.
#[test]
fn a_forgotten_failure_still_refuses_an_older_mark_9864() {
    const FAILURES: u64 = 4096 + 8;
    let ledger = Ledger::new(no_count);
    let since = ledger.mark();
    let mut last = 0;
    let mut failed = Vec::new();
    for _ in 0..FAILURES {
        last = queue(&ledger);
        failed.push(last);
    }
    ledger.settle(last, &failed);
    assert_eq!(
        ledger.wait(since, Duration::ZERO).map(drop),
        Err(AckBarrierError::RowNotWritten)
    );
    let later = ledger.mark();
    let next = queue(&ledger);
    ledger.settle(next, &[]);
    assert_eq!(ledger.wait(later, Duration::ZERO).map(drop), Ok(()));
}

/// The barrier deadline sits between the forensic lock budget (a healthy
/// append that met a contended lock still confirms) and the `mcp` stop's
/// in-flight budget (a refused request is answered before it is fenced).
#[test]
fn the_deadline_sits_between_the_lock_budget_and_the_stop_budget() {
    assert!(FORENSIC_LOCK_BUDGET < ACK_BARRIER_DEADLINE);
    assert!(ACK_BARRIER_DEADLINE < crate::mcp::shutdown::IN_FLIGHT_BUDGET);
    assert_eq!(ACK_BARRIER_DEADLINE, Duration::from_secs(5));
}

/// Inline mode (every process but `serve` and `mcp`): the row is in the file
/// when `append_row` returns, so a kill right after it loses nothing.
#[test]
fn inline_mode_row_is_on_disk_when_append_row_returns() {
    let _g = forensic_sink_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(!background_writer_enabled(), "lib tests run in inline mode");
    shutdown();
    let tmp = TempDir::new().expect("tempdir");
    init(tmp.path(), None).expect("init");
    try_record_decision(
        "ai:inline-9864",
        "allow",
        "bash",
        "R9864",
        ForensicPayload::new(),
    )
    .expect("record");
    let path = daily_path(tmp.path(), &Utc::now());
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    shutdown();
    assert_eq!(
        text.lines()
            .filter(|l| l.contains("ai:inline-9864"))
            .count(),
        1,
        "the row is not in {} when append_row returned",
        path.display()
    );
}
