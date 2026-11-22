// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9864 — the acknowledgement barrier: a reply to a request that can mutate
//! leaves the process only once the forensic audit row it produced is durable.
//!
//! Class: an acknowledgement is sent before the state it acknowledges is
//! durable. In `serve` and `mcp` the row goes through the background writer
//! (#1472), so `append_row` returns while the row is still queued; a SIGKILL,
//! an OOM kill or a service-manager stop timeout in that window lost the row
//! of a request the client had already been told succeeded.
//!
//! How it works. Every row queued for the background writer gets a sequence
//! number from the [`Ledger`] (assigned under the sink lock, so sequence order
//! is channel order is chain order). After each batch the writer flushes the
//! file to stable storage (`sync_data`) and then settles the ledger: every
//! sequence number up to the batch's highest is processed, and the ones whose
//! row was not written are recorded as failed. A request handler takes an
//! [`AckMark`] before it runs and calls [`wait_durable`] before it replies: the
//! wait returns the [`AuditDurable`] proof once every row queued so far is
//! processed and none queued after the mark failed, or the named
//! [`AckBarrierError`] at [`ACK_BARRIER_DEADLINE`].
//!
//! Known limit: on a barrier timeout the mutation may already be committed, so
//! the guarantee is "acknowledged implies row", not "mutated implies row";
//! the refusal text says the mutation may have been applied (a retry of
//! `memory_store` upserts on title and namespace, a retry of `memory_link`
//! inserts nothing new), and the row stays queued and is written once the
//! writer recovers. Those two properties bound that window.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long a reply waits for its audit row to be durable. It sits between the
/// forensic lock budget (one append may wait that long for the cross-process
/// lock) and the `mcp` stop's in-flight budget, so a healthy writer that met a
/// contended lock still confirms in time, and a request refused at the bound
/// is answered before the stop path fences it. Pinned by
/// `ack_barrier_9864_tests::the_deadline_sits_between_the_lock_budget_and_the_stop_budget`.
pub const ACK_BARRIER_DEADLINE: Duration = Duration::from_secs(5);

/// Test seam: the barrier deadline in milliseconds, read once in debug and
/// test builds only. `0` makes the barrier look once and refuse if the row is
/// not durable yet, so a test bounds the wait by op count, not wall time.
pub const ACK_BARRIER_DEADLINE_TEST_ENV: &str = "AI_MEMORY_TEST_ACK_BARRIER_DEADLINE_MS";

/// The fixed prefix of every refusal text (the `serve` body and the `mcp`
/// JSON-RPC error message both start with it).
pub const AUDIT_NOT_DURABLE_REASON: &str = "audit row not durable";

/// How many failed sequence numbers the ledger remembers. A wait whose mark
/// is older than the oldest one it forgot refuses (it can no longer prove
/// that none of its rows failed), so the window only bounds memory.
const FAILED_SEQ_WINDOW: usize = 4096;

/// The ledger position a request saw before it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AckMark(u64);

/// Proof that every audit row queued before the wait is on stable storage.
/// Only [`Ledger::wait`] constructs it, so a success reply that needs one
/// cannot be built without the wait (fail closed by construction).
#[must_use]
#[derive(Debug)]
pub struct AuditDurable {
    _private: (),
}

/// The named refusal of the barrier. The reply carries [`Self`]'s `Display`
/// text, which starts with [`AUDIT_NOT_DURABLE_REASON`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckBarrierError {
    /// The writer did not confirm within the deadline. The row stays queued.
    NotDurable {
        /// The deadline that expired, in milliseconds.
        deadline_ms: u64,
    },
    /// The writer processed the row but could not write or sync it.
    RowNotWritten,
}

impl std::fmt::Display for AckBarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDurable { deadline_ms } => write!(
                f,
                "{AUDIT_NOT_DURABLE_REASON}: the forensic audit writer did not confirm the audit \
                 row within {deadline_ms} ms, so this request is not acknowledged; the mutation \
                 may have been applied and its audit row stays queued until the writer recovers \
                 (#9864)"
            ),
            Self::RowNotWritten => write!(
                f,
                "{AUDIT_NOT_DURABLE_REASON}: the forensic audit writer could not write an audit \
                 row for this request, so it is not acknowledged; the mutation may have been \
                 applied (#9864)"
            ),
        }
    }
}

impl std::error::Error for AckBarrierError {}

struct LedgerState {
    /// Highest sequence number handed to the writer.
    enqueued: u64,
    /// Highest sequence number the writer has settled (written and synced,
    /// or recorded as failed).
    processed: u64,
    /// Settled sequence numbers whose row is not durable, oldest first.
    failed: VecDeque<u64>,
    /// The highest failed sequence number dropped from `failed`.
    forgotten_up_to: u64,
}

/// The sequence ledger between the request threads and the background writer.
pub(crate) struct Ledger {
    state: Mutex<LedgerState>,
    settled: Condvar,
    /// Called once per refusal (production: the sink-unavailable metric).
    on_refusal: fn(),
}

impl Ledger {
    pub(crate) const fn new(on_refusal: fn()) -> Self {
        Self {
            state: Mutex::new(LedgerState {
                enqueued: 0,
                processed: 0,
                failed: VecDeque::new(),
                forgotten_up_to: 0,
            }),
            settled: Condvar::new(),
            on_refusal,
        }
    }

    /// A poisoned ledger is still consistent: every update is one field
    /// store, so the data is recovered (per CONCURRENCY-18).
    fn lock(&self) -> MutexGuard<'_, LedgerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hand the next sequence number to `send`, which queues the row. The
    /// number counts as enqueued only when `send` succeeds. The ledger lock is
    /// held across `send` (an unbounded channel send never blocks), so the
    /// writer cannot settle a number the ledger has not counted yet.
    ///
    /// # Errors
    /// `send`'s error, or the sequence space is exhausted.
    pub(crate) fn enqueue(
        &self,
        send: impl FnOnce(u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut st = self.lock();
        let seq = st
            .enqueued
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("forensic audit sequence space exhausted (#9864)"))?;
        send(seq)?;
        st.enqueued = seq;
        Ok(())
    }

    /// The writer settled every number up to `max_seq`; `failed` are those
    /// whose row is not durable.
    pub(crate) fn settle(&self, max_seq: u64, failed: &[u64]) {
        let mut st = self.lock();
        st.processed = st.processed.max(max_seq);
        for &seq in failed {
            st.failed.push_back(seq);
        }
        while st.failed.len() > FAILED_SEQ_WINDOW {
            if let Some(old) = st.failed.pop_front() {
                st.forgotten_up_to = st.forgotten_up_to.max(old);
            }
        }
        drop(st);
        self.settled.notify_all();
    }

    pub(crate) fn mark(&self) -> AckMark {
        AckMark(self.lock().enqueued)
    }

    /// Wait until every row queued so far is settled, at most `deadline`
    /// (zero: look once). Refuses when the deadline passes first, or when a
    /// row queued after `since` failed.
    ///
    /// # Errors
    /// [`AckBarrierError::NotDurable`] at the deadline,
    /// [`AckBarrierError::RowNotWritten`] for a failed row.
    pub(crate) fn wait(
        &self,
        since: AckMark,
        deadline: Duration,
    ) -> Result<AuditDurable, AckBarrierError> {
        let until = Instant::now().checked_add(deadline);
        let mut st = self.lock();
        let target = st.enqueued;
        while st.processed < target {
            let now = Instant::now();
            let remaining = match until {
                Some(until) => until.saturating_duration_since(now),
                // A deadline past `Instant`'s range: wait in the largest steps.
                None => Duration::MAX,
            };
            if remaining.is_zero() {
                drop(st);
                return Err(self.refuse(AckBarrierError::NotDurable {
                    deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                }));
            }
            st = match self.settled.wait_timeout(st, remaining) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        let failed = st.forgotten_up_to > since.0
            || st.failed.iter().any(|&seq| seq > since.0 && seq <= target);
        drop(st);
        if failed {
            return Err(self.refuse(AckBarrierError::RowNotWritten));
        }
        Ok(AuditDurable { _private: () })
    }

    fn refuse(&self, e: AckBarrierError) -> AckBarrierError {
        (self.on_refusal)();
        e
    }
}

/// The process ledger of the background writer.
pub(crate) static LEDGER: Ledger = Ledger::new(crate::metrics::inc_forensic_sink_unavailable);

/// Take the mark before a request that can mutate runs.
#[must_use]
pub fn ack_mark() -> AckMark {
    LEDGER.mark()
}

/// Block until the audit rows of a request marked with `since` are durable,
/// at most [`ACK_BARRIER_DEADLINE`]. In a process without the background
/// writer nothing is ever enqueued, so this returns at once.
///
/// # Errors
/// The named [`AckBarrierError`]; each refusal is counted in
/// `ai_memory_forensic_sink_unavailable_total`.
pub fn wait_durable(since: AckMark) -> Result<AuditDurable, AckBarrierError> {
    LEDGER.wait(since, ack_barrier_deadline())
}

/// The deadline in force: [`ACK_BARRIER_DEADLINE`], or the test seam.
pub(crate) fn ack_barrier_deadline() -> Duration {
    #[cfg(any(test, debug_assertions))]
    {
        static SEAM: std::sync::OnceLock<Option<Duration>> = std::sync::OnceLock::new();
        if let Some(d) = *SEAM.get_or_init(|| {
            std::env::var(ACK_BARRIER_DEADLINE_TEST_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_millis)
        }) {
            return d;
        }
    }
    ACK_BARRIER_DEADLINE
}
