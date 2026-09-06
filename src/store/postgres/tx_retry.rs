// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3520 — the SHARED bounded-retry funnel for a postgres transaction
//! that PostgreSQL itself aborted as a concurrency victim.
//!
//! # The defect this closes
//!
//! `store::postgres` opens a transaction per destructive operation
//! (archive-copy + link snapshot + cascade DELETE + AGE unprojection, all in
//! one tx). A daemon booting — or self-healing — against the same live
//! database runs its idempotent bootstrap DDL concurrently, and
//! `CREATE INDEX IF NOT EXISTS` takes a relation-level `ShareLock` even when
//! the index already exists. Two sessions taking two relation locks in
//! opposite orders is a textbook deadlock, and PostgreSQL resolves it by
//! aborting one side with SQLSTATE `40P01`. Pre-#3520 the store surfaced that
//! abort verbatim as [`StoreError::BackendUnavailable`] and the caller's
//! operation simply FAILED — observed on the #3519 gate as
//! `size_gc archive: BackendUnavailable { detail: "size_gc delete victim:
//! ... deadlock detected" }`.
//!
//! # Why retrying is SAFE here, and only here
//!
//! On `40P01` (`deadlock_detected`) and `40001` (`serialization_failure`)
//! PostgreSQL has ALREADY rolled the whole transaction back, atomically:
//! nothing the aborted attempt wrote is visible to anyone, and the connection
//! is returned to a clean state. Re-running the SAME transaction body is
//! therefore not a partial-write replay — it is a first attempt against an
//! unchanged database. That is what makes this a DEGRADE (a few milliseconds
//! of extra latency) rather than a data-integrity trade.
//!
//! Three limits keep it that way, and all three are load-bearing:
//!
//! 1. **Only these two SQLSTATEs.** Every other failure — a constraint
//!    violation, a syntax error, a disk-full, a `lock_timeout` — is either
//!    permanent or has a different disposition, so retrying it burns budget
//!    and delays a refusal the caller needs to see. `55P03`
//!    (`lock_not_available`) is deliberately EXCLUDED: on the DML path a
//!    `lock_timeout` abort means an ordinary writer is holding the row and
//!    the correct answer is to surface the contention, not to hammer it.
//!    (The blocking-DDL arms have their own, differently-tuned budget — see
//!    `DDL_RETRYABLE_SQLSTATES` in the parent module.)
//! 2. **Classification is STRUCTURAL.** The decision reads the SQLSTATE the
//!    driver reported, carried on
//!    [`StoreError::BackendUnavailable::sqlstate`] by `to_store_err`. It
//!    NEVER substring-matches the rendered message: postgres message text is
//!    an operator-facing rendering that is free to change per server version
//!    and per locale, and branching control flow on it is how a transient
//!    abort gets mistaken for a permanent one (or, worse, the reverse).
//! 3. **The body must be a whole TRANSACTION and nothing else.** A caller
//!    wraps `begin` -> statements -> `commit`. It must not perform work whose
//!    effects live outside that transaction — no file writes, no channel
//!    sends, no counter mutation, no consuming a moved-in value it cannot
//!    re-derive — because those would run twice while the database work ran
//!    once. Wrapping a NON-transactional statement here would be worse than
//!    not retrying at all.
//!
//! # Fail-closed terminal state
//!
//! After [`TX_RETRY_MAX_ATTEMPTS`] the ORIGINAL
//! [`StoreError::BackendUnavailable`] is returned unchanged. The bound exists
//! so a genuinely wedged database produces a clear, prompt refusal instead of
//! an unbounded stall — the same reasoning as the #2614 blocking-DDL budget.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::store::{StoreError, StoreResult};

/// Where this funnel's retry lines land. A dedicated child of the adapter's
/// `store::postgres` target so an operator can raise ONLY the retry chatter
/// (`RUST_LOG=store::postgres::tx_retry=debug`) without the whole adapter.
const TRACE_TARGET: &str = "store::postgres::tx_retry";

/// SQLSTATE `40P01` — `deadlock_detected`. PostgreSQL detected a lock cycle
/// and chose THIS transaction as the victim; the transaction is fully rolled
/// back before the error is reported.
pub(crate) const SQLSTATE_DEADLOCK_DETECTED: &str = "40P01";

/// SQLSTATE `40001` — `serialization_failure`. The transaction could not be
/// serialised against a concurrent one; likewise fully rolled back.
pub(crate) const SQLSTATE_SERIALIZATION_FAILURE: &str = "40001";

/// The CLOSED set of SQLSTATEs this funnel retries. Adding to it is a
/// data-integrity decision, not a tuning decision: every member must be a
/// code for which PostgreSQL guarantees the transaction was rolled back
/// atomically before reporting.
pub(crate) const TX_RETRYABLE_SQLSTATES: &[&str] =
    &[SQLSTATE_DEADLOCK_DETECTED, SQLSTATE_SERIALIZATION_FAILURE];

/// Total attempts (the first try plus the retries). Three is the same shape
/// as [`super::DDL_ARM_MAX_ATTEMPTS`]: a deadlock victim's peer commits in
/// milliseconds, so if two further attempts both lose the race the
/// contention is structural and the caller deserves the refusal now.
pub(crate) const TX_RETRY_MAX_ATTEMPTS: u32 = 3;

/// Base backoff (ms) before the FIRST retry; doubled per subsequent attempt
/// and then jittered. Deliberately small — unlike the DDL arms (seconds,
/// waiting out a long-running writer) the peer here is an ordinary
/// transaction that has already committed or aborted by the time we notice.
pub(crate) const TX_RETRY_BASE_BACKOFF_MS: u64 = 20;

/// Ceiling (ms) for the doubling backoff, so the whole budget stays a small
/// multiple of a request rather than a visible stall.
pub(crate) const TX_RETRY_MAX_BACKOFF_MS: u64 = 320;

/// Symmetric jitter applied to each backoff, in percent. UNLIKE the
/// migration advisory lock — where exactly one node is ever in the loop, so
/// #3519 correctly applies no jitter — a deadlock can pick several victims
/// across a fleet at once, and an unjittered doubling schedule would march
/// them back into the same collision. This is the anti-thundering-herd term.
pub(crate) const TX_RETRY_JITTER_PERCENT: u64 = 50;

/// Count of retries this process has actually performed, across every
/// funnel. Observability first (it is the honest answer to "is my fleet
/// deadlocking?"), and it also lets the #3520 regression test assert that a
/// provoked `40P01` was RETRIED rather than merely succeeding on a sleep.
static TX_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Reads the process-wide retry counter. Monotonic; a test takes a
/// before/after delta rather than an absolute value so it composes with any
/// other retry that happened in the same binary.
pub(crate) fn retries_total() -> u64 {
    TX_RETRIES_TOTAL.load(Ordering::Relaxed)
}

/// `true` when `code` is one of the two SQLSTATEs PostgreSQL guarantees it
/// rolled the transaction back for. Pure, so the decision is unit-testable
/// without a live server (`sqlx::Error` has no public constructor for a
/// database error).
pub(crate) fn is_retryable_tx_sqlstate(code: &str) -> bool {
    TX_RETRYABLE_SQLSTATES.contains(&code)
}

/// The retryable SQLSTATE carried by `e`, or `None` when this error is not a
/// retryable postgres transaction abort.
///
/// Reads the STRUCTURAL [`StoreError::BackendUnavailable::sqlstate`] field —
/// never the rendered `detail`. An error from any other variant, from a
/// non-database fault (pool/connect/config, where `sqlstate` is `None`), or
/// carrying a code outside [`TX_RETRYABLE_SQLSTATES`], is not retryable.
pub(crate) fn retryable_tx_sqlstate(e: &StoreError) -> Option<&str> {
    let StoreError::BackendUnavailable { sqlstate, .. } = e else {
        return None;
    };
    sqlstate
        .as_deref()
        .filter(|code| is_retryable_tx_sqlstate(code))
}

/// Backoff (ms) before the retry that FOLLOWS `attempt` (1-based), jittered
/// symmetrically by [`TX_RETRY_JITTER_PERCENT`] using `seed`.
///
/// Pure so the bound and the spread are both testable without a clock. The
/// result is always at least 1 ms: a zero backoff would spin the two victims
/// straight back into each other.
pub(crate) fn backoff_delay_ms(attempt: u32, seed: u64) -> u64 {
    let doubled = TX_RETRY_BASE_BACKOFF_MS
        .saturating_mul(1_u64 << attempt.saturating_sub(1).min(16))
        .min(TX_RETRY_MAX_BACKOFF_MS);
    let span = doubled.saturating_mul(TX_RETRY_JITTER_PERCENT.min(99)) / 100;
    if span == 0 {
        return doubled.max(1);
    }
    let width = span.saturating_mul(2).saturating_add(1);
    let offset = seed % width;
    doubled.saturating_add(offset).saturating_sub(span).max(1)
}

/// A fresh jitter seed. `OsRng` rather than a process-static counter so two
/// daemons that boot together do not draw the same schedule (the
/// `wake_sink::uds` reconnect-jitter precedent).
fn jitter_seed() -> u64 {
    use rand_core::RngCore as _;
    rand_core::OsRng.next_u64()
}

/// The bounded-retry DRIVER for one postgres transaction.
///
/// Deliberately a small state machine rather than a `run(closure)` helper.
/// A closure-taking funnel cannot be expressed here without either boxing
/// every attempt's future or an unstable `AsyncFnMut::CallRefFuture` bound:
/// the `MemoryStore` trait is `#[async_trait]`, so every method future must
/// be `Send`, and a higher-ranked closure future is not provably `Send` for
/// all lifetimes. This shape keeps the transaction body INLINE at the call
/// site — which also keeps the "no effects outside the transaction"
/// invariant visible to the reader who has to uphold it — while classifying,
/// budgeting, pacing, logging and counting in exactly ONE place.
///
/// Usage:
///
/// ```ignore
/// let mut retry = tx_retry::TxRetry::new("size_gc victim tx");
/// loop {
///     let attempt: StoreResult<()> = async {
///         let mut tx = self.pool.begin().await.map_err(...)?;
///         // ... statements ...
///         tx.commit().await.map_err(...)?;
///         Ok(())
///     }
///     .await;
///     match attempt {
///         Ok(()) => break,
///         Err(e) => retry.consider(e).await?,
///     }
/// }
/// ```
pub(crate) struct TxRetry<'a> {
    /// Operation name for the WARN line; never interpolated into SQL.
    label: &'a str,
    /// 1-based index of the attempt that just failed.
    attempt: u32,
}

impl<'a> TxRetry<'a> {
    /// A fresh budget for one logical transaction.
    pub(crate) const fn new(label: &'a str) -> Self {
        Self { label, attempt: 1 }
    }

    /// How many attempts have failed so far. Exposed for call-site assertions
    /// and for tests that pin the budget.
    #[cfg(test)]
    pub(crate) const fn attempts_failed(&self) -> u32 {
        self.attempt - 1
    }

    /// Decides what to do about a failed transaction attempt.
    ///
    /// `Ok(())` means PostgreSQL rolled the transaction back as a concurrency
    /// victim, budget remains, and this call has already paced the retry —
    /// the caller re-runs the SAME transaction body.
    ///
    /// # Errors
    ///
    /// Returns `err` UNCHANGED when it is not a retryable rollback, or when
    /// the bounded budget is spent. The caller propagates it, so the funnel
    /// stays fail-CLOSED: a wedged database produces a prompt refusal, never
    /// a silent partial application and never an unbounded stall.
    pub(crate) async fn consider(&mut self, err: StoreError) -> StoreResult<()> {
        // Copy the code out before the borrow ends: `err` is moved on both
        // non-retry exits below.
        let Some(sqlstate) = retryable_tx_sqlstate(&err).map(str::to_owned) else {
            return Err(err);
        };

        if self.attempt >= TX_RETRY_MAX_ATTEMPTS {
            tracing::warn!(
                target: TRACE_TARGET,
                op = self.label,
                sqlstate = %sqlstate,
                attempts = self.attempt,
                max_attempts = TX_RETRY_MAX_ATTEMPTS,
                "#3520: postgres transaction still aborted as a concurrency victim after the bounded retry budget; refusing (fail-closed)"
            );
            return Err(err);
        }

        let backoff_ms = backoff_delay_ms(self.attempt, jitter_seed());
        tracing::warn!(
            target: TRACE_TARGET,
            op = self.label,
            sqlstate = %sqlstate,
            attempt = self.attempt,
            max_attempts = TX_RETRY_MAX_ATTEMPTS,
            backoff_ms,
            "#3520: postgres rolled this transaction back as a concurrency victim; retrying"
        );
        TX_RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        self.attempt = self.attempt.saturating_add(1);
        Ok(())
    }
}
