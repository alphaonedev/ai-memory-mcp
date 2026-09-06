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

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_err(sqlstate: Option<&str>) -> StoreError {
        StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            detail: "size_gc delete victim: whatever the server said".to_string(),
            sqlstate: sqlstate.map(str::to_owned),
        }
    }

    #[test]
    fn only_the_two_rolled_back_sqlstates_are_retryable_3520() {
        assert!(is_retryable_tx_sqlstate(SQLSTATE_DEADLOCK_DETECTED));
        assert!(is_retryable_tx_sqlstate(SQLSTATE_SERIALIZATION_FAILURE));
        // 55P03 lock_not_available is the DDL arms' concern, NOT this
        // funnel's: on the DML path a lock_timeout abort means an ordinary
        // writer holds the row and the contention must be surfaced.
        assert!(!is_retryable_tx_sqlstate("55P03"));
        // A constraint violation is permanent; retrying it would delay a
        // refusal the caller needs.
        assert!(!is_retryable_tx_sqlstate("23505"));
        assert!(!is_retryable_tx_sqlstate("57014"));
        assert!(!is_retryable_tx_sqlstate(""));
    }

    #[test]
    fn classification_reads_the_sqlstate_field_never_the_message_3520() {
        assert_eq!(
            retryable_tx_sqlstate(&backend_err(Some(SQLSTATE_DEADLOCK_DETECTED))),
            Some(SQLSTATE_DEADLOCK_DETECTED)
        );
        // The DETAIL says "deadlock detected" verbatim, exactly as the #3520
        // reproduction rendered it — and with no structural code this is NOT
        // retryable. That is the whole point: message text is not evidence.
        let text_only = StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            detail: "size_gc delete victim: error returned from database: deadlock detected"
                .to_string(),
            sqlstate: None,
        };
        assert_eq!(retryable_tx_sqlstate(&text_only), None);
        assert_eq!(retryable_tx_sqlstate(&backend_err(Some("23505"))), None);
        assert_eq!(
            retryable_tx_sqlstate(&StoreError::NotFound {
                id: "x".to_string()
            }),
            None
        );
    }

    #[test]
    fn backoff_doubles_stays_inside_the_ceiling_and_never_reaches_zero_3520() {
        for attempt in 1_u32..=8 {
            for seed in 0_u64..64 {
                let d = backoff_delay_ms(attempt, seed.wrapping_mul(0x9E37_79B9));
                assert!(
                    d >= 1,
                    "attempt {attempt} seed {seed} produced a 0 ms backoff"
                );
                let ceiling = TX_RETRY_MAX_BACKOFF_MS
                    + TX_RETRY_MAX_BACKOFF_MS * TX_RETRY_JITTER_PERCENT / 100;
                assert!(
                    d <= ceiling,
                    "attempt {attempt} seed {seed} produced {d} ms, above the {ceiling} ms band"
                );
            }
        }
        // Undoubled midpoints: attempt 1 centres on the base, attempt 2 on 2x.
        assert_eq!(backoff_delay_ms(1, 10), TX_RETRY_BASE_BACKOFF_MS);
        assert_eq!(backoff_delay_ms(2, 20), TX_RETRY_BASE_BACKOFF_MS * 2);
    }

    #[test]
    fn backoff_actually_spreads_so_victims_do_not_re_collide_3520() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0_u64..256 {
            seen.insert(backoff_delay_ms(3, seed.wrapping_mul(0x9E37_79B9)));
        }
        assert!(
            seen.len() > 8,
            "jitter collapsed to {} distinct delays; a fleet would re-collide",
            seen.len()
        );
    }

    /// The driver contract, exercised without a server: a rolled-back victim
    /// is retried, the body runs again, and the retry is COUNTED (so the live
    /// #3520 regression test can assert on evidence, not on a sleep).
    #[tokio::test]
    async fn a_deadlock_victim_is_retried_and_then_succeeds_3520() {
        let before = retries_total();
        let mut retry = TxRetry::new("unit: victim then commit");
        let mut calls = 0_u32;
        let outcome: StoreResult<u32> = loop {
            calls += 1;
            let attempt: StoreResult<u32> = if calls == 1 {
                Err(backend_err(Some(SQLSTATE_DEADLOCK_DETECTED)))
            } else {
                Ok(calls)
            };
            match attempt {
                Ok(v) => break Ok(v),
                Err(e) => {
                    if let Err(terminal) = retry.consider(e).await {
                        break Err(terminal);
                    }
                }
            }
        };
        assert_eq!(outcome.expect("second attempt commits"), 2);
        assert_eq!(calls, 2, "the transaction body must be re-run exactly once");
        // Per-INSTANCE budget is exact; the process-wide counter is shared
        // with every other test in this binary, so only its direction is
        // assertable here.
        assert_eq!(retry.attempts_failed(), 1);
        assert!(retries_total() > before);
    }

    #[tokio::test]
    async fn a_permanent_error_is_never_retried_3520() {
        let mut retry = TxRetry::new("unit: constraint violation");
        let out = retry.consider(backend_err(Some("23505"))).await;
        assert!(out.is_err(), "a permanent error must propagate immediately");
        assert_eq!(retry.attempts_failed(), 0, "no budget may be burned");
    }

    #[tokio::test]
    async fn a_non_database_fault_is_never_retried_3520() {
        // `sqlstate: None` is the pool / connect / config class: there is no
        // rollback guarantee to lean on, so it must fail through untouched.
        let mut retry = TxRetry::new("unit: pool acquire");
        assert!(retry.consider(backend_err(None)).await.is_err());
        assert_eq!(retry.attempts_failed(), 0, "no budget may be burned");
    }

    #[tokio::test]
    async fn the_budget_is_bounded_and_the_terminal_error_is_preserved_3520() {
        let before = retries_total();
        let mut retry = TxRetry::new("unit: wedged");
        let mut calls = 0_u32;
        let terminal = loop {
            calls += 1;
            let e = backend_err(Some(SQLSTATE_SERIALIZATION_FAILURE));
            if let Err(t) = retry.consider(e).await {
                break t;
            }
            assert!(
                calls < TX_RETRY_MAX_ATTEMPTS,
                "the funnel must not exceed its declared budget"
            );
        };
        // Fail-CLOSED: the caller still sees BackendUnavailable, unchanged.
        assert!(matches!(terminal, StoreError::BackendUnavailable { .. }));
        assert_eq!(
            calls, TX_RETRY_MAX_ATTEMPTS,
            "the funnel must attempt exactly the declared budget"
        );
        assert_eq!(retry.attempts_failed(), TX_RETRY_MAX_ATTEMPTS - 1);
        assert!(retries_total() > before);
    }

    // ------------------------------------------------------------------
    // v1.0.0 #3520 — LIVE regression. Runs iff AI_MEMORY_TEST_POSTGRES_URL
    // is set; otherwise it self-skips so the offline `cargo test` flow is
    // unaffected (the module convention in `store::postgres`).
    //
    // Provokes a REAL SQLSTATE 40P01 the way the issue describes — two
    // sessions taking two relation locks in opposite order — and asserts on
    // EVIDENCE (the funnel's retry counter and the attempt count), never on a
    // sleep: a test that only slept could pass against a funnel that does
    // nothing at all, which is the failure mode this whole issue is about.
    // ------------------------------------------------------------------

    /// Waits until `relation` has at least one PENDING (ungranted) lock
    /// request, i.e. some session is provably blocked on it.
    ///
    /// This is the ORDERING primitive, not an assertion: the two sessions
    /// must enter the cycle in a known order for the victim to be known.
    /// It polls a catalog view rather than sleeping a guessed interval, so a
    /// slow host makes the test slower, never flaky.
    #[cfg(test)]
    async fn await_pending_lock(pool: &sqlx::PgPool, relation: &str) -> bool {
        for _ in 0..600_u32 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks l \
                   JOIN pg_class c ON c.oid = l.relation \
                  WHERE c.relname = $1 AND NOT l.granted",
            )
            .bind(relation)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            if waiting > 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// TWO sessions take TWO relation locks in opposite order. PostgreSQL
    /// detects the cycle and aborts one side with `40P01`; the funnel must
    /// recognise that abort STRUCTURALLY, retry the transaction, and commit.
    ///
    /// Determinism comes from the ordering, not from timing: the funnel
    /// session begins WAITING first (its deadlock check therefore fires
    /// first, and PostgreSQL aborts the process that detects the cycle), and
    /// the peer only requests its second lock once `pg_locks` shows the
    /// funnel is genuinely blocked. The outer bounded repeat exists so that a
    /// host which nonetheless picks the peer as the victim re-runs the
    /// provocation instead of reporting a false green.
    #[tokio::test]
    async fn a_live_40p01_deadlock_is_retried_by_the_funnel_and_commits_3520() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let pool = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip: cannot reach AI_MEMORY_TEST_POSTGRES_URL: {e}");
                return;
            }
        };

        // Per-run relation names so concurrent lib tests cannot collide.
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let (r1, r2) = (format!("t3520_a_{tag}"), format!("t3520_b_{tag}"));
        sqlx::raw_sql(&format!(
            "CREATE TABLE {r1} (x int); CREATE TABLE {r2} (x int);"
        ))
        .execute(&pool)
        .await
        .expect("create scratch relations");

        let mut observed_retry = false;
        let mut total_attempts = 0_u32;
        // Bounded: each round provokes one cycle. Two rounds is already
        // generous given the ordering guarantee below.
        for _round in 0..4_u32 {
            let before = retries_total();
            let peer_pool = pool.clone();
            let (peer_r1, peer_r2) = (r1.clone(), r2.clone());
            let poll_pool = pool.clone();
            let poll_r2 = r2.clone();

            // PEER: holds r2, then queues for r1 — but only once the funnel
            // is provably waiting on r2, so the funnel's deadlock check is
            // the one that fires first and the funnel is the victim.
            //
            // TWO hand-offs, both catalog-observed rather than timed: the
            // funnel may not start until the peer HOLDS r2 (otherwise there
            // is no cycle at all), and the peer may not request r1 until the
            // funnel is BLOCKED on r2 (otherwise the peer waits first and
            // PostgreSQL aborts the peer instead).
            let (holds_r2_tx, holds_r2_rx) = tokio::sync::oneshot::channel::<()>();
            let peer = tokio::spawn(async move {
                let mut tx = peer_pool.begin().await.expect("peer begin");
                sqlx::query(&format!("LOCK TABLE {peer_r2} IN ACCESS EXCLUSIVE MODE"))
                    .execute(&mut *tx)
                    .await
                    .expect("peer locks r2");
                let _ = holds_r2_tx.send(());
                let _blocked = await_pending_lock(&poll_pool, &poll_r2).await;
                let _ = sqlx::query(&format!("LOCK TABLE {peer_r1} IN ACCESS EXCLUSIVE MODE"))
                    .execute(&mut *tx)
                    .await;
                let _ = tx.commit().await;
            });
            if holds_r2_rx.await.is_err() {
                let _ = peer.await;
                continue;
            }

            // FUNNEL: the shared driver, wrapping a transaction that takes
            // r1 then r2 — the opposite order.
            let mut retry = TxRetry::new("test: provoked 40P01");
            let mut attempts = 0_u32;
            let outcome: StoreResult<()> = loop {
                attempts += 1;
                let attempt: StoreResult<()> = async {
                    let mut tx = pool
                        .begin()
                        .await
                        .map_err(|e| super::super::to_store_err("t3520 begin", e))?;
                    sqlx::query(&format!("LOCK TABLE {r1} IN ACCESS EXCLUSIVE MODE"))
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| super::super::to_store_err("t3520 lock r1", e))?;
                    sqlx::query(&format!("LOCK TABLE {r2} IN ACCESS EXCLUSIVE MODE"))
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| super::super::to_store_err("t3520 lock r2", e))?;
                    tx.commit()
                        .await
                        .map_err(|e| super::super::to_store_err("t3520 commit", e))?;
                    Ok(())
                }
                .await;
                match attempt {
                    Ok(()) => break Ok(()),
                    Err(e) => {
                        if let Err(terminal) = retry.consider(e).await {
                            break Err(terminal);
                        }
                    }
                }
            };
            let _ = peer.await;

            outcome.expect("the funnel must COMMIT, not surface the deadlock");
            total_attempts = attempts;
            if retries_total() > before {
                observed_retry = true;
                assert!(
                    attempts >= 2,
                    "a counted retry must correspond to a re-run transaction body"
                );
                break;
            }
        }

        let _ = sqlx::raw_sql(&format!(
            "DROP TABLE IF EXISTS {r1}; DROP TABLE IF EXISTS {r2};"
        ))
        .execute(&pool)
        .await;

        assert!(
            observed_retry,
            "no 40P01 was provoked in the bounded rounds (last attempt count {total_attempts}); \
             the regression test proved nothing"
        );
    }
}
