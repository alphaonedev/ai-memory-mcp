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

    /// Reserved prefix for every relation this suite creates. One prefix, so
    /// "what does this test touch?" has a one-line answer.
    const SCRATCH_PREFIX: &str = "t3520_";

    /// The CI coverage workflow's THROWAWAY postgres container.
    ///
    /// Recorded as an explicit ALLOWED case (lane rule, 2026-09-07): a
    /// live-store guard must key on the database NAME **and** port 5445 when
    /// it guards at all, never on the name alone — because `ai_memory_test`
    /// on port 5432 is exactly the disposable container CI stands up, and a
    /// name-only guard would silently refuse to run there while still looking
    /// green.
    const CI_COVERAGE_STORE_URL: &str =
        "postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test";

    /// The certified f1 tier, for contrast: a DIFFERENT name on a DIFFERENT
    /// port, and equally allowed.
    const CERTIFIED_TIER_STORE_URL: &str =
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_f1_3520?sslmode=verify-full";

    /// Fresh, uuid-scoped scratch relation names for one run of the live
    /// regression.
    ///
    /// This is the property that makes the suite safe to point at ANY store,
    /// and therefore the reason it needs no name/port guard in the first
    /// place: every relation it creates is minted here under
    /// [`SCRATCH_PREFIX`] with a fresh uuid, and dropped at the end. It
    /// touches no substrate table.
    fn scratch_relations() -> (String, String) {
        let tag = uuid::Uuid::new_v4().simple().to_string();
        (
            format!("{SCRATCH_PREFIX}a_{tag}"),
            format!("{SCRATCH_PREFIX}b_{tag}"),
        )
    }

    /// Whether this suite refuses a store URL on its SHAPE — host, port, or
    /// database name — as opposed to on reachability.
    ///
    /// Always `None`, and that is the point: this suite gates ONLY on
    /// `AI_MEMORY_TEST_POSTGRES_URL` being set and the pool connecting. The
    /// function exists as a TRIPWIRE. A future name-only guard — the exact
    /// failure mode the lane rule exists to stop, and one that would exclude
    /// the CI container while the suite still reported green — cannot be
    /// added without either wiring it through here (where the pin below
    /// fails) or deleting a documented function, which a reviewer sees.
    fn store_url_refused_by_shape(_url: &str) -> Option<&'static str> {
        None
    }

    /// Allowed-case pin for the live regression's store gate.
    ///
    /// Both the CI throwaway container and the certified tier must be
    /// admitted, and the uuid isolation that makes admitting anything safe
    /// must be real.
    #[test]
    fn the_live_regression_admits_the_ci_throwaway_store_3520() {
        for url in [CI_COVERAGE_STORE_URL, CERTIFIED_TIER_STORE_URL] {
            assert_eq!(
                store_url_refused_by_shape(url),
                None,
                "the live regression must run against {url}; a name-only or \
                 port-only guard here would silently skip a whole CI leg"
            );
        }

        // The isolation that earns the unguarded gate: uuid-scoped names
        // under one reserved prefix, distinct within a run and across runs.
        let (a, b) = scratch_relations();
        assert!(a.starts_with(SCRATCH_PREFIX) && b.starts_with(SCRATCH_PREFIX));
        assert_ne!(a, b, "the two scratch relations must differ");
        let (c, _) = scratch_relations();
        assert_ne!(a, c, "scratch names must be unique per run");
    }

    /// Prefix of every setup failure of the live cells. A cell that cannot
    /// build its precondition FAILS with this text; it never passes and
    /// never silently retries.
    #[cfg(test)]
    const SETUP_ERROR: &str = "setup error";

    /// Deadline for every wait on the other session in the live cell.
    #[cfg(test)]
    const SETUP_WAIT_DEADLINE: Duration = Duration::from_secs(30);

    /// The peer session's own `deadlock_timeout`. Far above the funnel's
    /// default (1s) and above [`SETUP_WAIT_DEADLINE`], so the peer's deadlock
    /// check can never fire first and the funnel is always the victim.
    #[cfg(test)]
    const PEER_DEADLOCK_TIMEOUT: &str = "60s";

    /// Interval of the catalog poll in [`await_pending_lock`].
    #[cfg(test)]
    const PENDING_LOCK_POLL: Duration = Duration::from_millis(10);

    /// How long the cleanup session waits for a lock on a scratch relation
    /// before it reports a failed cleanup instead of hanging the test run.
    #[cfg(test)]
    const CLEANUP_LOCK_TIMEOUT: &str = "20s";

    /// Prefix of every cleanup failure of the live cell.
    #[cfg(test)]
    const CLEANUP_ERROR: &str = "cleanup error";

    /// Ends every session of this cell that still holds or queues for one of
    /// the scratch `names`, then drops them, on one FRESH connection.
    ///
    /// A cell that fails early leaves its peer task parked on a transaction
    /// that holds `ACCESS EXCLUSIVE` on a scratch relation; a plain
    /// `DROP TABLE` would queue behind it. The names carry a per-run uuid, so
    /// the sessions ended here are this cell's own and no other test's.
    #[cfg(test)]
    async fn drop_scratch(url: &str, names: &[String]) -> anyhow::Result<()> {
        use sqlx::Connection as _;
        let mut conn = sqlx::postgres::PgConnection::connect(url)
            .await
            .map_err(|_| anyhow::anyhow!("{CLEANUP_ERROR}: cannot open the cleanup session"))?;
        sqlx::query(
            "SELECT pg_terminate_backend(l.pid) FROM pg_locks l \
               JOIN pg_class c ON c.oid = l.relation \
              WHERE c.relname = ANY($1) AND l.pid <> pg_backend_pid()",
        )
        .bind(names)
        .execute(&mut conn)
        .await
        .map_err(|e| anyhow::anyhow!("{CLEANUP_ERROR}: ending the cell's sessions: {e}"))?;
        sqlx::query(&format!("SET lock_timeout = '{CLEANUP_LOCK_TIMEOUT}'"))
            .execute(&mut conn)
            .await
            .map_err(|e| anyhow::anyhow!("{CLEANUP_ERROR}: lock_timeout: {e}"))?;
        for name in names {
            sqlx::query(&format!("DROP TABLE IF EXISTS {name}"))
                .execute(&mut conn)
                .await
                .map_err(|e| anyhow::anyhow!("{CLEANUP_ERROR}: dropping {name}: {e}"))?;
        }
        Ok(())
    }

    /// Owns the two scratch tables of the live cell (#9252).
    ///
    /// Created BEFORE the tables, so a half-built setup is cleaned too. The
    /// drop runs on EVERY exit path: [`Self::finish`] on the passing path
    /// (where a failed cleanup fails the cell), and `Drop` on any other exit,
    /// a setup error, a failed assertion or a panic. `Drop` cannot await, so
    /// it runs [`drop_scratch`] on a fresh runtime in its own thread and never
    /// panics (`OWNERSHIP-25`).
    #[cfg(test)]
    struct ScratchRelations {
        url: String,
        names: [String; 2],
        cleaned: bool,
    }

    #[cfg(test)]
    impl ScratchRelations {
        fn new(url: &str, r1: &str, r2: &str) -> Self {
            Self {
                url: url.to_owned(),
                names: [r1.to_owned(), r2.to_owned()],
                cleaned: false,
            }
        }

        async fn finish(mut self) -> anyhow::Result<()> {
            drop_scratch(&self.url, &self.names).await?;
            self.cleaned = true;
            Ok(())
        }
    }

    #[cfg(test)]
    impl Drop for ScratchRelations {
        fn drop(&mut self) {
            if self.cleaned {
                return;
            }
            let url = self.url.clone();
            let names = self.names.clone();
            let joined = std::thread::spawn(move || -> anyhow::Result<()> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| anyhow::anyhow!("{CLEANUP_ERROR}: runtime: {e}"))?;
                rt.block_on(drop_scratch(&url, &names))
            })
            .join();
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("{e}"),
                Err(_) => eprintln!("{CLEANUP_ERROR}: the cleanup thread panicked"),
            }
        }
    }

    /// Waits until `relation` has at least one PENDING (ungranted) lock
    /// request, i.e. some session is provably blocked on it. Returns the
    /// named setup error when the request does not appear before
    /// [`SETUP_WAIT_DEADLINE`].
    ///
    /// This is the ORDERING primitive, not an assertion: the two sessions
    /// must enter the cycle in a known order for the victim to be known.
    /// It polls a catalog view against a deadline rather than sleeping a
    /// guessed interval, so a slow host makes the test slower, never flaky.
    #[cfg(test)]
    async fn await_pending_lock(pool: &sqlx::PgPool, relation: &str) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + SETUP_WAIT_DEADLINE;
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks l \
                   JOIN pg_class c ON c.oid = l.relation \
                  WHERE c.relname = $1 AND NOT l.granted",
            )
            .bind(relation)
            .fetch_one(pool)
            .await
            .map_err(|e| anyhow::anyhow!("{SETUP_ERROR}: pg_locks probe failed: {e}"))?;
            if waiting > 0 {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "{SETUP_ERROR}: no session ever queued a lock request on {relation}"
                ));
            }
            tokio::time::sleep(PENDING_LOCK_POLL).await;
        }
    }

    /// TWO sessions take TWO relation locks in opposite order. PostgreSQL
    /// detects the cycle and aborts one side with `40P01`; the funnel must
    /// recognise that abort STRUCTURALLY, retry the transaction, and commit.
    ///
    /// #9252 — the cycle AND its victim are fixed by construction, with no
    /// timing round and no sleep as a synchroniser:
    ///
    /// 1. the peer holds `r2` and reports that; the funnel takes `r1` and its
    ///    `LOCK` statement RETURNS (the lock is held);
    /// 2. only then is the peer's second step sent: it requests `r1` and parks
    ///    behind the funnel;
    /// 3. the funnel sends its own second step (`LOCK r2`) only after
    ///    `pg_locks` shows the peer's ungranted request on `r1`, so the cycle
    ///    is closed by the FUNNEL's request;
    /// 4. the peer raised its own `deadlock_timeout` (`SET LOCAL`), so its
    ///    deadlock check cannot fire first and PostgreSQL aborts the funnel's
    ///    wait. The peer being the victim is impossible, not merely unlikely.
    ///
    /// Every wait on the other session has a deadline; passing it (or any
    /// refused precondition) is the named `setup error`, never a pass and
    /// never a silent extra round.
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

        // Per-run relation names so concurrent lib tests cannot collide — and
        // so this suite is safe against ANY store it is pointed at. See
        // [`scratch_relations`].
        let (r1, r2) = scratch_relations();
        // Owns both tables from BEFORE they exist: every exit below (a setup
        // panic, a failed assertion, a failed `expect`) drops them (#9252).
        let scratch = ScratchRelations::new(&url, &r1, &r2);
        sqlx::raw_sql(&format!(
            "CREATE TABLE {r1} (x int); CREATE TABLE {r2} (x int);"
        ))
        .execute(&pool)
        .await
        .expect("create scratch relations");

        let mut observed_retry = false;
        let total_attempts: u32;
        // ONE provocation, built in a fixed order (see the doc comment).
        {
            let before = retries_total();
            let peer_pool = pool.clone();
            let (peer_r1, peer_r2) = (r1.clone(), r2.clone());

            // PEER: holds r2 and reports that (or the named setup error that
            // stopped it), then requests r1 only once the funnel reports it
            // HOLDS r1.
            let (peer_ready_tx, peer_ready_rx) =
                tokio::sync::oneshot::channel::<anyhow::Result<()>>();
            let (funnel_holds_r1_tx, funnel_holds_r1_rx) = tokio::sync::oneshot::channel::<()>();
            let peer = tokio::spawn(async move {
                let prepared: Result<_, String> = async {
                    let mut tx = peer_pool
                        .begin()
                        .await
                        .map_err(|e| format!("{SETUP_ERROR}: peer begin: {e}"))?;
                    sqlx::query(&format!(
                        "SET LOCAL deadlock_timeout = '{PEER_DEADLOCK_TIMEOUT}'"
                    ))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        format!(
                            "{SETUP_ERROR}: the peer session cannot raise its own \
                             deadlock_timeout (the role must be allowed to SET it): {e}"
                        )
                    })?;
                    sqlx::query(&format!("LOCK TABLE {peer_r2} IN ACCESS EXCLUSIVE MODE"))
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| format!("{SETUP_ERROR}: peer cannot lock r2: {e}"))?;
                    Ok(tx)
                }
                .await;
                let mut tx = match prepared {
                    Ok(tx) => {
                        let _ = peer_ready_tx.send(Ok(()));
                        tx
                    }
                    Err(setup) => {
                        let _ = peer_ready_tx.send(Err(anyhow::anyhow!("{setup}")));
                        return Err(setup);
                    }
                };
                // The second step is released by the funnel, after it holds r1.
                tokio::time::timeout(SETUP_WAIT_DEADLINE, funnel_holds_r1_rx)
                    .await
                    .map_err(|_| format!("{SETUP_ERROR}: the funnel never reported holding r1"))?
                    .map_err(|_| format!("{SETUP_ERROR}: the funnel ended before holding r1"))?;
                // Parks behind the funnel's r1. It is NOT the victim: its own
                // deadlock check is raised above the whole cell, so this
                // request is granted once the funnel's transaction aborts.
                sqlx::query(&format!("LOCK TABLE {peer_r1} IN ACCESS EXCLUSIVE MODE"))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| format!("peer was aborted instead of the funnel: {e}"))?;
                tx.commit()
                    .await
                    .map_err(|e| format!("peer commit failed: {e}"))
            });

            // FUNNEL: the shared driver, wrapping a transaction that takes
            // r1 then r2 — the opposite order. The barrier runs on the first
            // attempt only; a retry has nothing left to provoke.
            let mut retry = TxRetry::new("test: provoked 40P01");
            let mut barrier = Some((peer_ready_rx, funnel_holds_r1_tx));
            let mut first_abort: Option<String> = None;
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
                    if let Some((peer_ready, funnel_holds_r1)) = barrier.take() {
                        // r1 is held (the LOCK above returned) and the peer
                        // holds r2: release the peer's request, then wait
                        // until the DATABASE shows it parked on r1.
                        match tokio::time::timeout(SETUP_WAIT_DEADLINE, peer_ready).await {
                            Ok(Ok(Ok(()))) => {}
                            Ok(Ok(Err(setup))) => panic!("{setup}"),
                            Ok(Err(_)) => {
                                panic!("{SETUP_ERROR}: the peer ended before locking r2")
                            }
                            Err(_) => panic!("{SETUP_ERROR}: the peer never locked r2"),
                        }
                        let _ = funnel_holds_r1.send(());
                        if let Err(setup) = await_pending_lock(&pool, &r1).await {
                            panic!("{setup}");
                        }
                    }
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
                        if attempts == 1 {
                            first_abort = retryable_tx_sqlstate(&e).map(str::to_owned);
                        }
                        if let Err(terminal) = retry.consider(e).await {
                            break Err(terminal);
                        }
                    }
                }
            };
            let peer_outcome = peer.await.expect("peer task must not panic");
            peer_outcome.expect("the peer must commit after the funnel's abort");

            // The cell proves its own provocation: the funnel's FIRST attempt
            // was aborted with 40P01 itself (not merely "some retryable code").
            eprintln!("t3520 provoked: first abort {first_abort:?}, attempts {attempts}");
            assert_eq!(
                first_abort.as_deref(),
                Some(SQLSTATE_DEADLOCK_DETECTED),
                "the funnel's first attempt must be aborted with 40P01 by construction"
            );

            outcome.expect("the funnel must COMMIT, not surface the deadlock");
            total_attempts = attempts;
            if retries_total() > before {
                observed_retry = true;
                assert!(
                    attempts >= 2,
                    "a counted retry must correspond to a re-run transaction body"
                );
            }
        }

        scratch
            .finish()
            .await
            .expect("the scratch relations must be dropped");

        assert!(
            observed_retry,
            "no 40P01 was provoked in the bounded rounds (last attempt count {total_attempts}); \
             the regression test proved nothing"
        );
    }

    /// #9252 — structural pin on the live 40P01 cell.
    ///
    /// Class: a regression test that can end without having provoked the
    /// state it tests. The present cell picks the deadlock victim by RACING
    /// two deadlock-check timers (the peer's request for the second lock must
    /// land inside the funnel's `deadlock_timeout`), so a slow host makes the
    /// peer the victim, the funnel commits with no retry, and the cell reaches
    /// its "proved nothing" line. That outcome cannot be forced
    /// deterministically from outside the test body, so this pin holds the
    /// invariant on the body itself: the cell never repeats the provocation in
    /// rounds, waits for the other session's lock in the database, and fails
    /// with a named setup error when a precondition is not met.
    #[test]
    fn the_live_40p01_cell_provokes_by_construction_not_in_rounds_9252() {
        const SELF_START: &str = "fn the_live_40p01_cell_provokes_by_construction";
        let source = include_str!("tx_retry.rs");
        let cell_start = source
            .find("async fn a_live_40p01_deadlock_is_retried")
            .expect("the live cell exists");
        let pin_start = source.find(SELF_START).expect("this pin exists");
        let cell = &source[cell_start..pin_start];
        for forbidden in ["for _round", "continue;", "0..4_u32"] {
            assert!(
                !cell.contains(forbidden),
                "the live 40P01 cell must provoke the deadlock by construction; \
                 it still contains `{forbidden}`"
            );
        }
        assert!(
            cell.contains("pg_locks") || cell.contains("await_pending_lock"),
            "the second step must wait for the first lock to be seen in the database"
        );
        assert!(
            cell.contains("SETUP_ERROR"),
            "an unmet provocation precondition must fail with a named setup error"
        );
    }
}
