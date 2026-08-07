// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2583](https://github.com/alphaonedev/ai-memory-mcp/issues/2583) —
//! paced refresh of the `ai_memory_memories` corpus-size gauge, so a
//! Prometheus scrape stops doing O(corpus) database work.
//!
//! **What this replaces.** `GET /metrics` called `db::stats` on EVERY
//! scrape and used exactly ONE of the ten fields it computes
//! (`stats.total`). `db::stats` issues eight statements — three `COUNT`s
//! over `memories`, two full `GROUP BY` aggregations (tier, namespace),
//! an expiring-soon `COUNT`, a `COUNT` over `memory_links`, and
//! `dim_violations`, which walks every row's `embedding` BLOB. Measured on
//! a real corpus the set costs ~15 ms at 8k rows and ~130 ms at 130k rows,
//! of which `dim_violations` alone is 11 ms and 98 ms — and all of it was
//! thrown away except the first `COUNT`. Worse, it ran while holding the
//! daemon's single `Arc<Mutex<Connection>>`, and `/metrics` is exempt from
//! admission control, so scrape rate — which the daemon does not control —
//! multiplied a corpus-proportional mutex hold.
//!
//! **What this does instead.** A background loop issues ONE
//! `SELECT COUNT(*) FROM memories` on a paced cadence and publishes it into
//! the gauge. The scrape path renders pre-computed values and touches no
//! database at all, so its cost is independent of both corpus size AND
//! scrape rate. `ai_memory_memories` is a GAUGE that Prometheus already
//! samples at 15-60 s, so bounded staleness costs nothing an operator did
//! not already have.
//!
//! **The freshness gauge is not optional.** A refresh loop that dies would
//! otherwise freeze `ai_memory_memories` at a plausible-looking value
//! forever — including through a mass deletion — while Prometheus `up`
//! stays 1. That is precisely the
//! [#2444](https://github.com/alphaonedev/ai-memory-mcp/issues/2444)
//! shape, so this module also publishes
//! `ai_memory_memories_refreshed_at_seconds` and alert rules can assert
//! freshness (`time() - ai_memory_memories_refreshed_at_seconds > N`).
//! `0` means "never computed", which is distinguishable from a genuine
//! empty corpus (where the count gauge is 0 but the timestamp is not).
//!
//! An incrementally-maintained in-process counter was considered and
//! REJECTED: other OS processes write the same SQLite file (the MCP stdio
//! server, `ai-memory curator`, every CLI invocation), so an in-process
//! delta would DRIFT and publish a confidently wrong number. SQLite also
//! has no `pg_class.reltuples` equivalent — `COUNT(*)` scans the narrowest
//! index end to end and `sqlite_stat1` holds only a stale post-`ANALYZE`
//! estimate — so a cheap exact count does not exist and a cheap estimate
//! would be a wrong number sold as truth. Paced-and-honest beats both.
//!
//! Design resolved by the 5-agent adversarial vote (`4d3ea1c5`), 4-1 for
//! the pre-computed gauge over a per-scrape single `COUNT`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Operator override for the refresh cadence, in whole seconds. `0`
/// disables the loop; the gauge then carries whatever the scrape path's
/// cold-start prime computed and its freshness timestamp exposes the age.
pub const ENV_INTERVAL_SECS: &str = "AI_MEMORY_METRICS_GAUGE_REFRESH_SECS";

/// Default cadence: 60 s. Corpus size does not move meaningfully inside a
/// minute, and one `COUNT` per minute is ~0.2% duty cycle even at a
/// million rows.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// `tracing` target for every event this module emits.
pub const TRACE_TARGET: &str = "ai_memory::metrics_gauge";

/// Resolve the configured cadence: [`ENV_INTERVAL_SECS`] when it parses to
/// a `u64`, else [`DEFAULT_INTERVAL`]. An explicit `0` disables the loop;
/// an unparseable value falls through to the default rather than silently
/// freezing the gauge.
#[must_use]
pub fn resolve_interval() -> Duration {
    match std::env::var(ENV_INTERVAL_SECS) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => DEFAULT_INTERVAL,
        },
        Err(_) => DEFAULT_INTERVAL,
    }
}

/// Publish `total` (and the wall-clock instant it was computed) onto an
/// EXPLICIT metrics handle.
///
/// Taking the handle rather than reaching for the process-global registry is
/// what makes the publish contract testable: the two gauges must move
/// together or not at all, and asserting that on a process-global that every
/// other test in the binary also mutates is a race, not a test.
pub fn publish_into(metrics: &crate::metrics::Metrics, total: i64, now_unix: i64) {
    metrics.memories_gauge.set(total);
    metrics.memories_gauge_refreshed_at.set(now_unix);
}

/// Publish onto the process metrics registry — the production entry point.
pub fn publish(total: i64, now_unix: i64) {
    publish_into(crate::metrics::registry(), total, now_unix);
}

/// Read the corpus size with ONE statement.
///
/// Deliberately NOT `db::stats`: the gauge needs `total` and nothing else,
/// and every other field that function computes is a full scan or a full
/// aggregation whose result the scrape path discarded.
///
/// # Errors
///
/// Propagates the rusqlite error; the caller logs and leaves the previous
/// gauge value in place (a stale-but-true number beats a zeroed one).
pub fn read_total(conn: &rusqlite::Connection) -> rusqlite::Result<i64> {
    conn.query_row(crate::SQL_COUNT_MEMORIES, [], |r| r.get(0))
}

/// Run one refresh against an already-open connection, publishing onto an
/// EXPLICIT metrics handle. Returns the count it published, or `None` when
/// the read failed — in which case NOTHING is published, so the previous
/// value and its freshness stamp are both retained.
pub fn refresh_once_into(
    metrics: &crate::metrics::Metrics,
    conn: &rusqlite::Connection,
    now_unix: i64,
) -> Option<i64> {
    match read_total(conn) {
        Ok(total) => {
            publish_into(metrics, total, now_unix);
            Some(total)
        }
        Err(e) => {
            tracing::warn!(
                target: TRACE_TARGET,
                error = %e,
                "corpus-size gauge refresh failed; the previous value is retained and \
                 ai_memory_memories_refreshed_at_seconds will age"
            );
            None
        }
    }
}

/// Run one refresh against the process metrics registry — the production
/// entry point (the paced loop and the scrape-path cold prime).
pub fn refresh_once(conn: &rusqlite::Connection, now_unix: i64) -> Option<i64> {
    refresh_once_into(crate::metrics::registry(), conn, now_unix)
}

/// The daemon's shared-connection tuple, as owned by
/// [`crate::handlers::transport::Db`].
type DbTuple = (
    rusqlite::Connection,
    std::path::PathBuf,
    crate::config::ResolvedTtl,
    bool,
);

/// Spawn the paced corpus-size gauge refresher.
///
/// A zero `interval` returns a task that exits immediately (the spawn list
/// stays uniform). The count runs on `spawn_blocking` with the daemon's
/// mutex held only for the single `COUNT` — the same shape as
/// [`crate::handlers::transport::db_op`] — so it never pins a tokio worker
/// and never holds the connection across an `await`.
#[must_use]
pub fn spawn(state: Arc<Mutex<DbTuple>>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        if interval.as_secs() == 0 {
            tracing::info!(
                target: TRACE_TARGET,
                env = ENV_INTERVAL_SECS,
                "corpus-size gauge refresher DISABLED by configuration"
            );
            return;
        }
        loop {
            let db = Arc::clone(&state);
            let now = chrono::Utc::now().timestamp();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let guard = db.blocking_lock();
                refresh_once(&guard.0, now);
            })
            .await
            {
                tracing::error!(target: TRACE_TARGET, error = %e, "gauge refresh worker died");
            }
            tokio::time::sleep(interval).await;
        }
    })
}

// ---------------------------------------------------------------------
// v1.0.0 #2621 — postgres/SAL corpus-size gauge refresher.
//
// The sqlite `spawn` above counts the local sqlite `Db` handle. On a
// `--store-url postgres://…` daemon that handle is the local SIDECAR the
// federation nonce cache + other host-local state live in — NOT the served
// corpus — so counting it publishes 0 (or the sidecar's count) for a
// populated postgres corpus (#2621). The refresher must count via the
// ACTIVE store the daemon serves from (`app.store`), so it routes through
// the SAL trait's existing `stats()` method — `stats.total` is the SAME
// physical `COUNT(*)` the sqlite `read_total` publishes. This mirrors the
// `crate::background::access_fold::{SalFoldStore,spawn_sal}` shape so both
// backends' loops are unit-testable with a mock rather than only through a
// live daemon boot.
// ---------------------------------------------------------------------

/// The one substrate verb the SAL gauge loop drives, narrowed from the
/// full [`crate::store::MemoryStore`] so the loop is testable with a mock
/// (the [`crate::background::access_fold::SalFoldStore`] precedent — a
/// minimal trait, not the whole store surface).
#[cfg(feature = "sal")]
#[async_trait::async_trait]
pub trait SalCountStore: Send + Sync {
    /// The physical corpus row count (`stats.total`) of the ACTIVE store.
    ///
    /// # Errors
    /// Propagates the substrate stats error; the caller logs and retains
    /// the previous gauge value (a stale-but-true number beats a zeroed one).
    async fn count_total(&self) -> anyhow::Result<i64>;
}

/// Bridge the daemon's `Arc<dyn MemoryStore>` to the narrowed
/// [`SalCountStore`] verb (the trait-object blanket impl lets [`spawn_sal`]
/// take `app_state.store` directly). Reads `stats().total`, the SAME
/// physical `COUNT(*)` the sqlite [`read_total`] path publishes.
#[cfg(feature = "sal")]
#[async_trait::async_trait]
impl SalCountStore for dyn crate::store::MemoryStore {
    async fn count_total(&self) -> anyhow::Result<i64> {
        let total = self.stats().await.map_err(anyhow::Error::from)?.total;
        // `Stats::total` is a `usize` row count; a corpus that overflows
        // `i64` is not physically representable, so the saturating cast is
        // order-preserving and never wraps to a negative gauge.
        Ok(i64::try_from(total).unwrap_or(i64::MAX))
    }
}

/// Run one SAL refresh, publishing onto an EXPLICIT metrics handle (the
/// async sibling of [`refresh_once_into`]). Returns the count it published,
/// or `None` when the store read failed — in which case NOTHING is
/// published, so the previous value and its freshness stamp are retained.
#[cfg(feature = "sal")]
pub async fn refresh_once_sal_into<S: SalCountStore + ?Sized>(
    metrics: &crate::metrics::Metrics,
    store: &S,
    now_unix: i64,
) -> Option<i64> {
    match store.count_total().await {
        Ok(total) => {
            publish_into(metrics, total, now_unix);
            Some(total)
        }
        Err(e) => {
            tracing::warn!(
                target: TRACE_TARGET,
                error = %e,
                "corpus-size gauge refresh (postgres) failed; the previous value is \
                 retained and ai_memory_memories_refreshed_at_seconds will age"
            );
            None
        }
    }
}

/// Run one SAL refresh against the process metrics registry — the
/// production entry point (the paced loop and the scrape-path cold prime).
#[cfg(feature = "sal")]
pub async fn refresh_once_sal<S: SalCountStore + ?Sized>(store: &S, now_unix: i64) -> Option<i64> {
    refresh_once_sal_into(crate::metrics::registry(), store, now_unix).await
}

/// Spawn the postgres/SAL corpus-size gauge refresher at `interval`. Each
/// tick sleeps then counts the ACTIVE store and publishes it (the
/// [`crate::background::access_fold::spawn_sal`] cadence — the first publish
/// lands after one `interval`; the scrape-path cold prime in
/// [`crate::handlers::prometheus_metrics`] covers the value before then).
/// Returns a [`JoinHandle`] the caller aborts on shutdown; the loop tolerates
/// transient substrate errors (logs + retains the previous value), and a zero
/// interval disables it (the [`spawn`] precedent).
#[cfg(feature = "sal")]
#[must_use]
pub fn spawn_sal<S>(store: Arc<S>, interval: Duration) -> JoinHandle<()>
where
    S: SalCountStore + ?Sized + 'static,
{
    tokio::spawn(async move {
        if interval.as_secs() == 0 {
            tracing::info!(
                target: TRACE_TARGET,
                env = ENV_INTERVAL_SECS,
                "corpus-size gauge refresher (postgres) DISABLED by configuration"
            );
            return;
        }
        loop {
            tokio::time::sleep(interval).await;
            let now = chrono::Utc::now().timestamp();
            refresh_once_sal(store.as_ref(), now).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ISOLATED registry per test. The process-global `registry()` is
    /// mutated by every other test in this binary (`metrics.rs` sets
    /// `memories_gauge` to 42), so asserting exact values on it is a race
    /// with whatever else the harness happens to be running in parallel —
    /// which is precisely how this cell first failed.
    fn isolated() -> crate::metrics::Metrics {
        crate::metrics::Metrics::try_new().expect("build isolated metrics registry")
    }

    #[test]
    fn publish_sets_both_gauges() {
        let m = isolated();
        publish_into(&m, 7, 1_234);
        assert_eq!(m.memories_gauge.get(), 7);
        assert_eq!(m.memories_gauge_refreshed_at.get(), 1_234);
    }

    #[test]
    fn default_interval_is_a_minute_and_nonzero() {
        assert_eq!(DEFAULT_INTERVAL.as_secs(), 60);
    }

    #[test]
    fn a_failed_read_retains_the_previous_value() {
        let m = isolated();
        publish_into(&m, 99, 1_000);
        // A connection with no `memories` table: the read errors.
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        assert_eq!(refresh_once_into(&m, &conn, 2_000), None);
        assert_eq!(m.memories_gauge.get(), 99, "stale-but-true beats zeroed");
        assert_eq!(
            m.memories_gauge_refreshed_at.get(),
            1_000,
            "the freshness stamp must NOT advance on a failed read — that is the whole \
             point of publishing it"
        );
    }

    #[test]
    fn a_successful_read_moves_both_gauges_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = crate::storage::open(&dir.path().join("gauge.db")).expect("open");
        let m = isolated();
        assert_eq!(refresh_once_into(&m, &conn, 5_000), Some(0));
        assert_eq!(m.memories_gauge.get(), 0, "an empty corpus really is 0");
        assert_eq!(
            m.memories_gauge_refreshed_at.get(),
            5_000,
            "an empty corpus is distinguishable from `never computed` ONLY by this stamp"
        );
    }

    // ---- v1.0.0 #2621 — SAL / postgres gauge refresher -------------

    /// The load-bearing #2621 regression: on a postgres-backed daemon the
    /// gauge must count the ACTIVE store's corpus, NOT the local sqlite
    /// sidecar. Uses a real `SqliteStore` standing in for ANY `MemoryStore`
    /// (so the deterministic gate needs no live postgres) and proves the SAL
    /// path publishes the STORE's count (3) while the sidecar the pre-#2621
    /// gauge read is empty (0) — the exact divergence the defect reported.
    /// The live-postgres twin is `tests/pg_memories_gauge_2621.rs`
    /// (`#[ignore]` + `sal-postgres`, run via `--include-ignored`).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn sal_refresh_counts_the_active_store_not_the_sqlite_sidecar() {
        use crate::store::MemoryStore;
        let dir = tempfile::tempdir().expect("tempdir");
        // The ACTIVE store the daemon serves from holds a real corpus.
        let store = crate::store::sqlite::SqliteStore::open(&dir.path().join("active.db"))
            .expect("open active store");
        let ctx = crate::store::CallerContext::for_agent("gauge-2621");
        for i in 0..3 {
            let now = chrono::Utc::now().to_rfc3339();
            let mem = crate::models::Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("gauge-row-{i}"),
                content: "corpus body".to_string(),
                namespace: "gauge".to_string(),
                created_at: now.clone(),
                updated_at: now,
                ..Default::default()
            };
            store.store(&ctx, &mem).await.expect("store row");
        }
        let store: Arc<dyn crate::store::MemoryStore> = Arc::new(store);

        // The local sqlite sidecar the pre-#2621 gauge read is EMPTY — on a
        // postgres daemon its 0 is the WRONG number for a populated corpus.
        let sidecar = crate::storage::open(&dir.path().join("sidecar.db")).expect("open sidecar");
        let sidecar_metrics = isolated();
        assert_eq!(
            refresh_once_into(&sidecar_metrics, &sidecar, 1_000),
            Some(0),
            "the sqlite sidecar the pre-#2621 gauge read is empty — its 0 is the wrong number"
        );

        // The backend-correct SAL path counts the ACTIVE store's real corpus.
        let m = isolated();
        let published = refresh_once_sal_into(&m, store.as_ref(), 7_000).await;
        assert_eq!(
            published,
            Some(3),
            "the SAL gauge counts the active store's corpus (#2621), not the sidecar"
        );
        assert_eq!(m.memories_gauge.get(), 3);
        assert_eq!(m.memories_gauge_refreshed_at.get(), 7_000);
    }

    /// A failed SAL store read retains the previous value + freshness stamp
    /// (the async twin of `a_failed_read_retains_the_previous_value`).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn sal_a_failed_count_retains_the_previous_value() {
        struct ErrStore;
        #[async_trait::async_trait]
        impl SalCountStore for ErrStore {
            async fn count_total(&self) -> anyhow::Result<i64> {
                anyhow::bail!("synthetic sal stats failure")
            }
        }
        let m = isolated();
        publish_into(&m, 42, 1_000);
        assert_eq!(refresh_once_sal_into(&m, &ErrStore, 2_000).await, None);
        assert_eq!(m.memories_gauge.get(), 42, "stale-but-true beats zeroed");
        assert_eq!(
            m.memories_gauge_refreshed_at.get(),
            1_000,
            "the freshness stamp must NOT advance on a failed read"
        );
    }

    /// Drive the real [`spawn_sal`] tokio loop with a sub-millisecond
    /// interval so its body (count → publish → sleep) executes several
    /// times, then abort the handle (the `access_fold::spawn_sal` pattern).
    #[cfg(feature = "sal")]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_sal_loop_counts_across_ticks() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        struct CountingStore {
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl SalCountStore for CountingStore {
            async fn count_total(&self) -> anyhow::Result<i64> {
                let n = self.calls.fetch_add(1, SeqCst);
                Ok(i64::try_from(n).unwrap_or(0))
            }
        }
        let store = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
        });
        // A whole-second interval: the disable guard is `as_secs() == 0`, so
        // a sub-second `Duration` would be read as "disabled" and never tick.
        let handle = spawn_sal(Arc::clone(&store), Duration::from_secs(1));
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        handle.abort();
        let _ = handle.await;
        assert!(
            store.calls.load(SeqCst) >= 2,
            "spawn_sal loop should have counted the corpus at least twice"
        );
    }

    /// A zero interval disables the SAL loop (never counts) — the postgres
    /// twin of `default_interval_is_a_minute_and_nonzero`'s disable arm.
    #[cfg(feature = "sal")]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_sal_zero_interval_disables_the_loop() {
        struct NeverStore;
        #[async_trait::async_trait]
        impl SalCountStore for NeverStore {
            async fn count_total(&self) -> anyhow::Result<i64> {
                panic!("a disabled loop must never count the corpus");
            }
        }
        // A zero interval makes the spawned task return immediately.
        let handle = spawn_sal(Arc::new(NeverStore), Duration::from_secs(0));
        handle.await.expect("disabled loop returns cleanly");
    }
}
