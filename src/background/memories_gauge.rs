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

/// Publish `total` (and the wall-clock instant it was computed) onto the
/// process metrics registry.
///
/// Split out from the query so the publish contract is unit-testable
/// without a database, and so the scrape-path cold prime and the loop
/// cannot drift in what they publish.
pub fn publish(total: i64, now_unix: i64) {
    let r = crate::metrics::registry();
    r.memories_gauge.set(total);
    r.memories_gauge_refreshed_at.set(now_unix);
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

/// Run one refresh against an already-open connection. Returns the count
/// it published, or `None` when the read failed (previous value retained).
pub fn refresh_once(conn: &rusqlite::Connection, now_unix: i64) -> Option<i64> {
    match read_total(conn) {
        Ok(total) => {
            publish(total, now_unix);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_sets_both_gauges() {
        publish(7, 1_234);
        let r = crate::metrics::registry();
        assert_eq!(r.memories_gauge.get(), 7);
        assert_eq!(r.memories_gauge_refreshed_at.get(), 1_234);
        // Restore so sibling tests in this binary see a neutral registry.
        publish(0, 0);
    }

    #[test]
    fn default_interval_is_a_minute_and_nonzero() {
        assert_eq!(DEFAULT_INTERVAL.as_secs(), 60);
    }

    #[test]
    fn a_failed_read_retains_the_previous_value() {
        publish(99, 1_000);
        // A connection with no `memories` table: the read errors.
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        assert_eq!(refresh_once(&conn, 2_000), None);
        let r = crate::metrics::registry();
        assert_eq!(r.memories_gauge.get(), 99, "stale-but-true beats zeroed");
        assert_eq!(
            r.memories_gauge_refreshed_at.get(),
            1_000,
            "the freshness stamp must NOT advance on a failed read — that is the whole \
             point of publishing it"
        );
        publish(0, 0);
    }
}
