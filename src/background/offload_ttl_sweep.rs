// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-3 — daily TTL sweep for `offloaded_blobs`.
//!
//! The sweep removes rows where `stored_at + ttl_seconds < now`,
//! bounded at [`MAX_PER_RUN`] deletions per pass with a [`SLEEP_BETWEEN_DELETES`]
//! gap between deletes so the connection lock window stays short
//! under contended writes (matches the K2 pending-actions sweeper
//! discipline).
//!
//! Spawned by `daemon_runtime::bootstrap_serve` alongside the GC and
//! transcript-lifecycle loops; aborted on shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::offload::sweep_expired;

/// Cadence between sweeps. Daily — matches the prompt's "daily task"
/// directive. Operators that want a shorter cadence (testing,
/// disaster-recovery exercises) call [`spawn`] with an override.
/// Sourced from the substrate-wide `SECS_PER_DAY` SSOT
/// (`src/lib.rs`) so the canonical time-window magnitudes are pinned
/// in one place and the vendor-literals gate's SECS_PER_*
/// drift-block recipe applies here automatically.
#[allow(clippy::cast_sign_loss)]
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(crate::SECS_PER_DAY as u64);

/// Maximum number of rows deleted per sweep pass. 1000 keeps the
/// outer loop bounded in pathological backlog scenarios (a thousand
/// rows times the 10 ms sleep = 10 seconds wall clock, well under
/// the daily cadence).
pub const MAX_PER_RUN: usize = 1000;

/// Sleep between consecutive deletes. 10 ms lets concurrent writes
/// land between the SELECT-then-DELETE pairs that make up the sweep
/// body so the connection mutex isn't held for the whole pass.
pub const SLEEP_BETWEEN_DELETES: Duration = Duration::from_millis(10);

/// Spawn the daily sweep loop. Returns a [`JoinHandle`] the caller
/// aborts on shutdown.
///
/// The state lock is held only for the duration of each pass; the
/// in-pass `std::thread::sleep` between deletes happens INSIDE that
/// lock window, which is acceptable because the sweep is a single
/// background thread and not a hot data-plane path. v0.8.0 may
/// move the per-row sleep outside the lock if the offload write
/// volume grows.
#[must_use]
pub fn spawn<T>(state: Arc<Mutex<T>>, interval: Duration) -> JoinHandle<()>
where
    T: SweepAdapter + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let now_unix = chrono::Utc::now().timestamp();
            let lock = state.lock().await;
            match lock.run_sweep(now_unix) {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target: "offload.ttl_sweep",
                    "TTL sweep removed {n} expired offloaded blob(s)"
                ),
                Err(e) => tracing::warn!(
                    target: "offload.ttl_sweep",
                    "TTL sweep failed: {e}"
                ),
            }
        }
    })
}

/// Trait wrapping the daemon's `(Connection, ...)` tuple so the
/// sweep is testable without depending on the full daemon state
/// shape. The concrete production `Db` (alias for the daemon's
/// `(Connection, PathBuf, ResolvedTtl, bool)` tuple) implements
/// this via the blanket impl below.
pub trait SweepAdapter {
    fn run_sweep(&self, now_unix: i64) -> anyhow::Result<usize>;
}

impl SweepAdapter
    for (
        rusqlite::Connection,
        std::path::PathBuf,
        crate::config::ResolvedTtl,
        bool,
    )
{
    fn run_sweep(&self, now_unix: i64) -> anyhow::Result<usize> {
        sweep_expired(&self.0, now_unix, MAX_PER_RUN, SLEEP_BETWEEN_DELETES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test adapter — uses a bare connection so the sweep
    /// surface is exercised end-to-end without standing up the full
    /// daemon `Db` shape.
    struct ConnAdapter(rusqlite::Connection);
    impl SweepAdapter for ConnAdapter {
        fn run_sweep(&self, now_unix: i64) -> anyhow::Result<usize> {
            sweep_expired(&self.0, now_unix, MAX_PER_RUN, Duration::ZERO)
        }
    }

    #[test]
    fn run_sweep_is_idempotent_on_empty_table() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let adapter = ConnAdapter(conn);
        let n = adapter.run_sweep(0).unwrap();
        assert_eq!(n, 0);
        let n2 = adapter.run_sweep(0).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn run_sweep_removes_expired_row() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let off = crate::offload::ContextOffloader::new(
            &conn,
            None,
            crate::offload::OffloadConfig::default(),
        );
        let r = off.offload("expiring", "ns", Some(1), "ai:alice").unwrap();
        let adapter = ConnAdapter(conn);
        // Sweep at stored_at + 60s to guarantee expiry.
        let n = adapter.run_sweep(r.stored_at + 60).unwrap();
        assert_eq!(n, 1);
    }

    /// Default-const sanity: the cadence + per-run + per-delete tunables
    /// resolve to the documented values so a drift in the SECS_PER_DAY
    /// SSOT or the magic-number consts trips here.
    #[test]
    fn tunable_defaults_are_documented_values() {
        assert_eq!(
            DEFAULT_INTERVAL,
            Duration::from_secs(crate::SECS_PER_DAY as u64)
        );
        assert_eq!(MAX_PER_RUN, 1000);
        assert_eq!(SLEEP_BETWEEN_DELETES, Duration::from_millis(10));
    }

    /// Adapter whose `run_sweep` always errors — exercises the `Err`
    /// arm of the [`spawn`] loop's `match` (the `tracing::warn!` path).
    struct ErrAdapter;
    impl SweepAdapter for ErrAdapter {
        fn run_sweep(&self, _now_unix: i64) -> anyhow::Result<usize> {
            anyhow::bail!("synthetic sweep failure")
        }
    }

    /// Adapter that reports a deletion count so the `Ok(n)` info-log arm
    /// of the loop fires, and counts how many times the loop ticked so
    /// the test can prove the spawned task actually ran the body.
    struct CountingAdapter {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl SweepAdapter for CountingAdapter {
        fn run_sweep(&self, _now_unix: i64) -> anyhow::Result<usize> {
            // Report a non-zero deletion on the first tick (Ok(n) arm),
            // zero thereafter (Ok(0) arm) — both loop arms get covered.
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(usize::from(n == 0))
        }
    }

    /// Drive the real [`spawn`] tokio loop with a sub-millisecond
    /// interval so the loop body (sleep → lock → run_sweep → match arms)
    /// executes several times, then abort the handle. Covers the
    /// `Ok(0)`, `Ok(n)`, and loop-cadence lines.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_loop_drives_run_sweep_across_arms() {
        let adapter = Arc::new(Mutex::new(CountingAdapter {
            calls: std::sync::atomic::AtomicUsize::new(0),
        }));
        let handle = spawn(Arc::clone(&adapter), Duration::from_millis(1));
        // With paused time we advance the clock deterministically so the
        // loop wakes for several iterations.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
        handle.abort();
        let _ = handle.await;
        assert!(
            adapter
                .lock()
                .await
                .calls
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2,
            "spawn loop should have ticked run_sweep at least twice"
        );
    }

    /// Drive the [`spawn`] loop against an always-erroring adapter so the
    /// `Err(e)` warn-log arm of the loop `match` is exercised.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_loop_tolerates_sweep_errors() {
        let handle = spawn(Arc::new(Mutex::new(ErrAdapter)), Duration::from_millis(1));
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
        // The loop must keep running (not panic) through the error arm.
        assert!(!handle.is_finished());
        handle.abort();
        let _ = handle.await;
    }

    /// The production blanket `impl SweepAdapter for (Connection, …)`
    /// tuple delegates to [`sweep_expired`]. Drive it end-to-end so the
    /// blanket impl body (lines 95-97) is covered, not just the test
    /// `ConnAdapter`.
    #[test]
    fn production_tuple_adapter_runs_sweep_expired() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let off = crate::offload::ContextOffloader::new(
            &conn,
            None,
            crate::offload::OffloadConfig::default(),
        );
        let r = off.offload("expiring2", "ns", Some(1), "ai:bob").unwrap();
        let tuple = (
            conn,
            std::path::PathBuf::from(":memory:"),
            crate::config::ResolvedTtl::default(),
            true,
        );
        // Before expiry: nothing removed.
        assert_eq!(tuple.run_sweep(r.stored_at).unwrap(), 0);
        // After expiry: the row is swept.
        assert_eq!(tuple.run_sweep(r.stored_at + 60).unwrap(), 1);
    }
}
