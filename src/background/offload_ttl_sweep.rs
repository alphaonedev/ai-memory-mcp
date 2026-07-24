// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-3 — daily TTL sweep for `offloaded_blobs`.
//!
//! The sweep removes rows where `stored_at + ttl_seconds < now`,
//! bounded at [`MAX_PER_RUN`] deletions per pass.
//!
//! ## Chunked-locking contract (#2359)
//!
//! The daemon's shared `Db` handle is a single
//! `Arc<Mutex<(Connection, …)>>` that serves EVERY HTTP handler, so
//! the sweep must never hold that mutex for the length of a full
//! pass. [`spawn`] therefore locks **per chunk**: it acquires the
//! lock, deletes at most [`CHUNK_CAP`] rows with NO in-pass sleep
//! ([`Duration::ZERO`]), drops the lock, then performs the
//! [`SLEEP_BETWEEN_CHUNKS`] pacing sleep OUTSIDE the lock (via
//! `tokio::time::sleep`, not a thread-blocking `std::thread::sleep`)
//! so concurrent HTTP requests can acquire the mutex between chunks.
//! It repeats until the cumulative [`MAX_PER_RUN`] cap is reached or
//! a chunk returns fewer rows than requested (backlog drained).
//!
//! This supersedes the pre-#2359 posture where the whole pass — every
//! per-row `std::thread::sleep` included — ran under one lock, stalling
//! all HTTP traffic for up to `MAX_PER_RUN × 10ms` (~10s) per pass and
//! parking a tokio worker thread on a blocking sleep.
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

/// Maximum number of rows deleted per sweep pass (cumulative across
/// all chunks). 1000 keeps the pass bounded in pathological backlog
/// scenarios; the daemon re-invokes at the daily cadence to drain a
/// larger backlog over successive passes.
pub const MAX_PER_RUN: usize = 1000;

/// Rows deleted per locked chunk (#2359). Small so the shared `Db`
/// mutex is held only briefly on each acquisition; the sweep releases
/// it and pauses [`SLEEP_BETWEEN_CHUNKS`] between chunks so concurrent
/// HTTP handlers can interleave.
pub const CHUNK_CAP: usize = 50;

/// Pacing sleep BETWEEN chunks (#2359), performed OUTSIDE the lock via
/// `tokio::time::sleep`. Lets concurrent writes/reads land between
/// chunk deletions without holding the connection mutex across the
/// pause, and without a thread-blocking `std::thread::sleep` inside
/// the async task. The in-pass per-delete sleep is now
/// [`Duration::ZERO`] — pacing lives here, off the lock.
pub const SLEEP_BETWEEN_CHUNKS: Duration = Duration::from_millis(10);

/// Spawn the daily sweep loop. Returns a [`JoinHandle`] the caller
/// aborts on shutdown.
///
/// Per the chunked-locking contract (#2359, see the module doc), the
/// shared `Db` mutex is acquired PER CHUNK — never across a whole
/// pass. Each chunk deletes at most [`CHUNK_CAP`] rows under the lock
/// with no in-pass sleep, the lock is dropped, and the
/// [`SLEEP_BETWEEN_CHUNKS`] pacing sleep runs OUTSIDE the lock so
/// concurrent HTTP handlers can interleave. The pass ends when the
/// cumulative [`MAX_PER_RUN`] cap is reached or a chunk returns fewer
/// rows than requested (backlog drained).
#[must_use]
pub fn spawn<T>(state: Arc<Mutex<T>>, interval: Duration) -> JoinHandle<()>
where
    T: SweepAdapter + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let now_unix = chrono::Utc::now().timestamp();
            let mut swept = 0usize;
            loop {
                let chunk_cap = MAX_PER_RUN.saturating_sub(swept).min(CHUNK_CAP);
                if chunk_cap == 0 {
                    break; // cumulative MAX_PER_RUN reached
                }
                // Acquire the lock ONLY for the chunk; the guard is
                // dropped at the end of this block, BEFORE the pacing
                // sleep below — the whole point of #2359.
                let outcome = {
                    let lock = state.lock().await;
                    lock.run_sweep_chunk(now_unix, chunk_cap)
                };
                match outcome {
                    Ok(n) => {
                        swept += n;
                        if n < chunk_cap {
                            break; // backlog drained
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "offload.ttl_sweep",
                            "TTL sweep failed: {e}"
                        );
                        break;
                    }
                }
                // Pacing sleep OUTSIDE the lock so concurrent requests
                // can acquire the shared Db mutex between chunks.
                tokio::time::sleep(SLEEP_BETWEEN_CHUNKS).await;
            }
            if swept > 0 {
                tracing::info!(
                    target: "offload.ttl_sweep",
                    "TTL sweep removed {swept} expired offloaded blob(s)"
                );
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
    /// Delete up to `chunk_cap` expired rows in a SINGLE locked pass,
    /// with NO in-pass sleep ([`Duration::ZERO`]) — [`spawn`] performs
    /// the inter-chunk pacing sleep OUTSIDE the lock (#2359). Returns
    /// the count deleted; a return `< chunk_cap` signals the backlog
    /// is drained.
    fn run_sweep_chunk(&self, now_unix: i64, chunk_cap: usize) -> anyhow::Result<usize>;
}

impl SweepAdapter
    for (
        rusqlite::Connection,
        std::path::PathBuf,
        crate::config::ResolvedTtl,
        bool,
    )
{
    fn run_sweep_chunk(&self, now_unix: i64, chunk_cap: usize) -> anyhow::Result<usize> {
        sweep_expired(&self.0, now_unix, chunk_cap, Duration::ZERO)
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
        fn run_sweep_chunk(&self, now_unix: i64, chunk_cap: usize) -> anyhow::Result<usize> {
            sweep_expired(&self.0, now_unix, chunk_cap, Duration::ZERO)
        }
    }

    #[test]
    fn run_sweep_is_idempotent_on_empty_table() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let adapter = ConnAdapter(conn);
        let n = adapter.run_sweep_chunk(0, MAX_PER_RUN).unwrap();
        assert_eq!(n, 0);
        let n2 = adapter.run_sweep_chunk(0, MAX_PER_RUN).unwrap();
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
        let n = adapter
            .run_sweep_chunk(r.stored_at + 60, MAX_PER_RUN)
            .unwrap();
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
        assert_eq!(CHUNK_CAP, 50);
        assert_eq!(SLEEP_BETWEEN_CHUNKS, Duration::from_millis(10));
    }

    /// Adapter whose `run_sweep` always errors — exercises the `Err`
    /// arm of the [`spawn`] loop's `match` (the `tracing::warn!` path).
    struct ErrAdapter;
    impl SweepAdapter for ErrAdapter {
        fn run_sweep_chunk(&self, _now_unix: i64, _chunk_cap: usize) -> anyhow::Result<usize> {
            anyhow::bail!("synthetic sweep failure")
        }
    }

    /// Adapter that reports a deletion count so the `Ok(n)` aggregate
    /// info-log fires, and counts how many chunk calls the loop made so
    /// the test can prove the spawned task actually ran the body. Each
    /// chunk returns `< CHUNK_CAP` so the inner chunk loop breaks after
    /// one chunk per tick (no inter-chunk sleep on these ticks).
    struct CountingAdapter {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl SweepAdapter for CountingAdapter {
        fn run_sweep_chunk(&self, _now_unix: i64, _chunk_cap: usize) -> anyhow::Result<usize> {
            // Report a non-zero deletion on the first tick (aggregate
            // Ok(n) info-log arm), zero thereafter (silent arm).
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(usize::from(n == 0))
        }
    }

    /// Drive the real [`spawn`] tokio loop with a sub-millisecond
    /// interval so the loop body (sleep → lock → run_sweep_chunk →
    /// match arms) executes several times, then abort the handle.
    /// Covers the zero, non-zero, and loop-cadence lines.
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
    /// blanket impl body is covered, not just the test `ConnAdapter`.
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
        assert_eq!(tuple.run_sweep_chunk(r.stored_at, MAX_PER_RUN).unwrap(), 0);
        // After expiry: the row is swept.
        assert_eq!(
            tuple
                .run_sweep_chunk(r.stored_at + 60, MAX_PER_RUN)
                .unwrap(),
            1
        );
    }

    /// Adapter that always reports a FULL chunk so [`spawn`]'s inner
    /// chunk loop keeps going (multiple chunks + inter-chunk sleeps)
    /// until the cumulative `MAX_PER_RUN` cap — modelling a large
    /// backlog. The chunk counter lives in a shared `Arc<AtomicUsize>`
    /// so the test can observe sweep progress WITHOUT taking the mutex
    /// under test. Used by the lock-release regression below.
    struct FullChunkAdapter {
        chunks: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl SweepAdapter for FullChunkAdapter {
        fn run_sweep_chunk(&self, _now_unix: i64, chunk_cap: usize) -> anyhow::Result<usize> {
            self.chunks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Full chunk (== chunk_cap) ⇒ the loop does NOT treat the
            // backlog as drained and proceeds to an inter-chunk sleep.
            Ok(chunk_cap)
        }
    }

    /// #2359 regression: the shared `Db` mutex MUST NOT be held across
    /// the inter-chunk pacing sleep. With paused time we drive the
    /// [`spawn`] loop until it has run its FIRST chunk and parked at
    /// the FIRST inter-chunk sleep (the sweep is mid-pass — a large
    /// backlog with `MAX_PER_RUN / CHUNK_CAP` chunks still pending),
    /// then prove a contender can acquire the lock WITHOUT advancing
    /// the clock past that sleep — i.e. the lock is free DURING the
    /// sleep. Under the pre-#2359 hold-across-the-whole-pass posture
    /// the lock would stay held for every remaining chunk + sleep of
    /// the pass, so this acquisition would block.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn lock_released_between_chunks_2359() {
        let chunks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(FullChunkAdapter {
            chunks: Arc::clone(&chunks),
        }));
        // interval (1ms) ≪ SLEEP_BETWEEN_CHUNKS (10ms), and the drive
        // loop below advances at most 8ms of virtual time — strictly
        // less than one inter-chunk sleep — so we observe the sweep
        // parked at its FIRST inter-chunk sleep and never let a second
        // chunk run.
        let handle = spawn(Arc::clone(&state), Duration::from_millis(1));

        // Let the spawned task register its interval timer, then step
        // the clock 1ms at a time until exactly one chunk has run. At
        // that point the sweep has released the lock and is parked at
        // the first inter-chunk sleep.
        tokio::task::yield_now().await;
        for _ in 0..8 {
            if chunks.load(std::sync::atomic::Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
        let before = chunks.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            before, 1,
            "sweep should have run exactly one chunk and parked at the inter-chunk sleep"
        );

        // The sweep is parked at the inter-chunk sleep with the lock
        // dropped — a contender must acquire it immediately, WITHOUT
        // us advancing past the 10ms sleep to drain the pass.
        {
            let contended = state.try_lock();
            assert!(
                contended.is_ok(),
                "Db mutex must be free during the inter-chunk sleep (#2359)"
            );
        }
        // And no further chunk ran while we probed — the sweep is
        // genuinely parked at the sleep, not spinning under the lock.
        assert_eq!(
            chunks.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "sweep must stay parked at the inter-chunk sleep during the lock probe"
        );

        handle.abort();
        let _ = handle.await;
    }
}
