// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 P0-1 (#1869) — periodic recall-access FOLD loop.
//!
//! With recall PURE by default (zero writes to `memories` on any
//! recall path), the append-only `recall_observations` ledger carries
//! the access signal and this loop batch-applies the legacy touch
//! ladders from unfolded rows via
//! [`crate::storage::fold_recall_accesses`] (access_count bump,
//! `last_accessed_at`, per-tier TTL floor-extend, mid→long promotion,
//! priority decade ladder, opt-in confidence decay).
//!
//! Cadence: [`crate::config::access_fold_interval_secs`] (env
//! `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS`, default 60 s). A value of
//! `0` means this loop is NOT spawned — the fold then rides the gc
//! tick only (`daemon_runtime::spawn_gc_loop_with_shadow_retention`
//! folds at the top of every tick regardless), so count freshness
//! degrades to the 30-minute gc cadence.
//!
//! Structurally mirrors [`crate::background::lease_sweep`]; spawned by
//! `daemon_runtime::bootstrap_serve`, aborted on shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Tracing target shared by the sqlite fold loop here and the postgres
/// SAL fold loop in `daemon_runtime` (one named const, no scattered
/// target literals — the `store::postgres::TRACE_TARGET` precedent).
pub(crate) const TRACE_TARGET: &str = "access.fold";

/// Trait wrapping the daemon's `(Connection, ...)` tuple so the fold is
/// testable without the full daemon state shape (the
/// [`crate::background::lease_sweep::LeaseSweepAdapter`] pattern).
pub trait AccessFoldAdapter {
    /// Run one fold pass; returns the number of distinct memories
    /// folded.
    ///
    /// # Errors
    /// Propagates the substrate fold error.
    fn run_access_fold(&self) -> anyhow::Result<usize>;
}

impl AccessFoldAdapter
    for (
        rusqlite::Connection,
        std::path::PathBuf,
        crate::config::ResolvedTtl,
        bool,
    )
{
    fn run_access_fold(&self) -> anyhow::Result<usize> {
        crate::storage::fold_recall_accesses(
            &self.0,
            self.2.short_extend_secs,
            self.2.mid_extend_secs,
        )
    }
}

/// Spawn the fold loop at `interval`. Returns a [`JoinHandle`] the
/// caller aborts on shutdown. The state lock is held only for the
/// duration of each pass; the fold itself is chunked
/// ([`crate::storage::FOLD_CHUNK_MEMORIES`]) with a zero-work early
/// return, so an idle tick costs one indexed probe.
#[must_use]
pub fn spawn<T>(state: Arc<Mutex<T>>, interval: Duration) -> JoinHandle<()>
where
    T: AccessFoldAdapter + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let lock = state.lock().await;
            match lock.run_access_fold() {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target: TRACE_TARGET,
                    "recall-access fold applied {n} memory(ies)"
                ),
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    "recall-access fold failed: {e}"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal adapter over a bare connection (the lease_sweep
    /// `ConnAdapter` pattern).
    struct ConnAdapter(rusqlite::Connection);
    impl AccessFoldAdapter for ConnAdapter {
        fn run_access_fold(&self) -> anyhow::Result<usize> {
            crate::storage::fold_recall_accesses(&self.0, crate::SECS_PER_HOUR, crate::SECS_PER_DAY)
        }
    }

    #[test]
    fn run_access_fold_is_zero_on_empty_ledger() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let adapter = ConnAdapter(conn);
        assert_eq!(adapter.run_access_fold().unwrap(), 0);
        assert_eq!(adapter.run_access_fold().unwrap(), 0, "idempotent");
    }

    #[test]
    fn run_access_fold_applies_unfolded_row() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('af-1', 'long', 'test', 'af', 'c', '2025-01-01T00:00:00Z', \
                     '2025-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        crate::observations::record_recall(
            &conn,
            "r-af-1",
            &[crate::observations::Candidate {
                memory_id: "af-1",
                retriever: "fts5",
                rank: 1,
                score: 0.9,
            }],
        )
        .unwrap();
        let adapter = ConnAdapter(conn);
        assert_eq!(adapter.run_access_fold().unwrap(), 1);
        let ac: i64 = adapter
            .0
            .query_row(
                "SELECT access_count FROM memories WHERE id = 'af-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ac, 1, "fold applied the access bump");
        assert_eq!(adapter.run_access_fold().unwrap(), 0, "second fold no-op");
    }

    /// Adapter that counts ticks so the spawned loop's arms are
    /// covered (the lease_sweep `CountingAdapter` pattern).
    struct CountingAdapter {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl AccessFoldAdapter for CountingAdapter {
        fn run_access_fold(&self) -> anyhow::Result<usize> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(usize::from(n == 0))
        }
    }

    struct ErrAdapter;
    impl AccessFoldAdapter for ErrAdapter {
        fn run_access_fold(&self) -> anyhow::Result<usize> {
            anyhow::bail!("synthetic fold failure")
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_loop_drives_fold_across_arms() {
        let adapter = Arc::new(Mutex::new(CountingAdapter {
            calls: std::sync::atomic::AtomicUsize::new(0),
        }));
        let handle = spawn(Arc::clone(&adapter), Duration::from_millis(1));
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
            "spawn loop should have ticked run_access_fold at least twice"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_loop_tolerates_fold_errors() {
        let handle = spawn(Arc::new(Mutex::new(ErrAdapter)), Duration::from_millis(1));
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
        }
        assert!(!handle.is_finished());
        handle.abort();
        let _ = handle.await;
    }
}
