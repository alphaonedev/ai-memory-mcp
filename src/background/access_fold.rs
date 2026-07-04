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

// ---------------------------------------------------------------------
// v0.9.0 P0-1 (#1869) — postgres/SAL fold loop.
//
// The sqlite `spawn` above folds the LOCAL sqlite ledger only. A
// postgres-backed daemon records its recalls through the SAL trait, so
// the fold (and the previously caller-less `recall_observation_gc`
// ledger pruner — T7c) must run through the trait too. This mirrors the
// sqlite loop's shape (a `spawn_*` + a minimal adapter trait) so BOTH
// backends' loops are unit-testable with a mock rather than only through
// a live daemon boot.
// ---------------------------------------------------------------------

/// The two substrate verbs the SAL fold loop drives, narrowed from the
/// full [`crate::store::MemoryStore`] so the loop is testable with a
/// mock (the sqlite side's [`AccessFoldAdapter`] precedent — a minimal
/// trait, not the whole store surface).
#[cfg(feature = "sal")]
#[async_trait::async_trait]
pub trait SalFoldStore: Send + Sync {
    /// Apply the access ladders from unfolded ledger rows; returns the
    /// number of distinct memories folded.
    ///
    /// # Errors
    /// Propagates the substrate fold error.
    async fn fold(&self) -> anyhow::Result<usize>;

    /// Prune `recall_observations` rows older than `ttl_days`; returns
    /// the number of ledger rows pruned.
    ///
    /// # Errors
    /// Propagates the substrate prune error.
    async fn prune_ledger(&self, ttl_days: i64) -> anyhow::Result<usize>;
}

/// Bridge the daemon's `Arc<dyn MemoryStore>` to the narrowed
/// [`SalFoldStore`] verbs (the trait-object blanket impl lets
/// [`spawn_sal`] take `app_state.store` directly).
#[cfg(feature = "sal")]
#[async_trait::async_trait]
impl SalFoldStore for dyn crate::store::MemoryStore {
    async fn fold(&self) -> anyhow::Result<usize> {
        self.fold_recall_accesses()
            .await
            .map_err(anyhow::Error::from)
    }

    async fn prune_ledger(&self, ttl_days: i64) -> anyhow::Result<usize> {
        self.recall_observation_gc(ttl_days)
            .await
            .map_err(anyhow::Error::from)
    }
}

/// Spawn the postgres/SAL fold loop at `interval`. Every tick folds the
/// SAL ledger; every `SECS_PER_HOUR / interval` ticks (≈ hourly, min 1)
/// it also prunes the `recall_observations` ledger at `prune_ttl_days`.
/// Returns a [`JoinHandle`] the caller aborts on shutdown; the loop
/// tolerates transient substrate errors (logs + continues) exactly like
/// the sqlite [`spawn`] loop.
#[cfg(feature = "sal")]
#[must_use]
pub fn spawn_sal<S>(store: Arc<S>, interval: Duration, prune_ttl_days: i64) -> JoinHandle<()>
where
    S: SalFoldStore + ?Sized + 'static,
{
    // The pruner rides the fold loop on a coarser ~hourly cadence: at a
    // 60 s fold interval that is every 60 ticks; sub-second intervals
    // (tests) floor to 1 so the pruner fires every tick.
    let prune_every = (crate::SECS_PER_HOUR.unsigned_abs() / interval.as_secs().max(1)).max(1);
    tokio::spawn(async move {
        let mut ticks: u64 = 0;
        loop {
            tokio::time::sleep(interval).await;
            match store.fold().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target: TRACE_TARGET,
                    "recall-access fold (postgres) applied {n} memory(ies)"
                ),
                Err(e) => tracing::warn!(
                    target: TRACE_TARGET,
                    "recall-access fold (postgres) failed: {e}"
                ),
            }
            ticks += 1;
            if ticks % prune_every == 0 {
                match store.prune_ledger(prune_ttl_days).await {
                    Ok(n) if n > 0 => {
                        tracing::info!("recall_observations gc (postgres): pruned {n} row(s)");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("recall_observations gc (postgres) failed: {e}"),
                }
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

    // ---- SAL / postgres fold loop (`spawn_sal`) --------------------

    /// Mock `SalFoldStore` counting fold + prune calls, with optional
    /// error injection (the `CountingAdapter` / `ErrAdapter` pattern
    /// above, for the async SAL trait).
    #[cfg(feature = "sal")]
    struct MockSalStore {
        fold_calls: std::sync::atomic::AtomicUsize,
        prune_calls: std::sync::atomic::AtomicUsize,
        fold_err: bool,
        prune_err: bool,
    }

    #[cfg(feature = "sal")]
    #[async_trait::async_trait]
    impl SalFoldStore for MockSalStore {
        async fn fold(&self) -> anyhow::Result<usize> {
            let n = self
                .fold_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fold_err {
                anyhow::bail!("synthetic sal fold failure");
            }
            // First tick folds one memory; later ticks are idempotent
            // no-ops — exercises BOTH the `Ok(n)` and `Ok(0)` arms.
            Ok(usize::from(n == 0))
        }

        async fn prune_ledger(&self, _ttl_days: i64) -> anyhow::Result<usize> {
            let n = self
                .prune_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.prune_err {
                anyhow::bail!("synthetic sal prune failure");
            }
            // First prune removes a row; later ones are no-ops —
            // exercises BOTH the `Ok(n) if n > 0` and `Ok(_)` arms.
            Ok(usize::from(n == 0))
        }
    }

    #[cfg(feature = "sal")]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_sal_drives_fold_and_prune_arms() {
        use std::sync::atomic::Ordering::SeqCst;
        let store = Arc::new(MockSalStore {
            fold_calls: std::sync::atomic::AtomicUsize::new(0),
            prune_calls: std::sync::atomic::AtomicUsize::new(0),
            fold_err: false,
            prune_err: false,
        });
        // interval == 1 h ⇒ prune_every == 1 ⇒ the pruner fires every
        // tick, so a few ticks cover the fold + prune success arms.
        let handle = spawn_sal(Arc::clone(&store), Duration::from_secs(3600), 30);
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(3600)).await;
            tokio::task::yield_now().await;
        }
        handle.abort();
        let _ = handle.await;
        assert!(
            store.fold_calls.load(SeqCst) >= 2,
            "fold ran across ticks (Ok(n) then Ok(0) arms)"
        );
        assert!(
            store.prune_calls.load(SeqCst) >= 2,
            "pruner fired every tick at the hourly cadence (Ok(n>0) then Ok(0) arms)"
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_sal_tolerates_fold_and_prune_errors() {
        use std::sync::atomic::Ordering::SeqCst;
        let store = Arc::new(MockSalStore {
            fold_calls: std::sync::atomic::AtomicUsize::new(0),
            prune_calls: std::sync::atomic::AtomicUsize::new(0),
            fold_err: true,
            prune_err: true,
        });
        let handle = spawn_sal(Arc::clone(&store), Duration::from_secs(3600), 30);
        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(3600)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            !handle.is_finished(),
            "loop survives both fold and prune errors"
        );
        handle.abort();
        let _ = handle.await;
        assert!(store.fold_calls.load(SeqCst) >= 1, "fold error arm reached");
        assert!(
            store.prune_calls.load(SeqCst) >= 1,
            "prune error arm reached"
        );
    }

    /// The `dyn MemoryStore` blanket impl forwards to the real SAL
    /// verbs. A fresh sqlite store has an empty ledger, so both verbs
    /// short-circuit to zero-work — enough to cover the bridge.
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn sal_fold_store_bridges_dyn_memory_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::store::sqlite::SqliteStore::open(dir.path().join("bridge.db"))
            .expect("open sqlite store");
        let dyn_store: &dyn crate::store::MemoryStore = &store;
        assert_eq!(
            SalFoldStore::fold(dyn_store).await.unwrap(),
            0,
            "empty-ledger fold is zero-work"
        );
        // Prune over an empty ledger removes nothing; the call
        // exercises the bridge's forward to `recall_observation_gc`.
        let _ = SalFoldStore::prune_ledger(dyn_store, 30).await.unwrap();
    }
}
