// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — periodic sweep that reclaims expired action
//! `leases`.
//!
//! A lease with `expires_at <= now` is reclaimable: its holder is presumed
//! dead or done, and a fresh holder must be able to re-acquire the action.
//! The sweep DELETEs every such row so the next `lease_acquire` no longer
//! sees a stale row. It mirrors the offloaded-blobs TTL sweep
//! ([`crate::background::offload_ttl_sweep`]) structurally; the cadence is
//! tighter (hourly, not daily) because leases are short-lived.
//!
//! #2371 — a reclaim is a FORCED revocation of coordination authority (the
//! holder did not voluntarily surrender the lease), so the sweep drives the
//! audited primitive [`crate::actions::sweep_expired_leases_audited`], which
//! appends one `coordination.lease_expire_reclaim` `signed_events` row per
//! reclaimed lease — the tamper-evident twin of the voluntary
//! acquire/renew/release audit rows.
//!
//! Spawned by `daemon_runtime::bootstrap_serve` alongside the GC, TTL, and
//! transcript-lifecycle loops; aborted on shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Cadence between lease sweeps. Hourly — leases are short-lived
/// (seconds-to-minutes TTLs), so a daily cadence would leave reclaimable
/// rows lying around far longer than their lifetime. Operators that want a
/// shorter cadence (testing, disaster-recovery exercises) call [`spawn`]
/// with an override. Sourced from the substrate-wide `SECS_PER_HOUR` SSOT
/// (`src/lib.rs`) so the canonical time-window magnitudes are pinned in one
/// place and the vendor-literals gate's SECS_PER_* drift-block recipe applies
/// here automatically.
#[allow(clippy::cast_sign_loss)]
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(crate::SECS_PER_HOUR as u64);

/// Trait wrapping the daemon's `(Connection, ...)` tuple so the sweep is
/// testable without depending on the full daemon state shape. The concrete
/// production `Db` (alias for the daemon's `(Connection, PathBuf, ResolvedTtl,
/// bool)` tuple) implements this via the blanket impl below.
pub trait LeaseSweepAdapter {
    fn run_lease_sweep(&self, now_unix: i64) -> anyhow::Result<usize>;
}

impl LeaseSweepAdapter
    for (
        rusqlite::Connection,
        std::path::PathBuf,
        crate::config::ResolvedTtl,
        bool,
    )
{
    fn run_lease_sweep(&self, now_unix: i64) -> anyhow::Result<usize> {
        crate::actions::sweep_expired_leases_audited(&self.0, now_unix).map_err(anyhow::Error::from)
    }
}

/// Spawn the hourly lease-reclaim loop. Returns a [`JoinHandle`] the caller
/// aborts on shutdown.
///
/// The state lock is held only for the duration of each pass.
#[must_use]
pub fn spawn<T>(state: Arc<Mutex<T>>, interval: Duration) -> JoinHandle<()>
where
    T: LeaseSweepAdapter + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let now_unix = chrono::Utc::now().timestamp();
            let lock = state.lock().await;
            match lock.run_lease_sweep(now_unix) {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target: "lease.sweep",
                    "lease sweep reclaimed {n} expired lease(s)"
                ),
                Err(e) => tracing::warn!(
                    target: "lease.sweep",
                    "lease sweep failed: {e}"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test adapter — uses a bare connection so the sweep surface is
    /// exercised end-to-end without standing up the full daemon `Db` shape.
    struct ConnAdapter(rusqlite::Connection);
    impl LeaseSweepAdapter for ConnAdapter {
        fn run_lease_sweep(&self, now_unix: i64) -> anyhow::Result<usize> {
            crate::actions::sweep_expired_leases_audited(&self.0, now_unix)
                .map_err(anyhow::Error::from)
        }
    }

    #[test]
    fn run_lease_sweep_is_idempotent_on_empty_table() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let adapter = ConnAdapter(conn);
        assert_eq!(adapter.run_lease_sweep(0).unwrap(), 0);
        assert_eq!(adapter.run_lease_sweep(0).unwrap(), 0);
    }

    #[test]
    fn run_lease_sweep_removes_expired_row() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let now = 1_700_000_000;
        // A lease references a real action row, so create one first.
        let action = crate::models::Action {
            id: "ls-1".to_string(),
            namespace: "_act".to_string(),
            kind: "test.kind".to_string(),
            state: crate::models::ActionState::Pending,
            title: "t".to_string(),
            payload: serde_json::json!({}),
            priority: 5,
            agent_id: None,
            claimed_by: None,
            vector_clock: serde_json::json!({}),
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        crate::actions::create(&conn, &action).unwrap();
        // Acquire a lease whose deadline is already in the past.
        crate::actions::lease_acquire(&conn, "ls-1", "holder", now, now - 1).unwrap();
        let adapter = ConnAdapter(conn);
        assert_eq!(adapter.run_lease_sweep(now).unwrap(), 1);
    }

    /// #2371 — the sweep is a FORCED lease revocation, so it must leave the
    /// same coordination-audit trace the voluntary ops do: exactly one
    /// `coordination.lease_expire_reclaim` `signed_events` row per reclaimed
    /// lease, attributed to the reclaimed holder. Mirrors the voluntary
    /// lease-op audit test in `coordination_audit::tests`.
    #[test]
    fn run_lease_sweep_emits_coordination_audit_per_reclaimed_lease() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        let now = 1_700_000_000;
        let action = crate::models::Action {
            id: "audit-ls-1".to_string(),
            namespace: "_act".to_string(),
            kind: "test.kind".to_string(),
            state: crate::models::ActionState::Pending,
            title: "t".to_string(),
            payload: serde_json::json!({}),
            priority: 5,
            agent_id: None,
            claimed_by: None,
            vector_clock: serde_json::json!({}),
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        crate::actions::create(&conn, &action).unwrap();
        crate::actions::lease_acquire(&conn, "audit-ls-1", "holder-x", now, now - 1).unwrap();

        let adapter = ConnAdapter(conn);
        assert_eq!(adapter.run_lease_sweep(now).unwrap(), 1);

        let (count, agent): (i64, String) = adapter
            .0
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::LEASE_SWEEP_RECLAIM],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one lease-sweep reclaim audit row");
        assert_eq!(agent, "holder-x", "attributed to the reclaimed holder");
    }

    /// Default-const sanity: the cadence resolves to the documented value so a
    /// drift in the `SECS_PER_HOUR` SSOT trips here.
    #[test]
    fn tunable_defaults_are_documented_values() {
        assert_eq!(
            DEFAULT_INTERVAL,
            Duration::from_secs(crate::SECS_PER_HOUR as u64)
        );
    }

    /// Adapter whose `run_lease_sweep` always errors — exercises the `Err` arm
    /// of the [`spawn`] loop's `match` (the `tracing::warn!` path).
    struct ErrAdapter;
    impl LeaseSweepAdapter for ErrAdapter {
        fn run_lease_sweep(&self, _now_unix: i64) -> anyhow::Result<usize> {
            anyhow::bail!("synthetic lease sweep failure")
        }
    }

    /// Adapter that reports a reclaim count so the `Ok(n)` info-log arm of the
    /// loop fires, and counts how many times the loop ticked so the test can
    /// prove the spawned task actually ran the body.
    struct CountingAdapter {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl LeaseSweepAdapter for CountingAdapter {
        fn run_lease_sweep(&self, _now_unix: i64) -> anyhow::Result<usize> {
            // Report a non-zero reclaim on the first tick (Ok(n) arm), zero
            // thereafter (Ok(0) arm) — both loop arms get covered.
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(usize::from(n == 0))
        }
    }

    /// Drive the real [`spawn`] tokio loop with a sub-millisecond interval so
    /// the loop body (sleep → lock → run_lease_sweep → match arms) executes
    /// several times, then abort the handle. Covers the `Ok(0)`, `Ok(n)`, and
    /// loop-cadence lines.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_loop_drives_run_lease_sweep_across_arms() {
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
            "spawn loop should have ticked run_lease_sweep at least twice"
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
}
