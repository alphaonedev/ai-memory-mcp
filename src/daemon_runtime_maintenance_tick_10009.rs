// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10009 — one tick of each background maintenance loop, as a function.
//!
//! The loops in `daemon_runtime` sleep, then run one tick. Before #10009 the
//! tick was the loop body itself, so no test could run it: the archive
//! retention leg (an unset bound deletes nothing, a set bound deletes only
//! the archived rows older than it, #9945) was proven on the trait method
//! but not on the loop that calls it. Each tick is now a function the loop
//! calls once per interval, with no change in order or behaviour, and the
//! integration cells in `tests/archive_purge_unset_bound_9945.rs` drive it
//! directly on both backends.
//!
//! * [`pg_maintenance_tick`] — the PostgreSQL loop
//!   (`spawn_postgres_maintenance_loop_if_enabled`): recall-access fold,
//!   `run_gc`, `retention_purge`, `lease_sweep_expired` and the K2
//!   pending-action timeout sweep with its lifecycle event.
//! * [`sqlite_gc_tick`] — the first three legs of the SQLite loop
//!   (`spawn_gc_loop_with_shadow_retention_tracked`): recall-access fold,
//!   `db::gc` and `db::auto_purge_archive`. The loop's later legs (erasure
//!   sweep, shadow retention, the rest) keep running after it under the same
//!   lock, in the same order.
//!
//! Every leg logs its failure and the tick goes on to the next leg (degrade,
//! never corrupt); a tick never aborts its loop.

use crate::db;

/// One tick of the PostgreSQL maintenance loop (#10009). The loop in
/// `spawn_postgres_maintenance_loop_if_enabled` sleeps `GC_INTERVAL_SECS`
/// and then calls this once.
///
/// `admin` is the daemon's admin context (every owner's archives are in
/// scope, as on the unscoped SQLite purge). `archive_max_days` is the
/// validated retention bound: `None` deletes no archived row; `Some(d)`
/// deletes only the archived rows older than `d` days
/// ([`crate::store::MemoryStore::retention_purge`], #9945).
#[cfg(feature = "sal")]
#[doc(hidden)]
pub async fn pg_maintenance_tick(
    app: &crate::handlers::AppState,
    admin: &crate::store::CallerContext,
    archive_on_gc: bool,
    archive_max_days: Option<crate::validate::RetentionDays>,
) {
    // Fold-before-gc (pg twin of the sqlite loop): apply pending
    // recall-access TTL extensions before evaluating eviction.
    if let Err(e) = app.store.fold_recall_accesses().await {
        tracing::warn!("pg-maint: recall-access fold failed (pre-gc): {e}");
    }
    match app.store.run_gc(archive_on_gc).await {
        Ok(n) if n > 0 => tracing::info!("pg-maint: expired {n} memories"),
        Ok(_) => {}
        Err(e) => tracing::warn!("pg-maint: run_gc failed: {e}"),
    }
    match app.store.retention_purge(admin, archive_max_days).await {
        Ok(n) if n > 0 => {
            tracing::info!("pg-maint: purged {n} old archived memories");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("pg-maint: retention_purge failed: {e}"),
    }
    let now = chrono::Utc::now().timestamp();
    match app.store.lease_sweep_expired(now).await {
        Ok(n) if n > 0 => tracing::info!("pg-maint: reclaimed {n} expired leases"),
        Ok(_) => {}
        Err(e) => tracing::warn!("pg-maint: lease_sweep_expired failed: {e}"),
    }
    // FBL-22 residual — K2 pending-timeout sweep on the pg corpus. The
    // sqlite `spawn_pending_timeout_sweep_loop` binds the LOCAL sqlite
    // `Db` mutex + the rusqlite free fn, so a postgres daemon never
    // expired its governance `pending_actions` (approvable forever +
    // unbounded queue growth). Drive the SAL trait method here and fan
    // out the SAME `pending_action_expired` lifecycle event the sqlite
    // loop dispatches — both backends fire the identical event shape.
    match app
        .store
        .sweep_pending_action_timeouts(super::PENDING_TIMEOUT_DEFAULT_SECS)
        .await
    {
        Ok(expired) if !expired.is_empty() => {
            tracing::info!(
                "pg-maint: expired {} stale pending_action(s)",
                expired.len()
            );
            for (id, namespace) in expired {
                crate::handlers::dispatch_event_postgres(
                    app,
                    "pending_action_expired",
                    &id,
                    &namespace,
                    None,
                    None,
                )
                .await;
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("pg-maint: sweep_pending_action_timeouts failed: {e}");
        }
    }
}

/// The first three legs of one SQLite gc tick (#10009): recall-access fold,
/// `db::gc`, then `db::auto_purge_archive`. The loop in
/// `spawn_gc_loop_with_shadow_retention_tracked` calls it under the `Db`
/// lock, then runs its later legs.
///
/// `archive_max_days` is the validated retention bound: `None` deletes no
/// archived row; `Some(d)` deletes only the archived rows older than `d`
/// days (#9945).
#[doc(hidden)]
pub fn sqlite_gc_tick(
    conn: &rusqlite::Connection,
    ttl: &crate::config::ResolvedTtl,
    archive_on_gc: bool,
    archive_max_days: Option<crate::validate::RetentionDays>,
) {
    // v0.9.0 P0-1 (#1869) — fold-before-gc is LOAD-BEARING:
    // with recall pure by default, a recalled row's TTL
    // extension lives in unfolded `recall_observations` rows
    // until a fold applies it. Folding at the TOP of every gc
    // tick guarantees a recalled row is extended before
    // eviction is evaluated — including when
    // AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0 disables the
    // dedicated fold loop (the fold then rides this tick).
    match db::fold_recall_accesses(conn, ttl.short_extend_secs, ttl.mid_extend_secs) {
        Ok(n) if n > 0 => {
            tracing::info!("gc: folded recall accesses for {n} memories (pre-gc)");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("recall-access fold failed (pre-gc): {e}"),
    }
    match db::gc(conn, archive_on_gc) {
        Ok(n) if n > 0 => tracing::info!("gc: expired {n} memories"),
        Ok(_) => {}
        Err(e) => tracing::warn!("gc: expiry pass failed: {e}"),
    }
    // Auto-purge old archives if configured
    match db::auto_purge_archive(conn, archive_max_days) {
        Ok(n) if n > 0 => tracing::info!("gc: purged {n} old archived memories"),
        Ok(_) => {}
        Err(e) => tracing::warn!("gc: archive retention purge failed: {e}"),
    }
}
