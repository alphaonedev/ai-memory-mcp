// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use crate::{db, handlers::Db};
use anyhow::Result;

/// v0.9.0 G5b (#1822 follow-up) — graceful-shutdown audit flush: emit a
/// final dual-chain audit-head witness anchor for the CURRENT chain head
/// (bypassing the `WATERMARK_INTERVAL` throttle), then run the final WAL
/// checkpoint so the witness row itself is folded in.
///
/// Called by [`super::serve`] AFTER the HTTP server has fully quiesced and the
/// deferred-audit queue has drained, so the witnessed head includes every
/// append of the daemon's life. Inherits the emitter's own gating: with no
/// enrolled witness key the emission is a no-op (byte-identical legacy
/// shutdown). The caller must treat any witness/checkpoint failure as an
/// uncertified shutdown. A failure can leave a witness checkpoint or
/// off-table anchor partially committed; neither is a clean-shutdown claim,
/// and both remain available for operator triage and idempotent recovery.
///
/// # Errors
/// Returns an error when final witness emission or the WAL checkpoint fails.
pub async fn shutdown_witness_flush_and_checkpoint(db_state: &Db) -> Result<()> {
    let lock = db_state.lock().await;
    crate::signed_events::try_force_emit_audit_head_witness(&lock.0)?;
    db::checkpoint(&lock.0)
}

/// Certify the selected corpus, never silently substitute the SQLite sidecar.
///
/// # Errors
/// Returns unsupported-backend, witness, or durable persistence failures.
#[cfg(feature = "sal")]
pub async fn shutdown_active_store_witness(store: &dyn crate::store::MemoryStore) -> Result<()> {
    store.certify_shutdown().await.map_err(anyhow::Error::from)
}

/// Join every owned writer before closing deferred audit or certifying a head.
pub(super) async fn join_background_writers(
    tasks: Vec<tokio::task::JoinHandle<()>>,
    blocking_tasks: &std::sync::atomic::AtomicUsize,
    atomise_worker: Option<std::thread::JoinHandle<()>>,
    task_join_deadline: tokio::time::Instant,
) -> Result<()> {
    use super::fatal_shutdown;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        match tokio::time::timeout_at(task_join_deadline, task).await {
            Err(_) => {
                return Err(fatal_shutdown(
                    "background writer shutdown deadline exceeded",
                ));
            }
            Ok(Err(error)) if !error.is_cancelled() => {
                tracing::error!(%error, "background writer task failed before shutdown");
                return Err(fatal_shutdown("background writer task failed"));
            }
            Ok(Ok(())) | Ok(Err(_)) => {}
        }
    }
    while blocking_tasks.load(Ordering::SeqCst) != 0 {
        if tokio::time::Instant::now() >= task_join_deadline {
            return Err(fatal_shutdown("blocking writer shutdown deadline exceeded"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if let Some(worker) = atomise_worker {
        while !worker.is_finished() {
            if tokio::time::Instant::now() >= task_join_deadline {
                return Err(fatal_shutdown("atomise writer shutdown deadline exceeded"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if worker.join().is_err() {
            return Err(fatal_shutdown("atomise writer failed before shutdown"));
        }
    }
    Ok(())
}
