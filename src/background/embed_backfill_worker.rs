// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3342 — live embedding-backfill worker for `embed_mode=async`.
//!
//! The serve-boot sweep (`run_embedding_backfill_on_store`) ran **once**
//! and then exited. A row stored with `embed_status: pending` stayed
//! `embedding IS NULL` (invisible to semantic recall) until the next
//! daemon restart — a silent-wrong-result on the certified pg tier.
//!
//! This worker drains `MemoryStore::list_unembedded` for the process
//! lifetime: a periodic tick plus an immediate wake from async creates.
//! Failures log and retry on the next tick (they must not die the
//! worker — that would recreate the boot-only hole). CONCURRENCY-22:
//! the shared sweep still owns embed_batch; we do not pin extra
//! request-path work here.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::embeddings::Embedder;
use crate::store::{CallerContext, MemoryStore};

/// Default wake interval when no async-create notify has fired.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(2);

fn notify() -> &'static Arc<Notify> {
    static HANDLE: OnceLock<Arc<Notify>> = OnceLock::new();
    HANDLE.get_or_init(|| Arc::new(Notify::new()))
}

/// Wake the live backfill worker after a durable `embed_mode=async` insert.
/// No-op if the worker has not been spawned (tests / MCP stdio).
pub fn wake() {
    notify().notify_one();
}

/// Spawn the long-lived drain. Cheap when idle (parked on interval/notify).
pub fn spawn(
    store: Arc<dyn MemoryStore>,
    embedder: Arc<Option<Embedder>>,
    batch_size: usize,
) -> JoinHandle<()> {
    let notify = Arc::clone(notify());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DEFAULT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick completes immediately so boot still drains the
        // historical unembedded backlog before parking.
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = notify.notified() => {}
            }
            let Some(emb) = embedder.as_ref() else {
                crate::metrics::registry().embed_backfill_pending.set(0);
                continue;
            };
            let ctx = CallerContext::for_admin(crate::identity::sentinels::EMBEDDING_BACKFILL);
            match store.list_unembedded(&ctx, batch_size).await {
                Ok(peek) => {
                    let pending = i64::try_from(peek.len()).unwrap_or(i64::MAX);
                    crate::metrics::registry()
                        .embed_backfill_pending
                        .set(pending);
                    if peek.is_empty() {
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("embed backfill worker: unembedded scan failed: {e}");
                    continue;
                }
            }
            let written = crate::store::run_embedding_backfill_on_store(
                store.as_ref(),
                &ctx,
                emb,
                batch_size,
            )
            .await;
            if written > 0 {
                tracing::info!("embed backfill worker: {written} row(s) embedded");
            }
            if let Ok(left) = store.list_unembedded(&ctx, 1).await {
                crate::metrics::registry()
                    .embed_backfill_pending
                    .set(if left.is_empty() { 0 } else { 1 });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_before_spawn_does_not_panic() {
        wake();
    }
}
