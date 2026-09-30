// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4089 — every CPU-bound embed or rerank an HTTP handler needs runs on
//! tokio's blocking pool through this module, never inline on a runtime
//! worker (rust-1.98 CONCURRENCY-22).
//!
//! A candle forward pass (local embedder, cross-encoder) holds whichever
//! thread runs it for 10–200 ms per row, and far longer for a bulk batch or
//! the smart_load family vote. Run inline, it takes a tokio worker out of
//! service for that whole time; since tokio 1.52.2 reverted LIFO-slot
//! stealing (tokio#8100), a task parked behind that worker (`/health`, the
//! postgres pool acquire, graceful shutdown) stays stranded until the
//! forward returns. #3988 fixed the boot backfill; this module is the
//! request-path twin.
//!
//! **Failure posture.** A blocking task that does not complete (the closure
//! panicked, or the runtime is shutting down) surfaces as `None` from
//! [`on_blocking_pool`], after one `embed.task.failed` WARN naming the
//! surface and one `ai_memory_embed_task_failed_total{surface}` increment.
//! Each caller maps `None` onto the SAME degrade its embed-failure arm
//! already takes (vectorless write, keyword recall, pre-rerank ordering,
//! keyword family routing) or onto its fail-closed refusal
//! (`check_duplicate` 503). Never a panic, never `unwrap()` on a join
//! handle (ERRORS-06), never a wrong result.

use crate::embeddings::{Embed, Embedder};

/// Tracing target of the WARN every failed blocking embed/rerank task emits.
pub const EMBED_TASK_FAILED_TARGET: &str = "embed.task.failed";

/// Run `work` on the blocking pool and await it without holding this worker.
///
/// Returns `None` (after the WARN + counter above) when the task did not
/// complete. `surface` is one of [`crate::metrics::EMBED_TASK_SURFACES`].
pub async fn on_blocking_pool<T, F>(surface: &'static str, work: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(out) => Some(out),
        Err(e) => {
            tracing::warn!(
                target: EMBED_TASK_FAILED_TARGET,
                surface,
                error = %e,
                "embed/rerank task on the blocking pool did not complete; the request \
                 degrades exactly as on an embed failure (#4089)"
            );
            crate::metrics::inc_embed_task_failed(surface);
            None
        }
    }
}

/// Embed one document-role `text` with a clone of `emb` (all-`Arc` inside,
/// so the clone shares the model) on the blocking pool.
///
/// `None` = the task did not complete; `Some(Err)` = the embedder failed.
pub async fn embed_document(
    surface: &'static str,
    emb: &Embedder,
    text: String,
) -> Option<anyhow::Result<Vec<f32>>> {
    let emb = emb.clone();
    on_blocking_pool(surface, move || emb.embed(&text)).await
}

/// The recall query embedding through the bounded #2577 funnel
/// ([`crate::embeddings::recall_query_embedding`]: cache, budget, degrade)
/// on the blocking pool. `None` means keyword-only recall, exactly as when
/// the funnel itself degrades; a task that did not complete also counts as
/// a recall-embed degrade (`ai_memory_recall_embed_degraded_total`).
pub async fn recall_query_embedding(emb: Option<&Embedder>, text: &str) -> Option<Vec<f32>> {
    let emb = emb?.clone();
    let text = text.to_string();
    match on_blocking_pool(crate::metrics::EMBED_SURFACE_RECALL, move || {
        crate::embeddings::recall_query_embedding(&emb, &text)
    })
    .await
    {
        Some(vector) => vector,
        None => {
            crate::metrics::inc_recall_embed_degraded();
            None
        }
    }
}

/// The `memory_smart_load` family pick
/// ([`crate::mcp::pick_family_for_intent`]). With an embedder the pick
/// embeds the intent AND every family descriptor, so it runs on the blocking
/// pool; a task that did not complete falls back to the keyword-only pick,
/// the same routing the pick itself uses when the embedder fails. Without
/// an embedder the pick is pure keyword scoring and stays inline.
pub async fn pick_family_for_intent(
    emb: Option<&Embedder>,
    intent: &str,
) -> (crate::profile::Family, f32, &'static str) {
    let Some(emb) = emb else {
        return crate::mcp::pick_family_for_intent(intent, None);
    };
    let emb = emb.clone();
    let owned = intent.to_string();
    match on_blocking_pool(crate::metrics::EMBED_SURFACE_SMART_LOAD, move || {
        crate::mcp::pick_family_for_intent(&owned, Some(&emb as &dyn Embed))
    })
    .await
    {
        Some(pick) => pick,
        None => crate::mcp::pick_family_for_intent(intent, None),
    }
}

#[cfg(test)]
mod tests {
    use super::on_blocking_pool;
    use std::time::Duration;

    /// A task that panics on the blocking pool is `None` (never a panic on
    /// the caller, never an `unwrap()`), counted under its surface.
    #[tokio::test]
    async fn a_panicked_task_is_none_and_counted_4089() {
        let surface = crate::metrics::EMBED_SURFACE_REFLECT;
        let before = crate::metrics::embed_task_failed_count(surface);
        let out: Option<u8> = on_blocking_pool(surface, || panic!("forward pass blew up")).await;
        assert_eq!(out, None, "a panicked task must degrade to None");
        assert!(
            crate::metrics::embed_task_failed_count(surface) > before,
            "the failure must be counted under its surface"
        );
    }

    /// The offload keeps the ONE runtime worker free while the closure blocks:
    /// a freshly spawned task is polled at once, not after the block (the
    /// #3988 one-worker shape). Inline, the probe would wait out `BLOCK`.
    #[test]
    fn the_worker_stays_free_while_the_closure_blocks_4089() {
        const BLOCK: Duration = Duration::from_secs(2);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("one-worker runtime");
        let (tx, rx) = std::sync::mpsc::channel();
        let probe_wait = rt.block_on(async move {
            let blocked = tokio::spawn(on_blocking_pool(
                crate::metrics::EMBED_SURFACE_RECALL,
                move || {
                    let _ = tx.send(());
                    std::thread::sleep(BLOCK);
                    7_u8
                },
            ));
            rx.recv_timeout(Duration::from_secs(10))
                .expect("closure started");
            let started = std::time::Instant::now();
            tokio::spawn(async {}).await.expect("probe joined");
            let wait = started.elapsed();
            assert_eq!(blocked.await.expect("offload joined"), Some(7));
            wait
        });
        assert!(
            probe_wait < Duration::from_secs(1),
            "probe waited {probe_wait:?} behind a blocked worker (block was {BLOCK:?})"
        );
    }
}
