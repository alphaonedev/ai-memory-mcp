// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3342 — live embedding-backfill worker for `embed_mode=async`.
//!
//! Periodic tick + wake after durable Pending inserts. Permanently
//! unembeddable rows (`embedding IS NULL` but decrypt-skipped, #1779/#2317)
//! stay in the SQL scan forever; without a skip/backoff the worker would
//! re-WARN every 2 s (Fable review #2). This process-local skip set + idle
//! backoff (2 s → 30 s while nothing was written, reset on [`wake`]) makes
//! the worker **converge**. Durable skip markers remain #3344.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::embeddings::{Embed, Embedder};
use crate::store::{CallerContext, MemoryStore};

/// Tick while there is embeddable work.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(2);
/// Tick while the last pass wrote nothing (caught up / only skipped rows).
pub const IDLE_INTERVAL: Duration = Duration::from_secs(30);

fn notify() -> &'static Arc<Notify> {
    static HANDLE: OnceLock<Arc<Notify>> = OnceLock::new();
    HANDLE.get_or_init(|| Arc::new(Notify::new()))
}

/// Wake after a durable `embed_mode=async` insert. Clears idle/skip so the
/// new Pending row is drained on the next pass.
pub fn wake() {
    notify().notify_one();
}

#[derive(Debug, Default)]
struct DrainState {
    /// Ids peeked but not written — treated as permanently unembeddable
    /// until [`DrainState::reset`] (wake).
    skip: HashSet<String>,
    /// When true the next tick must NOT scan or sweep (converged).
    caught_up: bool,
}

impl DrainState {
    fn reset(&mut self) {
        self.skip.clear();
        self.caught_up = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DrainOutcome {
    written: usize,
    ran_sweep: bool,
    next_delay: Duration,
}

async fn drain_once(
    state: &mut DrainState,
    store: &dyn MemoryStore,
    emb: &dyn Embed,
    batch_size: usize,
) -> DrainOutcome {
    if state.caught_up {
        crate::metrics::registry().embed_backfill_pending.set(0);
        return DrainOutcome {
            written: 0,
            ran_sweep: false,
            next_delay: IDLE_INTERVAL,
        };
    }
    let ctx = CallerContext::for_admin(crate::identity::sentinels::EMBEDDING_BACKFILL);
    let peek = match store.list_unembedded(&ctx, batch_size).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("embed backfill worker: unembedded scan failed: {e}");
            return DrainOutcome {
                written: 0,
                ran_sweep: false,
                next_delay: IDLE_INTERVAL,
            };
        }
    };
    let work: Vec<(String, String, String)> = peek
        .into_iter()
        .filter(|(id, _, _)| !state.skip.contains(id))
        .collect();
    let pending = i64::try_from(work.len()).unwrap_or(i64::MAX);
    crate::metrics::registry()
        .embed_backfill_pending
        .set(pending);
    if work.is_empty() {
        state.caught_up = true;
        return DrainOutcome {
            written: 0,
            ran_sweep: false,
            next_delay: IDLE_INTERVAL,
        };
    }
    let written = crate::store::run_embedding_backfill_on_store(store, &ctx, emb, batch_size).await;
    if written > 0 {
        tracing::info!("embed backfill worker: {written} row(s) embedded");
    }
    let left = match store.list_unembedded(&ctx, batch_size).await {
        Ok(rows) => rows,
        Err(_) => {
            return DrainOutcome {
                written,
                ran_sweep: true,
                next_delay: IDLE_INTERVAL,
            };
        }
    };
    if written == 0 {
        // Zero-progress: these ids will never embed (decrypt-skip /
        // oversize). Remember them and idle.
        for (id, _, _) in &left {
            state.skip.insert(id.clone());
        }
        for (id, _, _) in &work {
            state.skip.insert(id.clone());
        }
        state.caught_up = true;
        crate::metrics::registry().embed_backfill_pending.set(0);
        return DrainOutcome {
            written: 0,
            ran_sweep: true,
            next_delay: IDLE_INTERVAL,
        };
    }
    // Progress: an empty leftover means only decrypt-skipped rows remain
    // (they are filtered out of the scan result). Idle. A non-empty
    // leftover is remaining embeddable work — keep the fast tick.
    if left.is_empty() {
        state.caught_up = true;
        crate::metrics::registry().embed_backfill_pending.set(0);
        DrainOutcome {
            written,
            ran_sweep: true,
            next_delay: IDLE_INTERVAL,
        }
    } else {
        crate::metrics::registry()
            .embed_backfill_pending
            .set(i64::try_from(left.len()).unwrap_or(i64::MAX));
        DrainOutcome {
            written,
            ran_sweep: true,
            next_delay: DEFAULT_INTERVAL,
        }
    }
}

/// Spawn the long-lived drain. Cheap when idle (parked on sleep/notify).
pub fn spawn(
    store: Arc<dyn MemoryStore>,
    embedder: Arc<Option<Embedder>>,
    batch_size: usize,
) -> JoinHandle<()> {
    let notify = Arc::clone(notify());
    tokio::spawn(async move {
        let mut state = DrainState::default();
        let mut delay = Duration::ZERO;
        loop {
            if delay > Duration::ZERO {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = notify.notified() => {
                        state.reset();
                    }
                }
            }
            let Some(emb) = embedder.as_ref() else {
                crate::metrics::registry().embed_backfill_pending.set(0);
                delay = IDLE_INTERVAL;
                continue;
            };
            let out = drain_once(&mut state, store.as_ref(), emb, batch_size).await;
            delay = out.next_delay;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AgentRegistration, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, Tier,
    };
    use crate::store::{Capabilities, Filter, StoreError, StoreResult, UpdatePatch, VerifyReport};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingStore {
        /// Embeddable unembedded rows.
        rows: Mutex<Vec<(String, String, String)>>,
        list_calls: AtomicUsize,
        sweep_writes: AtomicUsize,
    }

    impl CountingStore {
        fn new(rows: Vec<(String, String, String)>) -> Self {
            Self {
                rows: Mutex::new(rows),
                list_calls: AtomicUsize::new(0),
                sweep_writes: AtomicUsize::new(0),
            }
        }
    }

    fn dummy(id: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: "mock".into(),
            title: "t".into(),
            content: "c".into(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "mock".into(),
            access_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "alice"}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: LifecycleState::Open,
        }
    }

    #[async_trait::async_trait]
    impl MemoryStore for CountingStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities::DURABLE
        }
        async fn store(&self, _: &CallerContext, m: &Memory) -> StoreResult<String> {
            Ok(m.id.clone())
        }
        async fn get(&self, _: &CallerContext, id: &str) -> StoreResult<Memory> {
            Err(StoreError::NotFound { id: id.to_string() })
        }
        async fn update(&self, _: &CallerContext, _: &str, _: UpdatePatch) -> StoreResult<()> {
            Ok(())
        }
        async fn delete(&self, _: &CallerContext, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn list(&self, _: &CallerContext, _: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(vec![dummy("listed")])
        }
        async fn search(&self, _: &CallerContext, _: &str, _: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(vec![])
        }
        async fn verify(&self, _: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            Ok(VerifyReport {
                memory_id: id.to_string(),
                integrity_ok: true,
                findings: vec![],
                signature_verified: false,
                cid_ok: None,
                cid_mismatch: None,
            })
        }
        async fn link(&self, _: &CallerContext, _: &MemoryLink) -> StoreResult<()> {
            Ok(())
        }
        async fn list_links(&self, _: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            Ok(vec![])
        }
        async fn register_agent(
            &self,
            _: &CallerContext,
            _: &AgentRegistration,
        ) -> StoreResult<()> {
            Ok(())
        }
        async fn list_unembedded(
            &self,
            _ctx: &CallerContext,
            limit: usize,
        ) -> StoreResult<Vec<(String, String, String)>> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            let rows = self.rows.lock().expect("rows");
            Ok(rows.iter().take(limit).cloned().collect())
        }
        async fn set_embeddings_batch(
            &self,
            _ctx: &CallerContext,
            entries: &[(String, Vec<f32>)],
            _space: &str,
        ) -> StoreResult<usize> {
            let mut rows = self.rows.lock().expect("rows");
            let before = rows.len();
            rows.retain(|(id, _, _)| !entries.iter().any(|(e, _)| e == id));
            let n = before.saturating_sub(rows.len());
            self.sweep_writes.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }
    }

    struct CountingEmbed {
        batches: AtomicUsize,
    }
    impl Embed for CountingEmbed {
        fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
            Ok(vec![0.01; 8])
        }
        fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
            self.batches.fetch_add(1, Ordering::SeqCst);
            texts.iter().map(|t| self.embed(t)).collect()
        }
    }

    #[tokio::test]
    async fn drain_converges_when_only_permanently_unembeddable_rows_remain() {
        // One pending row (written on first sweep). After it is gone the
        // scan returns empty (postgres decrypt-skip of poison rows yields
        // empty) — second tick must NOT sweep / embed.
        let store = CountingStore::new(vec![("pending".into(), "t".into(), "c".into())]);
        let emb = CountingEmbed {
            batches: AtomicUsize::new(0),
        };
        let mut state = DrainState::default();
        let first = drain_once(&mut state, &store, &emb, 8).await;
        assert!(first.ran_sweep);
        assert!(first.written >= 1);
        assert_eq!(first.next_delay, IDLE_INTERVAL);
        assert_eq!(crate::metrics::registry().embed_backfill_pending.get(), 0);
        let lists_after_first = store.list_calls.load(Ordering::SeqCst);
        let batches_after_first = emb.batches.load(Ordering::SeqCst);
        assert!(batches_after_first >= 1);

        let second = drain_once(&mut state, &store, &emb, 8).await;
        assert!(!second.ran_sweep, "caught-up tick must not run the sweep");
        assert_eq!(second.written, 0);
        assert_eq!(
            store.list_calls.load(Ordering::SeqCst),
            lists_after_first,
            "caught-up tick must not re-scan"
        );
        assert_eq!(
            emb.batches.load(Ordering::SeqCst),
            batches_after_first,
            "caught-up tick must not call embed_batch"
        );
        assert_eq!(crate::metrics::registry().embed_backfill_pending.get(), 0);
    }

    #[tokio::test]
    async fn wake_resets_caught_up_so_a_new_pending_row_is_drained() {
        let store = CountingStore::new(vec![]);
        let emb = CountingEmbed {
            batches: AtomicUsize::new(0),
        };
        let mut state = DrainState::default();
        let first = drain_once(&mut state, &store, &emb, 8).await;
        assert!(!first.ran_sweep);
        assert!(state.caught_up);
        state.reset();
        store
            .rows
            .lock()
            .expect("rows")
            .push(("new-pending".into(), "t".into(), "c".into()));
        let again = drain_once(&mut state, &store, &emb, 8).await;
        assert!(again.ran_sweep);
        assert!(again.written >= 1);
    }

    #[test]
    fn wake_before_spawn_does_not_panic() {
        wake();
    }
}
