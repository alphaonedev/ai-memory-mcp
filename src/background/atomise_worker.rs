// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2986 / #2984 — bounded, single-consumer background worker for
//! Batman auto-atomisation.
//!
//! # The defect this closes
//!
//! Pre-v1.0.0 the deferred auto-atomise path did a raw
//! `std::thread::spawn` PER over-threshold store
//! (`src/hooks/pre_store/auto_atomise.rs`): each spawned thread opened
//! its OWN rusqlite connection and drove an LLM curator round trip with
//! the 3-retry ~3.1 s backoff ladder. Unbounded, unpaced, unresumable —
//! a write burst converted directly into thread / connection / vendor-QPS
//! exhaustion. That is the bare-spawn shape the #2587 vote already
//! rejected for `auto_tag`; it was latent only because #2983 made the
//! whole path inert, and it would have gone live the moment the wiring
//! landed.
//!
//! # The fix, per the remediation vote (2026-08-16, protocol `4d3ea1c5`)
//!
//! The durable INSERT completes first — atoms are DERIVED data, the
//! memory TEXT is the source of truth — and the enqueue is a
//! **non-blocking `try_send` onto a BOUNDED channel with exactly ONE
//! consumer**. At most one curator round trip is in flight per daemon,
//! so a concurrent write storm cannot burst the vendor. A full queue
//! DROPS the job (counted + WARNed + an honest
//! `skipped_queue_full` envelope token) — a DEGRADE (no atoms for that
//! write; the durable text is untouched and `memory_atomise` recovers
//! it), never a write failure.
//!
//! # Why a plain OS thread, not a tokio task
//!
//! The two surfaces that enqueue have DIFFERENT runtime shapes:
//!
//! * **HTTP `serve`** is multi-threaded tokio.
//! * **MCP stdio** is a synchronous, single-threaded JSON-RPC loop with
//!   no runtime at all (the #965 audit).
//!
//! A `std::sync::mpsc::sync_channel` + one dedicated OS thread serves
//! BOTH: `try_send` is synchronous and non-blocking, so it is safe to
//! call from an async handler AND from the stdio loop, and the consumer
//! thread can drive the blocking curator call directly (the atomiser is
//! `rusqlite::Connection`-bound and blocking by construction — running
//! it on a tokio worker would either block a runtime thread or need
//! `spawn_blocking` on every job).
//!
//! # Staleness is structurally impossible
//!
//! The worker holds an [`AtomiserProvider`] — a closure resolved at
//! DRAIN time, never a boot-pinned `Arc<Atomiser>`. This is the whole
//! reason the #2983 vote abolished the process-global `OnceLock` rather
//! than installing it: a pinned client keeps egressing to a REVOKED
//! vendor after an `[llm]` / egress reload AND emits signed
//! `atomisation_complete` payloads whose `curator_model` names a model
//! that never ran — a false attestation laundered into the #1870 lane.
//!
//! # Backend confinement
//!
//! No postgres job is ever enqueued: the enqueue SITES branch on the
//! storage backend and report `skipped_backend_unsupported`. The
//! atomiser is `rusqlite::Connection`-bound, and landing atoms in a
//! different store than their source would be mixed-state corruption.

use std::path::PathBuf;
use std::sync::Arc;

use crate::atomisation::Atomiser;

/// Env var resolving the bounded channel capacity. A plain positive-usize
/// resolver (the `AI_MEMORY_AUTOTAG_QUEUE_CAPACITY` / #2587 shape, itself
/// modelled on `AI_MEMORY_VECTOR_INDEX_CAPACITY`): disabling atomisation
/// entirely is already governed by the namespace standard's
/// `auto_atomise` knob, so a second disable lever here would be
/// redundant tri-state complexity.
pub const ENV_ATOMISE_QUEUE_CAPACITY: &str = "AI_MEMORY_ATOMISE_QUEUE_CAPACITY";

/// Compiled default queue depth. One consumer drains at roughly one LLM
/// round trip per few seconds; 256 absorbs a multi-second burst without
/// dropping, while bounding worst-case memory to a small fixed number of
/// in-flight [`AtomiseJob`] structs (each holds only ids + a path — the
/// multi-KB content NEVER crosses the queue, it is re-read from the
/// durable row by the worker).
pub const ATOMISE_QUEUE_CAPACITY_DEFAULT: usize = 256;

/// Thread name for the single consumer, so an operator reading `top -H`
/// or a core dump can attribute the LLM round trip.
const WORKER_THREAD_NAME: &str = "ai-memory-atomise";

/// Tracing target for worker-lifecycle + queue events.
const TRACE_TARGET: &str = "atomise.worker";

/// One deferred atomisation job.
///
/// Deliberately carries NO content: the worker re-reads the durable row
/// through its own connection, so the multi-KB body never crosses the
/// channel (the Cluster-F PERF-10 discipline) and a job can never carry
/// a stale copy of text the caller has since superseded.
#[derive(Debug, Clone)]
pub struct AtomiseJob {
    /// The sqlite file the committed row lives in. The worker opens its
    /// OWN connection against this path rather than borrowing the
    /// daemon's single `Arc<Mutex<Connection>>` — holding that mutex
    /// across an LLM round trip is the exact availability class #2587
    /// moved `auto_tag` off the request path for.
    pub db_path: PathBuf,
    /// The COMMITTED primary key (never a caller-supplied value).
    pub memory_id: String,
    /// The namespace the row landed in — telemetry only.
    pub namespace: String,
    /// The ORIGINAL WRITER's resolved agent id, so the atomiser's signed
    /// `atomisation_complete` event and the atoms' authorship attribute
    /// to the agent that wrote the source — never an admin principal.
    pub agent_id: String,
    /// Per-namespace atom token budget resolved at enqueue time.
    pub max_atom_tokens: u32,
}

/// Resolves the CURRENT atomiser at DRAIN time. Returns `None` when no
/// curator is wired (keyword tier, egress-refused, or a disabling
/// `[llm]` reload landed between enqueue and drain).
pub type AtomiserProvider = Arc<dyn Fn() -> Option<Arc<Atomiser>> + Send + Sync>;

/// Cheap, cloneable producer handle. Held by `AppState` (HTTP) and by
/// the MCP stdio loop.
#[derive(Clone)]
pub struct AtomiseQueue {
    tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::SyncSender<AtomiseJob>>>>,
}

impl std::fmt::Debug for AtomiseQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomiseQueue").finish_non_exhaustive()
    }
}

impl AtomiseQueue {
    /// Close admission across every producer clone. Already accepted jobs drain.
    pub fn close(&self) {
        self.tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    /// Non-blocking enqueue. Returns `false` when the bounded queue is
    /// full or the consumer has gone away — the caller reports
    /// `skipped_queue_full` and the durable write (already committed)
    /// is untouched.
    ///
    /// Never waits for channel capacity or consumer work. The admission mutex
    /// covers only `try_send` or close, making this callable from an async
    /// handler and from the synchronous MCP stdio loop alike.
    #[must_use]
    pub fn try_enqueue(&self, job: AtomiseJob) -> bool {
        let id = job.memory_id.clone();
        let sender = self
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(tx) = sender.as_ref() else {
            crate::metrics::inc_atomise_dropped();
            return false;
        };
        let result = tx.try_send(job);
        drop(sender);
        match result {
            Ok(()) => {
                crate::metrics::inc_atomise_enqueued();
                true
            }
            Err(e) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    "atomise.queue.dropped: bounded queue refused the job for {id} — \
                     skipping atomisation (the durable write already succeeded; \
                     `memory_atomise` can recover it): {e}"
                );
                crate::metrics::inc_atomise_dropped();
                false
            }
        }
    }
}

/// Resolve the bounded-channel capacity from
/// [`ENV_ATOMISE_QUEUE_CAPACITY`]. `0` or an unparseable value falls
/// through to [`ATOMISE_QUEUE_CAPACITY_DEFAULT`] with a `WARN` — an
/// unrecognised token must NEVER silently widen a resource bound to
/// "unbounded" (the #131 / FBL-14 rule).
#[must_use]
pub fn resolve_queue_capacity() -> usize {
    match std::env::var(ENV_ATOMISE_QUEUE_CAPACITY) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(0) => {
                tracing::warn!(
                    "{ENV_ATOMISE_QUEUE_CAPACITY}=0 is not a valid capacity (clear \
                     `auto_atomise` on the namespace standard to disable atomisation) — \
                     falling back to the default ({ATOMISE_QUEUE_CAPACITY_DEFAULT})"
                );
                ATOMISE_QUEUE_CAPACITY_DEFAULT
            }
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    "{ENV_ATOMISE_QUEUE_CAPACITY}={raw:?} is not a valid positive integer — \
                     falling back to the default ({ATOMISE_QUEUE_CAPACITY_DEFAULT})"
                );
                ATOMISE_QUEUE_CAPACITY_DEFAULT
            }
        },
        Err(_) => ATOMISE_QUEUE_CAPACITY_DEFAULT,
    }
}

/// Spawn the single-consumer atomise worker and return the producer
/// handle.
///
/// The consumer exits when admission closes or every [`AtomiseQueue`] clone is dropped
/// (process shutdown), so `provider` MUST NOT capture anything that
/// transitively owns the queue — otherwise the sender is kept alive by
/// the worker itself and the thread never joins. Production providers
/// capture only the swappable LLM handle + tier + keypair.
///
/// # Panics
///
/// Never in normal operation; a failure to spawn the OS thread is
/// surfaced as an `Err` from `std::thread::Builder::spawn`, which is
/// logged and degrades to "no worker" (`try_enqueue` then reports
/// queue-full honestly) rather than aborting boot.
#[must_use]
pub fn spawn(provider: AtomiserProvider) -> Option<AtomiseQueue> {
    spawn_joinable(provider).map(|(queue, _handle)| queue)
}

/// Like [`spawn`] but also hands back the consumer thread's [`JoinHandle`].
///
/// The consumer exits on explicit close or when every producer is dropped: closing
/// the channel makes `rx.recv()` return `Err` only AFTER every buffered job has
/// been drained, so `handle.join()` is a DETERMINISTIC "await full drain" —
/// no wall-clock deadline. The daemon uses an accounted, joinable worker and
/// bounds its shutdown wait; tests use this to observe that the
/// deferred atoms have landed without racing a timer (#2986: the old 15s poll
/// flaked under llvm-cov instrumentation, which slows the worker past the
/// deadline even though it always completes).
pub fn spawn_joinable(
    provider: AtomiserProvider,
) -> Option<(AtomiseQueue, std::thread::JoinHandle<()>)> {
    spawn_accounted(provider, None)
}

/// Spawn a daemon-owned worker, accounting for its entire OS-thread lifetime.
pub(crate) fn spawn_tracked(
    provider: AtomiserProvider,
    tracker: Arc<std::sync::atomic::AtomicUsize>,
) -> Option<(AtomiseQueue, std::thread::JoinHandle<()>)> {
    tracker.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    spawn_accounted(provider, Some(WorkerAccounting(tracker)))
}

struct WorkerAccounting(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for WorkerAccounting {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn spawn_accounted(
    provider: AtomiserProvider,
    accounting: Option<WorkerAccounting>,
) -> Option<(AtomiseQueue, std::thread::JoinHandle<()>)> {
    let capacity = resolve_queue_capacity();
    let (tx, rx) = std::sync::mpsc::sync_channel::<AtomiseJob>(capacity);
    let spawned = std::thread::Builder::new()
        .name(WORKER_THREAD_NAME.to_string())
        .spawn(move || {
            let _accounting = accounting;
            tracing::info!(
                target: TRACE_TARGET,
                "atomise worker started (bounded capacity={capacity}, single consumer)"
            );
            while let Ok(job) = rx.recv() {
                apply_atomise_job(provider.as_ref(), &job);
            }
            tracing::info!(target: TRACE_TARGET, "atomise worker stopped");
        });
    match spawned {
        Ok(handle) => Some((
            AtomiseQueue {
                tx: Arc::new(std::sync::Mutex::new(Some(tx))),
            },
            handle,
        )),
        Err(e) => {
            tracing::error!(
                target: TRACE_TARGET,
                "failed to spawn the atomise worker thread: {e} — deferred auto_atomise \
                 will report `skipped_queue_full` (durable writes are unaffected)"
            );
            None
        }
    }
}

/// Drive one job. Every exit path is a soft failure — this function
/// never panics and never propagates an error (the notify-class
/// contract: the memory is already durable).
fn apply_atomise_job(
    provider: &(dyn Fn() -> Option<Arc<Atomiser>> + Send + Sync),
    job: &AtomiseJob,
) {
    // Resolve the atomiser NOW, not at enqueue time. A `[llm]` reload
    // (or an egress refusal) between enqueue and drain must be honoured
    // — that is the #2172 boot-capture this design refuses to repeat.
    let Some(atomiser) = provider() else {
        tracing::warn!(
            target: TRACE_TARGET,
            "atomise.worker.no_curator: memory {} in namespace {} was queued for \
             atomisation but no curator is wired at drain time (LLM absent or hot-swapped \
             away) — skipping; the durable row is untouched",
            job.memory_id,
            job.namespace
        );
        crate::metrics::inc_atomise_no_curator();
        return;
    };
    crate::hooks::pre_store::auto_atomise::run_deferred_atomise(
        &job.db_path,
        &atomiser,
        &job.memory_id,
        job.max_atom_tokens,
        &job.agent_id,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomisation::AtomiserConfig;
    use crate::atomisation::curator::{Atom, Curator, CuratorError};
    use crate::config::FeatureTier;
    use std::sync::Mutex;

    struct TwoAtoms;
    impl Curator for TwoAtoms {
        fn decompose(
            &self,
            _body: &str,
            _max_atom_tokens: u32,
            _max_retries: u32,
        ) -> Result<Vec<Atom>, CuratorError> {
            Ok(vec![
                Atom {
                    text: "worker atom one".into(),
                },
                Atom {
                    text: "worker atom two".into(),
                },
            ])
        }
    }

    fn atomiser() -> Arc<Atomiser> {
        Arc::new(Atomiser::new(
            Box::new(TwoAtoms),
            None,
            AtomiserConfig::default(),
            FeatureTier::Smart,
        ))
    }

    /// These three tests mutate the same process-global env var. CI
    /// `cargo test --lib` is parallel; without a lock, `honours_explicit`
    /// can observe DEFAULT (256) when `default_when_unset` races it
    /// (ubuntu-latest sqlite, #3136).
    fn atomise_capacity_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn resolve_queue_capacity_default_when_unset() {
        let _g = atomise_capacity_env_lock();
        // SAFETY: exclusive lock held; no concurrent reader of this var.
        unsafe { std::env::remove_var(ENV_ATOMISE_QUEUE_CAPACITY) };
        assert_eq!(resolve_queue_capacity(), ATOMISE_QUEUE_CAPACITY_DEFAULT);
    }

    #[test]
    fn resolve_queue_capacity_honours_explicit_positive_value() {
        let _g = atomise_capacity_env_lock();
        unsafe { std::env::set_var(ENV_ATOMISE_QUEUE_CAPACITY, "19") };
        assert_eq!(resolve_queue_capacity(), 19);
        unsafe { std::env::remove_var(ENV_ATOMISE_QUEUE_CAPACITY) };
    }

    #[test]
    fn resolve_queue_capacity_falls_through_on_zero_and_garbage() {
        let _g = atomise_capacity_env_lock();
        unsafe { std::env::set_var(ENV_ATOMISE_QUEUE_CAPACITY, "0") };
        assert_eq!(resolve_queue_capacity(), ATOMISE_QUEUE_CAPACITY_DEFAULT);
        unsafe { std::env::set_var(ENV_ATOMISE_QUEUE_CAPACITY, "not-a-number") };
        assert_eq!(resolve_queue_capacity(), ATOMISE_QUEUE_CAPACITY_DEFAULT);
        unsafe { std::env::remove_var(ENV_ATOMISE_QUEUE_CAPACITY) };
    }

    #[test]
    fn a_full_bounded_queue_drops_rather_than_blocking() {
        // The load-bearing bound: a rendezvous channel with NO consumer
        // must refuse immediately, never block the caller's write path.
        let (tx, rx) = std::sync::mpsc::sync_channel::<AtomiseJob>(0);
        let q = AtomiseQueue {
            tx: Arc::new(std::sync::Mutex::new(Some(tx))),
        };
        let job = AtomiseJob {
            db_path: PathBuf::from("/nonexistent/ai-memory.db"),
            memory_id: "m-1".into(),
            namespace: "ns".into(),
            agent_id: "ai:test".into(),
            max_atom_tokens: 50,
        };
        assert!(!q.try_enqueue(job), "a full queue must DROP, never block");
        drop(rx);
    }

    #[test]
    fn provider_is_consulted_at_drain_time_not_enqueue_time() {
        // A provider whose answer CHANGES between enqueue and drain must
        // be observed at drain — the property that makes a revoked
        // vendor unreachable after an `[llm]` reload (#2172).
        let calls = Arc::new(Mutex::new(0usize));
        let c2 = Arc::clone(&calls);
        let provider: AtomiserProvider = Arc::new(move || {
            *c2.lock().unwrap() += 1;
            None
        });
        let job = AtomiseJob {
            db_path: PathBuf::from("/nonexistent/ai-memory.db"),
            memory_id: "m-1".into(),
            namespace: "ns".into(),
            agent_id: "ai:test".into(),
            max_atom_tokens: 50,
        };
        assert_eq!(*calls.lock().unwrap(), 0, "not consulted before the drain");
        apply_atomise_job(provider.as_ref(), &job);
        assert_eq!(*calls.lock().unwrap(), 1, "consulted exactly once at drain");
    }

    #[test]
    fn spawned_worker_drains_a_job_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("ai-memory.db");
        let conn = crate::storage::open(&path).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "worker-ns".into(),
            title: "worker-drain".into(),
            content: "proposition token padding here. ".repeat(400),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            ..Default::default()
        };
        let id = crate::storage::insert(&conn, &mem).unwrap();
        drop(conn);

        let a = atomiser();
        let provider: AtomiserProvider = Arc::new(move || Some(Arc::clone(&a)));
        let q = spawn(provider).expect("worker spawns");
        assert!(q.try_enqueue(AtomiseJob {
            db_path: path.clone(),
            memory_id: id.clone(),
            namespace: "worker-ns".into(),
            agent_id: "ai:test".into(),
            max_atom_tokens: 50,
        }));
        // Poll for the drain (the worker sleeps 100ms for WAL visibility).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut atoms = 0i64;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let c = crate::storage::open(&path).unwrap();
            atoms = c
                .query_row(
                    "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                    rusqlite::params![&id],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if atoms >= 2 {
                break;
            }
        }
        assert_eq!(atoms, 2, "the worker must land the curator's two atoms");
        drop(q);
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use crate::atomisation::{
        AtomiserConfig,
        curator::{Atom, Curator, CuratorError},
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;

    struct LatchedCurator {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Curator for LatchedCurator {
        fn decompose(
            &self,
            _body: &str,
            _tokens: u32,
            _retries: u32,
        ) -> Result<Vec<Atom>, CuratorError> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            Ok(vec![
                Atom {
                    text: "first durable atom".into(),
                },
                Atom {
                    text: "second durable atom".into(),
                },
            ])
        }
    }

    #[test]
    fn admission_closes_across_clones_and_writer_remains_accounted_until_drain_4062() {
        let _no_pass = crate::test_support::no_passphrase_guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latched.db");
        let conn = crate::db::open(&path).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let source = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: "latched source".into(),
            namespace: "shutdown4062".into(),
            tier: crate::models::Tier::Mid,
            content: "A deployment must pass its readiness checks before receiving traffic. "
                .repeat(100),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id":"ai:test"}),
            ..Default::default()
        };
        let id = crate::db::insert(&conn, &source).unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let atomiser = Arc::new(Atomiser::new(
            Box::new(LatchedCurator {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            None,
            AtomiserConfig::default(),
            crate::config::FeatureTier::Smart,
        ));
        let provider: AtomiserProvider = Arc::new(move || Some(atomiser.clone()));
        let tracker = Arc::new(AtomicUsize::new(0));
        let (queue, worker) = spawn_tracked(provider, tracker.clone()).unwrap();
        let retained_request_sender = queue.clone();
        let job = AtomiseJob {
            db_path: path,
            memory_id: id.clone(),
            namespace: source.namespace,
            agent_id: "ai:test".into(),
            max_atom_tokens: 50,
        };
        assert!(queue.try_enqueue(job.clone()));
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        queue.close();
        assert!(
            !retained_request_sender.try_enqueue(job),
            "shutdown must close every AppState clone's admission"
        );
        assert_eq!(
            tracker.load(Ordering::SeqCst),
            1,
            "the held curator must keep the certification barrier closed"
        );
        assert!(!worker.is_finished());
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(before, 0);
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(tracker.load(Ordering::SeqCst), 0);
        let after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            after, 2,
            "all admitted derivations must land before the barrier opens"
        );
        let completed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = 'atomisation_complete'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            completed, 1,
            "the worker's final audit append precedes certification"
        );
    }
}
