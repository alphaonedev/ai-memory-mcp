// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::similar_names,
    clippy::let_and_return,
    clippy::needless_pass_by_value,
    clippy::ignored_unit_patterns,
    clippy::map_unwrap_or,
    clippy::redundant_closure_for_method_calls,
    clippy::items_after_statements,
    clippy::if_not_else,
    clippy::option_map_unit_fn
)]

//! v0.7.0 WT-1-D — auto-atomisation `pre_store` hook acceptance suite.
//!
//! Seven acceptance tests pinned to the WT-1-D brief. Every test
//! injects a deterministic `MockCurator` through the EXPLICIT
//! `AtomiseWiring` (#2983 abolished the process-global dispatch slot),
//! so the suite never burns an LLM round-trip. The mock RESPONSE QUEUE
//! is still shared, so the suite keeps its `Mutex<()>` serialisation for
//! that reason alone — not because any wiring is process-wide.

use ai_memory::models::ConfidenceSource;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::background::atomise_worker::{
    ATOMISE_QUEUE_CAPACITY_DEFAULT, AtomiseQueue, resolve_queue_capacity,
};
use ai_memory::config::FeatureTier;
use ai_memory::hooks::pre_store::auto_atomise::OUTCOME_SKIPPED_POLICY_DISABLED;
use ai_memory::hooks::pre_store::{
    AtomiseWiring, AutoAtomisationOutcome, maybe_enqueue_auto_atomise,
};
use ai_memory::models::{
    ApproverType, AtomisationPolicy, CorePolicy, GovernanceLevel, GovernancePolicy, Memory,
    MemoryKind, Tier,
};
use ai_memory::storage as db;

use chrono::Utc;
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// MockCurator — programmable, deterministic.
// ---------------------------------------------------------------------------

/// Shared mock that the integration suite installs once into the
/// process-wide `AUTO_ATOMISE_DISPATCH` slot. Tests swap the response
/// queue (and the recorded call log) via the inner `Mutex`-guarded
/// state.
struct MockCurator {
    state: Arc<Mutex<MockState>>,
}

struct MockState {
    /// Queue of canned responses. Drained from the front on each
    /// `decompose` call.
    responses: Vec<Result<Vec<Atom>, CuratorError>>,
    /// Total `decompose` invocations (used by the test asserting
    /// "no atomisation happened").
    calls: usize,
    /// `max_atom_tokens` of the most recent `decompose` call (#7215 r3
    /// F-4): lets a cell assert the budget the deferred job carried.
    last_max_atom_tokens: Option<u32>,
}

impl Curator for MockCurator {
    fn decompose(
        &self,
        _body: &str,
        max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        let mut s = self.state.lock().unwrap();
        s.calls += 1;
        s.last_max_atom_tokens = Some(max_atom_tokens);
        if s.responses.is_empty() {
            return Err(CuratorError::MalformedResponse(
                "mock: response queue exhausted".into(),
            ));
        }
        s.responses.remove(0)
    }
}

fn shared_state() -> Arc<Mutex<MockState>> {
    static SLOT: OnceLock<Arc<Mutex<MockState>>> = OnceLock::new();
    SLOT.get_or_init(|| {
        Arc::new(Mutex::new(MockState {
            responses: Vec::new(),
            calls: 0,
            last_max_atom_tokens: None,
        }))
    })
    .clone()
}

/// Serialise tests. The dispatch is process-wide and the mock state
/// is shared; only one test may drive at a time.
fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

/// v1.0.0 #3523 — INSTALL-FIRST fixture for the store-side governance hook.
///
/// # The defect this closes
///
/// `db::GOVERNANCE_PRE_WRITE` is a process-wide `OnceLock`: the FIRST `set`
/// in the binary wins and every later one is a silent no-op. Before #3523
/// the refusal case installed the hook inside its own body and then
/// SOFT-SKIPPED its assertions when the insert succeeded, on the theory that
/// "a prior test installed an Allow-all hook". That made the load-bearing
/// half of the case — `a refused write must never reach the auto-atomise
/// funnel` — conditional on TEST ORDERING, which libtest does not promise.
/// Today no other case in this binary installs a hook, so the skip branch is
/// dead; but nothing said so, and a case that can quietly stop asserting is
/// the `#2444` shape (reports success while doing nothing).
///
/// # Why install-first rather than an own binary
///
/// Every case in this binary already funnels through [`test_serial`], so
/// arming the hook HERE makes it a precondition of running at all: whichever
/// case libtest schedules first installs it, and the refusal leg is then
/// unconditional in every ordering. Moving the case to its own binary would
/// buy the same determinism at the cost of duplicating the whole private
/// worker + seeded-policy fixture.
///
/// The hook is DISCRIMINATING — it refuses only titles prefixed `refused-`
/// and allows everything else — so installing it for the whole binary
/// changes no other case's behaviour.
fn install_refusal_governance_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let installed = db::GOVERNANCE_PRE_WRITE
            .set(Box::new(|mem: &Memory| {
                if mem.title.starts_with("refused-") {
                    Err("test-policy: refused".to_string())
                } else {
                    Ok(())
                }
            }))
            .is_ok();
        assert!(
            installed,
            "#3523: `GOVERNANCE_PRE_WRITE` was already set by something else in \
             this binary, so the refusal case cannot make its write be refused. \
             The hook is a process-wide one-shot: route every installer in this \
             binary through `install_refusal_governance_hook` (or move the case \
             to its own test binary) rather than restoring the soft-skip, which \
             is how the assertion silently stopped running."
        );
    });
}

/// The one entry gate every case in this binary takes: install the
/// governance hook (idempotent, first call wins) and THEN serialise.
///
/// Acquiring the lock second is deliberate — the install is idempotent and
/// `OnceLock`-serialised in its own right, so holding the test mutex across
/// it would buy nothing and only widen the critical section.
fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    install_refusal_governance_hook();
    test_serial().lock().unwrap_or_else(|p| p.into_inner())
}

/// Push a canned curator response onto an EXPLICIT mock state — the
/// suite-wide one, or a case-private one (see [`private_worker`]).
fn enqueue_atoms_into(state: &Arc<Mutex<MockState>>, texts: &[&str]) {
    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
    s.responses.push(Ok(texts
        .iter()
        .map(|t| Atom {
            text: (*t).to_string(),
        })
        .collect()));
}

/// Reset the mock call counter + clear pending responses.
fn reset_mock() {
    let arc = shared_state();
    let mut s = arc.lock().unwrap();
    s.responses.clear();
    s.calls = 0;
    s.last_max_atom_tokens = None;
}

/// Read the current mock call count.
fn mock_call_count() -> usize {
    let arc = shared_state();
    let n = arc.lock().unwrap().calls;
    n
}

// ---------------------------------------------------------------------------
// Dispatch install
// ---------------------------------------------------------------------------

/// v1.0.0 #2983 — the process-global `AUTO_ATOMISE_DISPATCH` slot this
/// suite used to install is GONE (it had zero production callers, which
/// is the whole defect #2983 filed). The wiring is now threaded
/// explicitly, so the mock atomiser + the bounded background worker are
/// ordinary process-lifetime fixtures rather than a one-shot `OnceLock`
/// nobody could re-install between cases.
fn shared_atomiser() -> &'static Arc<Atomiser> {
    static A: OnceLock<Arc<Atomiser>> = OnceLock::new();
    A.get_or_init(|| {
        let curator: Box<dyn Curator> = Box::new(MockCurator {
            state: shared_state(),
        });
        Arc::new(Atomiser::new(
            curator,
            None,
            AtomiserConfig::default(),
            FeatureTier::Smart,
        ))
    })
}

/// The bounded, single-consumer worker (#2986) the deferred path now
/// enqueues onto instead of `std::thread::spawn`-ing one unbounded
/// detached thread per store.
fn shared_queue() -> &'static AtomiseQueue {
    static Q: OnceLock<AtomiseQueue> = OnceLock::new();
    Q.get_or_init(|| {
        ai_memory::background::atomise_worker::spawn(Arc::new(|| {
            Some(Arc::clone(shared_atomiser()))
        }))
        .expect("atomise worker spawns")
    })
}

fn wiring() -> AtomiseWiring<'static> {
    AtomiseWiring::new(Some(shared_atomiser()), Some(shared_queue()))
}

/// v1.0.0 #3509 — a CASE-PRIVATE curator + bounded worker, handed back
/// with the consumer's `JoinHandle` so the case can await quiescence
/// **deterministically**.
///
/// # Why this exists
///
/// [`shared_queue`] is a process-lifetime `OnceLock`: its in-flight
/// jobs can never be awaited, only guessed at. A drain helper guessed
/// by watching the suite-wide call counter hold still for a wall-clock
/// window — so on a saturated host a previous case's jobs are still
/// running when that window expires, and their curator calls land AFTER
/// the next case's `reset_mock()`. That is the #3509 flake verbatim:
/// `curator must not fire when the originating insert was refused —
/// left: 2, right: 0`, where the 2 were another case's leftovers.
///
/// `spawn_joinable` is the substrate's own quiescence signal (#2986):
/// dropping the last [`AtomiseQueue`] closes the channel, the consumer's
/// `recv()` returns `Err` only AFTER every buffered job has drained, so
/// `handle.join()` is "await full drain" with no deadline to lose under
/// load. Pairing it with a private curator also makes the observed call
/// count ATTRIBUTABLE to this case — nothing else in the binary can
/// reach this counter.
fn private_worker() -> (
    Arc<Mutex<MockState>>,
    Arc<Atomiser>,
    AtomiseQueue,
    std::thread::JoinHandle<()>,
) {
    private_worker_gated(None)
}

/// Holds the worker's per-job atomiser resolution closed until the test
/// opens it (#7215). The provider runs on the worker thread BEFORE any
/// curator call, so a closed gate parks the consumer at the very top of
/// a job: nothing the hook handed over can progress, and a hook that
/// waited on the worker could never return. Opening is idempotent and
/// also happens on drop, so a failing assertion never leaves the worker
/// parked.
#[derive(Clone)]
struct ProviderGate(Arc<(Mutex<bool>, Condvar)>);

impl ProviderGate {
    fn closed() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }

    fn open(&self) {
        let (lock, cvar) = &*self.0;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        cvar.notify_all();
    }

    /// Block until opened; the bounded wait is a hang guard only
    /// (CONCURRENCY-17), never the correctness condition.
    fn wait_open(&self) {
        let (lock, cvar) = &*self.0;
        let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = cvar
            .wait_timeout_while(guard, Duration::from_secs(120), |open| !*open)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

impl Drop for ProviderGate {
    fn drop(&mut self) {
        self.open();
    }
}

/// Close the producer side and await full drain of the private worker.
/// `drop(queue)` closes the channel; the consumer exits only after every
/// buffered job has run, so completion does not depend on host speed.
/// The 120 s bound is a hang guard, never the correctness condition.
fn await_worker_drain(queue: AtomiseQueue, worker: std::thread::JoinHandle<()>) {
    drop(queue);
    let start = std::time::Instant::now();
    while !worker.is_finished() {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "private atomise worker did not drain (hang guard)"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    worker.join().expect("private atomise worker joins");
}

/// [`private_worker`] with an optional [`ProviderGate`] the worker waits
/// on before it resolves the atomiser for each job.
fn private_worker_gated(
    gate: Option<ProviderGate>,
) -> (
    Arc<Mutex<MockState>>,
    Arc<Atomiser>,
    AtomiseQueue,
    std::thread::JoinHandle<()>,
) {
    let state = Arc::new(Mutex::new(MockState {
        responses: Vec::new(),
        calls: 0,
        last_max_atom_tokens: None,
    }));
    let atomiser = Arc::new(Atomiser::new(
        Box::new(MockCurator {
            state: Arc::clone(&state),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    ));
    // The provider captures ONLY the atomiser — never anything that
    // transitively owns the queue, or the sender would keep itself
    // alive and the join below would hang forever (the `spawn_joinable`
    // contract).
    let provider = Arc::clone(&atomiser);
    let (queue, handle) =
        ai_memory::background::atomise_worker::spawn_joinable(Arc::new(move || {
            if let Some(gate) = &gate {
                gate.wait_open();
            }
            Some(Arc::clone(&provider))
        }))
        .expect("private atomise worker spawns");
    (state, atomiser, queue, handle)
}

/// The PRODUCTION caller's sequence, in one place: commit the durable
/// row FIRST, then — and only then — offer the committed id to the
/// auto-atomise funnel.
///
/// Returns `None` when the substrate REFUSED the write, else the
/// COMMITTED primary key (never the caller-supplied one) paired with
/// the funnel's outcome. The `?` on `db::insert(..).ok()` is the point
/// of the helper: for a refused write the funnel below is unreachable
/// **by construction**, not because a test politely declined to call
/// it. Inverting these two statements in a production write path is
/// exactly the defect this case pins.
fn store_then_maybe_enqueue(
    conn: &Connection,
    mem: &Memory,
    wiring: AtomiseWiring<'_>,
) -> Option<(String, AutoAtomisationOutcome)> {
    let id = db::insert(conn, mem).ok()?;
    let outcome = maybe_enqueue_auto_atomise(conn, shared_db_path(), mem, &id, "ai:test", wiring);
    Some((id, outcome))
}

/// The dispatch's `db_path` is fixed at install time. Every test must
/// open the SAME on-disk DB so the worker thread opens the same file.
/// We rotate the namespace per-test to avoid cross-test interference.
fn shared_db_path() -> &'static PathBuf {
    static SHARED: OnceLock<PathBuf> = OnceLock::new();
    SHARED.get_or_init(|| {
        let tmp = std::env::var("TMPDIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(".local-runs")
                    .join("tmp")
            });
        // Ensure parent exists.
        std::fs::create_dir_all(&tmp).ok();
        tmp.join(format!("wt1d-auto-atomise-{}.db", uuid::Uuid::new_v4()))
    })
}

fn shared_db_conn() -> Connection {
    db::open(shared_db_path()).expect("open shared db")
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn opt_in_policy(threshold: u32, max_atom_tokens: u32) -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        atomisation: AtomisationPolicy {
            auto_atomise: Some(true),
            auto_atomise_threshold_cl100k: Some(threshold),
            auto_atomise_max_atom_tokens: Some(max_atom_tokens),
            auto_atomise_max_retries: None,
            auto_atomise_mode: None,
        },
        ..Default::default()
    }
}

fn opt_out_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        atomisation: AtomisationPolicy {
            auto_atomise: Some(false),
            auto_atomise_threshold_cl100k: None,
            auto_atomise_max_atom_tokens: None,
            auto_atomise_max_retries: None,
            auto_atomise_mode: None,
        },
        ..Default::default()
    }
}

/// Seed a namespace standard with the supplied policy. Idempotent —
/// running twice for the same namespace updates in place.
fn seed_policy(conn: &Connection, ns: &str, policy: GovernancePolicy) {
    let now = Utc::now().to_rfc3339();
    let gov_metadata = serde_json::json!({
        "agent_id": "ai:test",
        "governance": serde_json::to_value(&policy).unwrap(),
    });
    let std_mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("__standard_{ns}_{}", uuid::Uuid::new_v4().simple()),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: gov_metadata,
        ..Default::default()
    };
    let std_id = db::insert(conn, &std_mem).unwrap();
    db::set_namespace_standard(conn, ns, &std_id, None).unwrap();
}

/// Insert a memory with a long body whose cl100k token count
/// exceeds `target_tokens`. The body is built from a Lorem-style
/// repetition so the cl100k count is deterministic per host.
fn long_body(target_tokens: usize) -> String {
    // ~4 chars per cl100k token in English ⇒ multiply by 5 for safety.
    let unit = "The kubernetes rolling deploy strategy required canary instance health checks. \
                The pod readiness probe must pass before traffic shifts. Failures roll back \
                the deployment within 30 seconds. Operator dashboards track replica counts \
                and error rates. ";
    let approx_tokens_per_unit = db::count_tokens_cl100k(unit);
    let n = (target_tokens / approx_tokens_per_unit) + 2;
    unit.repeat(n)
}

/// Build (but do NOT insert) a Mid-tier memory. `title` is load-bearing
/// for the #3509 case: the governance hook it installs refuses exactly
/// the titles prefixed `refused-`, so the same builder produces both the
/// allowed control write and the refused write.
fn build_memory(ns: &str, title: &str, content: &str) -> Memory {
    let now = Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:test"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn insert_memory(conn: &Connection, ns: &str, content: &str) -> Memory {
    let mem = build_memory(
        ns,
        &format!("payload-{}", uuid::Uuid::new_v4().simple()),
        content,
    );
    let id = db::insert(conn, &mem).expect("insert");
    Memory { id, ..mem }
}

/// Read the `atomised_into` column on a memory id. None on NULL.
fn read_atomised_into(conn: &Connection, id: &str) -> Option<i64> {
    conn.query_row(
        "SELECT atomised_into FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, Option<i64>>(0),
    )
    .unwrap_or(None)
}

// ===========================================================================
// Test 1 — auto_atomise disabled does nothing
// ===========================================================================

#[test]
fn test_auto_atomise_disabled_does_nothing() {
    let _g = test_guard();
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    reset_mock();

    let ns = format!("wt1d/disabled-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, opt_out_policy());

    let body = long_body(1000); // well over default threshold
    let mem = insert_memory(&conn, &ns, &body);

    let outcome =
        maybe_enqueue_auto_atomise(&conn, shared_db_path(), &mem, &mem.id, "ai:test", wiring());
    match outcome {
        AutoAtomisationOutcome::Skipped { reason } => {
            assert_eq!(
                reason, OUTCOME_SKIPPED_POLICY_DISABLED,
                "expected the policy-disabled skip"
            );
        }
        other => panic!("expected Skipped(policy_disabled), got {other:?}"),
    }

    // Spin a bit to prove no background work fires.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        mock_call_count(),
        0,
        "curator must not have been called when policy is disabled"
    );
    // Parent memory's atomised_into must still be NULL.
    assert!(read_atomised_into(&conn, &mem.id).is_none());
}

// ===========================================================================
// Test 2 — below-threshold memory does nothing
// ===========================================================================

#[test]
fn test_auto_atomise_below_threshold_does_nothing() {
    let _g = test_guard();
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    reset_mock();

    let ns = format!("wt1d/below-{}", uuid::Uuid::new_v4().simple());
    // Threshold = 500. Body below ~400 tokens.
    seed_policy(&conn, &ns, opt_in_policy(500, 200));

    let body = long_body(400);
    // Sanity: ensure body is actually under 500 tokens.
    let tokens = db::count_tokens_cl100k(&body);
    assert!(
        tokens < 500,
        "test fixture invariant: body must be <500 tokens (was {tokens})"
    );
    let mem = insert_memory(&conn, &ns, &body);

    let outcome =
        maybe_enqueue_auto_atomise(&conn, shared_db_path(), &mem, &mem.id, "ai:test", wiring());
    match outcome {
        AutoAtomisationOutcome::UnderThreshold {
            tokens: t,
            threshold,
        } => {
            assert_eq!(threshold, 500);
            assert!(t < 500, "tokens should be under threshold (got {t})");
        }
        other => panic!("expected UnderThreshold, got {other:?}"),
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(mock_call_count(), 0);
    assert!(read_atomised_into(&conn, &mem.id).is_none());
}

// ===========================================================================
// Test 3 — above-threshold memory triggers atomisation
// ===========================================================================

#[test]
fn test_auto_atomise_above_threshold_triggers() {
    let _g = test_guard();
    let conn = shared_db_conn();

    let ns = format!("wt1d/above-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, opt_in_policy(500, 200));

    // #7268 - the one cell that exercises the real background worker to
    // completion. A case-private worker is drained by `join` (the
    // substrate's own quiescence signal), so completion does not depend
    // on host speed.
    let (curator_state, atomiser, queue, worker) = private_worker();

    // Queue 5 atoms for the curator (matches the WT-1-B
    // [min=2, max=10] envelope).
    enqueue_atoms_into(
        &curator_state,
        &[
            "Atom one: canary instances must health-check before traffic shifts.",
            "Atom two: pod readiness probes gate deploy rollout.",
            "Atom three: failures roll back deployment within 30 seconds.",
            "Atom four: operator dashboards track replica counts.",
            "Atom five: operator dashboards track error rates.",
        ],
    );

    let body = long_body(800);
    let mem = insert_memory(&conn, &ns, &body);

    let outcome = maybe_enqueue_auto_atomise(
        &conn,
        shared_db_path(),
        &mem,
        &mem.id,
        "ai:test",
        AtomiseWiring::new(Some(&atomiser), Some(&queue)),
    );
    match outcome {
        AutoAtomisationOutcome::Enqueued { ref memory_id, .. } => {
            assert_eq!(memory_id, &mem.id);
        }
        other => panic!("expected Enqueued, got {other:?}"),
    }

    await_worker_drain(queue, worker);
    let atom_count = read_atomised_into(&conn, &mem.id).unwrap_or(0);
    assert!(
        atom_count >= 2,
        "expected at least 2 atoms minted (got {atom_count})"
    );
    assert_eq!(
        curator_state.lock().unwrap().calls,
        1,
        "curator must have been called once"
    );
}

// ===========================================================================
// Test 4 — auto_atomise does NOT block store response latency
// ===========================================================================

#[test]
fn test_auto_atomise_does_not_block_store_response() {
    let _g = test_guard();
    let conn = shared_db_conn();

    // Namespace WITHOUT a policy -> hook short-circuits.
    let ns_off = format!("wt1d/lat-off-{}", uuid::Uuid::new_v4().simple());
    // Namespace WITH opt-in policy -> hook fires + enqueues.
    let ns_on = format!("wt1d/lat-on-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns_on, opt_in_policy(500, 200));

    // #7215 - blocking-independence proof, no wall-clock budget. A
    // case-private worker is held CLOSED (its per-job atomiser
    // resolution parks on the gate) for every on-path call, so a hook
    // that waited on the worker or the curator could never return. Every
    // call returning `Enqueued` while the gate is closed is the
    // contract; it holds under any host load.
    //
    // Requirement: the resolved queue capacity
    // (`resolve_queue_capacity`, env `AI_MEMORY_ATOMISE_QUEUE_CAPACITY`)
    // must be >= CALLS - 1 while the gate is closed, because the parked
    // worker holds one job and the queue buffer holds the rest. Unset, 0
    // or garbage resolves to `ATOMISE_QUEUE_CAPACITY_DEFAULT` (256), which
    // always satisfies it. A smaller capacity makes the hook report
    // `skipped_queue_full`, a different contract, so the cell skips (the
    // line shows under `--nocapture`). #7215 r3 F-5: the production
    // resolver is the single source of truth, not a re-implementation.
    const CALLS: usize = 5;
    let capacity = resolve_queue_capacity();
    if capacity < CALLS - 1 {
        eprintln!(
            "skipping #7215 cell: resolved queue capacity {capacity} is below CALLS - 1 ({}) \
             needed while the worker gate is closed (default {ATOMISE_QUEUE_CAPACITY_DEFAULT})",
            CALLS - 1
        );
        return;
    }
    let gate = ProviderGate::closed();
    let (curator_state, atomiser, queue, worker) = private_worker_gated(Some(gate.clone()));
    for _ in 0..CALLS {
        enqueue_atoms_into(
            &curator_state,
            &[
                "Atom alpha: lorem ipsum.",
                "Atom beta: dolor sit amet.",
                "Atom gamma: consectetur adipiscing.",
            ],
        );
    }
    let private = AtomiseWiring::new(Some(&atomiser), Some(&queue));

    let body = long_body(800);

    // Warm-up to load the cl100k BPE table.
    let _ = db::count_tokens_cl100k(&body);

    // Off path: insert + hook (short-circuits because no policy is
    // configured).
    let mut samples_off: Vec<Duration> = Vec::new();
    for _ in 0..CALLS {
        let m = insert_memory(&conn, &ns_off, &body);
        let t0 = std::time::Instant::now();
        let _ = maybe_enqueue_auto_atomise(&conn, shared_db_path(), &m, &m.id, "ai:test", private);
        samples_off.push(t0.elapsed());
    }

    // On path: insert + hook, with the worker gate CLOSED throughout.
    // Loose hang guard only: a true stall fails fast instead of hanging
    // CI. It is not a latency budget.
    let loop_start = std::time::Instant::now();
    let mut samples_on: Vec<Duration> = Vec::new();
    let mut queued_ids: Vec<String> = Vec::new();
    let mut queued_calls = 0usize;
    for _ in 0..CALLS {
        let m = insert_memory(&conn, &ns_on, &body);
        let t0 = std::time::Instant::now();
        let outcome =
            maybe_enqueue_auto_atomise(&conn, shared_db_path(), &m, &m.id, "ai:test", private);
        samples_on.push(t0.elapsed());
        assert!(
            matches!(outcome, AutoAtomisationOutcome::Enqueued { .. }),
            "hook must hand the job to the worker and return while the worker is closed \
             (needs AI_MEMORY_ATOMISE_QUEUE_CAPACITY >= CALLS - 1 while the gate is closed), got {outcome:?}"
        );
        queued_ids.push(m.id);
        queued_calls += 1;
        assert!(
            loop_start.elapsed() < Duration::from_secs(5),
            "on-path hook loop hung while the worker was closed"
        );
    }
    // The worker has done NOTHING: every call returned without it.
    assert_eq!(queued_calls, CALLS, "queued count must equal call count");
    assert_eq!(
        curator_state.lock().unwrap().calls,
        0,
        "no curator call may happen on the hook path while the worker is closed"
    );
    for id in &queued_ids {
        assert_eq!(
            read_atomised_into(&conn, id).unwrap_or(0),
            0,
            "no row may be atomised while the worker is closed"
        );
    }

    fn median(xs: &mut [Duration]) -> Duration {
        xs.sort();
        xs[xs.len() / 2]
    }

    let m_off = median(&mut samples_off);
    let m_on = median(&mut samples_on);

    // Two in-process medians compared against each other: the ratio is
    // load-independent. Below 1 ms the off path is dominated by
    // sub-millisecond jitter (Cluster-F PERF-1 removed the per-hook
    // `db::open`), so the ratio only applies above that.
    if m_off > Duration::from_millis(1) {
        let overhead_ratio_pct = m_on.as_nanos() * 100 / m_off.as_nanos().max(1);
        assert!(
            overhead_ratio_pct < 1000,
            "on/off ratio must be <10x ({m_on:?} / {m_off:?})"
        );
    }

    // Open the gate: the worker now lands every queued job. Draining by
    // join is deterministic, no deadline to lose under load.
    gate.open();
    await_worker_drain(queue, worker);
    assert_eq!(
        curator_state.lock().unwrap().calls,
        CALLS,
        "the worker must run the curator once per queued job after the gate opens"
    );
    for id in &queued_ids {
        assert!(
            read_atomised_into(&conn, id).unwrap_or(0) > 0,
            "queued memory {id} must be atomised once the worker runs"
        );
    }
}

// ===========================================================================
// Test 5 — inheritance: parent has policy, child omits, child triggers
// ===========================================================================

#[test]
fn test_auto_atomise_inheritance() {
    let _g = test_guard();
    let conn = shared_db_conn();

    let parent = format!("wt1d-inh-{}", uuid::Uuid::new_v4().simple());
    let child = format!("{parent}/team");

    // Parent has opt-in policy; child has NO standard. The
    // resolver walks leaf -> root and picks up the parent's policy.
    // Non-default budget (compiled default is 200) so the inherited value
    // is observable.
    seed_policy(&conn, &parent, opt_in_policy(500, 150));

    // #7268 - completion, not the clock. The enqueued job lands through
    // the real case-private worker and the cell waits on the worker's
    // join, never on the clock. The job's own inherited budget (150)
    // drives the split, and the row the hook named must be the row that
    // is atomised.
    let (curator_state, atomiser, queue, worker) = private_worker_gated(None);
    enqueue_atoms_into(
        &curator_state,
        &[
            "Inh atom one: parent policy resolved via ancestor walk.",
            "Inh atom two: child writes inherit auto_atomise.",
            "Inh atom three: leaf-first wins on conflict.",
        ],
    );

    let body = long_body(800);
    let mem = insert_memory(&conn, &child, &body);

    let outcome = maybe_enqueue_auto_atomise(
        &conn,
        shared_db_path(),
        &mem,
        &mem.id,
        "ai:test",
        AtomiseWiring::new(Some(&atomiser), Some(&queue)),
    );
    assert!(
        matches!(outcome, AutoAtomisationOutcome::Enqueued { .. }),
        "expected Enqueued via ancestor inheritance, got {outcome:?}"
    );

    // The child inherits the parent's resolved policy, including the
    // non-default atom token budget the job carries.
    let resolved = db::resolve_governance_policy_for_optional_feature(&conn, &child);
    assert!(resolved.effective_auto_atomise());
    assert_eq!(
        resolved.effective_auto_atomise_max_atom_tokens(),
        150,
        "child must inherit the parent's non-default atom budget"
    );

    // Land the enqueued job through the real worker; join is the
    // completion condition.
    await_worker_drain(queue, worker);
    assert!(
        read_atomised_into(&conn, &mem.id).unwrap_or(0) > 0,
        "expected child memory to be atomised via parent policy"
    );
    assert_eq!(
        curator_state.lock().unwrap().calls,
        1,
        "curator must have been called once"
    );
    // #7215 r3 F-4: the budget the DEFERRED JOB carried reached the
    // curator; the resolver assertion above proves only the resolver.
    assert_eq!(
        curator_state.lock().unwrap().last_max_atom_tokens,
        Some(150),
        "#7215/F-4: the enqueued job must carry the inherited atom budget (150) to the curator"
    );
}

// ===========================================================================
// Test 6 — child override: parent yes, child explicit no
// ===========================================================================

#[test]
fn test_auto_atomise_child_override() {
    let _g = test_guard();
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    reset_mock();

    let parent = format!("wt1d-ovr-{}", uuid::Uuid::new_v4().simple());
    let child = format!("{parent}/restricted");

    seed_policy(&conn, &parent, opt_in_policy(500, 200));
    seed_policy(&conn, &child, opt_out_policy());

    // Enqueue nothing — we expect the curator to NEVER fire.
    let body = long_body(900);
    let mem = insert_memory(&conn, &child, &body);

    let outcome =
        maybe_enqueue_auto_atomise(&conn, shared_db_path(), &mem, &mem.id, "ai:test", wiring());
    match outcome {
        AutoAtomisationOutcome::Skipped { reason } => {
            assert_eq!(reason, OUTCOME_SKIPPED_POLICY_DISABLED);
        }
        other => panic!("expected Skipped(policy_disabled) on child override, got {other:?}"),
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(mock_call_count(), 0);
    assert!(read_atomised_into(&conn, &mem.id).is_none());
}

// ===========================================================================
// Test 7 — governance-refused memory must not enqueue atomisation
// ===========================================================================

/// A refused write must never reach the auto-atomise funnel.
///
/// # #3509 — why this case owns a private worker
///
/// This assertion used to read the SUITE-WIDE `mock_call_count()` after
/// a 300 ms sleep. Both halves were wrong on a loaded host: the counter
/// is incremented by every case in the binary (via one process-lifetime
/// worker whose in-flight jobs cannot be awaited), and the sleep is a
/// guess, not a synchronisation. On the 2026-09-05 gate host it read
/// `left: 2, right: 0` — two of ANOTHER case's queued jobs completing
/// after this case's `reset_mock()`.
///
/// The case now owns a private curator and a private
/// [`spawn_joinable`](ai_memory::background::atomise_worker::spawn_joinable)
/// worker, so:
///
/// * the observed call count is ATTRIBUTABLE — no other case can reach
///   this counter; and
/// * quiescence is a `drop(queue)` + `join()`, the substrate's own
///   "every buffered job has drained" signal — no sleep, no poll, no
///   wall-clock deadline that host load can blow through.
///
/// A POSITIVE CONTROL runs first through the same wiring, so the
/// negative leg cannot pass vacuously: a harness that could never
/// observe a curator fire would prove nothing by observing none.
#[test]
fn test_auto_atomise_refused_memory_not_atomised() {
    let _g = test_guard();
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;

    // #3523: the discriminating `GOVERNANCE_PRE_WRITE` hook is installed by
    // `test_guard()` — the entry gate EVERY case in this binary takes — so it
    // is in force whichever case libtest schedules first, and the refusal leg
    // below is unconditional. It is NOT installed here: `OnceLock::set` is a
    // one-shot, so an in-body `let _ = ...set(...)` silently no-ops whenever
    // another case got there first — which is precisely how the assertion
    // used to stop running.
    let (curator_state, atomiser, queue, worker) = private_worker();
    let ns = format!("wt1d-refused-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, opt_in_policy(500, 200));
    let body = long_body(900);

    // --- Positive control: an ALLOWED write DOES reach the funnel ----
    enqueue_atoms_into(
        &curator_state,
        &[
            "Atom one: canary instances health-check before traffic shifts.",
            "Atom two: failures roll back the deployment within 30 seconds.",
        ],
    );
    let allowed = build_memory(
        &ns,
        &format!("allowed-{}", uuid::Uuid::new_v4().simple()),
        &body,
    );
    let control = store_then_maybe_enqueue(
        &conn,
        &allowed,
        AtomiseWiring::new(Some(&atomiser), Some(&queue)),
    );
    let (control_id, control_outcome) = control.expect("positive control write must commit");
    assert!(
        matches!(control_outcome, AutoAtomisationOutcome::Enqueued { .. }),
        "positive control must enqueue through the private wiring, got {control_outcome:?}"
    );

    // --- Negative leg: a REFUSED write must not reach the funnel -----
    let refused = build_memory(
        &ns,
        &format!("refused-{}", uuid::Uuid::new_v4().simple()),
        &body,
    );
    let outcome = store_then_maybe_enqueue(
        &conn,
        &refused,
        AtomiseWiring::new(Some(&atomiser), Some(&queue)),
    );

    // DETERMINISTIC QUIESCENCE (#3509). Dropping the only sender closes
    // the channel; the consumer's `recv()` returns `Err` only after
    // every buffered job has been drained, so this join is "await full
    // drain" — it cannot be raced by host load the way a sleep can.
    drop(queue);
    worker.join().expect("private atomise worker joins");
    let calls = curator_state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .calls;

    // The control fired and its atoms landed — proving this harness CAN
    // observe a curator fire, which is what makes the `== 1` below a
    // real negative result rather than a vacuous one.
    let control_atoms = read_atomised_into(&conn, &control_id).unwrap_or(0);
    assert!(
        control_atoms >= 2,
        "positive control must have minted atoms by the time the worker joined (got {control_atoms})"
    );

    match outcome {
        None => {
            // The substrate refused the write. `store_then_maybe_enqueue`
            // short-circuited, so the funnel was never offered the row.
            assert_eq!(
                calls, 1,
                "curator must not fire when the originating insert was refused \
                 (1 = the positive control, and nothing else)"
            );
            // Refusal ledger: the durable row does not exist at all …
            let rows: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM memories WHERE id = ?1",
                    rusqlite::params![refused.id],
                    |r| r.get(0),
                )
                .unwrap_or(-1);
            assert_eq!(rows, 0, "a refused write must leave no durable row");
            // … and therefore no atoms were derived from it.
            let atoms: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                    rusqlite::params![refused.id],
                    |r| r.get(0),
                )
                .unwrap_or(-1);
            assert_eq!(atoms, 0, "no atoms should exist for a refused memory");
        }
        Some(_) => {
            // #3523: UNCONDITIONAL. `store_then_maybe_enqueue` returns `Some`
            // only when `db::insert` COMMITTED, so reaching this arm means a
            // `refused-`-prefixed write was allowed — i.e. the discriminating
            // hook `test_guard()` installs is not the one in force. That is the
            // defect, not a reason to skip: the pre-#3523 code soft-skipped
            // here, which made the load-bearing half of this case conditional
            // on test ordering that libtest does not promise.
            panic!(
                "#3523: the governance hook installed by `test_guard()` must REFUSE a \
                 `refused-`-prefixed write, but the insert committed. The process-wide \
                 `GOVERNANCE_PRE_WRITE` one-shot was claimed by a different hook, so the \
                 no-enqueue invariant this case exists to prove would be asserting nothing."
            );
        }
    }
}
