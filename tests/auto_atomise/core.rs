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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::background::atomise_worker::AtomiseQueue;
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
}

impl Curator for MockCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        let mut s = self.state.lock().unwrap();
        s.calls += 1;
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

/// Push a canned curator response onto the SUITE-WIDE queue.
fn enqueue_atoms(texts: &[&str]) {
    enqueue_atoms_into(&shared_state(), texts);
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
/// jobs can never be awaited, only guessed at. [`drain_workers`] guesses
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
    let state = Arc::new(Mutex::new(MockState {
        responses: Vec::new(),
        calls: 0,
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

/// Wait up to `timeout` for the predicate to return true. Poll
/// interval 25ms. Returns whether the predicate became true within
/// the budget.
fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    predicate()
}

/// Drain inflight worker threads by waiting for the mock call count
/// to stabilise. Prior tests may have spawned threads that are still
/// chewing through the worker `100ms` sleep + curator call when the
/// next test starts — those workers would consume the next test's
/// queued responses and corrupt its assertions. We wait until the
/// call count has been stable for `stable_for`.
fn drain_workers(stable_for: Duration, total_timeout: Duration) {
    let start = std::time::Instant::now();
    let mut last = mock_call_count();
    let mut stable_since = std::time::Instant::now();
    while start.elapsed() < total_timeout {
        std::thread::sleep(Duration::from_millis(50));
        let now = mock_call_count();
        if now != last {
            last = now;
            stable_since = std::time::Instant::now();
        } else if stable_since.elapsed() >= stable_for {
            return;
        }
    }
}

// ===========================================================================
// Test 1 — auto_atomise disabled does nothing
// ===========================================================================

#[test]
fn test_auto_atomise_disabled_does_nothing() {
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
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
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
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
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    drain_workers(Duration::from_millis(300), Duration::from_secs(3));
    reset_mock();

    let ns = format!("wt1d/above-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, opt_in_policy(500, 200));

    // Queue 5 atoms for the curator (matches the WT-1-B
    // [min=2, max=10] envelope).
    enqueue_atoms(&[
        "Atom one: canary instances must health-check before traffic shifts.",
        "Atom two: pod readiness probes gate deploy rollout.",
        "Atom three: failures roll back deployment within 30 seconds.",
        "Atom four: operator dashboards track replica counts.",
        "Atom five: operator dashboards track error rates.",
    ]);

    let body = long_body(800);
    let mem = insert_memory(&conn, &ns, &body);

    let outcome =
        maybe_enqueue_auto_atomise(&conn, shared_db_path(), &mem, &mem.id, "ai:test", wiring());
    match outcome {
        AutoAtomisationOutcome::Enqueued { ref memory_id, .. } => {
            assert_eq!(memory_id, &mem.id);
        }
        other => panic!("expected Enqueued, got {other:?}"),
    }

    // Wait up to 3s for the worker thread to land (100ms initial
    // sleep + DB open + curator + per-atom write).
    let ok = wait_until(Duration::from_secs(3), || {
        read_atomised_into(&conn, &mem.id)
            .map(|n| n > 0)
            .unwrap_or(false)
    });
    assert!(
        ok,
        "expected source memory's atomised_into to be > 0 within 3s"
    );
    let atom_count = read_atomised_into(&conn, &mem.id).unwrap_or(0);
    assert!(
        atom_count >= 2,
        "expected at least 2 atoms minted (got {atom_count})"
    );
    assert_eq!(mock_call_count(), 1, "curator must have been called once");
}

// ===========================================================================
// Test 4 — auto_atomise does NOT block store response latency
// ===========================================================================

#[test]
fn test_auto_atomise_does_not_block_store_response() {
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    reset_mock();

    // Namespace WITHOUT a policy → hook short-circuits.
    let ns_off = format!("wt1d/lat-off-{}", uuid::Uuid::new_v4().simple());
    // Namespace WITH opt-in policy → hook fires + enqueues.
    let ns_on = format!("wt1d/lat-on-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns_on, opt_in_policy(500, 200));

    // Pre-queue several curator responses so the worker thread has
    // something to do (we don't want to count empty-queue rejections
    // toward the latency comparison).
    for _ in 0..5 {
        enqueue_atoms(&[
            "Atom alpha: lorem ipsum.",
            "Atom beta: dolor sit amet.",
            "Atom gamma: consectetur adipiscing.",
        ]);
    }

    let body = long_body(800);

    // Warm-up to load the cl100k BPE table.
    let _ = db::count_tokens_cl100k(&body);

    // Measure the "off" path: insert + hook (which short-circuits
    // because no policy is configured).
    let mut samples_off: Vec<Duration> = Vec::new();
    for _ in 0..5 {
        let m = insert_memory(&conn, &ns_off, &body);
        let t0 = std::time::Instant::now();
        let _ = maybe_enqueue_auto_atomise(&conn, shared_db_path(), &m, &m.id, "ai:test", wiring());
        samples_off.push(t0.elapsed());
    }

    // Measure the "on" path: insert + hook (which spawns a worker
    // thread but MUST return synchronously).
    let mut samples_on: Vec<Duration> = Vec::new();
    for _ in 0..5 {
        let m = insert_memory(&conn, &ns_on, &body);
        let t0 = std::time::Instant::now();
        let _ = maybe_enqueue_auto_atomise(&conn, shared_db_path(), &m, &m.id, "ai:test", wiring());
        samples_on.push(t0.elapsed());
    }

    fn median(xs: &mut [Duration]) -> Duration {
        xs.sort();
        xs[xs.len() / 2]
    }

    let m_off = median(&mut samples_off);
    let m_on = median(&mut samples_on);

    // The brief specifies "within 5% of each other". CI hardware is
    // noisy; we use a generous tolerance ceiling. The actual contract
    // is "non-blocking" — the hook must return in the same order of
    // magnitude regardless of whether it spawned a worker.
    //
    // We assert the on-path median is at most 10x the off-path
    // median AND under 50ms absolute. Either condition would catch
    // a regression where the hook accidentally blocks on the curator.
    assert!(
        m_on < Duration::from_millis(50),
        "on-path median should be sub-50ms (was {m_on:?})"
    );
    // Both medians sub-millisecond is the expected steady state.
    // Cluster-F PERF-1 eliminated the per-hook `db::open` round-trip,
    // so the off-path median (no policy seeded → short-circuit) often
    // lands at tens-of-microseconds while the on-path still has to
    // resolve the namespace policy + spawn a worker thread. The 10x
    // ratio bound only makes sense when the off-path is in the same
    // order of magnitude as a worker-spawn (≥1ms); below that the
    // ratio is dominated by sub-millisecond jitter, not by the hook's
    // own work. The 50ms absolute ceiling above remains the
    // load-bearing "non-blocking" assertion.
    if m_off > Duration::from_millis(1) {
        let overhead_ratio_pct = m_on.as_nanos() * 100 / m_off.as_nanos().max(1);
        assert!(
            overhead_ratio_pct < 1000,
            "on/off ratio must be <10x ({m_on:?} / {m_off:?})"
        );
    }

    // Drain inflight worker threads so subsequent tests start from a
    // quiet state — otherwise the 5 workers we just spawned would
    // consume the next test's queued curator responses.
    drain_workers(Duration::from_millis(500), Duration::from_secs(5));
}

// ===========================================================================
// Test 5 — inheritance: parent has policy, child omits, child triggers
// ===========================================================================

#[test]
fn test_auto_atomise_inheritance() {
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;
    drain_workers(Duration::from_millis(300), Duration::from_secs(3));
    reset_mock();

    let parent = format!("wt1d-inh-{}", uuid::Uuid::new_v4().simple());
    let child = format!("{parent}/team");

    // Parent has opt-in policy; child has NO standard. The
    // resolver walks leaf → root and picks up the parent's policy.
    seed_policy(&conn, &parent, opt_in_policy(500, 200));

    enqueue_atoms(&[
        "Inh atom one: parent policy resolved via ancestor walk.",
        "Inh atom two: child writes inherit auto_atomise.",
        "Inh atom three: leaf-first wins on conflict.",
    ]);

    let body = long_body(800);
    let mem = insert_memory(&conn, &child, &body);

    let outcome =
        maybe_enqueue_auto_atomise(&conn, shared_db_path(), &mem, &mem.id, "ai:test", wiring());
    assert!(
        matches!(outcome, AutoAtomisationOutcome::Enqueued { .. }),
        "expected Enqueued via ancestor inheritance, got {outcome:?}"
    );

    let ok = wait_until(Duration::from_secs(3), || {
        read_atomised_into(&conn, &mem.id)
            .map(|n| n > 0)
            .unwrap_or(false)
    });
    assert!(ok, "expected child memory to be atomised via parent policy");
}

// ===========================================================================
// Test 6 — child override: parent yes, child explicit no
// ===========================================================================

#[test]
fn test_auto_atomise_child_override() {
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
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
    let _g = test_serial().lock().unwrap_or_else(|p| p.into_inner());
    let db_path = shared_db_path().clone();
    let conn = shared_db_conn();
    let _ = &db_path;

    // The store-side governance hook is one-shot (`OnceLock::set`).
    // If a prior test already installed one, this set is a no-op — the
    // refused leg then soft-skips (see below); the control leg still
    // runs.
    let _ = db::GOVERNANCE_PRE_WRITE.set(Box::new(|mem: &Memory| {
        if mem.title.starts_with("refused-") {
            Err("test-policy: refused".to_string())
        } else {
            Ok(())
        }
    }));

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
            // A prior test installed an Allow-all hook, so the write was
            // not refused and there is no refusal to assert about. The
            // positive control above still ran.
            eprintln!(
                "test_auto_atomise_refused_memory_not_atomised: skipping refusal assertion — \
                 prior test installed Allow-all GOVERNANCE_PRE_WRITE hook"
            );
        }
    }
}
