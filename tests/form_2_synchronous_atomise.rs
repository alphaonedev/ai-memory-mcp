// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x Form 2 acceptance tests (issue #755) — synchronous
//! atomise-before-embed mode.
//!
//! Three tests cover the three `AutoAtomiseMode` variants:
//!
//! * Synchronous — source memory exists archived with
//!   `atomised_into > 0` BEFORE `memory_store` returns; atoms are
//!   queryable via FTS5 immediately.
//! * Deferred — existing WT-1-D behaviour preserved (atomiser runs
//!   on the worker thread; the source has `atomised_into = NULL`
//!   immediately after the response returns).
//! * Off — no atomisation occurs at all.

#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::let_and_return,
    clippy::map_unwrap_or,
    clippy::ignored_unit_patterns,
    clippy::redundant_closure_for_method_calls
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::background::atomise_worker::AtomiseQueue;
use ai_memory::config::{FeatureTier, ResolvedTtl};
use ai_memory::hooks::pre_store::AtomiseWiring;
use ai_memory::models::{
    ApproverType, AtomisationPolicy, AutoAtomiseMode, CorePolicy, GovernanceLevel,
    GovernancePolicy, Memory, Tier,
};
use ai_memory::storage as db;

use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// #3050 — NO shared mock state. Every test injects its OWN stateless curator
// (`StatelessTwoAtomCurator`, defined below) through an ISOLATED
// `AtomiseWiring`, so nothing this suite asserts on can be touched by a
// concurrent background atomise-worker OS thread (the #2986 worker is NOT
// covered by `test_serial`). The prior form shared ONE `MockCurator` whose
// response QUEUE the deferred test's worker drained asynchronously; under
// llvm-cov that worker was slow enough to (a) steal the synchronous test's
// freshly-enqueued response (source came back un-atomised, `#3050`) and
// (b) bump the shared call counter the off test read
// (`off_mode_skips_atomisation_entirely` false-fail, the CI regression).
// Removing the shared mutable state entirely is the structural fix.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shared DB path (process-wide file; every test rotates its namespace + ids).
// ---------------------------------------------------------------------------

fn local_runs_root() -> PathBuf {
    std::env::var("TMPDIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".local-runs")
                .join("tmp")
        })
}

fn shared_db_path() -> &'static PathBuf {
    static SHARED: OnceLock<PathBuf> = OnceLock::new();
    SHARED.get_or_init(|| {
        let root = local_runs_root();
        std::fs::create_dir_all(&root).ok();
        root.join(format!("form-2-synchronous-{}.db", uuid::Uuid::new_v4()))
    })
}

/// v1.0.0 #2983 / #3050 — build an ISOLATED atomiser over a stateless
/// per-test curator (`StatelessTwoAtomCurator`). Returns the atomiser plus
/// its OWN call counter, so a test asserts on state that NO other test — and
/// no concurrent background atomise-worker — can touch. The pre-#2983 form
/// injected the mock through a process-global `OnceLock` dispatch whose slot
/// had ZERO production callers; the pre-#3050 form injected a SHARED mock
/// whose response queue + call count a background worker raced. Both are
/// gone: the wiring is now per-test and stateless.
fn isolated_atomiser() -> (Arc<Atomiser>, Arc<Mutex<usize>>) {
    let calls = Arc::new(Mutex::new(0usize));
    let atomiser = Arc::new(Atomiser::new(
        Box::new(StatelessTwoAtomCurator {
            calls: Arc::clone(&calls),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    ));
    (atomiser, calls)
}

fn test_serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

/// #1751 — pin this test binary (and any spawned `ai-memory` child, which
/// inherits the process env) to the explicit permissive agent-attestation
/// opt-out. The v0.9 store-path default is REQUIRED and would reject this
/// suite's unsigned store fixtures; the required default itself is pinned
/// in `tests/agent_attestation_integrity.rs` + `tests/config_precedence.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}
fn open_shared_db() -> Connection {
    permissive_attestation_for_tests();
    db::open(shared_db_path()).expect("open shared db")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn seed_policy(conn: &Connection, ns: &str, policy: GovernancePolicy) {
    let now = Utc::now().to_rfc3339();
    let gov_metadata = json!({
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
    let std_id = db::insert(conn, &std_mem).expect("seed standard");
    db::set_namespace_standard(conn, ns, &std_id, None).expect("set standard");
}

fn make_policy(mode: Option<AutoAtomiseMode>, enable_legacy_flag: bool) -> GovernancePolicy {
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
            auto_atomise: if enable_legacy_flag { Some(true) } else { None },
            auto_atomise_threshold_cl100k: Some(20),
            auto_atomise_max_atom_tokens: Some(50),
            auto_atomise_max_retries: None,
            auto_atomise_mode: mode,
        },
        ..Default::default()
    }
}

fn long_body() -> String {
    let unit = "The kubernetes rolling deploy strategy required canary instance health checks. \
                The pod readiness probe must pass before traffic shifts. Failures roll back the \
                deployment within 30 seconds. ";
    unit.repeat(8)
}

/// #3050 — every store goes through an EXPLICIT per-test wiring; there is no
/// shared-wiring default any more (that default was the shared-state race).
fn store_through_mcp_with(
    conn: &Connection,
    db_path: &std::path::Path,
    ns: &str,
    wiring: AtomiseWiring<'_>,
) -> Value {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_with_atomise_for_tests(
        conn,
        db_path,
        &json!({
            "title": format!("form-2-{}-{}", ns, uuid::Uuid::new_v4()),
            "content": long_body(),
            "namespace": ns,
        }),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
        wiring,
    )
    .expect("memory_store ok")
}

/// #3050 — a STATELESS deterministic curator: always exactly two atoms,
/// no response QUEUE. The suite's shared `MockCurator` drains a shared
/// response queue, which the deferred test's background worker
/// (`shared_queue`, an OS thread NOT covered by `test_serial`) can pop
/// concurrently — under llvm-cov instrumentation that worker was slow
/// enough to steal the synchronous test's freshly-enqueued response,
/// leaving the source un-atomised (the #3050 flake). A stateless
/// per-test curator removes the shared mutable state entirely, so the
/// synchronous observation is deterministic without any timing
/// assumption.
struct StatelessTwoAtomCurator {
    calls: Arc<Mutex<usize>>,
}

impl Curator for StatelessTwoAtomCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        *self.calls.lock().unwrap() += 1;
        Ok(vec![
            Atom {
                text: "Canary instance health checks must pass.".to_string(),
            },
            Atom {
                text: "Failures roll back within 30 seconds.".to_string(),
            },
        ])
    }
}

fn read_atomised_into(conn: &Connection, id: &str) -> Option<i64> {
    conn.query_row(
        "SELECT atomised_into FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, Option<i64>>(0),
    )
    .ok()
    .flatten()
}

fn count_atoms_for_source(conn: &Connection, source_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
        [source_id],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Test 1: Synchronous mode — source archived BEFORE response returns;
// atoms queryable immediately.
// ---------------------------------------------------------------------------

#[test]
fn synchronous_mode_archives_source_and_atoms_visible_before_response() {
    let _guard = test_serial().lock().unwrap_or_else(|e| e.into_inner());

    // #3050 — ISOLATED wiring: a stateless per-test curator + NO queue.
    // The synchronous path runs the atomiser fully IN-PROCESS before the
    // response is built, so with a curator that shares no mutable state
    // (and no worker queue that any background thread could drain) the
    // whole observation is deterministic — no timing window for a
    // concurrent deferred-test worker to race. The prior form injected
    // the SHARED mock (whose response queue that worker pops), which is
    // what flaked under llvm-cov.
    let (atomiser, calls) = isolated_atomiser();
    let sync_wiring = AtomiseWiring::new(Some(&atomiser), None);

    let conn = open_shared_db();
    let ns = format!("sync-ns-{}", uuid::Uuid::new_v4().simple());
    seed_policy(
        &conn,
        &ns,
        make_policy(Some(AutoAtomiseMode::Synchronous), false),
    );

    let resp = store_through_mcp_with(&conn, shared_db_path(), &ns, sync_wiring);
    let source_id = resp["id"].as_str().expect("response id").to_string();

    // The DETERMINISTIC completion signal: `handle_store` sets
    // `atomise_outcome = "atomised"` ONLY after the synchronous
    // `atomise_sync_with_retries` returned `Ok` in-process. Asserting on
    // the RESPONSE (never a post-return read that assumes the sync work
    // has finished) is the load-bearing #3050 fix — Form 2's
    // atoms-before-the-response guarantee is proven by the envelope the
    // handler itself emitted, not by a race against it.
    assert_eq!(
        resp["atomise_mode"].as_str(),
        Some("synchronous"),
        "response must report the synchronous mode; got {resp}",
    );
    assert_eq!(
        resp["atomise_outcome"].as_str(),
        Some("atomised"),
        "synchronous atomise must have COMPLETED before the response returned; got {resp}",
    );
    // The completion signal above proves exactly one in-process curator
    // call landed; the isolated curator makes that count race-free.
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "synchronous mode: exactly one in-process curator call",
    );

    // With the completion signal asserted, the durable side effects are
    // guaranteed to have landed (the atomiser archives + writes atoms in
    // the SAME synchronous call that returned Ok). These reads no longer
    // race the sync path — they confirm the atoms the envelope promised.
    let atomised_into = read_atomised_into(&conn, &source_id);
    assert!(
        atomised_into.is_some_and(|n| n > 0),
        "source archived with atomised_into > 0 (synchronous); got: {atomised_into:?}",
    );
    let atom_count = count_atoms_for_source(&conn, &source_id);
    assert_eq!(atom_count, 2, "two atoms emitted by the stateless curator");
}

// ---------------------------------------------------------------------------
// Test 2: Deferred mode — existing WT-1-D behaviour preserved.
// `atomised_into` is NULL right after the response returns; the worker
// thread completes asynchronously.
// ---------------------------------------------------------------------------

#[test]
fn deferred_mode_preserves_existing_behaviour() {
    let _guard = test_serial().lock().unwrap_or_else(|e| e.into_inner());

    // #3050 — ISOLATED wiring: a per-test atomiser + a per-test bounded
    // worker whose provider yields THAT atomiser. Its curator state and
    // its background OS thread belong to this test alone, so no other
    // test's assertions can be perturbed by this worker's async drain
    // (the exact cross-test coupling that false-failed the off test), and
    // this test's own observations cannot be perturbed by anyone else's.
    let (atomiser, calls) = isolated_atomiser();
    let provider_atomiser = Arc::clone(&atomiser);
    let queue: AtomiseQueue = ai_memory::background::atomise_worker::spawn(Arc::new(move || {
        Some(Arc::clone(&provider_atomiser))
    }))
    .expect("atomise worker spawns");
    let deferred_wiring = AtomiseWiring::new(Some(&atomiser), Some(&queue));

    let conn = open_shared_db();
    let ns = format!("deferred-ns-{}", uuid::Uuid::new_v4().simple());
    // Deferred mode is enabled when auto_atomise_mode=Deferred OR
    // (auto_atomise=true AND auto_atomise_mode=None) per the
    // resolve table. We test the explicit-Deferred form here.
    seed_policy(
        &conn,
        &ns,
        make_policy(Some(AutoAtomiseMode::Deferred), false),
    );

    let resp = store_through_mcp_with(&conn, shared_db_path(), &ns, deferred_wiring);
    let source_id = resp["id"].as_str().expect("response id").to_string();

    // Form 2 deferred-mode contract: source's atomised_into is NULL at
    // the moment the response returned. The worker thread may complete
    // it later — that is the deferred semantic.
    let atomised_into_immediate = read_atomised_into(&conn, &source_id);
    assert!(
        atomised_into_immediate.is_none(),
        "deferred mode: atomised_into must be NULL right after store returns, got: {atomised_into_immediate:?}",
    );

    // #2987 — the envelope now reports the mode that ACTUALLY RAN on
    // EVERY branch. Deferred means deferred, and the outcome says the job
    // was queued; the pre-v1.0.0 form emitted no field at all here (and
    // hardcoded "synchronous" on the sync branch even when nothing ran).
    assert_eq!(resp["atomise_mode"].as_str(), Some("deferred"));
    assert_eq!(resp["atomise_outcome"].as_str(), Some("queued"));
    assert!(
        resp.get("atomise_mode_configured").is_none(),
        "deferred-configured + deferred-ran must NOT report a divergence"
    );

    // The deferred guarantee is EVENTUAL, not immediate — the bounded
    // worker (this test's own) lands the atoms out-of-band. Poll the
    // isolated curator's own counter + the source rows; both are race-free
    // because nothing else drives this atomiser. Dropping `queue` after the
    // assertion lets the worker thread exit cleanly (its only sender gone).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut atoms = 0i64;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
        atoms = count_atoms_for_source(&conn, &source_id);
        if atoms >= 2 {
            break;
        }
    }
    assert_eq!(
        atoms, 2,
        "deferred mode: the bounded worker must land the two atoms out-of-band",
    );
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "deferred mode: exactly one curator call, on the worker thread",
    );
    drop(queue);
}

// ---------------------------------------------------------------------------
// Test 3: Off mode — no atomisation occurs at all.
// ---------------------------------------------------------------------------

#[test]
fn off_mode_skips_atomisation_entirely() {
    let _guard = test_serial().lock().unwrap_or_else(|e| e.into_inner());

    // #3050 — ISOLATED wiring with a per-test call counter. Off mode is
    // resolved BEFORE the atomiser is ever consulted, so the load-bearing
    // "curator must not be called" assertion reads THIS test's own counter
    // (which nothing else can bump), not a process-global one a concurrent
    // deferred-test worker was racing — the exact false-fail CI surfaced.
    // A queue is wired so a spurious enqueue would be observable, but the
    // Off path never reaches it.
    let (atomiser, calls) = isolated_atomiser();
    let provider_atomiser = Arc::clone(&atomiser);
    let queue: AtomiseQueue = ai_memory::background::atomise_worker::spawn(Arc::new(move || {
        Some(Arc::clone(&provider_atomiser))
    }))
    .expect("atomise worker spawns");
    let off_wiring = AtomiseWiring::new(Some(&atomiser), Some(&queue));

    let conn = open_shared_db();
    let ns = format!("off-ns-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, make_policy(Some(AutoAtomiseMode::Off), false));

    let resp = store_through_mcp_with(&conn, shared_db_path(), &ns, off_wiring);
    let source_id = resp["id"].as_str().expect("response id").to_string();

    // #2987 — `off` is a mode too, and it is reported honestly. Asserting
    // on the ENVELOPE first proves nothing ran, deterministically.
    assert_eq!(resp["atomise_mode"].as_str(), Some("off"));
    assert_eq!(
        resp["atomise_outcome"].as_str(),
        Some("skipped_policy_disabled")
    );

    // The curator was NEVER called — read this test's OWN counter (was a
    // shared process-global before #3050, which a background worker raced).
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "Off mode: curator must not be called",
    );

    // Source is NOT archived — atomised_into stays NULL, zero atoms.
    let atomised_into = read_atomised_into(&conn, &source_id);
    assert!(
        atomised_into.is_none(),
        "Off mode: atomised_into must remain NULL, got: {atomised_into:?}",
    );
    let atom_count = count_atoms_for_source(&conn, &source_id);
    assert_eq!(atom_count, 0, "Off mode: zero atoms");
    drop(queue);
}
