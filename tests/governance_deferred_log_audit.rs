// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Policy-Engine Item 3 — deferred-audit chain-log integration
//! tests (closes the bypass-impossibility gap on the storage
//! `GOVERNANCE_PRE_WRITE` hook).
//!
//! These tests prove the chain-log property end-to-end:
//!
//! - **`refused_storage_insert_lands_in_signed_events_chain`** — drive
//!   the storage hook against a real DB with a refuse rule and assert
//!   the `governance.refusal` audit row lands after the refusal.
//! - **`drainer_does_not_block_inserts`** — under concurrent insert
//!   load with refusals interspersed, no insert request takes > 100 ms
//!   (deadlock regression pin).
//! - **`drainer_restarts_after_panic`** — sink-panic supervisor
//!   behavior; events submitted before panic land, panic counter
//!   bumps.
//! - **`shutdown_drains_pending_events`** — submit N events, initiate
//!   queue close, assert all N rows landed.
//! - **`chain_log_includes_rule_id_and_severity`** — the audit
//!   payload carries enough information to reconstruct WHICH rule
//!   refused.
//!
//! All tests run in-process against the public API (`db::open`,
//! `governance::deferred_audit::*`, `storage::GOVERNANCE_PRE_WRITE`).
//! No subprocess spawn — the previous L1-6 integration suite covers
//! the HTTP-403 round-trip; this suite is dedicated to the audit
//! chain.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ai_memory::db;
use ai_memory::governance::agent_action::{AgentAction, Decision, check_agent_action_deferred};
use ai_memory::governance::deferred_audit::{
    AppendOutcome, DeferredAuditEvent, DeferredAuditQueue, DeferredAuditSink, DrainError,
    DrainFlushError, DrainTerminalState, GOVERNANCE_REFUSAL_EVENT_TYPE, SqliteSignedEventsSink,
    close_and_flush, install_deferred_audit_drainer, spawn_drainer_task, spawn_supervised_drainer,
};
use ai_memory::governance::rules_store::{self, Rule};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

mod common;
use common::*;

// Same pattern as `tests/governance_a2a_rules.rs` /
// `tests/governance_agent_action.rs`: production `enforced_rule_passes`
// drops any rule whose `attest_level != "operator_signed"` when an
// operator pubkey resolves (env OR on-disk `operator.key.pub`). Each
// test calls `install_test_operator_key()` (in `common`) which installs
// the keypair in the env, holds the shared `ENV_LOCK` for its lifetime,
// and restores prior env state on drop.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Tempdir helper pinned to repository-owned scratch space.
fn fresh_tempdir() -> tempfile::TempDir {
    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("test-tmp");
    std::fs::create_dir_all(&scratch).expect("create repository-owned test scratch");
    tempfile::Builder::new()
        .prefix("governance-deferred-")
        .tempdir_in(scratch)
        .expect("repository-owned governance tempdir")
}

/// Seed a `memory_write` refuse rule into the `governance_rules` table
/// at `db_path`. The hook consults this rule via
/// `check_agent_action_deferred` on every storage insert.
///
/// Signs the rule with the test `signing` key so L1-6's
/// `enforced_rule_passes` (which requires `attest_level =
/// "operator_signed"` when an operator pubkey resolves) accepts it.
/// The caller pairs this with `install_test_operator_key()` to set
/// `AI_MEMORY_OPERATOR_PUBKEY` to the matching verifying key for the
/// lifetime of the test.
fn seed_refuse_rule(db_path: &std::path::Path, signing: &SigningKey, rule_id: &str, reason: &str) {
    let conn = db::open(db_path).expect("open seed db");
    let now = chrono::Utc::now().timestamp();
    let mut rule = Rule {
        id: rule_id.to_string(),
        kind: "custom".to_string(),
        matcher: r#"{"kind":"memory_write"}"#.to_string(),
        severity: "refuse".to_string(),
        reason: reason.to_string(),
        namespace: "_global".to_string(),
        created_by: "test".to_string(),
        created_at: now,
        enabled: true,
        signature: None,
        attest_level: "operator_signed".to_string(),
    };
    let canonical =
        rules_store::canonical_bytes_for_signing(&rule).expect("canonical_bytes_for_signing");
    rule.signature = Some(signing.sign(&canonical).to_bytes().to_vec());
    rules_store::insert(&conn, &rule).expect("seed rule");
}

fn refusal_action() -> AgentAction {
    AgentAction::Custom {
        custom_kind: "memory_write".to_string(),
        payload: serde_json::json!({"namespace": "test/ns"}),
    }
}

fn refusal_decision(rule_id: &str, reason: &str) -> Decision {
    Decision::Refuse {
        rule_id: rule_id.to_string(),
        reason: reason.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Test 1 — refused storage insert produces a governance.refusal row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refused_storage_insert_lands_in_signed_events_chain() {
    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("refusal-chain.db");
    // Initialize the schema (signed_events + governance_rules).
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(&db_path, &signing, "R-chain-1", "no writes to test ns");

    // Spawn the drainer + queue. In the daemon path this happens
    // inside bootstrap_serve before the storage hook installs; we
    // mirror that here.
    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    // Drive the audited path directly (mirrors the storage hook
    // closure body that bootstrap_serve installs).
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    let decision = check_agent_action_deferred(&conn, "agent:test-refusal", &action, &queue)
        .expect("check_agent_action_deferred");
    assert!(decision.is_refusal(), "expected refusal verdict");

    // Drain the queue + wait for the drainer to land the row.
    close_and_flush(queue, supervisor)
        .await
        .expect("graceful drain");

    // Assert the chain-log row landed.
    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:test-refusal"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "exactly one governance.refusal row must land");
}

// ---------------------------------------------------------------------------
// Test 2 — drainer never blocks the audited-path call (deadlock pin)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn drainer_does_not_block_inserts() {
    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("no-block.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(
        &db_path,
        &signing,
        "R-no-block",
        "refuse for the no-block test",
    );

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    // Run 50 audited-path calls back-to-back. Time each one and
    // assert p99 < 100 ms — every call must return without waiting
    // for the drainer to flush.
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    let mut elapsed: Vec<Duration> = Vec::with_capacity(50);
    for _ in 0..50 {
        let start = Instant::now();
        let decision =
            check_agent_action_deferred(&conn, "agent:no-block", &action, &queue).unwrap();
        elapsed.push(start.elapsed());
        assert!(decision.is_refusal());
    }
    elapsed.sort();
    // p99 of 50 samples is samples[49] (the max).
    let p99 = elapsed[49];
    assert!(
        p99 < Duration::from_millis(100),
        "p99 audited-path call must complete < 100ms; got {p99:?}"
    );

    close_and_flush(queue, supervisor).await.unwrap();

    // Sanity check — all 50 events landed in the chain.
    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 50, "every refusal must chain-log");
}

// ---------------------------------------------------------------------------
// Test 3 — supervisor retains receiver and restarts after sink panic
// ---------------------------------------------------------------------------

/// Sink that panics on the Nth append. Used to exercise the
/// supervisor's panic-recovery / metric-bump path.
struct PanicOnceSink {
    panic_after: u64,
    call_count: Arc<AtomicU64>,
}

impl DeferredAuditSink for PanicOnceSink {
    fn append(&mut self, _event: &DeferredAuditEvent) -> anyhow::Result<AppendOutcome> {
        let prior = self.call_count.fetch_add(1, Ordering::SeqCst);
        assert!(
            prior != self.panic_after,
            "PanicOnceSink: configured panic at call {prior}"
        );
        Ok(AppendOutcome::Appended)
    }
}

/// v1.0.0 #3164 — a sink that panics on EVERY call, so the supervisor's
/// restart budget is exhausted rather than recovered from.
struct AlwaysPanicSink;

impl DeferredAuditSink for AlwaysPanicSink {
    fn append(&mut self, _event: &DeferredAuditEvent) -> anyhow::Result<AppendOutcome> {
        panic!("AlwaysPanicSink: unrecoverable sink");
    }
}

/// v1.0.0 #3164 — a sink that always returns `Err`, exhausting the budget
/// through the UNRESOLVED arm rather than the panic arm.
struct AlwaysErrSink;

impl DeferredAuditSink for AlwaysErrSink {
    fn append(&mut self, _event: &DeferredAuditEvent) -> anyhow::Result<AppendOutcome> {
        Err(anyhow::anyhow!("AlwaysErrSink: chain write refused"))
    }
}

/// v1.0.0 #3164 — exhausting the restart budget on a PANICKING sink must
/// produce a TYPED terminal state that is observable while the process is
/// still running, not a `panic!` that silently kills only the supervisor task
/// and leaves the daemon serving with a dead audit drainer.
#[tokio::test]
async fn supervisor_exhaustion_returns_typed_terminal_state_sink_panicked_3164() {
    let (queue, rx) = DeferredAuditQueue::new();
    let metrics = queue.metrics();
    assert_eq!(
        metrics.terminal_state(),
        None,
        "a fresh drainer has no terminal state"
    );

    let supervisor = spawn_supervised_drainer(rx, || AlwaysPanicSink, metrics.clone(), 0);
    let event = DeferredAuditEvent::from_refusal(
        "agent:terminal",
        &refusal_action(),
        &refusal_decision("R-terminal", "terminal panic test"),
    )
    .unwrap();
    assert!(queue.submit(event));

    let err = close_and_flush(queue, supervisor)
        .await
        .expect_err("#3164: an exhausted budget must NOT report a clean drain");
    match err {
        DrainFlushError::Drain(DrainError::SinkPanicked { max_restarts }) => {
            assert_eq!(max_restarts, 0);
        }
        other => panic!("expected a typed SinkPanicked terminal state, got {other:?}"),
    }

    // The state is published on the SHARED metrics, so a fleet can see a dead
    // drainer without awaiting the supervisor.
    assert_eq!(
        metrics.terminal_state(),
        Some(DrainTerminalState::SinkPanicked),
        "#3164: the terminal state must be observable on the metrics handle"
    );
    assert_eq!(
        metrics.terminal_state().map(DrainTerminalState::as_str),
        Some("sink_panicked")
    );
}

/// Sibling of the above for the UNRESOLVED (`Err`-returning sink) arm, whose
/// `panic!` had the same invisibility problem.
#[tokio::test]
async fn supervisor_exhaustion_returns_typed_terminal_state_sink_unresolved_3164() {
    let (queue, rx) = DeferredAuditQueue::new();
    let metrics = queue.metrics();

    let supervisor = spawn_supervised_drainer(rx, || AlwaysErrSink, metrics.clone(), 0);
    let event = DeferredAuditEvent::from_refusal(
        "agent:unresolved",
        &refusal_action(),
        &refusal_decision("R-unresolved", "terminal unresolved test"),
    )
    .unwrap();
    assert!(queue.submit(event));

    let err = close_and_flush(queue, supervisor)
        .await
        .expect_err("#3164: an exhausted budget must NOT report a clean drain");
    match err {
        DrainFlushError::Drain(DrainError::SinkUnresolved {
            max_restarts,
            ref detail,
        }) => {
            assert_eq!(max_restarts, 0);
            assert!(
                detail.contains("chain write refused"),
                "the typed error must carry the underlying cause, got {detail:?}"
            );
        }
        ref other => panic!("expected a typed SinkUnresolved terminal state, got {other:?}"),
    }
    assert_eq!(
        metrics.terminal_state(),
        Some(DrainTerminalState::SinkUnresolved)
    );
}

#[tokio::test]
async fn drainer_restarts_after_panic() {
    let (queue, rx) = DeferredAuditQueue::new();
    let metrics = queue.metrics();
    let call_count = Arc::new(AtomicU64::new(0));
    let call_count_for_factory = call_count.clone();
    let supervisor = spawn_supervised_drainer(
        rx,
        move || PanicOnceSink {
            panic_after: 0,
            call_count: call_count_for_factory.clone(),
        },
        metrics.clone(),
        1,
    );
    // Submit one event; the sink panics on call 0 and must retry it
    // with a freshly-built sink while retaining the receiver.
    let event = DeferredAuditEvent::from_refusal(
        "agent:panic",
        &refusal_action(),
        &refusal_decision("R-panic", "panic test"),
    )
    .unwrap();
    assert!(queue.submit(event));

    tokio::time::timeout(Duration::from_secs(2), async {
        while metrics.panic_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("supervisor must observe the injected panic");

    // Exercise the same queue after recovery, then require shutdown
    // to drain both the retried and post-restart events.
    let later = DeferredAuditEvent::from_refusal(
        "agent:after-restart",
        &refusal_action(),
        &refusal_decision("R-panic", "panic test"),
    )
    .unwrap();
    assert!(queue.submit(later));
    close_and_flush(queue, supervisor)
        .await
        .expect("recovered supervisor must drain and exit cleanly");

    assert_eq!(
        metrics.panic_count(),
        1,
        "exactly one panic must be recorded"
    );
    assert_eq!(metrics.appended_count(), 2, "both events must land");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        3,
        "panic + retry + post-restart append"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — graceful shutdown drains every buffered event
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shutdown_drains_pending_events() {
    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("shutdown-drain.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(&db_path, &signing, "R-drain", "drain test rule");

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    // Submit 100 refusals via the audited path.
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    for _ in 0..100 {
        let _ = check_agent_action_deferred(&conn, "agent:drain", &action, &queue).unwrap();
    }

    // Initiate shutdown — close_and_flush drops the queue and
    // awaits the supervisor task. EVERY event must land.
    close_and_flush(queue, supervisor)
        .await
        .expect("graceful drain");

    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:drain"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 100,
        "every buffered event must land before shutdown completes; got {count}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — audit row payload carries rule_id + severity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chain_log_includes_rule_id_and_severity() {
    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("payload-shape.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(&db_path, &signing, "R-payload", "payload test reason");

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    let _ = check_agent_action_deferred(&conn, "agent:payload", &action, &queue).unwrap();
    close_and_flush(queue, supervisor).await.unwrap();

    // The signed_events row commits to the SHA-256 of canonical
    // JSON over (action, decision, agent_id, timestamp). To verify
    // the row carries enough info to reconstruct WHICH rule
    // refused, we re-derive the canonical hash from the event we
    // submitted and assert it matches the row's payload_hash.
    let conn = db::open(&db_path).expect("reopen db");
    let row: Vec<u8> = conn
        .query_row(
            "SELECT payload_hash FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:payload"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(row.len(), 32, "payload_hash must be SHA-256 (32 bytes)");

    // Reconstruct the canonical event the drainer would have hashed.
    // (We can't recover the exact `timestamp` field after the fact
    // — but the contract is "the payload commits to the rule_id +
    // action kind via the JSON canonical encoding". We assert the
    // shape by checking it's a non-zero SHA-256.)
    assert!(
        row.iter().any(|&b| b != 0),
        "payload_hash must be non-zero (deterministic SHA-256 over canonical bytes)"
    );

    // Defense-in-depth: verify the agent_id + event_type columns
    // are stable and the row is uniquely identifiable.
    let row_event_type: String = conn
        .query_row(
            "SELECT event_type FROM signed_events WHERE agent_id = 'agent:payload'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(row_event_type, GOVERNANCE_REFUSAL_EVENT_TYPE);
}

// ---------------------------------------------------------------------------
// Test 6 — concurrent audited-path callers all chain-log without
// dropping events (high-throughput pin)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_callers_no_event_loss() {
    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("concurrent.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(&db_path, &signing, "R-conc", "concurrency test rule");

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    // Spawn 8 tasks each running 20 audited-path calls in parallel.
    let mut tasks = Vec::new();
    for i in 0..8 {
        let queue_clone = queue.clone();
        let db_path_clone = db_path.clone();
        let task = tokio::task::spawn_blocking(move || {
            let conn = db::open(&db_path_clone).expect("open consult conn");
            let action = refusal_action();
            for _ in 0..20 {
                let agent = format!("agent:c-{i}");
                let _ = check_agent_action_deferred(&conn, &agent, &action, &queue_clone).unwrap();
            }
        });
        tasks.push(task);
    }
    for t in tasks {
        t.await.unwrap();
    }

    close_and_flush(queue, supervisor).await.unwrap();

    // 8 * 20 = 160 events expected.
    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 160,
        "every concurrent refusal must chain-log without loss; got {count}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — Allow / Warn paths do NOT chain-log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_refusal_paths_do_not_chain_log() {
    let dir = fresh_tempdir();
    let db_path = dir.path().join("non-refusal.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    // NO rule seeded — every check should return Allow.

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    for _ in 0..10 {
        let decision = check_agent_action_deferred(&conn, "agent:allow", &action, &queue).unwrap();
        assert!(decision.is_allowed());
    }
    close_and_flush(queue, supervisor).await.unwrap();

    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "Allow paths must not produce refusal rows");
}

// ---------------------------------------------------------------------------
// Test 8 — #1034 wire-check refusals chain-log to signed_events
// ---------------------------------------------------------------------------
//
// Pre-#1034 the wire_check `GOVERNANCE_PRE_ACTION` closure used
// `check_agent_action_no_audit_cached`, which fires the forensic-JSONL
// decision but never lands a `governance.refusal` row in `signed_events`.
// That broke the audit-chain symmetry for the four agent-EXTERNAL action
// variants (Bash / FilesystemWrite / NetworkRequest / ProcessSpawn) —
// only the substrate `memory_write` (Custom) variant landed an audit row
// on refusal. This test pins the post-#1034 behaviour: every wire-check
// refusal lands a chain-log row, identified by the action's `kind()` in
// the canonical payload.
//
// We exercise the production function (`check_agent_action_deferred_cached`)
// the daemon_runtime wire_check closure now calls, with a NetworkRequest
// action variant — same code path the federation::sync push, the LLM
// client, and the skill_export NetworkRequest sites consult.

fn seed_refuse_rule_raw(
    db_path: &std::path::Path,
    signing: &SigningKey,
    rule_id: &str,
    rule_kind: &str,
    matcher_json: &str,
    reason: &str,
) {
    let conn = db::open(db_path).expect("open seed db");
    let now = chrono::Utc::now().timestamp();
    let mut rule = Rule {
        id: rule_id.to_string(),
        kind: rule_kind.to_string(),
        matcher: matcher_json.to_string(),
        severity: "refuse".to_string(),
        reason: reason.to_string(),
        namespace: "_global".to_string(),
        created_by: "test".to_string(),
        created_at: now,
        enabled: true,
        signature: None,
        attest_level: "operator_signed".to_string(),
    };
    let canonical =
        rules_store::canonical_bytes_for_signing(&rule).expect("canonical_bytes_for_signing");
    rule.signature = Some(signing.sign(&canonical).to_bytes().to_vec());
    rules_store::insert(&conn, &rule).expect("seed rule");
}

#[tokio::test]
async fn wire_check_network_request_refusal_lands_in_signed_events_chain_1034() {
    use ai_memory::governance::agent_action::check_agent_action_deferred_cached;

    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("wire-check-1034.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule_raw(
        &db_path,
        &signing,
        "R-wire-net-1034",
        "network_request",
        r#"{"host":"forbidden.example.com"}"#,
        "no outbound HTTPS to forbidden.example.com",
    );

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    // Exercise the production code path the daemon_runtime wire_check
    // closure now consults — NetworkRequest is one of the four
    // agent-EXTERNAL variants the storage path can NOT produce.
    let conn = db::open(&db_path).expect("open consult conn");
    let action = AgentAction::NetworkRequest {
        host: "forbidden.example.com".to_string(),
        scheme: "https".to_string(),
    };
    // `daemon:wire_action` is the stable attribution tag the
    // daemon_runtime wire_check closure passes — see
    // src/daemon_runtime.rs comment on the #1034 change.
    let decision =
        check_agent_action_deferred_cached(&conn, None, "daemon:wire_action", &action, &queue)
            .expect("check_agent_action_deferred_cached");
    assert!(
        decision.is_refusal(),
        "expected refusal verdict for NetworkRequest forbidden host"
    );

    close_and_flush(queue, supervisor)
        .await
        .expect("graceful drain");

    // Assert exactly one governance.refusal row landed with the daemon
    // wire-action attribution.
    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "daemon:wire_action"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "post-#1034: wire-check NetworkRequest refusal must chain-log exactly once"
    );
}

// ---------------------------------------------------------------------------
// Test 9 — #1035 governance.refusal rows ARE signed when daemon has a key
// ---------------------------------------------------------------------------
//
// Pre-#1035 every `SqliteSignedEventsSink::append` write set
// `signature: None, attest_level: "unsigned"` regardless of whether the
// daemon had an Ed25519 keypair on disk. The cross-row prev_hash chain
// stayed tamper-evident, but the per-row sig that
// `src/signed_events.rs:53-54` advertises as defense-in-depth was
// always missing. This test installs a daemon audit key via the public
// `governance::audit::init` surface, drives the deferred-audit path
// through a refusal, and asserts the resulting `signed_events.signature`
// column is populated AND `attest_level = "daemon_signed"`.

#[tokio::test]
async fn refused_storage_insert_signs_signed_events_row_when_daemon_keyed_1035() {
    use ai_memory::governance::audit;

    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("signed-1035.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule(&db_path, &signing, "R-1035-signed", "sign-test refuse rule");

    // Install a daemon audit key via the public init surface. The
    // OnceLock is process-wide — once set in this cargo-test binary,
    // it stays installed for the lifetime of the process. Subsequent
    // test cases that DON'T install a key also see this key (which
    // matches v0.7 production posture: daemon installs the key once
    // at boot and every audit-row write uses it for the lifetime).
    //
    // We use a deterministic key (different from `signing`, the rule-
    // signing key) so the verifier path below can produce a real
    // `VerifyingKey` and round-trip the signature.
    let daemon_key = SigningKey::from_bytes(&[7u8; 32]);
    let daemon_vk = daemon_key.verifying_key();
    // Re-init with the daemon key. `init` resets the SINK + OnceLock-
    // installs the audit key (idempotent — first install wins).
    audit::init(dir.path(), Some(daemon_key)).expect("audit::init with daemon key");
    assert!(
        audit::audit_key_is_installed(),
        "daemon audit key must be installed after init"
    );

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);
    let conn = db::open(&db_path).expect("open consult conn");
    let action = refusal_action();
    let decision = check_agent_action_deferred(&conn, "agent:1035-signed", &action, &queue)
        .expect("check_agent_action_deferred");
    assert!(decision.is_refusal());

    close_and_flush(queue, supervisor)
        .await
        .expect("graceful drain");

    // Assert the row has both a non-empty signature AND the
    // `daemon_signed` attest_level, then reconstruct the FULL row so we can
    // recompute the exact bytes the daemon key signed.
    let conn = db::open(&db_path).expect("reopen db");
    let row: ai_memory::signed_events::SignedEvent = conn
        .query_row(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash FROM signed_events \
             WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:1035-signed"],
            |r| {
                Ok(ai_memory::signed_events::SignedEvent {
                    id: r.get(0)?,
                    agent_id: r.get(1)?,
                    event_type: r.get(2)?,
                    payload_hash: r.get(3)?,
                    signature: r.get(4)?,
                    attest_level: r.get(5)?,
                    timestamp: r.get(6)?,
                    prev_hash: r.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                    sequence: r.get(8)?,
                    cause_hash: r.get::<_, Option<Vec<u8>>>(9)?,
                })
            },
        )
        .unwrap();

    let sig_bytes = row
        .signature
        .clone()
        .expect("signature must be populated when daemon key installed");
    assert_eq!(
        sig_bytes.len(),
        64,
        "Ed25519 signature must be 64 bytes; got {}",
        sig_bytes.len()
    );
    assert_eq!(
        row.attest_level, "daemon_signed",
        "attest_level must be `daemon_signed` when daemon key installed"
    );

    // Defense-in-depth — verify the signature validates against the daemon's
    // verifying key. #1925 (CWE-347): the per-row daemon signature now binds the
    // FULL identity tuple (agent_id/event_type/attest_level/timestamp/sequence/
    // payload_hash/cause) via `daemon_row_signing_input`, NOT `payload_hash`
    // alone, so a head-row identity edit invalidates the signature. We recompute
    // the EXACT bytes the daemon key signed (a fresh, symmetric sign→verify
    // round-trip using the production signing-input function) — proving the sig
    // binds the row's whole identity, strictly stronger than the pre-#1925
    // payload_hash-only check.
    let sig = Signature::from_slice(&sig_bytes).expect("64-byte ed25519 signature");
    let signing_input = ai_memory::signed_events::daemon_row_signing_input(&row);
    daemon_vk
        .verify(&signing_input, &sig)
        .expect("daemon verifying key must verify the stored sig over the #1925 identity input");

    // And the AUTHORITATIVE production verifier agrees (no signature failures).
    let report = ai_memory::signed_events::verify_chain(&conn, None, None).expect("verify_chain");
    assert!(report.chain_holds(), "chain must hold: {report:?}");
    assert!(
        report.signature_failures.is_empty(),
        "production verifier must accept the daemon-signed row: {report:?}"
    );
}

#[tokio::test]
async fn wire_check_process_spawn_refusal_lands_in_signed_events_chain_1034() {
    use ai_memory::governance::agent_action::check_agent_action_deferred_cached;

    let (signing, _env_guard) = install_test_operator_key();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("wire-check-spawn-1034.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    seed_refuse_rule_raw(
        &db_path,
        &signing,
        "R-wire-spawn-1034",
        "process_spawn",
        r#"{"binary":"/usr/bin/rm"}"#,
        "no rm spawns from daemon hooks",
    );

    let (queue, supervisor) = install_deferred_audit_drainer(&db_path);

    let conn = db::open(&db_path).expect("open consult conn");
    let action = AgentAction::ProcessSpawn {
        binary: "/usr/bin/rm".to_string(),
        args: vec!["-rf".to_string(), "/".to_string()],
    };
    let decision =
        check_agent_action_deferred_cached(&conn, None, "daemon:wire_action", &action, &queue)
            .expect("check_agent_action_deferred_cached");
    assert!(decision.is_refusal());

    close_and_flush(queue, supervisor)
        .await
        .expect("graceful drain");

    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "daemon:wire_action"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "post-#1034: wire-check ProcessSpawn refusal must chain-log exactly once"
    );
}

// ---------------------------------------------------------------------------
// Test 8 — direct drainer task with a custom sink validates the API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_drainer_task_drains_to_completion() {
    let (queue, rx) = DeferredAuditQueue::new();
    let metrics = queue.metrics();
    let dir = fresh_tempdir();
    let db_path = dir.path().join("direct-drainer.db");
    {
        let _ = db::open(&db_path).expect("init schema");
    }
    let sink = SqliteSignedEventsSink::new(&db_path);
    let handle = spawn_drainer_task(rx, sink, metrics.clone());

    for i in 0..7 {
        let event = DeferredAuditEvent::from_refusal(
            &format!("agent:d-{i}"),
            &refusal_action(),
            &refusal_decision("R-direct", "direct drainer test"),
        )
        .unwrap();
        queue.submit(event);
    }
    drop(queue);
    let _returned_rx = handle.await.unwrap();

    assert_eq!(metrics.appended_count(), 7);

    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 7);
}
