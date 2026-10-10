// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5084 (the #2250 class) — a production writer that READS and then WRITES
//! must open `BEGIN IMMEDIATE`. Under WAL a DEFERRED transaction that has read
//! and then upgrades to a write fails at once with `SQLITE_BUSY_SNAPSHOT` when
//! another connection committed in between; `busy_timeout` does not retry it.
//!
//! Determinism: no sleeps. The harness arms a `trace` callback on the function
//! under test's connection. The callback fires as the FIRST write statement of
//! the function begins to run, i.e. after its read has established the
//! snapshot and before its write takes the lock. At that exact point a second
//! connection (`B`) tries to commit a row.
//!
//! * DEFERRED (base): `B` commits, the function's lock upgrade then fails with
//!   `SQLITE_BUSY_SNAPSHOT` (extended code 517).
//! * IMMEDIATE (tip): the function already holds the write lock from `BEGIN`,
//!   so `B` is refused (busy) and the function succeeds.
//!
//! Each test asserts the tip outcome AND that `B` was excluded, so a function
//! that regresses to DEFERRED fails on both counts.

use super::*;
use crate::models::{Memory, Tier};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

thread_local! {
    static HOOK_5084: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    /// `None`: the hook fires at the first write statement. `Some(n)`: only
    /// `INSERT INTO memories` statements count, and the hook fires at the
    /// `(n + 1)`th (used to land inside `mine`'s SECOND chunk transaction).
    static SKIP_INSERTS_5084: Cell<Option<usize>> = const { Cell::new(None) };
}

fn is_write_statement(sql: &str) -> bool {
    let s = sql.trim_start();
    ["UPDATE", "INSERT", "DELETE", "REPLACE"]
        .iter()
        .any(|p| s.starts_with(p))
}

fn trace_cb_5084(sql: &str) {
    if !is_write_statement(sql) {
        return;
    }
    if let Some(skip) = SKIP_INSERTS_5084.with(Cell::get) {
        if !sql.trim_start().starts_with("INSERT INTO memories") {
            return;
        }
        if skip > 0 {
            SKIP_INSERTS_5084.with(|c| c.set(Some(skip - 1)));
            return;
        }
    }
    if let Some(hook) = HOOK_5084.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

fn memory_5084(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "txn-5084".to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

/// Arm the interleaving on `conn_a` (the connection the function under test
/// runs on). Returns a cell that is `true` iff the second connection managed to
/// commit its row during the function's read-then-write window.
pub(crate) fn arm_interleaved_writer_5084(
    conn_a: &mut Connection,
    path: &std::path::Path,
) -> Rc<Cell<bool>> {
    let committed = install_hook_5084(path);
    conn_a.trace(Some(trace_cb_5084));
    committed
}

/// Install the second-writer hook without tracing any connection yet.
fn install_hook_5084(path: &std::path::Path) -> Rc<Cell<bool>> {
    let committed = Rc::new(Cell::new(false));
    let flag = Rc::clone(&committed);
    let path = path.to_path_buf();
    HOOK_5084.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            let Ok(b) = open(&path) else { return };
            // A short timeout: on the fixed tip the function holds the write
            // lock, so B must be refused rather than wait out the default.
            if b.busy_timeout(Duration::from_millis(150)).is_err() {
                return;
            }
            flag.set(insert(&b, &memory_5084("interleaved-writer-5084")).is_ok());
        }));
    });
    committed
}

/// Disarm: remove the trace callback and any hook that never fired. Returns
/// `true` iff the hook FIRED, so a caller can refuse a vacuous pass (a race
/// test whose interleaving never ran proves nothing).
#[must_use = "assert the hook fired, or the race test can pass vacuously"]
pub(crate) fn disarm_5084(conn_a: &mut Connection) -> bool {
    conn_a.trace(None);
    take_hook_fired_5084()
}

fn take_hook_fired_5084() -> bool {
    SKIP_INSERTS_5084.with(|c| c.set(None));
    HOOK_5084.with(|h| h.borrow_mut().take()).is_none()
}

/// Arm the interleaving for a function that OPENS ITS OWN connection from a
/// path (`mine`, `doctor --repair-schema-version`): the connection-open test
/// seam traces every connection opened on this thread until disarmed.
fn arm_on_open_5084(path: &std::path::Path, skip_inserts: Option<usize>) -> Rc<Cell<bool>> {
    SKIP_INSERTS_5084.with(|c| c.set(skip_inserts));
    let committed = install_hook_5084(path);
    super::connection::OPEN_TRACE_5084.with(|c| c.set(Some(trace_cb_5084)));
    committed
}

#[must_use = "assert the hook fired, or the race test can pass vacuously"]
fn disarm_on_open_5084() -> bool {
    super::connection::OPEN_TRACE_5084.with(|c| c.set(None));
    take_hook_fired_5084()
}

/// Run `f` on a fresh file-backed connection with the interleaver armed.
/// `seed` prepares the database (and returns fixture ids) on a separate,
/// already-closed connection.
fn run_race<S, T>(
    seed: impl FnOnce(&Connection) -> S,
    f: impl FnOnce(&mut Connection, &S) -> Result<T>,
) -> (Result<T>, bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("race-5084.db");
    let fixture = {
        let Ok(conn) = open(&path) else {
            panic!("#5084: seed open failed");
        };
        seed(&conn)
    };
    let Ok(mut a) = open(&path) else {
        panic!("#5084: open A failed");
    };
    let committed = arm_interleaved_writer_5084(&mut a, &path);
    let out = f(&mut a, &fixture);
    assert!(
        disarm_5084(&mut a),
        "#5084: the interleaving hook never fired, so this race test proved nothing"
    );
    (out, committed.get())
}

fn assert_immediate<T: std::fmt::Debug>(label: &str, out: &Result<T>, b_committed: bool) {
    assert!(
        out.is_ok(),
        "#5084 {label}: a read-then-write must open BEGIN IMMEDIATE and not fail the lock \
         upgrade (base returns SQLITE_BUSY_SNAPSHOT): {out:?}"
    );
    assert!(
        !b_committed,
        "#5084 {label}: the writer must hold the write lock from BEGIN, so a concurrent \
         writer cannot commit inside its read-then-write window"
    );
}

#[test]
fn stamp_contaminated_descendants_as_is_immediate_5084() {
    let (out, b_committed) = run_race(
        |conn| {
            let root = insert(conn, &memory_5084("root")).expect("root");
            let child = insert(conn, &memory_5084("child")).expect("child");
            create_link(conn, &child, &root, "derived_from").expect("link");
            assert!(
                !lineage_descendants(conn, &root, 3)
                    .expect("descendants")
                    .is_empty(),
                "fixture must give the root a descendant so the sweep reads then writes"
            );
            root
        },
        |a, root| stamp_contaminated_descendants_as(a, root, 3, StampAuthority::Admin),
    );
    assert_immediate("stamp_contaminated_descendants_as", &out, b_committed);
    assert_eq!(out.expect("report").stamped, 1);
}

#[test]
fn rekey_peer_is_immediate_5084() {
    const RAW: &str = "https://alice:s3cr3t@peer.example:9077/mesh?token=qpw";
    const RENDERED: &str = "https://peer.example:9077/mesh";
    let (out, b_committed) = run_race(
        |conn| {
            sync_state_observe(conn, "me", RAW, "2026-09-01T00:00:00Z").expect("observe");
        },
        |a, ()| sync_state_rekey::rekey_peer(a, "me", RAW, RENDERED),
    );
    assert_immediate("rekey_peer", &out, b_committed);
    assert!(out.expect("moved"), "the raw row must have been folded");
}

#[test]
fn set_embeddings_batch_is_immediate_5084() {
    let space = crate::embeddings::embedding_space_fingerprint("test-space");
    let (out, b_committed) = run_race(
        |conn| insert(conn, &memory_5084("embed")).expect("memory"),
        |a, id| set_embeddings_batch(a, &[(id.clone(), vec![0.5_f32; 4])], &space),
    );
    assert_immediate("set_embeddings_batch", &out, b_committed);
    assert_eq!(out.expect("written"), 1);
}

#[test]
fn set_embeddings_batch_reembed_is_immediate_5084() {
    let space = crate::embeddings::embedding_space_fingerprint("test-space");
    let (out, b_committed) = run_race(
        |conn| insert(conn, &memory_5084("reembed")).expect("memory"),
        |a, id| set_embeddings_batch_reembed(a, &[(id.clone(), vec![0.5_f32; 4])], &space),
    );
    assert_immediate("set_embeddings_batch_reembed", &out, b_committed);
    assert_eq!(out.expect("written"), 1);
}

// ---- #5243: the remaining converted functions -------------------------------

fn action_5084(id: &str) -> crate::models::Action {
    crate::models::Action {
        id: id.to_string(),
        namespace: "_act".to_string(),
        kind: "test.kind".to_string(),
        state: crate::models::ActionState::Pending,
        title: "t".to_string(),
        payload: serde_json::json!({"a": 1}),
        priority: 5,
        agent_id: Some("agent-x".to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

/// Like [`run_race`] for a function that opens its own connection from a path.
fn run_path_race<T>(
    skip_inserts: Option<usize>,
    seed: impl FnOnce(&std::path::Path),
    f: impl FnOnce(&std::path::Path) -> T,
) -> (T, bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("race-5084.db");
    seed(&path);
    let committed = arm_on_open_5084(&path, skip_inserts);
    let out = f(&path);
    assert!(
        disarm_on_open_5084(),
        "#5084: the interleaving hook never fired, so this race test proved nothing"
    );
    (out, committed.get())
}

#[test]
fn create_guarded_is_immediate_5084() {
    let (out, b_committed) = run_race(
        |_| (),
        |a, ()| {
            crate::actions::create_guarded(a, action_5084("cg-5084"))
                .map_err(|e| anyhow::anyhow!("{e:?}"))
        },
    );
    assert!(
        out.is_ok() && !b_committed,
        "#5084 create_guarded: {out:?} b_committed={b_committed}"
    );
}

#[test]
fn materialize_template_for_caller_is_immediate_5084() {
    let routine = crate::models::Routine {
        id: "rt-5084".to_string(),
        namespace: "_rt".to_string(),
        name: "deploy".to_string(),
        template: serde_json::json!({"actions": [
            {"kind": "work", "title": "first", "payload": {}, "metadata": {}}
        ]}),
        parameters: serde_json::json!([]),
        state: crate::models::RoutineState::Frozen,
        created_by: "agent-author".to_string(),
        created_at: 1,
        frozen_at: Some(1),
        signature: vec![],
        signer_pubkey: vec![],
        metadata: serde_json::json!({}),
    };
    let (out, b_committed) = run_race(
        |_| (),
        |a, ()| {
            crate::routines::materialization::materialize_template(
                a,
                &routine,
                &serde_json::json!({}),
                1,
            )
            .map_err(|e| anyhow::anyhow!(e))
        },
    );
    assert_immediate("materialize_template_for_caller", &out, b_committed);
    assert_eq!(out.expect("ids").len(), 1);
}

#[test]
fn sweep_expired_leases_reclaim_is_immediate_5084() {
    let now = 1_700_000_000;
    let (out, b_committed) = run_race(
        |conn| {
            crate::actions::create(conn, &action_5084("lease-5084")).expect("action");
            crate::actions::lease_acquire(conn, "lease-5084", "holder", now, now - 1)
                .expect("lease");
        },
        |a, ()| crate::actions::sweep_expired_leases(a, now).map_err(|e| anyhow::anyhow!("{e:?}")),
    );
    assert_immediate("sweep_expired_leases_reclaim", &out, b_committed);
    assert_eq!(out.expect("reclaimed").len(), 1);
}

#[test]
fn checkpoints_resolve_is_immediate_5084() {
    let cp = crate::models::Checkpoint {
        id: "cp-5084".to_string(),
        namespace: "_cp".to_string(),
        title: "needs approval".to_string(),
        condition_type: crate::models::ConditionType::Approval,
        condition: serde_json::json!({}),
        state: crate::models::CheckpointState::Pending,
        created_by: "agent-creator".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    };
    let (out, b_committed) = run_race(
        |conn| {
            crate::checkpoints::insert(conn, &cp).expect("checkpoint");
        },
        |a, ()| {
            crate::checkpoints::resolve(
                a,
                "cp-5084",
                crate::models::CheckpointState::Resolved,
                "agent-approver",
                Some("approved"),
                None,
                1_700_000_500,
                None,
            )
            .map_err(|e| anyhow::anyhow!("{e:?}"))
        },
    );
    assert_immediate("checkpoints::resolve", &out, b_committed);
}

#[test]
fn sweep_pending_action_timeouts_is_immediate_5084() {
    let (out, b_committed) = run_race(
        |conn| {
            conn.execute(
                "INSERT INTO pending_actions
                     (id, action_type, namespace, payload, requested_by, requested_at,
                      status, default_timeout_seconds)
                 VALUES ('stale-5084', 'store', 'ns/5084', '{}', 'tester', ?1, 'pending', NULL)",
                rusqlite::params![(chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339()],
            )
            .expect("stale pending row");
        },
        |a, ()| sweep_pending_action_timeouts(a, crate::SECS_PER_HOUR),
    );
    assert_immediate("sweep_pending_action_timeouts", &out, b_committed);
    assert_eq!(out.expect("expired").len(), 1);
}

#[test]
fn run_repair_schema_version_is_immediate_5084() {
    let (out, b_committed) = run_path_race(
        None,
        |path| {
            let Ok(conn) = open(path) else {
                panic!("#5084: seed open failed");
            };
            drop(conn);
        },
        |path| {
            let mut so: Vec<u8> = Vec::new();
            let mut se: Vec<u8> = Vec::new();
            let code = {
                let mut cli_out = crate::cli::CliOutput::from_std(&mut so, &mut se);
                crate::cli::doctor::run_repair_schema_version(
                    path,
                    crate::storage::migrations::current_schema_version(),
                    &mut cli_out,
                )
            };
            (code, String::from_utf8_lossy(&se).into_owned())
        },
    );
    assert!(
        matches!(out.0, Ok(0)) && !b_committed,
        "#5084 run_repair_schema_version: stderr={} b_committed={b_committed}",
        out.1
    );
}

fn write_claude_export_5084(dir: &std::path::Path, conversations: usize) -> std::path::PathBuf {
    let mut body = String::new();
    for i in 0..conversations {
        let conv = serde_json::json!({
            "uuid": format!("conv-{i}"),
            "name": format!("Conversation number {i}"),
            "created_at": "2026-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z",
            "chat_messages": [
                {"uuid": format!("a{i}"), "text": "hello", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z"},
                {"uuid": format!("b{i}"), "text": "hi", "sender": "assistant", "created_at": "2026-01-01T00:00:00.000Z"},
                {"uuid": format!("c{i}"), "text": "bye", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z"}
            ]
        });
        body.push_str(&conv.to_string());
        body.push('\n');
    }
    let path = dir.join("claude.jsonl");
    std::fs::write(&path, body).expect("write export");
    path
}

/// Run `mine` over `conversations` conversations with the interleaver firing at
/// the `(skip_inserts + 1)`th memory INSERT. `mine` counts a failed store as a
/// warning and returns Ok, so the failure shows up on stderr and in the count.
fn mine_race_5084(conversations: usize, skip_inserts: usize) -> (String, i64, bool) {
    let mut env = crate::cli::test_utils::TestEnv::fresh();
    let db_path = env.db_path.clone();
    let export_dir = tempfile::tempdir().expect("export dir");
    let export = write_claude_export_5084(export_dir.path(), conversations);
    let cfg = crate::config::AppConfig::default();
    let committed = arm_on_open_5084(&db_path, Some(skip_inserts));
    let result = {
        let mut out = env.output();
        crate::cli::io::mine(
            &db_path,
            crate::cli::io::MineArgs {
                path: export,
                format: "claude".to_string(),
                namespace: Some("mine-5084".to_string()),
                tier: "mid".to_string(),
                min_messages: 3,
                dry_run: false,
                on_conflict: crate::cli::io::OnConflict::Version,
            },
            false,
            &cfg,
            Some("miner"),
            &mut out,
        )
    };
    assert!(
        disarm_on_open_5084(),
        "#5084: the interleaving hook never fired, so this race test proved nothing"
    );
    assert!(result.is_ok(), "#5084: mine must succeed");
    let stderr = env.stderr_str().to_string();
    let Ok(reopened) = open(&db_path) else {
        panic!("#5084: reopen failed");
    };
    let stored: i64 = reopened
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = 'mine-5084'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    (stderr, stored, committed.get())
}

#[test]
fn mine_first_chunk_is_immediate_5084() {
    let (stderr, stored, b_committed) = mine_race_5084(2, 0);
    assert!(
        !b_committed && stored == 2 && !stderr.contains("failed to store"),
        "#5084 mine (first chunk): b_committed={b_committed} stored={stored} stderr={stderr}"
    );
}

#[test]
fn mine_second_chunk_is_immediate_5084() {
    // The chunk is closed and reopened after every 100 imports; the interleaver
    // fires at the 101st INSERT, i.e. inside the REOPENED transaction.
    let (stderr, stored, b_committed) = mine_race_5084(101, 100);
    assert!(
        !b_committed && stored == 101 && !stderr.contains("failed to store"),
        "#5084 mine (second chunk): b_committed={b_committed} stored={stored} stderr={stderr}"
    );
}
