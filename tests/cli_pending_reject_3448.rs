// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3448/#3487 — process-isolated coverage for `pending reject` under the
//! multi-agent posture.
//!
//! `AI_MEMORY_AGENT_ID` is process-global and is read by unrelated library
//! tests. Keeping these cases in their own integration-test binary prevents
//! their temporary identities from changing the behavior of concurrent
//! `src/**` tests. Tests within this binary still serialize and restore the
//! variable with [`AgentIdEnv`].

use ai_memory::cli::CliOutput;
use ai_memory::cli::agents::{PendingAction, PendingArgs, run_pending};
use ai_memory::db;
use rusqlite::params;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

struct AgentIdEnv {
    prev: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl AgentIdEnv {
    fn set(value: &str) -> Self {
        let lock = env_lock();
        let prev = std::env::var_os(ENV_AGENT_ID);
        // SAFETY: this process's mutations are serialized by `env_lock`,
        // which remains held for the guard's lifetime.
        unsafe { std::env::set_var(ENV_AGENT_ID, value) };
        Self { prev, _lock: lock }
    }
}

impl Drop for AgentIdEnv {
    fn drop(&mut self) {
        match self.prev.take() {
            // SAFETY: `_lock` is still held while the prior value is restored.
            Some(value) => unsafe { std::env::set_var(ENV_AGENT_ID, value) },
            // SAFETY: `_lock` is still held while the prior value is restored.
            None => unsafe { std::env::remove_var(ENV_AGENT_ID) },
        }
    }
}

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = std::env::current_dir()
        .expect("current dir")
        .join(".local-runs")
        .join("issue-3487-env-isolation");
    std::fs::create_dir_all(&scratch).expect("create scratch root");
    let dir = tempfile::Builder::new()
        .prefix("pending-reject-")
        .tempdir_in(scratch)
        .expect("tempdir under .local-runs");
    let path = dir.path().join("pending.db");
    db::open(&path).expect("initialize database");
    (dir, path)
}

fn seed_pending_action(db_path: &Path, id: &str, requested_by: &str) {
    let conn = db::open(db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO pending_actions \
         (id, action_type, namespace, payload, requested_by, requested_at, status) \
         VALUES (?1, 'store', 'ns-r3448', '{}', ?2, ?3, 'pending')",
        params![id, requested_by, now],
    )
    .expect("insert pending action");
}

fn register_agent(db_path: &Path, agent_id: &str) {
    let conn = db::open(db_path).expect("db::open");
    db::register_agent(&conn, agent_id, "ai:generic", &[]).expect("register agent");
}

fn reject(db_path: &Path, id: &str, actor: &str, json: bool) -> (anyhow::Result<()>, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = {
        let mut output = CliOutput::from_std(&mut stdout, &mut stderr);
        run_pending(
            db_path,
            PendingArgs {
                action: PendingAction::Reject { id: id.to_string() },
            },
            json,
            Some(actor),
            &mut output,
        )
    };
    (result, String::from_utf8(stdout).expect("UTF-8 stdout"))
}

fn assert_pending_untouched(db_path: &Path, id: &str) {
    let conn = db::open(db_path).expect("db::open");
    let pending = db::get_pending_action(&conn, id)
        .expect("read")
        .expect("row present");
    assert_eq!(pending.status, "pending", "a refused veto must not decide");
    assert!(pending.decided_by.is_none(), "no decider may be recorded");
}

#[test]
fn pending_reject_refuses_self_veto_under_posture_3448() {
    let _identity = AgentIdEnv::set("ai:alice3448");
    let (_dir, path) = fresh_db();
    seed_pending_action(&path, "pa-reject-self-3448", "ai:alice3448");
    register_agent(&path, "ai:alice3448");

    let message = reject(&path, "pa-reject-self-3448", "ai:alice3448", false)
        .0
        .expect_err("the requester must not veto their own action")
        .to_string();
    assert!(message.contains("reject refused"), "got: {message}");
    assert!(
        message.contains(ai_memory::errors::msg::SELF_APPROVAL_REFUSED),
        "shared separation-of-duties reason missing: {message}"
    );
    assert_pending_untouched(&path, "pa-reject-self-3448");
}

#[test]
fn pending_reject_refuses_unregistered_approver_3448() {
    let _identity = AgentIdEnv::set("ai:mallory3448");
    let (_dir, path) = fresh_db();
    seed_pending_action(&path, "pa-reject-unreg-3448", "ai:alice3448");

    let message = reject(&path, "pa-reject-unreg-3448", "ai:mallory3448", false)
        .0
        .expect_err("an unregistered agent must not veto")
        .to_string();
    assert!(message.contains("reject refused"), "got: {message}");
    assert!(
        message.contains("is not a registered agent"),
        "got: {message}"
    );
    assert_pending_untouched(&path, "pa-reject-unreg-3448");
}

#[test]
fn pending_reject_allows_registered_approver_3448() {
    let _identity = AgentIdEnv::set("ai:bob3448");
    let (_dir, path) = fresh_db();
    seed_pending_action(&path, "pa-reject-ok-3448", "ai:alice3448");
    register_agent(&path, "ai:bob3448");

    let (result, stdout) = reject(&path, "pa-reject-ok-3448", "ai:bob3448", true);
    result.expect("a registered non-requester approver must be allowed");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON output");
    assert_eq!(value["rejected"], true);
    assert_eq!(value["decided_by"], "ai:bob3448");

    let conn = db::open(&path).expect("db::open");
    let pending = db::get_pending_action(&conn, "pa-reject-ok-3448")
        .expect("read")
        .expect("row present");
    assert_eq!(pending.status, "rejected");
    assert_eq!(pending.decided_by.as_deref(), Some("ai:bob3448"));
}
