// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W4 / #1685 — the wire-action egress gate
//! ([`ai_memory`]'s `GOVERNANCE_PRE_ACTION`) MUST be installed on the MCP
//! stdio surface, not just the HTTP daemon.
//!
//! Pre-#1685 `run_mcp_server` installed only `GOVERNANCE_PRE_WRITE`
//! (the storage agent-action gate). The agent-EXTERNAL egress sinks —
//! `skill_export` (`FilesystemWrite`), federation sync + LLM
//! (`NetworkRequest`) — route through `governance::wire_check::check`,
//! which consults `GOVERNANCE_PRE_ACTION`. When that hook is unset
//! `wire_check::check` returns `Ok(())` (fail-OPEN), so on the MCP
//! surface — the primary NHI interface — a policy-denied egress action
//! was silently allowed. The fix installs the SAME closure in
//! `run_mcp_server` (`src/mcp/mod.rs`).
//!
//! These tests spawn the real `ai-memory mcp` subprocess (the
//! prime-directive pm-v3.3 fresh-subprocess probe) and exercise the
//! `memory_skill_export` egress tool both WITH and WITHOUT a seeded
//! `filesystem_write` refuse rule:
//!
//! * [`mcp_skill_export_refused_by_filesystem_write_rule_1685`] — with
//!   the rule, the export is REFUSED. This is the load-bearing pin: if
//!   the gate were not installed (fail-open) the export would succeed
//!   and write `SKILL.md`, so a refusal proves the install.
//! * [`mcp_skill_export_succeeds_without_rule_1685`] — with no rule the
//!   same export SUCCEEDS, proving the refusal above is caused by the
//!   gate consulting the rule, not by an unrelated export failure.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;

use ai_memory::db;

// #2525 — the per-response bound comes from the shared elastic helper
// (base x `AI_MEMORY_TEST_TIMING_BUDGET_MULT`, with fail-fast child-death
// detection) instead of the fixed 20s constant this file used to carry.
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl Drop for McpChild {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn local_runs_root() -> std::path::PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1685-mcp-pre-action-hook");
    std::fs::create_dir_all(&root).ok();
    root
}

fn unique_db() -> std::path::PathBuf {
    local_runs_root().join(format!("mcp-{}.db", uuid::Uuid::new_v4()))
}

/// Seed a `filesystem_write` REFUSE rule matching every path
/// (`{"glob":"**"}`). The rule `kind` column must equal the action kind
/// (`agent_action.rs:379` — `rule.kind != action.kind()` skips), which
/// for a `FilesystemWrite` is `"filesystem_write"`.
fn seed_filesystem_refuse_rule(db_path: &std::path::Path) {
    let conn = db::open(db_path).expect("open seed db");
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO governance_rules \
         (id, kind, matcher, severity, reason, namespace, created_by, \
          created_at, enabled, signature, attest_level) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
        rusqlite::params![
            "R-mcp-1685",
            "filesystem_write",
            r#"{"glob":"**"}"#,
            "refuse",
            "MCP egress (FilesystemWrite) MUST consult the wire-action gate (#1685)",
            "_global",
            "test",
            now,
            1,
            "unsigned",
        ],
    )
    .expect("seed filesystem_write rule");
}

fn spawn_mcp(db_path: &std::path::Path) -> (McpChild, mpsc::Receiver<String>) {
    // Hermetic key-dir isolation (mirrors the #1583 test): point
    // `AI_MEMORY_KEY_DIR` at an EMPTY project-local dir so the test runs
    // pre-L1-6 (no operator verifying key present), the mode in which an
    // `enabled = 1` UNSIGNED governance rule enforces. With a real
    // `operator.key.pub` on the host the unsigned rule would be dropped
    // as misconfiguration and the egress would NOT be refused, masking
    // the gate.
    let key_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&key_dir).ok();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &key_dir)
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory mcp");

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut s = stderr;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
    }
    let (tx, rx) = mpsc::channel();
    spawn_stdout_reader(stdout, tx);
    (
        McpChild {
            child: Some(child),
            stdin: Some(stdin),
        },
        rx,
    )
}

fn spawn_stdout_reader(stdout: ChildStdout, tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) if !line.trim().is_empty() => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

fn send_and_recv(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let line = serde_json::to_string(payload).unwrap();
    let ctx = payload["method"].as_str().unwrap_or("<unknown method>");
    writeln!(stdin, "{line}").expect("write to mcp stdin");
    stdin.flush().expect("flush mcp stdin");
    let resp = mcp_wait::recv_mcp_response(rx, ctx);
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse mcp response: {e}: {resp}"))
}

fn initialize(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>) {
    let init = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sec-test-1685", "version": "0"}
            }
        }),
    );
    assert!(init.get("result").is_some(), "initialize failed: {init}");
}

/// Register a minimal inline skill over MCP, returning its UUID (read
/// back from the `skills` table — robust against tool-result formatting).
fn register_skill(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    db_path: &std::path::Path,
) -> String {
    let inline = "---\nname: w4-egress-probe\nnamespace: sec-1685-ns\ndescription: probe skill for #1685 wire-action egress gate\n---\n\nThis SKILL.md exists only to exercise the FilesystemWrite egress sink.\n";
    let resp = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "memory_skill_register",
                "arguments": { "inline_skill": inline }
            }
        }),
    );
    let blob = serde_json::to_string(&resp).unwrap();
    let is_error = resp
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    assert!(
        !is_error && resp.get("error").is_none(),
        "#1685: memory_skill_register should succeed (no filesystem write); got: {blob}"
    );
    let conn = db::open(db_path).expect("reopen db for skill id");
    conn.query_row(
        "SELECT id FROM skills ORDER BY created_at DESC, rowid DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .expect("skill row must exist after register")
}

fn call_skill_export(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    skill_id: &str,
    target: &std::path::Path,
) -> serde_json::Value {
    send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "memory_skill_export",
                "arguments": {
                    "skill_id": skill_id,
                    "target_folder": target.to_str().unwrap()
                }
            }
        }),
    )
}

/// LOAD-BEARING: with a `filesystem_write` refuse rule seeded, the MCP
/// `memory_skill_export` egress MUST be refused — which can only happen
/// if `run_mcp_server` installed `GOVERNANCE_PRE_ACTION` (else
/// `wire_check::check` fails open and the export writes `SKILL.md`).
#[test]
fn mcp_skill_export_refused_by_filesystem_write_rule_1685() {
    let db_path = unique_db();
    seed_filesystem_refuse_rule(&db_path);

    let (mut guard, rx) = spawn_mcp(&db_path);
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let skill_id = register_skill(stdin, &rx, &db_path);

    // #3357 — `unique_db()` puts the store in `local_runs_root()`, so the
    // default export jail root is `local_runs_root()/skills-export`. Export
    // INSIDE it, exercising the shipped default with nothing configured.
    let target = local_runs_root()
        .join(ai_memory::mcp::DEFAULT_EXPORT_DIR_NAME)
        .join(format!("export-refused-{}", uuid::Uuid::new_v4()));
    let resp = call_skill_export(stdin, &rx, &skill_id, &target);
    let blob = serde_json::to_string(&resp).unwrap();

    let is_error = resp
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    let jsonrpc_error = resp.get("error").is_some();
    // The skill_export handler returns the exact prefix "governance
    // refused SKILL.md write:" when `wire_check::check` returns Err.
    let carries_refusal = blob.contains("governance refused");
    assert!(
        (is_error || jsonrpc_error) && carries_refusal,
        "#1685: MCP memory_skill_export must be refused by the seeded \
         filesystem_write rule (run_mcp_server must install \
         GOVERNANCE_PRE_ACTION; the test must run pre-L1-6 with no operator \
         key so the unsigned rule enforces); got: {blob}"
    );

    // Defense-in-depth: the refused export must NOT have written SKILL.md.
    assert!(
        !target.join("SKILL.md").exists(),
        "#1685: the refused egress must not have written SKILL.md to {}",
        target.display()
    );
}

/// POSITIVE CONTROL: with NO rule, the identical export SUCCEEDS and
/// writes `SKILL.md`. This proves the refusal above is caused by the
/// gate consulting the seeded rule — not by an unrelated export failure
/// (register/export round-trips when the policy allows).
#[test]
fn mcp_skill_export_succeeds_without_rule_1685() {
    let db_path = unique_db();
    // No governance rule seeded.

    let (mut guard, rx) = spawn_mcp(&db_path);
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let skill_id = register_skill(stdin, &rx, &db_path);

    // #3357 — `unique_db()` puts the store in `local_runs_root()`, so the
    // default export jail root is `local_runs_root()/skills-export`. Export
    // INSIDE it, exercising the shipped default with nothing configured.
    let target = local_runs_root()
        .join(ai_memory::mcp::DEFAULT_EXPORT_DIR_NAME)
        .join(format!("export-ok-{}", uuid::Uuid::new_v4()));
    let resp = call_skill_export(stdin, &rx, &skill_id, &target);
    let blob = serde_json::to_string(&resp).unwrap();

    let is_error = resp
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    assert!(
        !is_error && resp.get("error").is_none(),
        "#1685 control: with no rule the export must succeed; got: {blob}"
    );
    assert!(
        target.join("SKILL.md").exists(),
        "#1685 control: a successful export must write SKILL.md to {}",
        target.display()
    );
}
