// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1583 (SEC, MED) — the substrate `GOVERNANCE_PRE_WRITE`
//! agent-action gate MUST be installed on the MCP write surface, not
//! just the HTTP daemon.
//!
//! Pre-#1583 the hook was installed only by `bootstrap_serve` (the
//! `ai-memory serve` path). An operator who configured a `memory_write`
//! agent-action refuse rule had it enforced over HTTP but SILENTLY
//! BYPASSED over MCP (`ai-memory mcp`) — the primary NHI agent write
//! interface. (Namespace `CorePolicy` standards were always enforced
//! via `db::enforce_governance` on the store path; the gap was the
//! SEPARATE agent-action rule layer.)
//!
//! This test spawns the real `ai-memory mcp` subprocess against a DB
//! seeded with a `memory_write` refuse rule and asserts the
//! `memory_store` tool call is REFUSED. The CLI sibling
//! (`cli_one_shot_does_not_install_hook` in
//! `tests/governance_storage_insert_hook.rs`) pins the inverse: CLI
//! one-shot writes intentionally stay outside the hook.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::db;

const READ_TIMEOUT: Duration = Duration::from_secs(15);

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

fn local_runs_db() -> std::path::PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1583-mcp-governance-hook");
    std::fs::create_dir_all(&root).ok();
    root.join(format!("mcp-{}.db", uuid::Uuid::new_v4()))
}

fn spawn_mcp(db_path: &std::path::Path) -> (McpChild, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
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
    writeln!(stdin, "{line}").expect("write to mcp stdin");
    stdin.flush().expect("flush mcp stdin");
    let resp = rx
        .recv_timeout(READ_TIMEOUT)
        .expect("mcp response did not arrive within READ_TIMEOUT");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse mcp response: {e}: {resp}"))
}

/// Seed a `memory_write` agent-action REFUSE rule into the DB before
/// the MCP server boots, then drive a `memory_store` tool call and
/// assert it is refused — proving the MCP path installs the gate.
#[test]
fn mcp_store_is_refused_by_agent_action_rule_1583() {
    let db_path = local_runs_db();
    {
        let conn = db::open(&db_path).expect("open seed db");
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO governance_rules \
             (id, kind, matcher, severity, reason, namespace, created_by, \
              created_at, enabled, signature, attest_level) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
            rusqlite::params![
                "R-mcp-1583",
                "custom",
                r#"{"kind":"memory_write"}"#,
                "refuse",
                "MCP writes MUST consult the pre-write hook (#1583)",
                "_global",
                "test",
                now,
                1,
                "unsigned",
            ],
        )
        .expect("seed rule");
    }

    let (mut guard, rx) = spawn_mcp(&db_path);
    let stdin = guard.stdin.as_mut().unwrap();

    // Handshake.
    let init = send_and_recv(
        stdin,
        &rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sec-test-1583", "version": "0"}
            }
        }),
    );
    assert!(init.get("result").is_some(), "initialize failed: {init}");

    // memory_store call — must be REFUSED by the seeded rule.
    let resp = send_and_recv(
        stdin,
        &rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "memory_store",
                "arguments": {
                    "title": "should-be-refused-1583",
                    "content": "this MCP write must hit the agent-action gate",
                    "tier": "long",
                    "namespace": "sec-1583-ns"
                }
            }
        }),
    );

    let blob = serde_json::to_string(&resp).unwrap();
    // The refusal surfaces either as a JSON-RPC error or as an
    // isError/refusal-shaped tool result; both carry the rule reason or
    // a governance refusal marker. Assert the write did NOT silently
    // succeed (pre-#1583 behavior) and that a governance refusal is
    // present.
    let refused = blob.contains("#1583")
        || blob.to_lowercase().contains("refus")
        || blob.to_lowercase().contains("governance");
    assert!(
        refused,
        "#1583: MCP memory_store must be refused by the seeded memory_write \
         agent-action rule (the pre-write hook must be installed on MCP); got: {blob}"
    );

    // Defense-in-depth: confirm the row did NOT land in the DB.
    let conn = db::open(&db_path).expect("reopen db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1",
            rusqlite::params!["should-be-refused-1583"],
            |r| r.get(0),
        )
        .expect("count refused rows");
    assert_eq!(
        count, 0,
        "#1583: the refused MCP write must not have persisted a row"
    );
}
