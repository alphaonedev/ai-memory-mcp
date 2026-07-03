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
fn spawn_mcp(db_path: &std::path::Path) -> (McpChild, mpsc::Receiver<String>) {
    permissive_attestation_for_tests();
    // Hermetic key-dir isolation. `resolve_operator_pubkey()` searches the
    // default key dir (and `AI_MEMORY_KEY_DIR`), so on an operator's own
    // host — where the real `operator.key.pub` lives at the default path —
    // the L1-6 matrix flips: an `enabled = 1` but UNSIGNED governance rule
    // (what this test seeds) is correctly dropped as misconfiguration once
    // a verifying key is present, and the write is no longer refused. CI
    // has no operator key so it stays in pre-L1-6 mode and the rule fires;
    // the host leak made this test pass in CI but fail on the dev box.
    // Point `AI_MEMORY_KEY_DIR` at an EMPTY project-local dir so the test
    // is pre-L1-6 (no operator key) regardless of host, which is the mode
    // that proves the hook is installed: the unsigned rule enforces.
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
    // Assert the STRUCTURED refusal shape, not a loose substring of the
    // whole blob: a successful store echoes the request `title` back, and
    // a title containing "refus" (as ours does) would satisfy a naive
    // `blob.contains("refus")`, masking a non-refused write. The refusal
    // surfaces as a tool result with `isError = true` whose text carries
    // the `GOVERNANCE_REFUSED` marker (or as a JSON-RPC `error`); a
    // success has neither.
    let is_error = resp
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    let jsonrpc_error = resp.get("error").is_some();
    let carries_refusal_marker = blob.contains("GOVERNANCE_REFUSED");
    let refused = (is_error || jsonrpc_error) && carries_refusal_marker;
    assert!(
        refused,
        "#1583: MCP memory_store must be refused by the seeded memory_write \
         agent-action rule (the pre-write hook must be installed on MCP, and \
         the test must run pre-L1-6 with no operator key so the unsigned rule \
         enforces); got: {blob}"
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
