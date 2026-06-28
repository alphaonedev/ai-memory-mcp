// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W1 / gap G29 — end-to-end credential write-path screen.
//!
//! Spawns the real `ai-memory mcp` subprocess (the prime-directive pm-v3.3
//! fresh-subprocess probe) under each `AI_MEMORY_SECRET_SCREEN_MODE` and
//! drives `memory_store` to prove the acceptance contract:
//!
//! * **(a) refuse** — under the default `refuse` mode each credential pattern
//!   is rejected on `memory_store` (no row persists). Also exercised on the
//!   CLI `store` surface.
//! * **(b) redact** — under `redact` the row persists with the credential
//!   span masked.
//! * **(c) off** — under `off` the content is byte-identical to pre-W1.
//! * **(d) no false positive** — a benign high-entropy string (UUID / base64
//!   blob) is NOT refused under `refuse`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::db;

const READ_TIMEOUT: Duration = Duration::from_secs(20);
// A realistic-looking but non-live OpenAI-style key (high entropy, sk- prefix).
const FAKE_OPENAI_KEY: &str = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56";
const REDACTION_MARKER: &str = "[REDACTED:secret]";

struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}
impl Drop for McpChild {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn root() -> std::path::PathBuf {
    let r = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1821-secret-screen-g29");
    std::fs::create_dir_all(&r).ok();
    r
}
fn unique_db() -> std::path::PathBuf {
    root().join(format!("mcp-{}.db", uuid::Uuid::new_v4()))
}

fn spawn_mcp(db_path: &std::path::Path, mode: &str) -> (McpChild, mpsc::Receiver<String>) {
    let key_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&key_dir).ok();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &key_dir)
        .env("AI_MEMORY_SECRET_SCREEN_MODE", mode)
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
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    (
        McpChild {
            child: Some(child),
            stdin: Some(stdin),
        },
        rx,
    )
}

fn send_and_recv(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    payload: &serde_json::Value,
) -> serde_json::Value {
    writeln!(stdin, "{}", serde_json::to_string(payload).unwrap()).unwrap();
    stdin.flush().unwrap();
    let resp = rx.recv_timeout(READ_TIMEOUT).expect("mcp response timeout");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse: {e}: {resp}"))
}

fn initialize(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>) {
    let init = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"g29-test","version":"0"}}
        }),
    );
    assert!(init.get("result").is_some(), "init failed: {init}");
}

fn store(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    title: &str,
    content: &str,
) -> serde_json::Value {
    send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"memory_store","arguments":{
                "title":title,"content":content,"tier":"long","namespace":"g29-ns"}}
        }),
    )
}

fn is_error(resp: &serde_json::Value) -> bool {
    resp.get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        || resp.get("error").is_some()
}

fn stored_content(db_path: &std::path::Path, title: &str) -> Option<String> {
    let conn = db::open(db_path).expect("reopen db");
    conn.query_row(
        "SELECT content FROM memories WHERE title = ?1",
        rusqlite::params![title],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// (a) Under the default `refuse` mode, each credential pattern is refused on
/// `memory_store` and no row persists.
#[test]
fn mcp_store_refuses_credentials_under_refuse_g29() {
    let cases = [
        ("g29-openai", FAKE_OPENAI_KEY),
        ("g29-aws", "creds AKIAIOSFODNN7EXAMPLE here"),
        (
            "g29-pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBODY+lines/data\n-----END RSA PRIVATE KEY-----",
        ),
        ("g29-ghp", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ];
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "refuse");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    for (title, content) in cases {
        let resp = store(stdin, &rx, title, content);
        let blob = serde_json::to_string(&resp).unwrap();
        assert!(
            is_error(&resp) && blob.contains("credential material"),
            "G29: {title} must be REFUSED under default refuse; got: {blob}"
        );
        assert!(
            stored_content(&db_path, title).is_none(),
            "G29: refused write {title} must not persist a row"
        );
    }
}

/// (d) A benign high-entropy string (no credential prefix) is NOT refused.
#[test]
fn mcp_store_allows_benign_high_entropy_under_refuse_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "refuse");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let benign = "uuid 550e8400-e29b-41d4-a716-446655440000 sha aa03bc84 blob \
                  iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    let resp = store(stdin, &rx, "g29-benign", benign);
    assert!(
        !is_error(&resp),
        "G29: benign high-entropy content must NOT be refused; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    assert_eq!(
        stored_content(&db_path, "g29-benign").as_deref(),
        Some(benign),
        "G29: benign content must persist verbatim"
    );
}

/// (b) Under `redact`, a credential write persists with the span masked.
#[test]
fn mcp_store_redacts_under_redact_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "redact");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let resp = store(
        stdin,
        &rx,
        "g29-redact",
        &format!("key is {FAKE_OPENAI_KEY} ok"),
    );
    assert!(
        !is_error(&resp),
        "G29 redact: store must succeed; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    let stored = stored_content(&db_path, "g29-redact").expect("row must persist under redact");
    assert!(
        stored.contains(REDACTION_MARKER) && !stored.contains(FAKE_OPENAI_KEY),
        "G29 redact: the credential must be masked; stored = {stored:?}"
    );
}

/// (c) Under `off`, the content is byte-identical to pre-W1 (verbatim).
#[test]
fn mcp_store_verbatim_under_off_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "off");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let content = format!("key is {FAKE_OPENAI_KEY} ok");
    let resp = store(stdin, &rx, "g29-off", &content);
    assert!(!is_error(&resp), "G29 off: store must succeed");
    assert_eq!(
        stored_content(&db_path, "g29-off").as_deref(),
        Some(content.as_str()),
        "G29 off: content must persist byte-identical (no screening)"
    );
}

/// (a, CLI surface) `ai-memory store` refuses a credential under `refuse`.
#[test]
fn cli_store_refuses_credential_under_refuse_g29() {
    let db_path = unique_db();
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_SECRET_SCREEN_MODE", "refuse")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "store",
            "--title",
            "g29-cli",
            "--content",
            FAKE_OPENAI_KEY,
        ])
        .output()
        .expect("run ai-memory store");
    assert!(
        !out.status.success(),
        "G29 CLI: store of a credential must fail under refuse"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("credential material"),
        "G29 CLI: error must name the credential screen; got stderr: {stderr}"
    );
    assert!(
        stored_content(&db_path, "g29-cli").is_none(),
        "G29 CLI: refused write must not persist"
    );
}
