// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3393 — `memory_capture_turn` over MCP stdio stamps the RESOLVED caller
//! identity, never the raw `initialize.clientInfo.name`.
//!
//! Both tests FAIL on the pre-#3393 head: there the dispatcher handed the tool
//! the raw handshake string, so the row was attributed to `claude-code`
//! (no `ai:` prefix, no hostname, `AI_MEMORY_AGENT_ID` ignored) and the tool
//! envelope carried no `agent_id`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const CLIENT_NAME: &str = "claude-code";
const ENV_OWNER: &str = "ai:env-owner";

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
}

impl Mcp {
    fn start(db: &Path, key_dir: &Path, env_agent_id: Option<&str>) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_DB", db)
            .env("AI_MEMORY_KEY_DIR", key_dir)
            .env("HOME", key_dir.parent().expect("sandbox root").join("home"))
            .env(
                "XDG_CONFIG_HOME",
                key_dir.parent().expect("sandbox root").join("config"),
            )
            .args([
                "--db",
                db.to_str().expect("utf-8 db path"),
                "mcp",
                "--profile",
                "full",
                "--tier",
                "keyword",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(id) = env_agent_id {
            cmd.env("AI_MEMORY_AGENT_ID", id);
        }
        let mut child = cmd.spawn().expect("spawn ai-memory mcp");
        let input = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Self {
            child,
            input,
            output,
        };
        let response = mcp.request(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": "1"}
            }
        }));
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, request: &Value) -> Value {
        writeln!(self.input, "{request}").expect("MCP request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "capture_turn_identity_3393");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    fn call(&mut self, id: u64, tool: &str, arguments: &Value) -> Value {
        let response = self.request(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        }));
        assert!(
            response.get("error").is_none() && response["result"]["isError"] != true,
            "tool failed: {response}"
        );
        serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("tool text"),
        )
        .expect("tool JSON")
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sandbox() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).expect("key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let db = dir.path().join("memory.db");
    (dir, db, keys)
}

fn capture_and_read_back(mcp: &mut Mcp, turn: u64) -> (Value, Value) {
    let captured = mcp.call(
        10 + turn,
        "memory_capture_turn",
        &json!({
            "host_session_id": "session-3393",
            "host_turn_index": turn,
            "role": "user",
            "content": format!("identity probe turn {turn}")
        }),
    );
    let memory_id = captured["memory_id"]
        .as_str()
        .expect("memory_id")
        .to_string();
    let fetched = mcp.call(20 + turn, "memory_get", &json!({"id": memory_id}));
    (captured, fetched)
}

fn stored_agent_id(fetched: &Value) -> String {
    // `memory_get` returns the row (optionally wrapped); find the metadata.
    let meta = fetched
        .get("metadata")
        .or_else(|| fetched.get("memory").and_then(|m| m.get("metadata")))
        .expect("metadata in memory_get response");
    meta["agent_id"]
        .as_str()
        .expect("metadata.agent_id")
        .to_string()
}

/// `AI_MEMORY_AGENT_ID` wins over the handshake name, end to end.
/// FAILS ON HEAD: the row is attributed to `claude-code`.
#[test]
fn capture_turn_uses_env_identity_over_client_info_3393() {
    let (_dir, db, keys) = sandbox();
    let mut mcp = Mcp::start(&db, &keys, Some(ENV_OWNER));
    let (captured, fetched) = capture_and_read_back(&mut mcp, 0);
    assert_eq!(captured["agent_id"].as_str(), Some(ENV_OWNER), "{captured}");
    assert_eq!(stored_agent_id(&fetched), ENV_OWNER, "{fetched}");
}

/// With no configured identity the handshake name is only a validated,
/// `ai:`-prefixed durable derivation. FAILS ON HEAD: raw `claude-code`.
#[test]
fn capture_turn_client_info_fallback_is_prefixed_and_valid_3393() {
    let (_dir, db, keys) = sandbox();
    let mut mcp = Mcp::start(&db, &keys, None);
    let (captured, fetched) = capture_and_read_back(&mut mcp, 1);
    let stamped = stored_agent_id(&fetched);
    assert!(stamped.starts_with("ai:claude-code@"), "{stamped}");
    assert_ne!(stamped, CLIENT_NAME);
    ai_memory::validate::validate_agent_id(&stamped).expect("derived id is valid");
    assert_eq!(
        captured["agent_id"].as_str(),
        Some(stamped.as_str()),
        "{captured}"
    );
}
