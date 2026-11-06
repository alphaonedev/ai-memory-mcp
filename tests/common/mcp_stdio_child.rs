// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Leaf helper: drive a real `ai-memory mcp` stdio child over JSON-RPC
//! (#4059 / #4061 / #4064 / #4065 found-in-testing regressions).
//!
//! Same shape as the hand-rolled harness in `tests/mcp_format_refusal_3803.rs`,
//! factored into one `#[path]` leaf so the four suites share it. Depends only
//! on `std` + `serde_json` + `tempfile` plus the `mcp_wait` leaf (per
//! `tests/common/mcp_wait.rs`, the MCP suites deliberately do not pull the
//! heavy `tests/common/mod.rs` bag).
//!
//! ```ignore
//! #[path = "common/mcp_wait.rs"]
//! mod mcp_wait;
//! #[path = "common/mcp_stdio_child.rs"]
//! mod mcp_stdio_child;
//! ```

#![allow(dead_code)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use super::mcp_wait;

/// Hermetic `ai-memory` command against `db`, with HOME / config / key dir
/// sandboxed under `sandbox` and the ambient agent identity removed. The
/// key dir is only NAMED here (never created), so the #3733 key-dir mode
/// gate does not apply.
#[must_use]
pub fn command(sandbox: &Path, db: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("--db")
        .arg(db)
        .env("HOME", sandbox.join("home"))
        .env("XDG_CONFIG_HOME", sandbox.join("config"))
        .env("AI_MEMORY_KEY_DIR", sandbox.join("keys"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("RUST_LOG", "error")
        .env_remove("AI_MEMORY_AGENT_ID");
    cmd
}

/// Temp sandbox + database path for one test.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub db: PathBuf,
}

impl Fixture {
    #[must_use]
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture directory");
        let db = dir.path().join("memory.db");
        drop(ai_memory::db::open(&db).expect("fixture database"));
        Self { dir, db }
    }

    /// Hermetic command for this fixture.
    #[must_use]
    pub fn command(&self) -> Command {
        command(self.dir.path(), &self.db)
    }
}

/// A running `ai-memory mcp --profile full --tier keyword` child.
pub struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Mcp {
    /// Start the child bound to `agent` (`AI_MEMORY_AGENT_ID`), or with no
    /// configured identity (the local-operator posture) when `None`.
    #[must_use]
    pub fn start(fixture: &Fixture, agent: Option<&str>) -> Self {
        let mut cmd = fixture.command();
        if let Some(agent) = agent {
            cmd.env("AI_MEMORY_AGENT_ID", agent);
        }
        let mut child = cmd
            .args(["mcp", "--profile", "full", "--tier", "keyword"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("MCP child");
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
            next_id: 1,
        };
        // #6157 — the handshake asks for the server's own newest supported
        // revision (SSOT), not a hand-copied literal that drifts.
        let revision = ai_memory::mcp::jsonrpc::NEWEST_PROTOCOL_REVISION;
        let response = mcp.request(&json!({"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"fit4059","version":"1"}}}));
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    /// Send one request (its `id` is assigned here) and return the matching
    /// response.
    pub fn request(&mut self, request: &Value) -> Value {
        let mut request = request.clone();
        request["id"] = json!(self.next_id);
        self.next_id += 1;
        writeln!(self.input, "{request}").expect("MCP request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "fit4059-4065");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    /// The `result` object of a `tools/call`; a protocol-level error is a
    /// test failure, a handler refusal rides `isError`.
    pub fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let response = self.request(&json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":tool,"arguments":arguments}}));
        assert!(
            response.get("error").is_none(),
            "protocol error for {tool}: {response}"
        );
        response["result"].clone()
    }

    /// `call` that must succeed; returns the parsed JSON body of the text
    /// content (`format: json` is forced so the body is machine-readable).
    pub fn call_ok(&mut self, tool: &str, arguments: &Value) -> Value {
        let result = self.call(tool, arguments);
        assert_ne!(result["isError"], true, "{tool} refused: {result}");
        let text = Self::text(&result);
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
    }

    /// The first text content block of a tool result.
    #[must_use]
    pub fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().expect("tool text")
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
