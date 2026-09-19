// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3803: the MCP `format` argument of the four TOON-rendering tools is an
//! enum, not a free string. Before the fix the dispatch matched four exact
//! literals and every other value fell through to pretty JSON — so
//! `format:"TOON_COMPACT"` (wrong case) silently cost 10.7x the tokens of
//! the default on every call and the caller was never told the parameter
//! was ignored, while the HTTP surface refused the same value with 400.
//!
//! Cells (each drives a real `ai-memory mcp` child, `--tier keyword`):
//!   * RED on the untouched tip — `format:"TOON_COMPACT"` on each of
//!     `memory_recall` / `memory_list` / `memory_search` /
//!     `memory_session_start` is refused with `isError: true` and the SSOT
//!     `invalid_format_msg` text (the same sentence HTTP returns), and a
//!     non-string `format` is refused the same way.
//!   * allowed path — `toon_compact`, `toon` and `json` still render, and an
//!     omitted `format` still defaults to `toon_compact`.
//!   * scope — `memory_export_reflection` keeps its own `md|json|yaml`
//!     vocabulary: `format:"md"` there is NOT refused by the rendering-format
//!     gate (its own handler decides).

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};

use ai_memory::models::{Memory, Tier};
use ai_memory::toon::invalid_format_msg;
use serde_json::{Value, json};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const NS: &str = "fmt3803";
const NEEDLE: &str = "formatproof3803";
const RENDERING_TOOLS: [&str; 4] = [
    "memory_recall",
    "memory_list",
    "memory_search",
    "memory_session_start",
];

struct Fixture {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture directory");
        let path = dir.path().join("memory.db");
        let conn = ai_memory::db::open(&path).expect("fixture database");
        for i in 0..3 {
            let now = chrono::Utc::now().to_rfc3339();
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("{NEEDLE}-{i}"),
                content: format!("{NEEDLE} body {i}"),
                namespace: NS.to_string(),
                tier: Tier::Long,
                metadata: json!({"agent_id": "ai:seeder"}),
                created_at: now.clone(),
                updated_at: now,
                ..Memory::default()
            };
            ai_memory::db::insert(&conn, &mem).expect("seed memory");
        }
        Self { dir, path }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.arg("--db")
            .arg(&self.path)
            .env("HOME", self.dir.path().join("home"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("AI_MEMORY_KEY_DIR", self.dir.path().join("keys"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_EMBED_OFFLINE", "1")
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .env("RUST_LOG", "error")
            .env_remove("AI_MEMORY_AGENT_ID");
        cmd
    }
}

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Mcp {
    fn start(fixture: &Fixture) -> Self {
        let mut child = fixture
            .command()
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
        let response = mcp.request(&json!({"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fmt3803","version":"1"}}}));
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, request: &Value) -> Value {
        let mut request = request.clone();
        request["id"] = json!(self.next_id);
        self.next_id += 1;
        writeln!(self.input, "{request}").expect("MCP request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "fmt3803");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    /// The tool `result` object of a `tools/call` — protocol-level errors
    /// are a test failure; handler-level refusals ride `isError`.
    fn call_result(&mut self, tool: &str, arguments: &Value) -> Value {
        let response = self.request(&json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":tool,"arguments":arguments}}));
        assert!(
            response.get("error").is_none(),
            "protocol error for {tool}: {response}"
        );
        response["result"].clone()
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().expect("tool text")
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn args(tool: &str, format: Option<Value>) -> Value {
    let mut args = match tool {
        "memory_recall" => json!({"context": NEEDLE, "namespace": NS, "limit": 10}),
        "memory_search" => json!({"query": NEEDLE, "namespace": NS, "limit": 10}),
        // One arm on purpose, not a collapsed placeholder: the subject under
        // test is the `format` argument, and these two list-shaped tools take
        // the same minimal valid payload (`namespace` + `limit` — see
        // `session_start.rs`, which reads exactly those). Pedantic
        // `match_same_arms` would otherwise read the duplicate as intent.
        "memory_list" | "memory_session_start" => json!({"namespace": NS, "limit": 10}),
        other => unreachable!("not a rendering tool: {other}"),
    };
    if let Some(format) = format {
        args["format"] = format;
    }
    args
}

#[test]
fn wrong_case_format_is_refused_with_the_ssot_message_on_every_rendering_tool() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);
    for tool in RENDERING_TOOLS {
        let result = mcp.call_result(tool, &args(tool, Some(json!("TOON_COMPACT"))));
        assert_eq!(
            result["isError"], true,
            "{tool}: a wrong-case format must be a typed refusal, not a silent fall-through to JSON: {result}"
        );
        assert_eq!(
            Mcp::text(&result),
            invalid_format_msg("TOON_COMPACT"),
            "{tool}: the refusal must be the SAME sentence HTTP returns"
        );
    }
}

#[test]
fn non_string_format_is_refused_not_silently_defaulted() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);
    let result = mcp.call_result("memory_recall", &args("memory_recall", Some(json!(7))));
    assert_eq!(result["isError"], true, "{result}");
    assert!(Mcp::text(&result).starts_with("invalid format"), "{result}");
}

#[test]
fn allowed_formats_still_render_and_the_default_is_toon_compact() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);
    for tool in RENDERING_TOOLS {
        // Omitted → toon_compact (the MCP default, unchanged).
        let result = mcp.call_result(tool, &args(tool, None));
        assert_ne!(result["isError"], true, "{tool} default: {result}");
        let default_text = Mcp::text(&result).to_string();
        assert!(
            default_text.starts_with("count:"),
            "{tool}: the default must render TOON\n{default_text}"
        );

        let result = mcp.call_result(tool, &args(tool, Some(json!("toon_compact"))));
        assert_ne!(result["isError"], true, "{tool} toon_compact: {result}");
        assert_eq!(
            Mcp::text(&result),
            default_text,
            "{tool}: explicit toon_compact == default"
        );

        let result = mcp.call_result(tool, &args(tool, Some(json!("toon"))));
        assert_ne!(result["isError"], true, "{tool} toon: {result}");
        assert!(
            Mcp::text(&result).starts_with("count:"),
            "{tool} toon: {result}"
        );

        let result = mcp.call_result(tool, &args(tool, Some(json!("json"))));
        assert_ne!(result["isError"], true, "{tool} json: {result}");
        let parsed: Value = serde_json::from_str(Mcp::text(&result)).expect("json renders JSON");
        assert!(parsed.is_object(), "{tool} json: {parsed}");
    }
}

#[test]
fn export_reflection_keeps_its_own_format_vocabulary() {
    // `memory_export_reflection` takes `format: md|json|yaml`; the rendering
    // gate must not swallow it. A missing reflection is that handler's own
    // error, which must NOT be the rendering-format refusal.
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);
    let result = mcp.call_result(
        "memory_export_reflection",
        &json!({"memory_id": uuid::Uuid::new_v4().to_string(), "format": "md"}),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        !Mcp::text(&result).starts_with("invalid format"),
        "the rendering-format gate must not gate export_reflection's md|json|yaml: {result}"
    );
}
