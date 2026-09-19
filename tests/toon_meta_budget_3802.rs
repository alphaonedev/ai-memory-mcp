// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3802: a budget-truncated `memory_recall` must be distinguishable from
//! a small result on the DEFAULT MCP wire format (`toon_compact`).
//!
//! Before the fix the TOON meta line rendered only
//! `count|mode|tokens_used|budget_tokens` and discarded the nested `meta`
//! budget block, so `count:1` could mean "one matched" or "five matched,
//! four withheld for budget" and the agent had no way to tell. The JSON
//! twin of the identical call always reported `memories_dropped`.
//!
//! Cells:
//!   * RED on the untouched tip — a truncated recall carries
//!     `memories_dropped:<n>` (n >= 1) and `budget_overflow:` on the
//!     meta line in BOTH `toon_compact` and `toon`, with the SAME `n`
//!     the JSON twin reports (presence + agreement on one sink).
//!   * control — an untruncated recall under a generous budget carries
//!     `memories_dropped:0` (absence of truncation is stated, not
//!     implied).
//!   * control — a recall with no budget carries no budget keys at all
//!     (the pre-#3802 line, byte for byte).
//!
//! The MCP child runs at `--tier keyword` so no embedder is loaded; the
//! budget is applied to the FTS result set, which is the shape the
//! Conductor's audit measured.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};

use ai_memory::models::{Memory, Tier};
use serde_json::{Value, json};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const NS: &str = "toon3802";
const NEEDLE: &str = "budgetproof3802";
const SEEDED: usize = 5;
/// Small enough that one ~190-char body fits and the rest are withheld.
const TIGHT_BUDGET: u64 = 60;
/// Large enough that every seeded body fits.
const GENEROUS_BUDGET: u64 = 10_000;

struct Fixture {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture directory");
        let path = dir.path().join("memory.db");
        let conn = ai_memory::db::open(&path).expect("fixture database");
        for i in 0..SEEDED {
            let now = chrono::Utc::now().to_rfc3339();
            let body = format!(
                "{NEEDLE} row {i}: {}",
                "the quick brown fox jumps over the lazy dog and keeps running across the field "
                    .repeat(2)
            );
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("{NEEDLE}-{i}"),
                content: body,
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
        let response = mcp.request(&json!({"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"toon3802","version":"1"}}}));
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
            let line = mcp_wait::recv_mcp_response(&self.output, "toon3802");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    /// The raw `content[0].text` of a successful tool call — TOON or JSON,
    /// whatever the `format` argument selected.
    fn call_text(&mut self, tool: &str, arguments: &Value) -> String {
        let response = self.request(&json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":tool,"arguments":arguments}}));
        assert!(
            response.get("error").is_none() && response["result"]["isError"] != true,
            "tool failed: {response}"
        );
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text")
            .to_string()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn recall_args(budget_tokens: Option<u64>, format: &str) -> Value {
    let mut args = json!({
        "context": NEEDLE,
        "namespace": NS,
        "limit": 10,
        "format": format,
    });
    if let Some(budget) = budget_tokens {
        args["budget_tokens"] = json!(budget);
    }
    args
}

/// `key:value` pairs of the TOON meta line (the first line).
fn meta_pairs(toon: &str) -> Vec<(String, String)> {
    toon.lines()
        .next()
        .unwrap_or_default()
        .split('|')
        .map(|pair| {
            let (k, v) = pair.split_once(':').expect("meta pair");
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn meta_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[test]
fn budget_truncated_recall_states_memories_dropped_on_the_toon_meta_line() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);

    // The JSON twin is the reference: it has always carried the verdict.
    let json_twin: Value = serde_json::from_str(
        &mcp.call_text("memory_recall", &recall_args(Some(TIGHT_BUDGET), "json")),
    )
    .expect("json recall");
    let dropped = json_twin["meta"]["memories_dropped"]
        .as_u64()
        .expect("json twin reports memories_dropped");
    let overflow = json_twin["meta"]["budget_overflow"]
        .as_bool()
        .expect("json twin reports budget_overflow");
    let remaining = json_twin["meta"]["budget_tokens_remaining"]
        .as_u64()
        .expect("json twin reports budget_tokens_remaining");
    assert!(
        dropped >= 1,
        "the tight budget must withhold at least one of {SEEDED} seeded rows: {json_twin}"
    );

    for format in ["toon_compact", "toon"] {
        let toon = mcp.call_text("memory_recall", &recall_args(Some(TIGHT_BUDGET), format));
        let pairs = meta_pairs(&toon);
        assert_eq!(
            meta_value(&pairs, "memories_dropped"),
            Some(dropped.to_string().as_str()),
            "{format}: the meta line must state the SAME memories_dropped the JSON twin reports\n{toon}"
        );
        assert_eq!(
            meta_value(&pairs, "budget_overflow"),
            Some(overflow.to_string().as_str()),
            "{format}: budget_overflow missing from the meta line\n{toon}"
        );
        assert_eq!(
            meta_value(&pairs, "budget_tokens_remaining"),
            Some(remaining.to_string().as_str()),
            "{format}: budget_tokens_remaining missing from the meta line\n{toon}"
        );
        assert_eq!(
            meta_value(&pairs, "budget_tokens"),
            Some(TIGHT_BUDGET.to_string().as_str()),
            "{format}: the pre-#3802 budget_tokens key must survive\n{toon}"
        );
    }
}

#[test]
fn untruncated_recall_states_memories_dropped_zero() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);

    let toon = mcp.call_text(
        "memory_recall",
        &recall_args(Some(GENEROUS_BUDGET), "toon_compact"),
    );
    let pairs = meta_pairs(&toon);
    assert_eq!(
        meta_value(&pairs, "count"),
        Some(SEEDED.to_string().as_str()),
        "every seeded row fits the generous budget\n{toon}"
    );
    assert_eq!(
        meta_value(&pairs, "memories_dropped"),
        Some("0"),
        "an untruncated budgeted recall must SAY nothing was dropped\n{toon}"
    );
    assert_eq!(
        meta_value(&pairs, "budget_overflow"),
        Some("false"),
        "{toon}"
    );
}

#[test]
fn recall_without_a_budget_carries_no_budget_keys() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture);

    let toon = mcp.call_text("memory_recall", &recall_args(None, "toon_compact"));
    let pairs = meta_pairs(&toon);
    for key in [
        "budget_tokens",
        "memories_dropped",
        "budget_overflow",
        "budget_tokens_remaining",
    ] {
        assert_eq!(
            meta_value(&pairs, key),
            None,
            "no budget was supplied, so `{key}` must not appear\n{toon}"
        );
    }
    assert_eq!(
        meta_value(&pairs, "count"),
        Some(SEEDED.to_string().as_str()),
        "{toon}"
    );
}
