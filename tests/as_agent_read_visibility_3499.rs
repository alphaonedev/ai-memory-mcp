// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3499: a scope position narrows reads but never selects a caller identity.
//! CLI and MCP run in child processes so caller identities never mutate this
//! test process's environment. HTTP uses explicit request headers on both stores.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};

use ai_memory::models::{Memory, Tier};
use serde_json::{Value, json};

#[cfg(feature = "sal")]
#[path = "as_agent_read_visibility_3499/http.rs"]
mod http;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
const TEAM_AGENT: &str = "org/unit/team/alice";
const NS: &str = "scope3499";
const TEAM_NS: &str = "org/unit/team";
const INBOX: &str = "_messages/ai:alice";
const NEEDLE: &str = "scopeproof3499";
const URI: &str = "doc:scope3499";

struct Fixture {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    memories: Vec<Memory>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture directory");
        let path = dir.path().join("memory.db");
        let conn = ai_memory::db::open(&path).expect("fixture database");
        let mut memories = Vec::new();
        for (title, namespace, metadata) in [
            ("alice", NS, json!({"agent_id": ALICE})),
            ("bob", NS, json!({"agent_id": BOB})),
            (
                "public",
                NS,
                json!({"agent_id": ALICE, "scope": "collective"}),
            ),
            (
                "inbox",
                INBOX,
                json!({"agent_id": "ai:sender", "target_agent_id": ALICE}),
            ),
            (
                "team",
                TEAM_NS,
                json!({"agent_id": TEAM_AGENT, "scope": "team"}),
            ),
            (
                "team-root",
                TEAM_NS,
                json!({"agent_id": TEAM_AGENT, "scope": "collective"}),
            ),
            (
                "registry",
                "_agents",
                json!({"agent_id": ALICE, "scope": "collective"}),
            ),
        ] {
            let now = chrono::Utc::now().to_rfc3339();
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: title.to_string(),
                content: NEEDLE.to_string(),
                namespace: namespace.to_string(),
                tier: Tier::Long,
                metadata,
                source_uri: Some(URI.to_string()),
                created_at: now.clone(),
                updated_at: now,
                ..Memory::default()
            };
            ai_memory::db::insert(&conn, &mem).expect("seed memory");
            memories.push(mem);
        }
        Self {
            dir,
            path,
            memories,
        }
    }

    fn command(&self, caller: Option<&str>) -> Command {
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
        if let Some(caller) = caller {
            cmd.env("AI_MEMORY_AGENT_ID", caller);
        }
        cmd
    }

    fn id(&self, title: &str) -> &str {
        &self
            .memories
            .iter()
            .find(|mem| mem.title == title)
            .expect("fixture row")
            .id
    }
}

fn titles(response: &Value) -> Vec<String> {
    let rows = response["memories"]
        .as_array()
        .or_else(|| response["results"].as_array())
        .expect("result array");
    let mut titles: Vec<_> = rows
        .iter()
        .map(|row| row["title"].as_str().expect("title").to_string())
        .collect();
    titles.sort();
    titles
}

struct ReadCase {
    caller: Option<&'static str>,
    scope: Option<&'static str>,
    namespace: &'static str,
    expected: Vec<&'static str>,
}

fn cases() -> Vec<ReadCase> {
    vec![
        (None, None, NS, vec!["alice", "bob", "public"]),
        (None, Some(ALICE), NS, vec!["public"]),
        (None, Some(ALICE), INBOX, vec![]),
        (None, None, INBOX, vec!["inbox"]),
        (Some(ALICE), Some(ALICE), NS, vec!["alice", "public"]),
        (Some(ALICE), Some(BOB), NS, vec!["alice", "public"]),
        (Some(BOB), Some(ALICE), INBOX, vec![]),
        (Some(ALICE), Some(ALICE), INBOX, vec!["inbox"]),
        (
            Some(TEAM_AGENT),
            Some(TEAM_AGENT),
            TEAM_NS,
            vec!["team", "team-root"],
        ),
        (
            Some(TEAM_AGENT),
            Some("outside/unit/team/agent"),
            TEAM_NS,
            vec!["team-root"],
        ),
    ]
    .into_iter()
    .map(|(caller, scope, namespace, expected)| ReadCase {
        caller,
        scope,
        namespace,
        expected,
    })
    .collect()
}

#[test]
fn cli_recall_and_search_narrow_without_impersonation() {
    let fixture = Fixture::new();
    for ReadCase {
        caller,
        scope,
        namespace,
        expected,
    } in cases()
    {
        for verb in ["recall", "search"] {
            let mut cmd = fixture.command(caller);
            cmd.args(["--json", verb, NEEDLE, "--namespace", namespace]);
            // CLI search also has an exact AUTHOR filter sharing the global
            // agent_id argument. Name the sender so that independent filter
            // does not discard recipient-owned inbox mail before admission.
            if verb == "search" && namespace == INBOX {
                cmd.args(["--agent-id", "ai:sender"]);
            }
            if let Some(scope) = scope {
                cmd.args(["--as-agent", scope]);
            }
            let out = cmd.output().expect("CLI read");
            assert!(out.status.success(), "{verb} {caller:?} {scope:?}: {out:?}");
            let response: Value = serde_json::from_slice(&out.stdout).expect("CLI JSON");
            for row in response["memories"]
                .as_array()
                .or_else(|| response["results"].as_array())
                .expect("rows")
            {
                assert_eq!(row["id"], fixture.id(row["title"].as_str().expect("title")));
            }
            assert_eq!(
                titles(&response),
                expected,
                "{verb} {caller:?} {scope:?}: {response}"
            );
        }
    }
}

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
}

impl Mcp {
    fn start(fixture: &Fixture, caller: Option<&str>) -> Self {
        let mut child = fixture
            .command(caller)
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
        };
        let response = mcp.request(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"scope3499","version":"1"}}}));
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, request: &Value) -> Value {
        writeln!(self.input, "{request}").expect("MCP request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "scope3499");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let response = self.request(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":arguments}}));
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

#[test]
fn mcp_recall_and_both_search_paths_narrow_without_impersonation() {
    let fixture = Fixture::new();
    for caller in [None, Some(ALICE), Some(BOB), Some(TEAM_AGENT)] {
        let mut mcp = Mcp::start(&fixture, caller);
        for ReadCase {
            caller: case_caller,
            scope,
            namespace,
            expected,
        } in cases()
        {
            if case_caller != caller {
                continue;
            }
            for path in ["memory_recall", "memory_search", "source_uri"] {
                let tool = if path == "source_uri" {
                    "memory_search"
                } else {
                    path
                };
                let mut args = json!({"namespace": namespace, "format":"json", "limit":50});
                if path == "source_uri" {
                    args["source_uri"] = json!(URI);
                } else if tool == "memory_search" {
                    args["query"] = json!(NEEDLE);
                } else {
                    args["context"] = json!(NEEDLE);
                }
                if let Some(scope) = scope {
                    args["as_agent"] = json!(scope);
                }
                let response = mcp.call(tool, &args);
                assert_eq!(
                    titles(&response),
                    expected,
                    "{path} {caller:?} {scope:?}: {response}"
                );
            }
        }
    }
}
