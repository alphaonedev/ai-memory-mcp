// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3551: transport caller admission covers the reflection and every source.
//! MCP identities are isolated in child processes, never process-global mutations.
use ai_memory::models::{Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use serde_json::{Value, json};
use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};
#[cfg(feature = "sal")]
mod http;
#[path = "../common/mcp_wait.rs"]
mod mcp_wait;

const ALICE: &str = "ai:alice3551";
const BOB: &str = "ai:bob3551";
#[cfg(feature = "sal")]
const ADMIN: &str = "ai:admin3551";
const NS: &str = "reflection3551";
const SECRET: &str = "private-source-secret-3551";

struct Fixture {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    memories: Vec<Memory>,
    links: Vec<MemoryLink>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture");
        let path = dir.path().join("memory.db");
        let conn = ai_memory::db::open(&path).expect("fixture database");
        let mut memories = Vec::new();
        for (title, kind, scope, namespace) in [
            ("source", MemoryKind::Observation, "private", NS),
            ("private", MemoryKind::Reflection, "private", NS),
            ("shared", MemoryKind::Reflection, "collective", NS),
            ("missing-source", MemoryKind::Reflection, "collective", NS),
            (
                "substrate",
                MemoryKind::Observation,
                "collective",
                "_agents",
            ),
            ("substrate-source", MemoryKind::Reflection, "collective", NS),
        ] {
            let now = chrono::Utc::now().to_rfc3339();
            let memory = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: title.to_string(),
                content: SECRET.to_string(),
                namespace: namespace.to_string(),
                tier: Tier::Long,
                metadata: json!({"agent_id": ALICE, "scope":scope}),
                memory_kind: kind,
                reflection_depth: i32::from(kind == MemoryKind::Reflection),
                created_at: now.clone(),
                updated_at: now,
                ..Memory::default()
            };
            ai_memory::db::insert(&conn, &memory).expect("seed memory");
            memories.push(memory);
        }
        let mut f = Self {
            dir,
            path,
            memories,
            links: Vec::new(),
        };
        for (source, target) in [
            ("private", "source"),
            ("shared", "source"),
            ("substrate-source", "substrate"),
        ] {
            let link = MemoryLink {
                source_id: f.id(source).to_string(),
                target_id: f.id(target).to_string(),
                relation: MemoryLinkRelation::ReflectsOn,
                created_at: chrono::Utc::now().to_rfc3339(),
                signature: None,
                observed_by: Some(ALICE.to_string()),
                valid_from: None,
                valid_until: None,
                attest_level: None,
                source_cid: None,
                target_cid: None,
            };
            ai_memory::db::create_link_inbound(&conn, &link, "unsigned").expect("seed lineage");
            f.links.push(link);
        }
        // A dangling provenance edge models a source removed after reflection.
        conn.pragma_update(None, "foreign_keys", false)
            .expect("fixture foreign keys");
        conn.execute("INSERT INTO memory_links (source_id, target_id, relation, created_at) VALUES (?1, ?2, 'reflects_on', ?3)",
            rusqlite::params![f.id("missing-source"), uuid::Uuid::new_v4().to_string(), chrono::Utc::now().to_rfc3339()]).expect("dangling source");
        f
    }
    fn id(&self, title: &str) -> &str {
        &self
            .memories
            .iter()
            .find(|memory| memory.title == title)
            .expect("fixture row")
            .id
    }
    fn command(&self, caller: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        command
            .arg("--db")
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
            command.env("AI_MEMORY_AGENT_ID", caller);
        }
        command
    }
    fn snapshot(&self) -> Vec<u8> {
        let conn = ai_memory::db::open(&self.path).expect("snapshot database");
        snapshot(&conn)
    }
}

fn snapshot(conn: &rusqlite::Connection) -> Vec<u8> {
    // Includes signed bundles, resources and audit/event records as well as source rows.
    let mut result = Vec::new();
    for table in [
        "memories",
        "memory_links",
        "skills",
        "skill_resources",
        "signed_events",
    ] {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("snapshot table");
        let width = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..width)
                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("snapshot rows");
        for row in rows {
            result.extend_from_slice(
                format!("{table}:{:?}\n", row.expect("snapshot row")).as_bytes(),
            );
        }
    }
    result
}

fn promote_args(id: &str, name: &str) -> Value {
    json!({"reflection_id":id,"skill_name":name,"skill_description":"Admitted reflection promotion."})
}

fn assert_refusal(value: &Value, id: &str) {
    assert_eq!(
        value,
        &json!({"error":format!("reflection not found: {id}")}),
        "hidden and missing share one envelope"
    );
    assert!(!value.to_string().contains(SECRET));
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
        let response = mcp.request(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"reflection3551","version":"1"}}}));
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, request: &Value) -> Value {
        writeln!(self.input, "{request}").expect("MCP request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "reflection3551");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let response = self.request(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":arguments}}));
        if response["result"]["isError"] == true {
            return json!({"error": response["result"]["content"][0]["text"]});
        }
        assert!(response.get("error").is_none(), "RPC failure: {response}");
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
fn mcp_export_and_promotion_refuse_foreign_reflections_and_sources_without_writes() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture, Some(BOB));
    for name in ["private", "shared", "missing-source", "substrate-source"] {
        let id = fixture.id(name);
        let before = fixture.snapshot();
        for format in ["md", "json"] {
            assert_refusal(
                &mcp.call(
                    "memory_export_reflection",
                    &json!({"memory_id":id,"format":format}),
                ),
                id,
            );
        }
        assert_refusal(
            &mcp.call(
                "memory_skill_promote_from_reflection",
                &promote_args(id, "refused-3551"),
            ),
            id,
        );
        assert_eq!(
            fixture.snapshot(),
            before,
            "refusal changed durable state: {name}"
        );
    }
}

#[test]
fn mcp_owner_exports_and_promotes_private_sources() {
    let fixture = Fixture::new();
    let mut mcp = Mcp::start(&fixture, Some(ALICE));
    for name in ["private", "shared"] {
        let id = fixture.id(name);
        let exported = mcp.call(
            "memory_export_reflection",
            &json!({"memory_id":id,"format":"json"}),
        );
        assert!(
            exported["content"]
                .as_str()
                .expect("export content")
                .contains(SECRET)
        );
        let promoted = mcp.call(
            "memory_skill_promote_from_reflection",
            &promote_args(id, name),
        );
        assert_eq!(promoted["promoted"], true, "{promoted}");
        assert_eq!(promoted["sources_attached"], 1);
        let conn = ai_memory::db::open(&fixture.path).expect("stored skill");
        let actor: String = conn
            .query_row(
                "SELECT json_extract(metadata, '$.promoted_by') FROM skills WHERE id=?1",
                [promoted["skill_id"].as_str().expect("skill id")],
                |row| row.get(0),
            )
            .expect("attribution");
        assert_eq!(actor, ALICE);
        let resource: Vec<u8> = conn
            .query_row(
                "SELECT content_blob FROM skill_resources WHERE skill_id=?1",
                [promoted["skill_id"].as_str().expect("skill id")],
                |row| row.get(0),
            )
            .expect("resource bytes");
        let decoded = zstd::decode_all(resource.as_slice()).expect("resource decompression");
        assert!(
            String::from_utf8(decoded)
                .expect("resource text")
                .contains(SECRET)
        );
    }
}

#[test]
fn malformed_mcp_identity_refuses_before_serving_tools() {
    let fixture = Fixture::new();
    for caller in ["", "../../invalid"] {
        let output = fixture
            .command(Some(caller))
            .args(["mcp", "--tier", "keyword"])
            .stdin(Stdio::null())
            .output()
            .expect("invalid MCP startup");
        assert!(
            !output.status.success(),
            "invalid configured caller started MCP"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    }
}
