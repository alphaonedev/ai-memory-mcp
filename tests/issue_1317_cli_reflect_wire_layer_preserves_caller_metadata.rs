// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]

//! Wire-layer regression pin for issue #1317 — CLI-binary subprocess
//! parallel of PR #1316's MCP `tools/call → handle_reflect`
//! metadata-passthrough test, and sibling to
//! `tests/issue_1317_http_reflect_wire_layer_preserves_caller_metadata.rs`.
//!
//! ## Why this surface counts as the CLI test
//!
//! The CLI binary does not expose a flat `ai-memory reflect <metadata
//! json>` subcommand at v0.7.0 — the only CLI surface that reaches
//! `db::reflect` programmatically is `ai-memory curator --reflect`,
//! which synthesises its own `metadata: {}` from the cluster summary
//! (see `src/curator/reflection_pass.rs:357`) and has no operator-
//! supplied-metadata input. The CLI binary's substantive
//! `memory_reflect` surface is therefore the `ai-memory mcp` stdio
//! JSON-RPC sub-command (`src/daemon_runtime.rs::Command::Mcp`).
//!
//! That subcommand is a real CLI surface — it goes through the
//! `ai-memory` binary's process boundary, its clap-parsed subcommand
//! dispatch, the binary's stdio framing, the MCP protocol's
//! `dispatch_memory_reflect` adapter, and finally `handle_reflect`.
//! The in-process test in `tests/issue_1172_reflect_metadata_passthrough.rs::
//! mcp_handle_reflect_preserves_caller_supplied_entity_id` skips
//! every one of those layers by invoking `handle_reflect` directly as
//! a library call. This file pins the SAME invariants end-to-end
//! through the binary subprocess.
//!
//! ## Invariants pinned
//!
//! 1. **End-to-end entity-binding passthrough through the binary.**
//!    The `ai-memory mcp` subprocess processing a
//!    `tools/call memory_reflect` request with
//!    `metadata: {entity_id: "X", probe: "Y"}` produces a stored row
//!    whose `metadata` JSON column carries BOTH `entity_id = "X"` AND
//!    `probe = "Y"`, alongside the system-spliced `agent_id` +
//!    `reflection_metadata` keys.
//! 2. **PERF-8 indexed column populated.** The same call populates
//!    the `mentioned_entity_id` column with `"X"` via the
//!    `extract_mentioned_entity_id` step-1 path.
//! 3. **Back-compat.** Empty caller metadata (`{}`) still produces the
//!    canonical `{agent_id, reflection_metadata}` shape with no
//!    `entity_id` and a NULL `mentioned_entity_id` (mirrors invariant 4
//!    of `tests/issue_1172_reflect_metadata_passthrough.rs` onto the
//!    CLI subprocess path).
//!
//! ## Subprocess discipline
//!
//! Uses the same shape as `tests/mcp_integration.rs` —
//! `Command::new(env!("CARGO_BIN_EXE_ai-memory"))` so cargo wires the
//! binary built from THIS crate (not a stray brew install), with
//! `AI_MEMORY_NO_CONFIG=1` so the user's `~/.config/ai-memory/config.toml`
//! (which may set `tier=autonomous` triggering embedder / LLM init)
//! is bypassed. Each test gets a unique tempdir for the DB.
//!
//! ## Source role-categorical value
//!
//! Per the rationale in `tests/issue_1172_reflect_metadata_passthrough.rs`
//! §"On the choice of `source`": vendor-neutral role-categorical
//! `"api"` (an LLM-agnostic role any frontier-model AI NHI writing
//! through the substrate would naturally occupy).

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use chrono::Utc;
use serde_json::{Value, json};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Subprocess timing
//
// 10s mirrors `tests/mcp_integration.rs::READ_TIMEOUT`. The `initialize`
// handshake is the load-bearing latency — a cold cargo-bin spawn under
// release+thin-LTO compile pressure can run 2-3s on the first call;
// every subsequent `tools/call` is sub-100ms. 10s leaves comfortable
// headroom for both.
// ---------------------------------------------------------------------------

const READ_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FIXTURE_AGENT_ID: &str = "test-agent-1317-cli";
/// Vendor-neutral role-categorical source. See file-level docstring.
const FIXTURE_SOURCE: &str = "api";
const FIXTURE_ENTITY_ID: &str = "entity-uuid-1317-cli";
const FIXTURE_PROBE_VALUE: &str = "probe-1317-cli";

const NS_PASSTHROUGH: &str = "issue-1317-cli-pt";
const NS_BACKCOMPAT: &str = "issue-1317-cli-bc";

// ---------------------------------------------------------------------------
// MCP subprocess harness — mirrors tests/mcp_integration.rs shape.
// Kept self-contained because cargo treats each tests/*.rs as its own
// integration binary.
// ---------------------------------------------------------------------------

/// RAII guard for the MCP child. Drops kill the child so a failed
/// assertion doesn't leak the process.
struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl Drop for McpChild {
    fn drop(&mut self) {
        // Closing stdin ends the MCP server's read loop cleanly.
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `ai-memory mcp --tier keyword --profile full` against the
/// supplied DB path, returning the child guard + a worker-thread mpsc
/// receiver fed by the child's stdout. Caller pops responses with a
/// bounded `recv_timeout` so a hung response surfaces as a test
/// failure rather than a CI hang.
fn spawn_mcp(db: &std::path::Path) -> (McpChild, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        // `--tier keyword` is the cheapest tier that doesn't try to
        // load embedder / reranker models; `--profile full` exposes
        // the full 73-tool surface so `memory_reflect` is callable.
        .args([
            "--db",
            db.to_str().unwrap(),
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
    // Drain stderr so the child doesn't block writing to it.
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

    (
        McpChild {
            child: Some(child),
            stdin: Some(stdin),
        },
        rx,
    )
}

/// Send a JSON-RPC request line to the MCP child's stdin, then wait up
/// to `READ_TIMEOUT` for the next response line. Panics with a clear
/// signature on timeout (mirrors `tests/mcp_integration.rs`).
fn send_and_recv(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>, payload: &Value) -> Value {
    let line = serde_json::to_string(payload).unwrap();
    writeln!(stdin, "{line}").expect("write to mcp stdin");
    stdin.flush().expect("flush mcp stdin");
    let resp = rx
        .recv_timeout(READ_TIMEOUT)
        .expect("mcp response did not arrive within READ_TIMEOUT");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse mcp response: {e}: {resp}"))
}

/// Complete the MCP `initialize` handshake. Required before any
/// `tools/call` will be accepted — the dispatcher refuses requests
/// from unhandshaked clients. Mirrors the same shape `tests/mcp_integration.rs`
/// uses.
fn initialize(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>) {
    let resp = send_and_recv(
        stdin,
        rx,
        &json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "issue-1317-cli-test", "version": "1.0"}
            }
        }),
    );
    assert_eq!(resp["jsonrpc"], "2.0", "initialize jsonrpc tag");
    assert!(
        resp["result"].is_object(),
        "initialize result missing: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Fixture seeding
// ---------------------------------------------------------------------------

/// Seed one Observation directly via `db::insert` into the supplied DB
/// path. The MCP `tools/call memory_reflect` `source_ids` references
/// this row. Using a direct insert keeps the seed step deterministic
/// and avoids round-tripping through `ai-memory store` (which would
/// double the subprocess startup cost without adding coverage; the
/// invariant under test is `memory_reflect`, not `memory_store`).
fn seed_observation(db_path: &std::path::Path, namespace: &str, title: &str) -> String {
    let conn = db::open(db_path).expect("db::open for seed");
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("issue_1317 cli fixture observation: {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: FIXTURE_SOURCE.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": FIXTURE_AGENT_ID}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    db::insert(&conn, &mem).expect("insert observation")
}

/// Probe the sqlite row by id for the (`metadata` JSON,
/// `mentioned_entity_id`) pair. Mirrors the read-back discipline used
/// by `tests/issue_1172_reflect_metadata_passthrough.rs::
/// read_metadata_and_mention`.
fn read_metadata_and_mention(db_path: &std::path::Path, id: &str) -> (Value, Option<String>) {
    let conn = db::open(db_path).expect("db::open for probe");
    conn.query_row(
        "SELECT metadata, mentioned_entity_id FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let meta_str: String = row.get(0)?;
            let mention: Option<String> = row.get(1)?;
            Ok((
                serde_json::from_str(&meta_str).unwrap_or(Value::Null),
                mention,
            ))
        },
    )
    .expect("read row by id")
}

/// Helper — extract the new memory id from the MCP
/// `tools/call memory_reflect` response. The MCP wire shape wraps the
/// substrate envelope in `result.content[0].text` (a JSON string the
/// MCP host parses to get the structured payload). The MCP server
/// also sets `result.structuredContent` for newer hosts. We try both.
fn extract_new_id_from_mcp_resp(resp: &Value) -> String {
    // Prefer structuredContent when present (modern MCP host shape).
    if let Some(id) = resp
        .pointer("/result/structuredContent/id")
        .and_then(Value::as_str)
    {
        return id.to_string();
    }
    // Fallback: parse the legacy `content[0].text` JSON string.
    if let Some(text) = resp
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        && let Ok(parsed) = serde_json::from_str::<Value>(text)
        && let Some(id) = parsed.get("id").and_then(Value::as_str)
    {
        return id.to_string();
    }
    panic!(
        "MCP response did not carry an id in either result.structuredContent.id or result.content[0].text: {resp}"
    );
}

// ---------------------------------------------------------------------------
// (1) CLI subprocess wire-layer pin — `ai-memory mcp` subprocess
//     processing `tools/call memory_reflect` with caller-supplied
//     metadata.entity_id + probe key.
// ---------------------------------------------------------------------------

#[test]
fn cli_mcp_subprocess_reflect_preserves_caller_supplied_entity_id_and_probe() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("issue-1317-cli-pt.db");
    let src_id = seed_observation(&db, NS_PASSTHROUGH, "src-observation-1317-cli");

    let (mut guard, rx) = spawn_mcp(&db);
    let stdin = guard.stdin.as_mut().expect("mcp stdin");
    initialize(stdin, &rx);

    let resp = send_and_recv(
        stdin,
        &rx,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "memory_reflect",
                "arguments": {
                    "source_ids": [src_id],
                    "title": "reflection-via-cli-mcp-subprocess",
                    "content": "synthesised reflection content via the CLI binary mcp surface",
                    "namespace": NS_PASSTHROUGH,
                    "agent_id": FIXTURE_AGENT_ID,
                    "metadata": {
                        "entity_id": FIXTURE_ENTITY_ID,
                        "probe": FIXTURE_PROBE_VALUE,
                    },
                }
            }
        }),
    );

    // Wire-shape pin — the response must NOT carry an `error` object.
    // A regression that drops `metadata` typically still produces a
    // valid response (the substrate just writes the row with empty
    // user-metadata), so the load-bearing check is on the row state,
    // not the response envelope. But we still pin the no-error
    // invariant so a transport-level regression (the MCP dispatcher
    // failing entirely) is loud.
    assert!(
        resp.get("error").is_none(),
        "CLI mcp subprocess returned an error for memory_reflect: {resp}"
    );
    let new_id = extract_new_id_from_mcp_resp(&resp);

    // Read back via direct sqlite probe — the wire-layer invariant
    // lives in the COLUMN state, not the response envelope.
    let (meta, mention) = read_metadata_and_mention(&db, &new_id);

    // Invariant 1a — caller-supplied entity_id round-trips into stored metadata.
    assert_eq!(
        meta.get("entity_id").and_then(Value::as_str),
        Some(FIXTURE_ENTITY_ID),
        "CLI mcp subprocess must preserve caller-supplied metadata.entity_id end-to-end; full metadata = {meta}"
    );

    // Invariant 1b — auxiliary key passthrough. Pre-#1172 the metadata
    // splice DROPPED auxiliary keys alongside entity_id; this asserts
    // the additive contract is honoured for arbitrary caller keys
    // through the binary subprocess path.
    assert_eq!(
        meta.get("probe").and_then(Value::as_str),
        Some(FIXTURE_PROBE_VALUE),
        "CLI mcp subprocess must preserve auxiliary metadata keys (probe); full metadata = {meta}"
    );

    // System-spliced keys still land alongside caller keys.
    assert!(
        meta.get("agent_id").is_some(),
        "system-spliced agent_id must coexist with caller keys; full metadata = {meta}"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "system-spliced reflection_metadata must coexist with caller keys; full metadata = {meta}"
    );

    // Invariant 2 — PERF-8 denormalised column populated from caller entity_id.
    assert_eq!(
        mention.as_deref(),
        Some(FIXTURE_ENTITY_ID),
        "CLI mcp subprocess must populate mentioned_entity_id from caller-supplied metadata.entity_id"
    );
}

// ---------------------------------------------------------------------------
// (2) CLI subprocess back-compat pin — empty caller metadata still
//     produces the canonical {agent_id, reflection_metadata} shape
//     with NULL mentioned_entity_id. Mirrors invariant 4 of #1172
//     onto the CLI subprocess path so a future refactor that "fixes"
//     entity_id passthrough by ALWAYS injecting a synthetic entity_id
//     can't slip past on this surface either.
// ---------------------------------------------------------------------------

#[test]
fn cli_mcp_subprocess_reflect_empty_metadata_preserves_canonical_shape() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("issue-1317-cli-bc.db");
    let src_id = seed_observation(&db, NS_BACKCOMPAT, "src-observation-1317-cli-bc");

    let (mut guard, rx) = spawn_mcp(&db);
    let stdin = guard.stdin.as_mut().expect("mcp stdin");
    initialize(stdin, &rx);

    let resp = send_and_recv(
        stdin,
        &rx,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "memory_reflect",
                "arguments": {
                    "source_ids": [src_id],
                    "title": "empty-metadata-reflection-1317-cli",
                    "content": "synthesised reflection content with no caller metadata",
                    "namespace": NS_BACKCOMPAT,
                    "agent_id": FIXTURE_AGENT_ID,
                    "metadata": {},
                }
            }
        }),
    );

    assert!(
        resp.get("error").is_none(),
        "CLI mcp subprocess returned an error for empty-metadata memory_reflect: {resp}"
    );
    let new_id = extract_new_id_from_mcp_resp(&resp);

    let (meta, mention) = read_metadata_and_mention(&db, &new_id);

    // Canonical shape — system-spliced keys present.
    assert!(
        meta.get("agent_id").is_some(),
        "agent_id must be spliced into stored metadata; full metadata = {meta}"
    );
    assert!(
        meta.get("reflection_metadata").is_some(),
        "reflection_metadata block must be spliced in; full metadata = {meta}"
    );

    // No spurious entity_id when caller didn't supply one.
    assert!(
        meta.get("entity_id").is_none(),
        "no entity_id should appear when caller didn't supply one; full metadata = {meta}"
    );

    // mentioned_entity_id column stays NULL on the back-compat path.
    assert!(
        mention.is_none(),
        "mentioned_entity_id column stays NULL when caller supplied no entity binding; got {mention:?}"
    );
}
