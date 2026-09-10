// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3587 U4 — end-to-end acceptance tests for the `ai-memory
//! capture-turn` CLI twin of the `memory_capture_turn` MCP tool, driven
//! through the real binary (`CARGO_BIN_EXE_ai-memory`).
//!
//! Pins:
//! - `capture_turn_cli_envelope_matches_mcp_tool_3587` — the CLI `--json`
//!   envelope is structurally identical to the in-process
//!   `handle_capture_turn` envelope for the same params (all keys equal;
//!   `memory_id` + `elapsed_ms` normalised because they are inherently
//!   non-deterministic).
//! - `capture_turn_cli_refuses_empty_stdin_3587` — empty stdin refuses
//!   loudly without `--quiet`; with `--quiet` (the Stop-hook contract) it
//!   never fails and reports on stderr, exit 0.
//!
//! Scratch DBs live under the cargo target dir (project no-`/tmp` HARD RULE).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Output, Stdio};

use serde_json::{Value, json};

/// A fresh scratch dir + DB path under the cargo target dir.
fn scratch(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let root = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dir = tempfile::Builder::new()
        .prefix(&format!("capture-turn-3587-{tag}-"))
        .tempdir_in(root)
        .expect("scratch dir under the cargo target dir must be creatable");
    let db = dir.path().join("capture-turn.db");
    (dir, db)
}

/// Run `ai-memory --db <db> --agent-id test-agent-3587 <args...>` with
/// `stdin` piped in, `AI_MEMORY_NO_CONFIG=1` pinned so no developer config
/// leaks in.
fn run_cli(db: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(db)
        .arg("--agent-id")
        .arg("test-agent-3587")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait ai-memory")
}

/// Normalise the volatile envelope fields so the CLI + MCP twins can be
/// compared: `memory_id` is a fresh UUID per write and `elapsed_ms` is a
/// wall-clock measurement. Everything else must be byte-equal.
fn normalise(mut v: Value) -> Value {
    let obj = v.as_object_mut().expect("envelope is an object");
    obj.remove("elapsed_ms");
    if obj.contains_key("memory_id") {
        obj.insert("memory_id".to_string(), json!("<memory_id>"));
    }
    v
}

/// #3587 U4 acceptance — the CLI envelope matches the MCP tool envelope.
#[test]
fn capture_turn_cli_envelope_matches_mcp_tool_3587() {
    let params = json!({
        "host_session_id": "sess-parity-3587",
        "host_turn_index": 7,
        "role": "assistant",
        "content": "parity envelope probe",
        "host_kind": "claude-code",
    });

    // CLI surface: real binary, explicit body on stdin, explicit index.
    let (_cli_dir, cli_db) = scratch("parity-cli");
    let out = run_cli(&cli_db, &["capture-turn", "--json"], &params.to_string());
    assert!(
        out.status.success(),
        "capture-turn --json must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cli_envelope: Value =
        serde_json::from_slice(&out.stdout).expect("CLI emits exactly one JSON document");

    // MCP surface: same handler the MCP dispatch calls, same params.
    let (_mcp_dir, mcp_db) = scratch("parity-mcp");
    let conn = ai_memory::db::open(&mcp_db).expect("open scratch DB");
    let mcp_envelope = ai_memory::mcp::handle_capture_turn(&conn, &params, Some("test-agent-3587"))
        .expect("in-process MCP capture");

    assert_eq!(
        normalise(cli_envelope),
        normalise(mcp_envelope),
        "CLI + MCP capture-turn envelopes must be structurally identical"
    );
}

/// #3587 U4 acceptance — empty stdin refuses; `--quiet` never fails.
#[test]
fn capture_turn_cli_refuses_empty_stdin_3587() {
    let (_dir, db) = scratch("empty-stdin");

    // Non-quiet: a loud refusal (no JSON body, no Stop payload).
    let refused = run_cli(&db, &["capture-turn"], "");
    assert!(
        !refused.status.success(),
        "empty stdin without --quiet must refuse; stdout={}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("empty stdin"),
        "refusal must name the empty stdin; stderr={stderr}"
    );

    // Quiet: the Stop-hook contract — exit 0, message on stderr only.
    let quiet = run_cli(&db, &["capture-turn", "--quiet"], "");
    assert!(
        quiet.status.success(),
        "--quiet must never fail a hook; stderr={}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert!(
        String::from_utf8_lossy(&quiet.stderr).contains("ai-memory capture-turn:"),
        "quiet mode still reports the refusal on stderr"
    );
    assert!(
        quiet.stdout.is_empty(),
        "quiet refusal writes nothing to stdout"
    );
}

/// #3587 U4 acceptance (hook mode) — a Claude Code `Stop` payload with no
/// `host_turn_index` is captured through the in-transaction auto-index path;
/// a second delivery of the SAME turn is a content-guarded dedup hit.
#[test]
fn capture_turn_cli_stop_payload_auto_index_dedups_3587() {
    let (_dir, db) = scratch("stop-auto");
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": "sess-stop-3587",
        "last_assistant_message": "the finished assistant turn",
    })
    .to_string();

    let first = run_cli(&db, &["capture-turn", "--json"], &stop);
    assert!(
        first.status.success(),
        "Stop payload must capture; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_env: Value = serde_json::from_slice(&first.stdout).expect("first envelope");
    assert_eq!(
        first_env["dedup_hit"],
        Value::Bool(false),
        "got {first_env}"
    );

    // Host re-delivery of the identical turn → content-guarded dedup hit.
    let second = run_cli(&db, &["capture-turn", "--json"], &stop);
    assert!(second.status.success());
    let second_env: Value = serde_json::from_slice(&second.stdout).expect("second envelope");
    assert_eq!(
        second_env["dedup_hit"],
        Value::Bool(true),
        "re-delivered Stop payload must dedup; got {second_env}"
    );
    assert_eq!(
        second_env["memory_id"], first_env["memory_id"],
        "dedup hit returns the original memory id"
    );

    // The hook contract (`--quiet`) is silent on success: a Stop hook's
    // stdout is host-visible, so a per-turn status line would be noise.
    let quiet = run_cli(&db, &["capture-turn", "--quiet"], &stop);
    assert!(
        quiet.status.success(),
        "quiet capture must exit 0; stderr={}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert!(
        quiet.stdout.is_empty(),
        "quiet success must not write stdout; got {}",
        String::from_utf8_lossy(&quiet.stdout)
    );
    assert!(
        quiet.stderr.is_empty(),
        "quiet success must not write stderr; got {}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

/// #3587 U4 — a `Stop` payload whose `last_assistant_message` is null is an
/// explicit no-op (exit 0, no memory), never a refusal.
#[test]
fn capture_turn_cli_stop_payload_null_message_is_noop_3587() {
    let (_dir, db) = scratch("stop-null");
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": "sess-null-3587",
        "last_assistant_message": null,
    })
    .to_string();

    let out = run_cli(&db, &["capture-turn", "--json"], &stop);
    assert!(
        out.status.success(),
        "null message no-op must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "no-op emits no envelope; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}
