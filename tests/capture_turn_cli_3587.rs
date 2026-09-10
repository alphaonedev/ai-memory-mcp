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
    run_cli_env(db, args, stdin, &[])
}

/// As [`run_cli`], with extra child-process environment pairs layered on
/// top (used to pin `AI_MEMORY_SECRET_SCREEN_MODE=redact` for the
/// storage-form dedup probe).
fn run_cli_env(db: &Path, args: &[&str], stdin: &str, extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = StdCommand::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(db)
        .arg("--agent-id")
        .arg("test-agent-3587")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn ai-memory");
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

/// #3587 U4 acceptance (hook mode, guard 2) — two DIFFERENT turns in the
/// same session get distinct in-transaction indices (0 then 1), so the
/// auto-index derivation is itself load-bearing: a broken derivation that
/// pinned every turn to one index would still pass the re-delivery dedup
/// test above (different content ⇒ different `sha256`), so this pins the
/// actual `MAX+1` ladder and the distinct memory ids.
#[test]
fn capture_turn_cli_stop_payload_auto_index_advances_3587() {
    let (_dir, db) = scratch("stop-advance");
    let session = "sess-advance-3587";
    let turns = [
        "first finished assistant turn",
        "second finished assistant turn",
    ];

    let mut ids = Vec::new();
    for text in turns {
        let stop = json!({
            "hook_event_name": "Stop",
            "session_id": session,
            "last_assistant_message": text,
        })
        .to_string();
        let out = run_cli(&db, &["capture-turn", "--json"], &stop);
        assert!(
            out.status.success(),
            "distinct Stop payload must capture; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let env: Value = serde_json::from_slice(&out.stdout).expect("envelope");
        assert_eq!(
            env["dedup_hit"],
            Value::Bool(false),
            "distinct turns must not dedup; got {env}"
        );
        ids.push(env["memory_id"].as_str().expect("memory_id").to_string());
    }
    assert_ne!(
        ids[0], ids[1],
        "distinct turns must produce distinct memories"
    );

    // The derived indices must be the contiguous MAX+1 ladder 0, 1.
    let conn = ai_memory::db::open(&db).expect("open capture db");
    let mut stmt = conn
        .prepare(
            "SELECT host_turn_index FROM transcript_line_dedup \
             WHERE host_session_id = ?1 ORDER BY host_turn_index",
        )
        .expect("prepare index probe");
    let indices: Vec<i64> = stmt
        .query_map([session], |row| row.get(0))
        .expect("query indices")
        .collect::<std::result::Result<_, _>>()
        .expect("collect indices");
    assert_eq!(
        indices,
        vec![0, 1],
        "auto index must advance MAX+1 per session"
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

/// #3587 U4 round-2 — an `A,B,A` turn sequence in ONE session is THREE
/// distinct turns, not two. Guard 1 compares the incoming content only
/// against the session's LATEST stored turn, so the third delivery (A
/// again, after B) does not match B and must be captured; the auto index
/// ladder advances contiguously 0,1,2.
#[test]
fn capture_turn_cli_stop_payload_a_b_a_keeps_three_3587() {
    let (_dir, db) = scratch("stop-aba");
    let session = "sess-aba-3587";
    let turns = ["turn A body", "turn B body", "turn A body"];

    let mut ids = Vec::new();
    for text in turns {
        let stop = json!({
            "hook_event_name": "Stop",
            "session_id": session,
            "last_assistant_message": text,
        })
        .to_string();
        let out = run_cli(&db, &["capture-turn", "--json"], &stop);
        assert!(
            out.status.success(),
            "A,B,A delivery must capture; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let env: Value = serde_json::from_slice(&out.stdout).expect("envelope");
        assert_eq!(
            env["dedup_hit"],
            Value::Bool(false),
            "A,B,A must never dedup (latest-row-only guard); got {env}"
        );
        ids.push(env["memory_id"].as_str().expect("memory_id").to_string());
    }

    assert_eq!(ids.len(), 3, "three deliveries for A,B,A");
    let distinct: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "A,B,A must produce three distinct memories; got {ids:?}"
    );

    let conn = ai_memory::db::open(&db).expect("open capture db");
    let mut stmt = conn
        .prepare(
            "SELECT host_turn_index FROM transcript_line_dedup \
             WHERE host_session_id = ?1 ORDER BY host_turn_index",
        )
        .expect("prepare index probe");
    let indices: Vec<i64> = stmt
        .query_map([session], |row| row.get(0))
        .expect("query indices")
        .collect::<std::result::Result<_, _>>()
        .expect("collect indices");
    assert_eq!(
        indices,
        vec![0, 1, 2],
        "A,B,A auto indices must be the contiguous ladder 0,1,2"
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_line_dedup WHERE host_session_id = ?1",
            [session],
            |row| row.get(0),
        )
        .expect("count dedup rows");
    assert_eq!(count, 3, "A,B,A must leave exactly three dedup rows");
}

/// #3587 U4 round-2 — under `AI_MEMORY_SECRET_SCREEN_MODE=redact` the
/// storage funnel masks credential material, so the stored `content` is
/// NOT byte-equal to the raw host payload. Guard 1 must compare against
/// the incoming text both raw and in its redacted storage form, else the
/// identical redacted turn is re-captured on every host re-delivery.
#[test]
fn capture_turn_cli_stop_payload_dedups_redacted_storage_form_3587() {
    /// The canonical anchored AWS access-key-id fixture the screen fires
    /// on (`AKIA` + 16 uppercase-alnum).
    const AWS_ACCESS_KEY_FIXTURE: &str = "AKIAIOSFODNN7EXAMPLE";
    let (_dir, db) = scratch("stop-redact");
    let session = "sess-redact-3587";
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": session,
        "last_assistant_message": format!("rotate the key {AWS_ACCESS_KEY_FIXTURE} now"),
    })
    .to_string();

    let redact = [("AI_MEMORY_SECRET_SCREEN_MODE", "redact")];
    let first = run_cli_env(&db, &["capture-turn", "--json"], &stop, &redact);
    assert!(
        first.status.success(),
        "redact-mode capture must succeed; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_env: Value = serde_json::from_slice(&first.stdout).expect("first envelope");
    assert_eq!(
        first_env["dedup_hit"],
        Value::Bool(false),
        "first redacted capture must write; got {first_env}"
    );

    // Identical re-delivery under the same redact posture → storage-form
    // dedup hit on the original memory id.
    let second = run_cli_env(&db, &["capture-turn", "--json"], &stop, &redact);
    assert!(
        second.status.success(),
        "redacted re-delivery must succeed; stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_env: Value = serde_json::from_slice(&second.stdout).expect("second envelope");
    assert_eq!(
        second_env["dedup_hit"],
        Value::Bool(true),
        "redacted re-delivery must dedup on the storage form; got {second_env}"
    );
    assert_eq!(
        second_env["memory_id"], first_env["memory_id"],
        "storage-form dedup returns the original memory id"
    );

    let conn = ai_memory::db::open(&db).expect("open capture db");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .expect("count memories");
    assert_eq!(
        count, 1,
        "redacted re-delivery must leave exactly one memory"
    );
    let stored: String = conn
        .query_row("SELECT content FROM memories LIMIT 1", [], |row| row.get(0))
        .expect("stored content");
    assert!(
        !stored.contains(AWS_ACCESS_KEY_FIXTURE),
        "stored content must be redacted, not the raw credential; got {stored}"
    );
}

/// #3587 U4 (21:03Z session-salting note) — identical content delivered in
/// two DIFFERENT sessions must produce TWO memories: the dedup `sha256` is
/// computed over the session-salted canonical bytes
/// `session\0index\0role\0content`, and Guard 1 is scoped by
/// `host_session_id`. Re-delivering one of them is still a dedup hit.
#[test]
fn capture_turn_cli_stop_payload_same_content_two_sessions_3587() {
    let (_dir, db) = scratch("stop-two-sessions");
    let text = "identical assistant message in two separate sessions";
    let sessions = ["sess-salt-a-3587", "sess-salt-b-3587"];

    let mut ids = Vec::new();
    for session in sessions {
        let stop = json!({
            "hook_event_name": "Stop",
            "session_id": session,
            "last_assistant_message": text,
        })
        .to_string();
        let out = run_cli(&db, &["capture-turn", "--json"], &stop);
        assert!(
            out.status.success(),
            "per-session capture must succeed; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let env: Value = serde_json::from_slice(&out.stdout).expect("envelope");
        assert_eq!(
            env["dedup_hit"],
            Value::Bool(false),
            "a different session must not dedup; got {env}"
        );
        ids.push(env["memory_id"].as_str().expect("memory_id").to_string());
    }
    assert_ne!(
        ids[0], ids[1],
        "identical content in two sessions must be two memories"
    );

    let conn = ai_memory::db::open(&db).expect("open capture db");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .expect("count memories");
    assert_eq!(
        count, 2,
        "session-salting must yield two memories for identical content"
    );

    // Re-delivering the SAME (session, turn) is still a dedup hit.
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": sessions[0],
        "last_assistant_message": text,
    })
    .to_string();
    let again = run_cli(&db, &["capture-turn", "--json"], &stop);
    assert!(again.status.success());
    let again_env: Value = serde_json::from_slice(&again.stdout).expect("envelope");
    assert_eq!(
        again_env["dedup_hit"],
        Value::Bool(true),
        "same (session, content) re-delivery must dedup; got {again_env}"
    );
    assert_eq!(again_env["memory_id"], ids[0]);
}

/// #3587 U4 round-2 — the hook / parity stdin read is hard-capped at
/// `capture_turn::MAX_CAPTURE_TURN_STDIN_BYTES`: an over-cap payload
/// refuses with `INVALID_INPUT` before the JSON parse (CWE-400), and the
/// read never consumes more than the cap.
#[test]
fn capture_turn_cli_refuses_over_cap_stdin_3587() {
    /// Mirrors `src/cli/commands/capture_turn.rs::MAX_CAPTURE_TURN_STDIN_BYTES`
    /// (kept as a local literal so the test asserts the shipped 16 MiB).
    const CAPTURE_TURN_STDIN_CAP_BYTES: usize = 16 * 1024 * 1024;
    let (_dir, db) = scratch("stdin-cap");

    // Exactly one byte over the ceiling. Deliberately not valid JSON — the
    // cap must refuse BEFORE the parse.
    let over_cap = "a".repeat(CAPTURE_TURN_STDIN_CAP_BYTES + 1);
    let out = run_cli(&db, &["capture-turn"], &over_cap);
    assert!(
        !out.status.success(),
        "over-cap stdin without --quiet must refuse; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exceeds") && stderr.contains("MiB"),
        "refusal must name the cap; stderr={stderr}"
    );

    // Under --quiet the hook contract still refuses without failing.
    let quiet = run_cli(&db, &["capture-turn", "--quiet"], &over_cap);
    assert!(
        quiet.status.success(),
        "--quiet must never fail a hook; stderr={}",
        String::from_utf8_lossy(&quiet.stderr)
    );
    assert!(
        quiet.stdout.is_empty(),
        "quiet refusal writes nothing to stdout"
    );
}
