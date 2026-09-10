// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3587 U4 — `ai-memory capture-turn` CLI subcommand.
//!
//! Closes the last leg of the `memory_capture_turn` three-surface gap:
//! the MCP tool (`crate::mcp::handle_capture_turn`) and the HTTP route
//! (`POST /api/v1/capture_turn`) already landed; this module wires the
//! CLI surface so (a) operators can capture a turn from a terminal and
//! (b) the Claude Code `Stop` hook installed by
//! `ai-memory install claude-code --hook capture` has a command to run.
//!
//! ## DRY contract
//!
//! No business logic lives here. In the explicit-body mode the parsed
//! stdin JSON is handed to the same [`crate::mcp::handle_capture_turn`]
//! the MCP dispatcher calls, so the envelope is identical. In auto-index
//! mode (the `Stop` hook / `--host-turn-index auto`) the request flows
//! through [`crate::mcp::handle_capture_turn_auto`], which runs the SAME
//! permission + governance + signature gates and differs only in that
//! the per-session turn index is derived inside the write transaction.
//!
//! ## Two stdin shapes
//!
//! - **Host Stop payload** — an object carrying
//!   `hook_event_name: "Stop"`; the turn text is `last_assistant_message`
//!   and the session is `session_id` (the Claude Code Stop contract:
//!   no turn index is supplied, hence the auto derivation). When
//!   `last_assistant_message` is absent/null this is a no-op.
//! - **`memory_capture_turn` params** — any other JSON object is treated
//!   as the MCP tool body (`host_session_id`, `host_turn_index`, `role`,
//!   `content`, …). This is the parity mode pinned by
//!   `capture_turn_cli_envelope_matches_mcp_tool_3587`.
//!
//! Empty stdin refuses (unless `--quiet`, which must never fail so a
//! Stop hook can never block the operator's turn).

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// The `--host-turn-index` value that asks the substrate to derive the
/// next index for the session inside the capture transaction.
pub const HOST_TURN_INDEX_AUTO: &str = "auto";

/// Claude Code Stop-hook event name / host kind (single-sourced so the
/// installer, the CLI mapper, and the tests cannot drift).
pub const HOOK_EVENT_STOP: &str = "Stop";
pub const HOST_KIND_CLAUDE_CODE: &str = "claude-code";

/// CLI args for `ai-memory capture-turn`.
#[derive(Args, Debug, Clone)]
pub struct CaptureTurnArgs {
    /// Host session identifier. Optional when the stdin body supplies
    /// `host_session_id` or the Stop payload supplies `session_id`.
    #[arg(long, value_name = "ID")]
    pub host_session_id: Option<String>,

    /// Per-session turn counter, or `auto` to derive the next index
    /// inside the capture transaction. Optional when the stdin body
    /// supplies `host_turn_index`; defaults to `auto`.
    #[arg(long, value_name = "N|auto")]
    pub host_turn_index: Option<String>,

    /// Speaker classification (`user` / `assistant` / …). Optional when
    /// the body supplies `role`; the Stop payload implies `assistant`.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<String>,

    /// Verbatim turn text. Optional when the body/Stop payload supplies
    /// it on stdin; if neither does, the invocation refuses.
    #[arg(long, value_name = "TEXT")]
    pub content: Option<String>,

    /// Host implementation id (`claude-code`, `codex`, …). Defaults to
    /// `claude-code` in Stop-payload mode, else `unknown`.
    #[arg(long, value_name = "KIND")]
    pub host_kind: Option<String>,

    /// Host implementation version string.
    #[arg(long, value_name = "VERSION")]
    pub host_version: Option<String>,

    /// Substrate namespace the turn lands in.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Never fail: a hook must never block the host. Any refusal or DB
    /// error is reported on stderr and the process exits 0.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// `ai-memory capture-turn` dispatch entry.
///
/// `json_out` is the global `--json` flag (this verb is classified
/// [`crate::cli::json_contract::JsonSupport::Global`]).
///
/// # Errors
///
/// Empty/invalid stdin, an invalid `--host-turn-index`, a Postgres store
/// (`refuse_pg_store`), or any handler refusal. Under `--quiet` every
/// error is downgraded to a stderr line and `Ok(())` — the hook contract.
pub fn cmd_capture_turn(
    db_path: &std::path::Path,
    args: &CaptureTurnArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    match run_capture_turn(db_path, args, json_out, cli_agent_id, out) {
        Ok(()) => Ok(()),
        Err(e) if args.quiet => {
            writeln!(out.stderr, "ai-memory capture-turn: {e}")?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn run_capture_turn(
    db_path: &std::path::Path,
    args: &CaptureTurnArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let mut stdin_text = String::new();
    {
        use std::io::Read;
        // Non-TTY hook invocations always pipe the payload; a TTY would
        // block, so only read when stdin is not a terminal.
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            std::io::stdin().read_to_string(&mut stdin_text)?;
        }
    }
    let stdin_text = stdin_text.trim();

    let payload: Option<Value> = if stdin_text.is_empty() {
        None
    } else {
        Some(
            serde_json::from_str(stdin_text)
                .map_err(|e| anyhow!("INVALID_INPUT: stdin is not valid JSON: {e}"))?,
        )
    };

    // Map the Claude Code Stop payload (if that's what arrived) to the
    // canonical capture params. `None` => use the raw body/flags.
    let hook_params = payload.as_ref().and_then(map_stop_payload);
    let body = payload.as_ref().filter(|_| hook_params.is_none());

    // Merge precedence: explicit flags > Stop-payload mapping > body.
    let base = hook_params.as_ref().or(body).cloned();
    let base = match base {
        Some(v) => v,
        None => {
            // Stop payload with a null/absent `last_assistant_message`
            // is an explicit no-op, not a refusal.
            if payload
                .as_ref()
                .and_then(|p| p.get("hook_event_name"))
                .and_then(Value::as_str)
                == Some(HOOK_EVENT_STOP)
            {
                return Ok(());
            }
            bail!(
                "INVALID_INPUT: empty stdin — expected a `memory_capture_turn` JSON body \
                 or a host `{HOOK_EVENT_STOP}` hook payload on stdin"
            );
        }
    };
    let obj = base
        .as_object()
        .ok_or_else(|| anyhow!("INVALID_INPUT: stdin JSON must be an object"))?;
    let mut params = obj.clone();

    if let Some(v) = &args.host_session_id {
        params.insert("host_session_id".to_string(), json!(v));
    }
    if let Some(v) = &args.role {
        params.insert("role".to_string(), json!(v));
    }
    if let Some(v) = &args.content {
        params.insert("content".to_string(), json!(v));
    }
    if let Some(v) = &args.host_kind {
        params.insert("host_kind".to_string(), json!(v));
    }
    if let Some(v) = &args.host_version {
        params.insert("host_version".to_string(), json!(v));
    }
    if let Some(v) = &args.namespace {
        params.insert("namespace".to_string(), json!(v));
    }

    // Resolve auto vs explicit index. `None`/`auto` with no body index
    // derives in-transaction; an explicit integer (flag or body) does not.
    let auto_index = match args.host_turn_index.as_deref() {
        Some(HOST_TURN_INDEX_AUTO) => true,
        Some(raw) => {
            let n: i64 = raw
                .parse()
                .map_err(|_| anyhow!("INVALID_INPUT: --host-turn-index must be an integer or `auto`"))?;
            params.insert("host_turn_index".to_string(), json!(n));
            false
        }
        None => {
            if params.get("host_turn_index").is_some() {
                false
            } else {
                true
            }
        }
    };
    if auto_index {
        // Placeholder only: the real index is derived in-transaction.
        // Kept a valid i64 so the request struct + gates parse uniformly.
        params.insert("host_turn_index".to_string(), json!(0));
    }

    // Every required capture field must be present by now.
    for required in ["host_session_id", "role", "content", "host_turn_index"] {
        if params.get(required).is_none() {
            bail!(
                "INVALID_INPUT: missing `{required}` — supply it on stdin or via the CLI flag \
                 (host_turn_index defaults to `auto`)"
            );
        }
    }

    let db_path = crate::cli::backup::refuse_pg_store(db_path, "capture-turn", out)?;
    let conn = db::open(&db_path)?;
    let caller = crate::identity::resolve_agent_id(cli_agent_id, None)
        .map_err(|e| anyhow!("{e}"))?;

    let envelope = if auto_index {
        crate::mcp::handle_capture_turn_auto(&conn, &Value::Object(params), Some(&caller))
    } else {
        crate::mcp::handle_capture_turn(&conn, &Value::Object(params), Some(&caller))
    }
    .map_err(|e| anyhow!("{e}"))?;

    if json_out {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let id = envelope.get("memory_id").and_then(Value::as_str).unwrap_or("?");
    let dedup = envelope
        .get("dedup_hit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    writeln!(out.stdout, "capture-turn: memory_id={id} dedup_hit={dedup}")?;
    Ok(())
}

/// Map a Claude Code `Stop` hook payload onto the canonical
/// `memory_capture_turn` params. Returns `None` for any other shape (or
/// when the required `session_id` is absent). A Stop payload whose
/// `last_assistant_message` is null/absent yields `None` — the caller
/// distinguishes that from a non-Stop payload via `hook_event_name`.
fn map_stop_payload(payload: &Value) -> Option<Value> {
    let event = payload.get("hook_event_name").and_then(Value::as_str)?;
    if event != HOOK_EVENT_STOP {
        return None;
    }
    let session = payload.get("session_id").and_then(Value::as_str)?;
    let content = payload
        .get("last_assistant_message")
        .and_then(Value::as_str)?;
    Some(json!({
        "host_session_id": session,
        "role": "assistant",
        "content": content,
        "host_kind": HOST_KIND_CLAUDE_CODE,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_stop_payload_maps_session_and_message() {
        let p = json!({
            "hook_event_name": "Stop",
            "session_id": "sess-1",
            "last_assistant_message": "hello",
        });
        let m = map_stop_payload(&p).expect("maps");
        assert_eq!(m["host_session_id"], "sess-1");
        assert_eq!(m["content"], "hello");
        assert_eq!(m["role"], "assistant");
        assert_eq!(m["host_kind"], HOST_KIND_CLAUDE_CODE);
    }

    #[test]
    fn map_stop_payload_none_when_message_absent() {
        let p = json!({"hook_event_name": "Stop", "session_id": "s", "last_assistant_message": null});
        assert!(map_stop_payload(&p).is_none());
    }

    #[test]
    fn map_stop_payload_none_for_non_stop_event() {
        let p = json!({"hook_event_name": "PreToolUse", "session_id": "s"});
        assert!(map_stop_payload(&p).is_none());
    }
}
