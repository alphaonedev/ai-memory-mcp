// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory replay` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_replay`. The MCP
//! tool ([`crate::mcp::handle_replay`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! reconstruct the transcript chain that produced a memory from a
//! terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The transcript-union walk + truncation
//! semantics live in [`crate::mcp::handle_replay`]. The MCP, HTTP, and
//! CLI surfaces all share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory replay`. Mirrors the MCP `memory_replay`
/// `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct ReplayArgs {
    /// Memory id (full UUID or unique prefix).
    #[arg(long = "memory-id", value_name = "ID")]
    pub memory_id: String,

    /// When set, include full transcript content even for entries
    /// larger than `REPLAY_VERBOSE_THRESHOLD_BYTES` (100 KB). Without
    /// this flag, oversized entries are truncated=true.
    #[arg(long)]
    pub verbose: bool,

    /// L2-4 reflects_on hops. Omit for full chain; 0 = self only;
    /// N >= 1 = self plus N ancestor hops.
    #[arg(long, value_name = "N")]
    pub depth: Option<i64>,

    /// Optional agent_id used for the #912 permission gate (rare;
    /// most CLI callers leave this unset).
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable summary.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory replay` dispatch entry. Opens the DB at `db_path`,
/// builds the MCP-shaped JSON params bag, and routes through the
/// shared substrate primitive — guaranteeing the wire envelope is
/// byte-equal across MCP / HTTP / CLI.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_replay(
    db_path: &std::path::Path,
    args: &ReplayArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "memory_id": args.memory_id,
        "verbose": args.verbose,
    });
    if let Some(d) = args.depth {
        params["depth"] = json!(d);
    }
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }

    // CLI is a substrate-internal caller; no MCP `clientInfo.name`
    // available. Pass `None` so the same default-identity resolution
    // the MCP path uses applies (`host:<host>:pid-<pid>-…` fallback
    // when `agent_id` param is also absent).
    let envelope = crate::mcp::handle_replay(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("replay: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope
        .get("transcripts")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    writeln!(out.stdout, "replay: {count} transcript(s)")?;
    if let Some(arr) = envelope.get("transcripts").and_then(Value::as_array) {
        for t in arr {
            let tid = t
                .get("transcript_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let created = t.get("created_at").and_then(Value::as_str).unwrap_or("");
            let truncated = t.get("truncated").and_then(Value::as_bool).unwrap_or(false);
            let osize = t.get("original_size").and_then(Value::as_u64).unwrap_or(0);
            writeln!(
                out.stdout,
                "  {tid}  created={created}  bytes={osize}  truncated={truncated}",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn replay_cli_no_transcripts_returns_zero_count() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mid = seed_memory(&db, "ns", "replay-src", "content");
        let args = ReplayArgs {
            memory_id: mid,
            verbose: false,
            depth: None,
            agent_id: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_replay(&db, &args, &mut out).expect("replay ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        // No transcripts wired yet — substrate ships the primitive but
        // no production write path auto-links transcripts.
        let count = envelope
            .get("transcripts")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        assert_eq!(count, 0);
    }

    #[test]
    fn replay_cli_invalid_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ReplayArgs {
            memory_id: "bogus id".to_string(),
            verbose: false,
            depth: None,
            agent_id: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_replay(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("replay"), "got: {err}");
    }
}
