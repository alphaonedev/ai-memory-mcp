// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory inbox` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_inbox`. The MCP
//! tool ([`crate::mcp::handle_inbox`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! read an agent inbox (`_messages/<agent_id>/`) from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory inbox`.
#[derive(Args, Debug, Clone)]
pub struct InboxArgs {
    /// Inbox owner. Default = caller agent_id.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Only return messages with `access_count == 0`.
    #[arg(long = "unread-only")]
    pub unread_only: bool,

    /// Default 50, cap 500.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory inbox` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the listing.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_inbox(
    db_path: &std::path::Path,
    args: &InboxArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({});
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }
    if args.unread_only {
        params[crate::models::field_names::UNREAD_ONLY] = json!(true);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }

    // CLI is single-tenant (the operator runs it locally) → trust-all caller
    // (None), preserving the existing `--agent-id`-selects-inbox behavior. #1557.
    let envelope = crate::mcp::handle_inbox(&conn, &params, None, None)
        .map_err(|e| anyhow::anyhow!("inbox: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    let owner = envelope
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    writeln!(out.stdout, "inbox: {count} message(s) for {owner}")?;
    if let Some(arr) = envelope.get("messages").and_then(Value::as_array) {
        for m in arr {
            let id = m.get("id").and_then(Value::as_str).unwrap_or("?");
            let from = m.get("from").and_then(Value::as_str).unwrap_or("?");
            let title = m.get("title").and_then(Value::as_str).unwrap_or("");
            let read = m.get("read").and_then(Value::as_bool).unwrap_or(false);
            writeln!(out.stdout, "  {id}  from={from}  read={read}  {title}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn inbox_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = InboxArgs {
            agent_id: Some("ai:alice".into()),
            unread_only: false,
            limit: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn inbox_cli_text_output_lists_messages() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a message into _messages/ai:bob (the inbox namespace).
        crate::cli::test_utils::seed_memory(
            &db,
            "_messages/ai:bob",
            "hello bob",
            "message payload",
        );
        let args = InboxArgs {
            agent_id: Some("ai:bob".into()),
            unread_only: false,
            limit: Some(10),
            json: false,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("1 message(s) for ai:bob"), "got: {stdout}");
        assert!(stdout.contains("from=test-agent"), "got: {stdout}");
        assert!(stdout.contains("hello bob"), "got: {stdout}");
        assert!(stdout.contains("read=false"), "got: {stdout}");
    }

    #[test]
    fn inbox_cli_unread_only_filters() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        crate::cli::test_utils::seed_memory(&db, "_messages/ai:carol", "msg", "body");
        let args = InboxArgs {
            agent_id: Some("ai:carol".into()),
            unread_only: true,
            limit: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let envelope: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        // Freshly seeded row has access_count==0 → unread → still listed.
        assert_eq!(envelope["count"].as_u64(), Some(1));
    }
}
