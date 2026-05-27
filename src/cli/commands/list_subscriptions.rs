// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory list-subscriptions`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_list_subscriptions`.
//! The MCP tool ([`crate::mcp::handle_list_subscriptions`]) and the
//! HTTP route landed previously; this module wires the CLI surface so
//! operators can inspect their webhook fleet from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory list-subscriptions`.
#[derive(Args, Debug, Clone)]
pub struct ListSubscriptionsArgs {
    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory list-subscriptions` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the listing.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_list_subscriptions(
    db_path: &std::path::Path,
    args: &ListSubscriptionsArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let envelope = crate::mcp::handle_list_subscriptions(&conn, None)
        .map_err(|e| anyhow::anyhow!("list-subscriptions: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "list-subscriptions: {count} row(s)")?;
    if let Some(arr) = envelope.get("subscriptions").and_then(Value::as_array) {
        for s in arr {
            let id = s.get("id").and_then(Value::as_str).unwrap_or("?");
            let url = s.get("url").and_then(Value::as_str).unwrap_or("?");
            let events = s.get("events").and_then(Value::as_str).unwrap_or("*");
            writeln!(out.stdout, "  {id}  events={events}  url={url}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn list_subscriptions_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ListSubscriptionsArgs { json: true };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn list_subscriptions_cli_text_mode_emits_count_line() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ListSubscriptionsArgs { json: false };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(
            stdout.starts_with("list-subscriptions: 0 row(s)"),
            "got: {stdout}"
        );
    }
}
