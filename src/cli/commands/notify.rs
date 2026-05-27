// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory notify` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_notify`. The MCP
//! tool ([`crate::mcp::handle_notify`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! send an inter-agent inbox message from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — validation, namespace resolution
//! (`_messages/<target>/`), and the per-tier expiry computation live
//! in [`crate::mcp::handle_notify`]. The MCP, HTTP, and CLI surfaces
//! share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::storage as db;

/// CLI args for `ai-memory notify`.
#[derive(Args, Debug, Clone)]
pub struct NotifyArgs {
    /// Recipient agent_id.
    #[arg(long = "target-agent-id", value_name = "AGENT_ID")]
    pub target_agent_id: String,

    /// Subject (<= 200 chars).
    #[arg(long, value_name = "TEXT")]
    pub title: String,

    /// Message body.
    #[arg(long, value_name = "TEXT")]
    pub payload: String,

    /// Default 5; clamped 1..=10.
    #[arg(long, value_name = "N")]
    pub priority: Option<i64>,

    /// Tier: short=6h, mid=7d (default), long=no expiry.
    #[arg(long, value_name = "TIER")]
    pub tier: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory notify` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the notify (validation, tier parse, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_notify(
    db_path: &std::path::Path,
    args: &NotifyArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let resolved_ttl = app_config.effective_ttl();

    let mut params = json!({
        "target_agent_id": args.target_agent_id,
        "title": args.title,
        "payload": args.payload,
    });
    if let Some(p) = args.priority {
        params["priority"] = json!(p);
    }
    if let Some(t) = &args.tier {
        params["tier"] = json!(t);
    }

    let envelope = crate::mcp::handle_notify(&conn, &params, &resolved_ttl, None)
        .map_err(|e| anyhow::anyhow!("notify: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let id = envelope.get("id").and_then(Value::as_str).unwrap_or("?");
    let to = envelope.get("to").and_then(Value::as_str).unwrap_or("?");
    writeln!(out.stdout, "notify: id={id}  to={to}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn notify_cli_invalid_target_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = AppConfig::default();
        let args = NotifyArgs {
            target_agent_id: "bad agent with spaces".into(),
            title: "subject".into(),
            payload: "body".into(),
            priority: None,
            tier: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_notify(&db, &args, &cfg, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("notify"), "got: {err}");
    }

    #[test]
    fn notify_cli_happy_path_writes_envelope() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = AppConfig::default();
        let args = NotifyArgs {
            target_agent_id: "ai:bob".into(),
            title: "subject".into(),
            payload: "body".into(),
            priority: Some(7),
            tier: Some("mid".into()),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_notify(&db, &args, &cfg, &mut out).expect("notify ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["to"].as_str(), Some("ai:bob"));
    }
}
