// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory quota-status` CLI
//! subcommand.
//!
//! Closes the three-surface-parity gap on `memory_quota_status` (v0.7
//! K8 / #1156 per-namespace dimension). The MCP tool
//! ([`crate::mcp::handle_quota_status`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! inspect per-agent / per-namespace quota counters from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory quota-status`.
#[derive(Args, Debug, Clone)]
pub struct QuotaStatusArgs {
    /// Restrict to one agent.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Restrict to one namespace (v0.7.0 #1156).
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory quota-status` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_quota_status(
    db_path: &std::path::Path,
    args: &QuotaStatusArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({});
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }

    let envelope = crate::mcp::handle_quota_status(&conn, &params)
        .map_err(|e| anyhow::anyhow!("quota-status: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    // The handler returns one of four envelope shapes depending on
    // which args are present. Render the common-summary fields when
    // available; full detail goes via --json.
    if let Some(count) = envelope.get("count").and_then(Value::as_u64) {
        writeln!(out.stdout, "quota-status: {count} row(s)")?;
    } else {
        let aid = envelope
            .get("agent_id")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let ns = envelope
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or("?");
        writeln!(out.stdout, "quota-status: agent={aid}  namespace={ns}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn quota_status_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = QuotaStatusArgs {
            agent_id: None,
            namespace: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_quota_status(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn quota_status_cli_per_agent_returns_aggregate() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = QuotaStatusArgs {
            agent_id: Some("ai:alice".into()),
            namespace: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_quota_status(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["agent_id"].as_str(), Some("ai:alice"));
        // Aggregate label.
        assert_eq!(envelope["namespace"].as_str(), Some("_global"));
    }
}
