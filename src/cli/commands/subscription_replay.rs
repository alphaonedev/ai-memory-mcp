// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscription-replay`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_subscription_replay`
//! (v0.7 K7 reliability tool). The MCP tool
//! ([`crate::mcp::handle_subscription_replay`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can replay events from a webhook subscription's delivery log.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory subscription-replay`.
#[derive(Args, Debug, Clone)]
pub struct SubscriptionReplayArgs {
    /// Subscription id.
    #[arg(long = "subscription-id", value_name = "ID")]
    pub subscription_id: String,

    /// RFC3339 inclusive lower bound on `delivered_at`.
    #[arg(long, value_name = "RFC3339")]
    pub since: String,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory subscription-replay` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the replay (invalid RFC3339, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_subscription_replay(
    db_path: &std::path::Path,
    args: &SubscriptionReplayArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({
        "subscription_id": args.subscription_id,
        "since": args.since,
    });
    let envelope = crate::mcp::handle_subscription_replay(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("subscription-replay: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "subscription-replay: {count} event(s)")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn subscription_replay_cli_unknown_id_returns_empty() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = SubscriptionReplayArgs {
            subscription_id: "unknown-id".into(),
            since: "2024-01-01T00:00:00Z".into(),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_subscription_replay(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        // Owner-mismatch / non-existent ids return the same empty
        // envelope so existence isn't leaked (#1115 caller-ownership).
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }
}
