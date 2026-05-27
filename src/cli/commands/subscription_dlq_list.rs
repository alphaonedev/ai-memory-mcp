// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscription-dlq-list`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on
//! `memory_subscription_dlq_list` (v0.7 K7 dead-letter queue
//! introspection). The MCP tool
//! ([`crate::mcp::handle_subscription_dlq_list`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can list undeliverable webhook events from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory subscription-dlq-list`.
#[derive(Args, Debug, Clone)]
pub struct SubscriptionDlqListArgs {
    /// Filter to a single subscription id. Without it, the operator
    /// sees every DLQ row they own (cross-tenant rows are filtered
    /// per #1118 caller-ownership gate).
    #[arg(long = "subscription-id", value_name = "ID")]
    pub subscription_id: Option<String>,

    /// Default 100, ceiling 1000.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory subscription-dlq-list` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the listing.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_subscription_dlq_list(
    db_path: &std::path::Path,
    args: &SubscriptionDlqListArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let mut params = json!({});
    if let Some(s) = &args.subscription_id {
        params["subscription_id"] = json!(s);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }

    let envelope = crate::mcp::handle_subscription_dlq_list(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("subscription-dlq-list: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "subscription-dlq-list: {count} entry(ies)")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn subscription_dlq_list_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = SubscriptionDlqListArgs {
            subscription_id: None,
            limit: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_subscription_dlq_list(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }
}
