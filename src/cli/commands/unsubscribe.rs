// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory unsubscribe` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_unsubscribe`. The
//! MCP tool ([`crate::mcp::handle_unsubscribe`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can remove a webhook subscription from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — the substrate primitive enforces
//! the cross-tenant authorization gate (#870) so a CLI caller cannot
//! delete another tenant's row. The MCP, HTTP, and CLI surfaces share
//! [`crate::mcp::handle_unsubscribe`].

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory unsubscribe`.
#[derive(Args, Debug, Clone)]
pub struct UnsubscribeArgs {
    /// Subscription id to remove.
    #[arg(long, value_name = "ID")]
    pub id: String,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory unsubscribe` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the delete.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_unsubscribe(
    db_path: &std::path::Path,
    args: &UnsubscribeArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({"id": args.id});

    let envelope = crate::mcp::handle_unsubscribe(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("unsubscribe: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let removed = envelope
        .get("removed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    writeln!(out.stdout, "unsubscribe: id={}  removed={removed}", args.id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn unsubscribe_cli_unknown_id_returns_zero_removed() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = UnsubscribeArgs {
            id: "nonexistent".into(),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_unsubscribe(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["removed"].as_bool(), Some(false));
    }
}
