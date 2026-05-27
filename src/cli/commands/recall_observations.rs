// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory recall-observations` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_recall_observations`
//! (v0.7.0 Provenance Gap 3 / #886). The MCP tool
//! ([`crate::mcp::handle_recall_observations`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can inspect the recall-consumption ledger from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The filter / pagination semantics live
//! in [`crate::mcp::handle_recall_observations`]. The MCP, HTTP, and
//! CLI surfaces all share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory recall-observations`. Mirrors the MCP
/// `memory_recall_observations` `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct RecallObservationsArgs {
    /// Filter rows by recall_id.
    #[arg(long = "recall-id", value_name = "ID")]
    pub recall_id: Option<String>,

    /// Filter rows by consumed boolean. Pass `--consumed` for
    /// consumed-only rows, `--unconsumed` for the opposite. Omit
    /// for all rows.
    #[arg(long, conflicts_with = "unconsumed")]
    pub consumed: bool,

    /// Inverse of `--consumed`.
    #[arg(long)]
    pub unconsumed: bool,

    /// Lower bound on `created_at` (RFC3339).
    #[arg(long, value_name = "RFC3339")]
    pub since: Option<String>,

    /// Upper bound on `created_at` (RFC3339).
    #[arg(long, value_name = "RFC3339")]
    pub until: Option<String>,

    /// Max rows. Server default 200, ceiling 1000.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable table.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory recall-observations` dispatch entry. Opens the DB at
/// `db_path`, builds the MCP-shaped JSON params bag, and routes
/// through the shared substrate primitive — guaranteeing the wire
/// envelope is byte-equal across MCP / HTTP / CLI.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_recall_observations(
    db_path: &std::path::Path,
    args: &RecallObservationsArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({});
    if let Some(r) = &args.recall_id {
        params["recall_id"] = json!(r);
    }
    if args.consumed {
        params["consumed"] = json!(true);
    } else if args.unconsumed {
        params["consumed"] = json!(false);
    }
    if let Some(s) = &args.since {
        params["since"] = json!(s);
    }
    if let Some(u) = &args.until {
        params["until"] = json!(u);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }

    let envelope = crate::mcp::handle_recall_observations(&conn, &params)
        .map_err(|e| anyhow::anyhow!("recall-observations: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "recall-observations: {count} row(s)")?;
    if let Some(arr) = envelope.get("observations").and_then(Value::as_array) {
        for r in arr {
            let recall = r.get("recall_id").and_then(Value::as_str).unwrap_or("?");
            let mid = r.get("memory_id").and_then(Value::as_str).unwrap_or("?");
            let consumed = r.get("consumed_at").and_then(Value::as_str).is_some();
            let rank = r.get("rank").and_then(Value::as_u64).unwrap_or(0);
            writeln!(
                out.stdout,
                "  recall={recall}  memory={mid}  rank={rank}  consumed={consumed}",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn recall_observations_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = RecallObservationsArgs {
            recall_id: None,
            consumed: false,
            unconsumed: false,
            since: None,
            until: None,
            limit: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_recall_observations(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
        assert!(envelope["observations"].is_array());
    }

    #[test]
    fn recall_observations_cli_text_mode_emits_count_line() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = RecallObservationsArgs {
            recall_id: None,
            consumed: false,
            unconsumed: false,
            since: None,
            until: None,
            limit: None,
            json: false,
        };
        {
            let mut out = env.output();
            cmd_recall_observations(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(
            stdout.starts_with("recall-observations: 0 row(s)"),
            "got: {stdout}"
        );
    }
}
