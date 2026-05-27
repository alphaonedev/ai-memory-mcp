// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory kg-timeline` CLI
//! subcommand.
//!
//! Closes the three-surface-parity gap on `memory_kg_timeline`. The
//! MCP tool ([`crate::mcp::handle_kg_timeline`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can read the outbound-link timeline for an entity from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory kg-timeline`.
#[derive(Args, Debug, Clone)]
pub struct KgTimelineArgs {
    /// Source memory id (typically an entity_id).
    #[arg(long = "source-id", value_name = "ID")]
    pub source_id: String,

    /// RFC3339 inclusive lower bound on valid_from.
    #[arg(long, value_name = "RFC3339")]
    pub since: Option<String>,

    /// RFC3339 inclusive upper bound on valid_from.
    #[arg(long, value_name = "RFC3339")]
    pub until: Option<String>,

    /// Cap [1, 1000].
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory kg-timeline` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (validation, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_kg_timeline(
    db_path: &std::path::Path,
    args: &KgTimelineArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({"source_id": args.source_id});
    if let Some(s) = &args.since {
        params["since"] = json!(s);
    }
    if let Some(u) = &args.until {
        params["until"] = json!(u);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }

    let envelope = crate::mcp::handle_kg_timeline(&conn, &params)
        .map_err(|e| anyhow::anyhow!("kg-timeline: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "kg-timeline: {count} event(s)")?;
    if let Some(arr) = envelope.get("events").and_then(Value::as_array) {
        for e in arr {
            let tid = e.get("target_id").and_then(Value::as_str).unwrap_or("?");
            let rel = e.get("relation").and_then(Value::as_str).unwrap_or("?");
            let vf = e.get("valid_from").and_then(Value::as_str).unwrap_or("");
            writeln!(out.stdout, "  {vf}  {rel}  {tid}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn kg_timeline_cli_empty_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let s = seed_memory(&db, "ns", "src", "content");
        let args = KgTimelineArgs {
            source_id: s,
            since: None,
            until: None,
            limit: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_kg_timeline(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn kg_timeline_cli_invalid_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = KgTimelineArgs {
            source_id: "bad id with spaces".into(),
            since: None,
            until: None,
            limit: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_kg_timeline(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("kg-timeline"), "got: {err}");
    }
}
