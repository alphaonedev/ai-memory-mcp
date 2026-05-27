// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory dependents-of-invalidated`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on
//! `memory_dependents_of_invalidated` (v0.7.0 L2-3, issue #668). The
//! MCP tool ([`crate::mcp::handle_dependents_of_invalidated`]) and the
//! HTTP route landed previously; this module wires the CLI surface so
//! operators can list memories flagged by the L2-3 invalidation
//! walker from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory dependents-of-invalidated`.
#[derive(Args, Debug, Clone)]
pub struct DependentsOfInvalidatedArgs {
    /// Invalidated reflection id (the target of the `reflects_on`
    /// edges this verb enumerates).
    #[arg(long = "memory-id", value_name = "ID")]
    pub memory_id: String,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory dependents-of-invalidated` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_dependents_of_invalidated(
    db_path: &std::path::Path,
    args: &DependentsOfInvalidatedArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({"memory_id": args.memory_id});

    let envelope = crate::mcp::handle_dependents_of_invalidated(&conn, &params)
        .map_err(|e| anyhow::anyhow!("dependents-of-invalidated: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(
        out.stdout,
        "dependents-of-invalidated: {count} dependent(s)"
    )?;
    if let Some(arr) = envelope.get("dependents").and_then(Value::as_array) {
        for d in arr {
            let id = d.get("id").and_then(Value::as_str).unwrap_or("?");
            let ns = d.get("namespace").and_then(Value::as_str).unwrap_or("?");
            writeln!(out.stdout, "  {id}  ns={ns}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn dependents_of_invalidated_cli_empty_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = DependentsOfInvalidatedArgs {
            memory_id: "nonexistent".into(),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_dependents_of_invalidated(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn dependents_of_invalidated_cli_empty_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = DependentsOfInvalidatedArgs {
            memory_id: String::new(),
            json: true,
        };
        let mut out = env.output();
        let err = cmd_dependents_of_invalidated(&db, &args, &mut out).expect_err("must fail");
        assert!(
            err.to_string().contains("dependents-of-invalidated"),
            "got: {err}"
        );
    }
}
