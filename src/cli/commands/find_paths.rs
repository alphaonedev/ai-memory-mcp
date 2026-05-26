// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory find-paths` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_find_paths`. The
//! MCP tool ([`crate::mcp::handle_find_paths`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can enumerate KG paths between two memories from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The actual path-enumeration semantics
//! (BFS with cycle detection, `max_depth<=7`, `max_results<=50`) live
//! in [`crate::mcp::handle_find_paths`]. The MCP, HTTP, and CLI
//! surfaces all share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory find-paths`. Mirrors the MCP
/// `memory_find_paths` `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct FindPathsArgs {
    /// Path origin.
    #[arg(long = "source-id", value_name = "ID")]
    pub source_id: String,

    /// Path destination.
    #[arg(long = "target-id", value_name = "ID")]
    pub target_id: String,

    /// Max hops, ceiling 7. Defaults to 4 server-side.
    #[arg(long = "max-depth", value_name = "N")]
    pub max_depth: Option<u32>,

    /// Max paths, ceiling 50. Defaults to 10 server-side.
    #[arg(long = "max-results", value_name = "N")]
    pub max_results: Option<u32>,

    /// When set, include historically-invalidated edges.
    #[arg(long = "include-invalidated")]
    pub include_invalidated: bool,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable list.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory find-paths` dispatch entry. Opens the DB at `db_path`,
/// builds the MCP-shaped JSON params bag, and routes through the
/// shared substrate primitive — guaranteeing the wire envelope is
/// byte-equal across MCP / HTTP / CLI.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope (in
///   practice never happens with the shapes used here).
pub fn cmd_find_paths(
    db_path: &std::path::Path,
    args: &FindPathsArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "source_id": args.source_id,
        "target_id": args.target_id,
    });
    if let Some(d) = args.max_depth {
        params["max_depth"] = json!(d);
    }
    if let Some(m) = args.max_results {
        params["max_results"] = json!(m);
    }
    if args.include_invalidated {
        params["include_invalidated"] = json!(true);
    }

    let envelope = crate::mcp::handle_find_paths(&conn, &params)
        .map_err(|e| anyhow::anyhow!("find-paths: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "find-paths: {count} path(s)")?;
    if let Some(arr) = envelope.get("paths").and_then(Value::as_array) {
        for (idx, path) in arr.iter().enumerate() {
            if let Some(ids) = path.as_array() {
                let chain: Vec<&str> = ids.iter().filter_map(Value::as_str).collect();
                writeln!(out.stdout, "  [{}] {}", idx + 1, chain.join(" -> "))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn find_paths_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let a = seed_memory(&db, "ns", "fp-a", "alpha");
        let b = seed_memory(&db, "ns", "fp-b", "beta");
        let args = FindPathsArgs {
            source_id: a,
            target_id: b,
            max_depth: None,
            max_results: None,
            include_invalidated: false,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_find_paths(&db, &args, &mut out).expect("find-paths ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn find_paths_cli_invalid_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = FindPathsArgs {
            source_id: "bogus id with spaces".to_string(),
            target_id: "another bogus".to_string(),
            max_depth: None,
            max_results: None,
            include_invalidated: false,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_find_paths(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("find-paths"), "got: {err}");
    }
}
