// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G13-mem (#1859) — `ai-memory lineage` CLI subcommand.
//!
//! Three-surface parity for `memory_lineage`: the MCP tool
//! ([`crate::mcp::handle_lineage`]) and the HTTP route
//! (`GET /api/v1/memories/{id}/lineage`) land in the same change; this
//! module wires the CLI surface so operators can walk a memory's
//! derivation lineage-DAG from a terminal without driving MCP stdio
//! JSON-RPC.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser plus
//! an output formatter. The traversal semantics live in
//! [`crate::mcp::handle_lineage`] (which dispatches to
//! `db::lineage_ancestors` / `db::lineage_descendants`). The MCP, HTTP,
//! and CLI surfaces all share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory lineage`. Mirrors the MCP `memory_lineage`
/// `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct LineageArgs {
    /// Root memory id (full UUID).
    pub id: String,

    /// Walk descendants (newer derivatives) instead of ancestors.
    #[arg(long)]
    pub descendants: bool,

    /// Max hops, 1..=5. Defaults to 5.
    #[arg(long = "max-depth", value_name = "N")]
    pub max_depth: Option<u32>,

    /// Emit the raw JSON envelope instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

/// Execute `ai-memory lineage`.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_lineage(
    db_path: &std::path::Path,
    args: &LineageArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "id": args.id,
        "direction": if args.descendants {
            crate::mcp::LINEAGE_DIRECTION_DESCENDANTS
        } else {
            crate::mcp::LINEAGE_DIRECTION_ANCESTORS
        },
    });
    if let Some(d) = args.max_depth {
        params["max_depth"] = json!(d);
    }

    // #1800 — CLI is operator-as-actor (single-operator trust-all), so
    // pass `None` for the visibility caller (no root-owner gate).
    let envelope = crate::mcp::handle_lineage(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("lineage: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    let direction = envelope
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("ancestors");
    writeln!(out.stdout, "lineage: {count} {direction}")?;
    if let Some(arr) = envelope.get("nodes").and_then(Value::as_array) {
        for node in arr {
            let id = node.get("id").and_then(Value::as_str).unwrap_or("?");
            let relation = node.get("relation").and_then(Value::as_str).unwrap_or("?");
            let depth = node.get("depth").and_then(Value::as_u64).unwrap_or(0);
            let cid = node.get("cid").and_then(Value::as_str).unwrap_or("-");
            writeln!(out.stdout, "  [d{depth}] {id} ({relation}, cid {cid})")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn lineage_cli_empty_walk_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let a = seed_memory(&db, "ns", "lin-a", "alpha");
        let args = LineageArgs {
            id: a,
            descendants: false,
            max_depth: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_lineage(&db, &args, &mut out).expect("lineage ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
        assert_eq!(envelope["direction"].as_str(), Some("ancestors"));
    }

    #[test]
    fn lineage_cli_walks_a_reflects_on_edge_human_render() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let a = seed_memory(&db, "ns", "lin-src", "source");
        let r = seed_memory(&db, "ns", "lin-refl", "reflection");
        {
            let conn = db::open(&db).expect("open");
            db::create_link(&conn, &r, &a, "reflects_on").expect("link");
        }
        let args = LineageArgs {
            id: r.clone(),
            descendants: false,
            max_depth: Some(5),
            json: false,
        };
        {
            let mut out = env.output();
            cmd_lineage(&db, &args, &mut out).expect("lineage ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("lineage: 1 ancestors"), "got: {stdout}");
        assert!(stdout.contains(&a), "ancestor id rendered: {stdout}");
        assert!(
            stdout.contains("reflects_on"),
            "relation rendered: {stdout}"
        );
    }

    #[test]
    fn lineage_cli_invalid_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = LineageArgs {
            id: "not-a-valid-id!".to_string(),
            descendants: false,
            max_depth: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_lineage(&db, &args, &mut out).expect_err("must refuse invalid id");
        assert!(err.to_string().contains("lineage:"), "got: {err}");
    }
}
