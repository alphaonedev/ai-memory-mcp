// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory kg-query` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_kg_query`. The MCP
//! tool ([`crate::mcp::handle_kg_query`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! traverse the knowledge graph from a terminal without driving MCP
//! stdio JSON-RPC.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The actual traversal semantics live in
//! [`crate::mcp::handle_kg_query`]. The MCP, HTTP, and CLI surfaces
//! all share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory kg-query`. Mirrors the MCP `memory_kg_query`
/// `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct KgQueryArgs {
    /// Source memory id (full UUID or unique prefix).
    #[arg(long = "source-id", value_name = "ID")]
    pub source_id: Option<String>,

    /// #889 — list every memory rooted at the given source_uri instead
    /// of traversing from a specific source memory.
    #[arg(long = "by-source-uri", value_name = "URI")]
    pub by_source_uri: Option<String>,

    /// Max hops, 1..=5. Defaults to 1 server-side.
    #[arg(long = "max-depth", value_name = "N")]
    pub max_depth: Option<u32>,

    /// Restrict to a specific namespace.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// RFC3339 timestamp — keep only links valid at this instant.
    #[arg(long = "valid-at", value_name = "RFC3339")]
    pub valid_at: Option<String>,

    /// Comma-separated allowlist of observed_by agent ids.
    #[arg(long = "allowed-agents", value_name = "CSV")]
    pub allowed_agents: Option<String>,

    /// Hard cap across all depths (1..=1000).
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// When set, traverse historically-invalidated edges as well.
    #[arg(long = "include-invalidated")]
    pub include_invalidated: bool,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable table.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory kg-query` dispatch entry. Opens the DB at `db_path`,
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
pub fn cmd_kg_query(
    db_path: &std::path::Path,
    args: &KgQueryArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if args.source_id.is_none() && args.by_source_uri.is_none() {
        anyhow::bail!("kg-query: either --source-id or --by-source-uri is required");
    }
    let conn = db::open(db_path)?;

    let mut params = json!({});
    if let Some(sid) = &args.source_id {
        params["source_id"] = json!(sid);
    }
    if let Some(uri) = &args.by_source_uri {
        params["by_source_uri"] = json!(uri);
    }
    if let Some(d) = args.max_depth {
        params["max_depth"] = json!(d);
    }
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(t) = &args.valid_at {
        params["valid_at"] = json!(t);
    }
    if let Some(csv) = &args.allowed_agents {
        let agents: Vec<&str> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        params["allowed_agents"] = json!(agents);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }
    if args.include_invalidated {
        params["include_invalidated"] = json!(true);
    }

    let envelope = crate::mcp::handle_kg_query(&conn, &params)
        .map_err(|e| anyhow::anyhow!("kg-query: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    // Human-readable summary.
    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "kg-query: {count} row(s)")?;
    if let Some(arr) = envelope.get("memories").and_then(Value::as_array) {
        for m in arr {
            let target = m.get("target_id").and_then(Value::as_str).unwrap_or("?");
            let title = m.get("title").and_then(Value::as_str).unwrap_or("");
            let depth = m.get("depth").and_then(Value::as_u64).unwrap_or(0);
            let relation = m.get("relation").and_then(Value::as_str).unwrap_or("");
            writeln!(out.stdout, "  [d={depth}] {target}  {relation}  {title}",)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn kg_query_cli_requires_source_or_uri() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = KgQueryArgs {
            source_id: None,
            by_source_uri: None,
            max_depth: None,
            namespace: None,
            valid_at: None,
            allowed_agents: None,
            limit: None,
            include_invalidated: false,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_kg_query(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("source-id"), "got: {err}");
    }

    #[test]
    fn kg_query_cli_empty_db_returns_zero_rows() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let src_id = seed_memory(&db, "ns", "kg-source", "content");
        let args = KgQueryArgs {
            source_id: Some(src_id),
            by_source_uri: None,
            max_depth: None,
            namespace: None,
            valid_at: None,
            allowed_agents: None,
            limit: None,
            include_invalidated: false,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_kg_query(&db, &args, &mut out).expect("kg-query ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }
}
