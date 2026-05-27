// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory reflect` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_reflect`. The MCP
//! tool ([`crate::mcp::handle_reflect`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! drive the recursive-learning primitive from a terminal without
//! constructing an MCP-stdio JSON-RPC envelope.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The reflect pipeline (depth-cap,
//! signature, `reflects_on` edge writes) lives in
//! [`crate::mcp::handle_reflect`]. The MCP, HTTP, and CLI surfaces
//! share that one implementation.
//!
//! ## Signing posture
//!
//! Matches the existing CLI convention (Persona / Calibrate / Skill):
//! the CLI dispatches with `active_keypair = None` and `embedder /
//! vector_index = None`. Operators who want signed `reflects_on`
//! edges or LLM-driven dedup must drive `memory_reflect` over the
//! MCP / HTTP daemon where the resolved keypair + embedder are
//! ambient. The CLI surface stays unsigned by design so shell scripts
//! can drive reflections without re-implementing the keypair-load
//! ceremony.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory reflect`. Mirrors the MCP `memory_reflect`
/// `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct ReflectArgs {
    /// One or more source memory ids (comma-separated). Required.
    #[arg(long = "source-ids", value_name = "CSV", value_delimiter = ',')]
    pub source_ids: Vec<String>,

    /// Reflection title.
    #[arg(long, value_name = "TEXT")]
    pub title: String,

    /// Reflection body.
    #[arg(long, value_name = "TEXT")]
    pub content: String,

    /// Tier: short / mid / long.
    #[arg(long, value_name = "TIER")]
    pub tier: Option<String>,

    /// Namespace. Defaults to the source memories' namespace.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Priority 1..=10. Default 5.
    #[arg(long, value_name = "N")]
    pub priority: Option<i64>,

    /// Confidence 0.0..=1.0. Default 1.0.
    #[arg(long, value_name = "F32")]
    pub confidence: Option<f64>,

    /// Optional tags (comma-separated).
    #[arg(long, value_name = "CSV", value_delimiter = ',')]
    pub tags: Vec<String>,

    /// Caller-asserted depth (#1325 — substrate refuses if mismatched).
    #[arg(long, value_name = "N")]
    pub depth: Option<i64>,

    /// Caller agent_id override (rare).
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable summary.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory reflect` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the reflection (depth cap, governance veto,
///   validation, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_reflect(
    db_path: &std::path::Path,
    args: &ReflectArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if args.source_ids.is_empty() {
        anyhow::bail!("reflect: --source-ids is required (comma-separated list)");
    }
    let conn = db::open(db_path)?;

    let mut params = json!({
        "source_ids": args.source_ids,
        "title": args.title,
        "content": args.content,
    });
    if let Some(t) = &args.tier {
        params["tier"] = json!(t);
    }
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(p) = args.priority {
        params["priority"] = json!(p);
    }
    if let Some(c) = args.confidence {
        params["confidence"] = json!(c);
    }
    if !args.tags.is_empty() {
        params["tags"] = json!(args.tags);
    }
    if let Some(d) = args.depth {
        params["depth"] = json!(d);
    }
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }

    // CLI is a substrate-internal caller. Match the existing CLI
    // convention (Skill / Persona / Calibrate): no embedder, no
    // vector index, no signing keypair, no clientInfo.name. Operators
    // who need any of those go through the MCP / HTTP daemon.
    let envelope = crate::mcp::handle_reflect(&conn, db_path, &params, None, None, None, None)
        .map_err(|e| anyhow::anyhow!("reflect: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let id = envelope.get("id").and_then(Value::as_str).unwrap_or("?");
    let depth = envelope
        .get("reflection_depth")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    writeln!(out.stdout, "reflect: id={id}  depth={depth}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn reflect_cli_missing_source_ids_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ReflectArgs {
            source_ids: vec![],
            title: "t".into(),
            content: "c".into(),
            tier: None,
            namespace: None,
            priority: None,
            confidence: None,
            tags: vec![],
            depth: None,
            agent_id: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_reflect(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("source-ids"), "got: {err}");
    }

    #[test]
    fn reflect_cli_happy_path_writes_envelope() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let s = seed_memory(&db, "rns", "reflect-src", "source content");
        let args = ReflectArgs {
            source_ids: vec![s],
            title: "synthesis".into(),
            content: "reflection body".into(),
            tier: Some("mid".into()),
            namespace: None,
            priority: None,
            confidence: None,
            tags: vec![],
            depth: None,
            agent_id: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_reflect(&db, &args, &mut out).expect("reflect ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert!(envelope.get("id").and_then(Value::as_str).is_some());
    }
}
