// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory kg-invalidate` CLI
//! subcommand.
//!
//! Closes the three-surface-parity gap on `memory_kg_invalidate`.
//! The MCP tool ([`crate::mcp::handle_kg_invalidate`]) and the HTTP
//! route landed previously; this module wires the CLI surface so
//! operators can supersede a KG link from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — link-triple validation, governance
//! gate (K9 permissions), `valid_until` semantics, and the webhook
//! dispatch on supersession all live in
//! [`crate::mcp::handle_kg_invalidate`].

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory kg-invalidate`.
#[derive(Args, Debug, Clone)]
pub struct KgInvalidateArgs {
    /// Source memory id.
    #[arg(long = "source-id", value_name = "ID")]
    pub source_id: String,

    /// Target memory id.
    #[arg(long = "target-id", value_name = "ID")]
    pub target_id: String,

    /// Relation label (e.g. `related_to`, `supersedes`).
    #[arg(long, value_name = "REL")]
    pub relation: String,

    /// RFC3339 supersession instant. Default = now.
    #[arg(long = "valid-until", value_name = "RFC3339")]
    pub valid_until: Option<String>,

    /// Caller agent_id override (rare).
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory kg-invalidate` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (link-triple validation,
///   governance deny, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_kg_invalidate(
    db_path: &std::path::Path,
    args: &KgInvalidateArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "source_id": args.source_id,
        "target_id": args.target_id,
        "relation": args.relation,
    });
    if let Some(t) = &args.valid_until {
        params["valid_until"] = json!(t);
    }
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }

    let envelope = crate::mcp::handle_kg_invalidate(&conn, db_path, &params)
        .map_err(|e| anyhow::anyhow!("kg-invalidate: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let found = envelope
        .get("found")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if found {
        let vu = envelope
            .get("valid_until")
            .and_then(Value::as_str)
            .unwrap_or("?");
        writeln!(out.stdout, "kg-invalidate: invalidated  valid_until={vu}")?;
    } else {
        writeln!(out.stdout, "kg-invalidate: not found")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn kg_invalidate_cli_nonexistent_returns_not_found() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let a = seed_memory(&db, "ns", "src", "alpha");
        let b = seed_memory(&db, "ns", "tgt", "beta");
        let args = KgInvalidateArgs {
            source_id: a,
            target_id: b,
            relation: "related_to".into(),
            valid_until: None,
            agent_id: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_kg_invalidate(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["found"].as_bool(), Some(false));
    }

    #[test]
    fn kg_invalidate_cli_invalid_triple_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = KgInvalidateArgs {
            source_id: "bogus id with spaces".into(),
            target_id: "another".into(),
            relation: "related_to".into(),
            valid_until: None,
            agent_id: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_kg_invalidate(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("kg-invalidate"), "got: {err}");
    }
}
