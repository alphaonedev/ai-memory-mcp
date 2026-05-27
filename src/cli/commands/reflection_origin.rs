// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory reflection-origin`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_reflection_origin`
//! (v0.7.0 L2-2 / S6-M1). The MCP tool
//! ([`crate::mcp::handle_reflection_origin`]) and the HTTP route
//! landed previously; this module wires the CLI surface so operators
//! can inspect the cross-peer federation provenance of a reflection
//! memory from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory reflection-origin`.
#[derive(Args, Debug, Clone)]
pub struct ReflectionOriginArgs {
    /// Memory id whose origin to inspect.
    #[arg(long = "memory-id", value_name = "ID")]
    pub memory_id: String,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory reflection-origin` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (validation, id not found).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_reflection_origin(
    db_path: &std::path::Path,
    args: &ReflectionOriginArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({"memory_id": args.memory_id});

    let envelope = crate::mcp::handle_reflection_origin(&conn, &params)
        .map_err(|e| anyhow::anyhow!("reflection-origin: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let is_refl = envelope
        .get("is_reflection")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let peer = envelope
        .get("peer_origin")
        .and_then(Value::as_str)
        .unwrap_or("");
    let depth = envelope
        .get("original_depth")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    writeln!(
        out.stdout,
        "reflection-origin: is_reflection={is_refl}  peer_origin={peer}  original_depth={depth}"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn reflection_origin_cli_known_id_returns_envelope() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mid = seed_memory(&db, "ns", "plain", "body");
        let args = ReflectionOriginArgs {
            memory_id: mid,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_reflection_origin(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        // Plain (non-reflection) memory → envelope with is_reflection=false.
        assert_eq!(envelope["is_reflection"].as_bool(), Some(false));
    }

    #[test]
    fn reflection_origin_cli_empty_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ReflectionOriginArgs {
            memory_id: String::new(),
            json: true,
        };
        let mut out = env.output();
        let err = cmd_reflection_origin(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("reflection-origin"), "got: {err}");
    }
}
