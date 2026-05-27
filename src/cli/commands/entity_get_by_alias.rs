// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory entity-get-by-alias`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_entity_get_by_alias`.
//! The MCP tool ([`crate::mcp::handle_entity_get_by_alias`]) and the
//! HTTP route landed previously; this module wires the CLI surface so
//! operators can resolve an alias to its canonical entity from a
//! terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory entity-get-by-alias`.
#[derive(Args, Debug, Clone)]
pub struct EntityGetByAliasArgs {
    /// Alias to resolve (whitespace trimmed).
    #[arg(long, value_name = "ALIAS")]
    pub alias: String,

    /// Optional namespace filter. Without it, the most-recently-
    /// created match across namespaces wins.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory entity-get-by-alias` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (validation).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_entity_get_by_alias(
    db_path: &std::path::Path,
    args: &EntityGetByAliasArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({"alias": args.alias});
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }

    let envelope = crate::mcp::handle_entity_get_by_alias(&conn, &params)
        .map_err(|e| anyhow::anyhow!("entity-get-by-alias: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let found = envelope
        .get("found")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if found {
        let id = envelope
            .get("entity_id")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let name = envelope
            .get("canonical_name")
            .and_then(Value::as_str)
            .unwrap_or("?");
        writeln!(
            out.stdout,
            "entity-get-by-alias: entity_id={id}  canonical_name={name}"
        )?;
    } else {
        writeln!(out.stdout, "entity-get-by-alias: no match")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn entity_get_by_alias_cli_unknown_alias_returns_not_found() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = EntityGetByAliasArgs {
            alias: "nonexistent-alias".into(),
            namespace: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_entity_get_by_alias(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["found"].as_bool(), Some(false));
    }

    #[test]
    fn entity_get_by_alias_cli_round_trip_finds_entity() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed via the entity-register path.
        let reg = crate::mcp::handle_entity_register(
            &crate::storage::open(&db).unwrap(),
            &json!({
                "canonical_name": "Bob",
                "namespace": "people",
                "aliases": ["bobby"],
                "agent_id": "ai:tester",
            }),
            None,
        )
        .expect("register");
        let expected_id = reg["entity_id"].as_str().unwrap().to_string();
        let args = EntityGetByAliasArgs {
            alias: "bobby".into(),
            namespace: Some("people".into()),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_entity_get_by_alias(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["found"].as_bool(), Some(true));
        assert_eq!(envelope["entity_id"].as_str(), Some(expected_id.as_str()));
    }
}
