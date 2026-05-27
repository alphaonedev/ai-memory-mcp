// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory entity-register` CLI
//! subcommand.
//!
//! Closes the three-surface-parity gap on `memory_entity_register`.
//! The MCP tool ([`crate::mcp::handle_entity_register`]) and the HTTP
//! route landed previously; this module wires the CLI surface so
//! operators can register a canonical entity (with aliases) from a
//! terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory entity-register`.
#[derive(Args, Debug, Clone)]
pub struct EntityRegisterArgs {
    /// Display name (entity memory title).
    #[arg(long = "canonical-name", value_name = "NAME")]
    pub canonical_name: String,

    /// Entity namespace.
    #[arg(long, value_name = "NS")]
    pub namespace: String,

    /// Optional aliases (comma-separated). Blanks skipped, deduped.
    #[arg(long, value_name = "CSV", value_delimiter = ',')]
    pub aliases: Vec<String>,

    /// Optional caller agent_id override.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory entity-register` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (validation, name collision with
///   non-entity row).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_entity_register(
    db_path: &std::path::Path,
    args: &EntityRegisterArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "canonical_name": args.canonical_name,
        "namespace": args.namespace,
    });
    if !args.aliases.is_empty() {
        params["aliases"] = json!(args.aliases);
    }
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }

    let envelope = crate::mcp::handle_entity_register(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("entity-register: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let id = envelope
        .get("entity_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let created = envelope
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    writeln!(
        out.stdout,
        "entity-register: entity_id={id}  created={created}"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn entity_register_cli_happy_path_writes_envelope() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = EntityRegisterArgs {
            canonical_name: "Alice".into(),
            namespace: "characters".into(),
            aliases: vec!["al".into(), "ali".into()],
            agent_id: Some("ai:tester".into()),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_entity_register(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["canonical_name"].as_str(), Some("Alice"));
        assert_eq!(envelope["created"].as_bool(), Some(true));
    }

    #[test]
    fn entity_register_cli_empty_name_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = EntityRegisterArgs {
            canonical_name: String::new(),
            namespace: "characters".into(),
            aliases: vec![],
            agent_id: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_entity_register(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("entity-register"), "got: {err}");
    }
}
