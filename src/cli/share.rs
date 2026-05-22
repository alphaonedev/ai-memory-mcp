// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1095 — `ai-memory share` CLI subcommand.
//!
//! Closes the SR-4 three-surface-parity gap on `memory_share`. The MCP
//! tool ([`crate::mcp::tools::share::handle_share`]) and the HTTP route
//! (`POST /api/v1/share`, [`crate::handlers::share::share_memory`])
//! landed at v0.7.0 RC; this module wires the third surface so operators
//! can share a memory from a terminal without driving MCP-stdio JSON-RPC
//! or constructing an HTTP request by hand.
//!
//! ## Wire shape
//!
//! ```text
//! ai-memory share \
//!     --memory-id <source uuid or unique prefix> \
//!     --target-agent <recipient agent_id> \
//!     [--json]
//! ```
//!
//! Both `--memory-id` and `--target-agent` are required and validated by
//! the shared substrate primitive ([`crate::validate::validate_id`] /
//! [`crate::validate::validate_agent_id`]). The dispatch is byte-equal
//! to the MCP tool so the JSON envelope (`shared_memory_id`,
//! `source_memory_id`, `target_namespace`, `target_agent_id`,
//! `from_agent_id`) round-trips intact.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser plus
//! an output formatter. The actual share semantics (provenance metadata,
//! `_shared/<from>→<to>/` namespace construction, fresh row insert) live
//! in [`crate::mcp::tools::share::handle_share`]. The MCP, HTTP, and CLI
//! surfaces share that one implementation; adding a CLI verb is one
//! `Command::Share(ShareArgs)` arm + this module.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory share`. Mirrors the MCP `memory_share`
/// `input_schema` shape: `source_memory_id` (here exposed as
/// `--memory-id` for shell ergonomics) + `target_agent_id` (here
/// `--target-agent` for the same reason). The substrate primitive
/// accepts both spellings via the JSON params bag the CLI constructs
/// below.
#[derive(Args, Debug, Clone)]
pub struct ShareArgs {
    /// Memory id (full UUID or unique prefix) to share. Resolved by
    /// the same `validate_id` + `resolve_id` substrate path the MCP
    /// tool uses, so callers can pass the short-id shell flow.
    #[arg(long = "memory-id", value_name = "ID")]
    pub memory_id: String,

    /// Recipient agent id. Must satisfy `validate_agent_id` (the same
    /// validator the MCP tool routes through). Typical: `ai:bob`,
    /// `host:node-2`, or any `[A-Za-z0-9_\\-:@./]{1,128}` token.
    #[arg(long = "target-agent", value_name = "AGENT_ID")]
    pub target_agent: String,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of the human-readable summary line.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory share` dispatch entry. Opens the DB at `db_path`, builds
/// the same JSON params bag the MCP tool consumes, and routes through
/// the shared [`crate::mcp::tools::share::handle_share`] substrate
/// primitive — guaranteeing the wire envelope is byte-equal across the
/// three surfaces.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate validation rejects the supplied `--memory-id` /
///   `--target-agent` (invalid format, source row not found, …).
/// - `serde_json::to_string` cannot serialise the envelope (in practice
///   never happens with the shapes used here).
pub fn cmd_share(
    db_path: &std::path::Path,
    args: &ShareArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    // Build the JSON params bag the substrate primitive consumes. The
    // CLI flag names diverge from the MCP wire shape for shell
    // ergonomics (`--memory-id` vs `source_memory_id`) but the shared
    // dispatcher only sees the canonical MCP field names.
    let params: Value = json!({
        "source_memory_id": args.memory_id,
        "target_agent_id": args.target_agent,
    });

    let envelope = crate::mcp::share::handle_share(&conn, &params)
        .map_err(|e| anyhow::anyhow!("share: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    // Human-readable summary. Pull the four documented envelope keys
    // and emit a single line. Defensive `unwrap_or("?")` on the off-
    // chance the substrate primitive ever drops a field — the wire
    // contract is pinned by the MCP + HTTP integration tests.
    let shared_id = envelope
        .get("shared_memory_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let target_ns = envelope
        .get("target_namespace")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let from_agent = envelope
        .get("from_agent_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    writeln!(
        out.stdout,
        "shared {} ({} → {}) into {}",
        shared_id, from_agent, args.target_agent, target_ns,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    /// v0.7.0 #1095 — CLI share happy path. Pins the third surface of
    /// the three-surface-parity contract: a row stored under one agent
    /// is copied into the `_shared/<from>→<to>/` namespace when shared.
    /// MCP + HTTP pin the same invariant; this test ensures the CLI
    /// arm reaches the substrate primitive without dropping fields.
    #[test]
    fn share_cli_copies_memory_into_shared_namespace_1095() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a source memory authored by ai:alice (the seed_memory
        // helper stamps `agent_id` into the metadata via the default
        // construction path).
        let src_id = seed_memory(&db, "alice/notes", "shared-src-cli", "share me via CLI");
        // The seed helper does NOT stamp a specific agent_id; pre-seed
        // a metadata.agent_id so the share primitive can derive the
        // `from_agent_id` envelope field. Open a connection and patch
        // the row.
        {
            let conn = db::open(&db).expect("open db for metadata patch");
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', 'ai:alice') WHERE id = ?1",
                rusqlite::params![src_id],
            )
            .expect("patch metadata.agent_id");
        }

        let args = ShareArgs {
            memory_id: src_id.clone(),
            target_agent: "ai:bob".to_string(),
            json: true,
        };
        {
            let mut out = env.output();
            cmd_share(&db, &args, &mut out).expect("share ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        // Wire shape parity with MCP + HTTP.
        assert!(
            envelope["shared_memory_id"].is_string(),
            "#1095: shared_memory_id present"
        );
        assert_eq!(
            envelope["source_memory_id"], src_id,
            "#1095: source_memory_id echoes input"
        );
        assert_eq!(
            envelope["target_agent_id"], "ai:bob",
            "#1095: target_agent_id echoes input"
        );
        assert_eq!(
            envelope["from_agent_id"], "ai:alice",
            "#1095: from_agent_id derived from source row metadata"
        );
        assert!(
            envelope["target_namespace"]
                .as_str()
                .unwrap_or("")
                .starts_with("_shared/"),
            "#1095: target_namespace begins with _shared/"
        );
    }

    /// v0.7.0 #1095 — text-mode output renders a one-line summary
    /// pointing at the new row. Pins the non-JSON dispatch path.
    #[test]
    fn share_cli_text_mode_emits_one_line_summary_1095() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let src_id = seed_memory(&db, "alice/notes", "shared-src-text", "share me");
        {
            let conn = db::open(&db).expect("open db for metadata patch");
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', 'ai:alice') WHERE id = ?1",
                rusqlite::params![src_id],
            )
            .expect("patch metadata.agent_id");
        }

        let args = ShareArgs {
            memory_id: src_id,
            target_agent: "ai:bob".to_string(),
            json: false,
        };
        {
            let mut out = env.output();
            cmd_share(&db, &args, &mut out).expect("share ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.starts_with("shared "), "got: {stdout}");
        assert!(stdout.contains("ai:alice"), "got: {stdout}");
        assert!(stdout.contains("ai:bob"), "got: {stdout}");
        assert!(stdout.contains("_shared/"), "got: {stdout}");
    }

    /// v0.7.0 #1095 — substrate rejection (missing source row) bubbles
    /// up as a CLI error rather than a panic or silent success. Pins
    /// the failure envelope from the substrate primitive.
    #[test]
    fn share_cli_missing_source_returns_err_1095() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ShareArgs {
            memory_id: uuid::Uuid::new_v4().to_string(),
            target_agent: "ai:bob".to_string(),
            json: true,
        };
        let mut out = env.output();
        let err = cmd_share(&db, &args, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("not found"), "got: {err}");
    }
}
