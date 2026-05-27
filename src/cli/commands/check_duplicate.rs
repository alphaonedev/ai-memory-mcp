// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory check-duplicate` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_check_duplicate`.
//! The MCP tool ([`crate::mcp::handle_check_duplicate`]) and the HTTP
//! route landed previously; this module wires the CLI surface so
//! operators can pre-flight a write from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The actual semantic-cosine + raw-text
//! short-circuit semantics live in
//! [`crate::mcp::handle_check_duplicate`]. The MCP, HTTP, and CLI
//! surfaces all share that one implementation.
//!
//! Requires the embedder (semantic tier or above) — the CLI wires it
//! through the same [`crate::daemon_runtime::build_embedder`]
//! resolution ladder the daemon uses.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::storage as db;

/// CLI args for `ai-memory check-duplicate`. Mirrors the MCP
/// `memory_check_duplicate` `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct CheckDuplicateArgs {
    /// Candidate title.
    #[arg(long, value_name = "TEXT")]
    pub title: String,

    /// Candidate content.
    #[arg(long, value_name = "TEXT")]
    pub content: String,

    /// Namespace filter — only look for duplicates inside this scope.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Cosine threshold. Floor 0.5. Default 0.85 tuned for MiniLM-L6-v2.
    #[arg(long, value_name = "F32")]
    pub threshold: Option<f64>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable summary line.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory check-duplicate` dispatch entry. Opens the DB at
/// `db_path`, resolves the embedder, builds the MCP-shaped JSON params
/// bag, and routes through the shared substrate primitive —
/// guaranteeing the wire envelope is byte-equal across MCP / HTTP /
/// CLI.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The embedder cannot be built (semantic tier not enabled).
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope.
pub async fn cmd_check_duplicate(
    db_path: &std::path::Path,
    args: &CheckDuplicateArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({
        "title": args.title,
        "content": args.content,
    });
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(t) = args.threshold {
        params["threshold"] = json!(t);
    }

    let feature_tier = app_config.effective_tier(None);
    let embedder = crate::daemon_runtime::build_embedder(feature_tier, app_config).await;

    let envelope = crate::mcp::handle_check_duplicate(
        &conn,
        &params,
        embedder
            .as_ref()
            .map(|e| e as &dyn crate::embeddings::Embed),
    )
    .map_err(|e| anyhow::anyhow!("check-duplicate: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let is_dup = envelope
        .get("is_duplicate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scanned = envelope
        .get("candidates_scanned")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if is_dup {
        let merge = envelope
            .get("suggested_merge")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let sim = envelope
            .get("nearest")
            .and_then(|n| n.get("similarity"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        writeln!(
            out.stdout,
            "check-duplicate: DUPLICATE  suggested_merge={merge}  similarity={sim:.3}  candidates_scanned={scanned}",
        )?;
    } else {
        writeln!(
            out.stdout,
            "check-duplicate: ok  no duplicate  candidates_scanned={scanned}",
        )?;
    }
    Ok(())
}
