// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscribe` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_subscribe`. The MCP
//! tool ([`crate::mcp::handle_subscribe`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! register a webhook subscription from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — the URL validation, HMAC secret
//! requirement (R3-S1.HMAC v0.7.0), and registered-agent gate live in
//! [`crate::mcp::handle_subscribe`]. The MCP, HTTP, and CLI surfaces
//! share that one implementation.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory subscribe`. Mirrors the MCP
/// `memory_subscribe` `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct SubscribeArgs {
    /// Webhook URL the daemon will POST events to.
    #[arg(long, value_name = "URL")]
    pub url: String,

    /// Comma-separated event-name filter, or "*" for all. Default "*".
    #[arg(long, value_name = "CSV")]
    pub events: Option<String>,

    /// HMAC secret. Required when no server-wide
    /// `[hooks.subscription] hmac_secret` is configured.
    #[arg(long, value_name = "SECRET")]
    pub secret: Option<String>,

    /// Optional namespace filter.
    #[arg(long = "namespace-filter", value_name = "NS")]
    pub namespace_filter: Option<String>,

    /// Optional agent_id filter.
    #[arg(long = "agent-filter", value_name = "AGENT_ID")]
    pub agent_filter: Option<String>,

    /// Optional structured per-event-type opt-in (comma-separated).
    #[arg(long = "event-types", value_name = "CSV", value_delimiter = ',')]
    pub event_types: Vec<String>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return).
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory subscribe` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the registration (missing HMAC secret,
///   unregistered agent, malformed URL, etc.).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_subscribe(
    db_path: &std::path::Path,
    args: &SubscribeArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({"url": args.url});
    if let Some(e) = &args.events {
        params["events"] = json!(e);
    }
    if let Some(s) = &args.secret {
        params["secret"] = json!(s);
    }
    if let Some(ns) = &args.namespace_filter {
        params["namespace_filter"] = json!(ns);
    }
    if let Some(a) = &args.agent_filter {
        params["agent_filter"] = json!(a);
    }
    if !args.event_types.is_empty() {
        params["event_types"] = json!(args.event_types);
    }

    let envelope = crate::mcp::handle_subscribe(&conn, &params, None)
        .map_err(|e| anyhow::anyhow!("subscribe: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let id = envelope.get("id").and_then(Value::as_str).unwrap_or("?");
    let url = envelope.get("url").and_then(Value::as_str).unwrap_or("?");
    writeln!(out.stdout, "subscribe: id={id}  url={url}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn subscribe_cli_unregistered_agent_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = SubscribeArgs {
            url: "https://example.com/hook".into(),
            events: None,
            secret: Some("topsecret".into()),
            namespace_filter: None,
            agent_filter: None,
            event_types: vec![],
            json: true,
        };
        let mut out = env.output();
        // The CLI dispatcher caller is not registered in `_agents` →
        // substrate refuses with the registration-required error.
        let err = cmd_subscribe(&db, &args, &mut out).expect_err("must fail");
        assert!(
            err.to_string().contains("subscribe") || err.to_string().contains("register"),
            "got: {err}"
        );
    }
}
