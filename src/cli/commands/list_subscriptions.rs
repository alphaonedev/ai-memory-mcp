// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory list-subscriptions`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_list_subscriptions`.
//! The MCP tool ([`crate::mcp::handle_list_subscriptions`]) and the
//! HTTP route landed previously; this module wires the CLI surface so
//! operators can inspect their webhook fleet from a terminal.

use crate::models::field_names;
use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory list-subscriptions`.
#[derive(Args, Debug, Clone)]
pub struct ListSubscriptionsArgs {
    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory list-subscriptions` dispatch entry.
///
/// `cli_agent_id` is the global `--agent-id` flag. The #872
/// cross-tenant list gate scopes to that resolved caller (#3433).
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the listing.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_list_subscriptions(
    db_path: &std::path::Path,
    args: &ListSubscriptionsArgs,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let caller = crate::identity::resolve_agent_id(cli_agent_id, None)
        .map_err(|e| anyhow::anyhow!(crate::errors::msg::list_subscriptions(e)))?;
    let envelope = crate::mcp::handle_list_subscriptions_as_caller(&conn, &caller)
        .map_err(|e| anyhow::anyhow!(crate::errors::msg::list_subscriptions(e.message())))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(out.stdout, "list-subscriptions: {count} row(s)")?;
    if let Some(arr) = envelope
        .get(field_names::SUBSCRIPTIONS)
        .and_then(Value::as_array)
    {
        for s in arr {
            let id = s.get("id").and_then(Value::as_str).unwrap_or("?");
            let url = s.get("url").and_then(Value::as_str).unwrap_or("?");
            let events = s.get("events").and_then(Value::as_str).unwrap_or("*");
            writeln!(out.stdout, "  {id}  events={events}  url={url}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn list_subscriptions_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ListSubscriptionsArgs { json: true };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, None, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn list_subscriptions_cli_text_mode_emits_count_line() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ListSubscriptionsArgs { json: false };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, None, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(
            stdout.starts_with("list-subscriptions: 0 row(s)"),
            "got: {stdout}"
        );
    }

    #[test]
    fn list_subscriptions_cli_text_mode_lists_rows() {
        crate::config::set_active_hooks_hmac_secret(None);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            let agent_id = crate::identity::resolve_agent_id(None, None).unwrap();
            db::register_agent(&conn, &agent_id, "test", &[]).expect("register");
            crate::mcp::handle_subscribe(
                &conn,
                &serde_json::json!({"url": "https://example.com/hook", "secret": "topsecret"}),
                None,
            )
            .expect("subscribe");
        }
        let args = ListSubscriptionsArgs { json: false };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, None, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("1 row(s)"), "got: {stdout}");
        assert!(
            stdout.contains("url=https://example.com/hook"),
            "got: {stdout}"
        );
    }

    /// DENIED (#3433): `--agent-id alice` does not see bob's subscriptions.
    #[test]
    fn list_subscriptions_cli_other_caller_sees_zero_3433() {
        crate::config::set_active_hooks_hmac_secret(None);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            db::register_agent(&conn, "ai:bob", "test", &[]).expect("register");
            crate::mcp::handle_subscribe_as_created_by(
                &conn,
                &serde_json::json!({"url": "https://example.com/hook-bob", "secret": "topsecret"}),
                "ai:bob",
            )
            .expect("subscribe");
        }
        let args = ListSubscriptionsArgs { json: true };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, Some("ai:alice"), &mut out).expect("ok");
        }
        let envelope: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    /// ALLOWED (#3433): `--agent-id bob` lists bob's own subscriptions.
    #[test]
    fn list_subscriptions_cli_owner_sees_own_3433() {
        crate::config::set_active_hooks_hmac_secret(None);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            db::register_agent(&conn, "ai:bob", "test", &[]).expect("register");
            crate::mcp::handle_subscribe_as_created_by(
                &conn,
                &serde_json::json!({"url": "https://example.com/hook-bob", "secret": "topsecret"}),
                "ai:bob",
            )
            .expect("subscribe");
        }
        let args = ListSubscriptionsArgs { json: true };
        {
            let mut out = env.output();
            cmd_list_subscriptions(&db, &args, Some("ai:bob"), &mut out).expect("ok");
        }
        let envelope: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(envelope["count"].as_u64(), Some(1));
    }
}
