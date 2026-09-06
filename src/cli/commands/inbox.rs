// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory inbox` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_inbox`. The MCP
//! tool ([`crate::mcp::handle_inbox`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! read an agent inbox (`_inbox/<agent_id>/`) from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory inbox`.
#[derive(Args, Debug, Clone)]
pub struct InboxArgs {
    /// Inbox owner. Default = caller agent_id.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Only return messages with `access_count == 0`.
    #[arg(long = "unread-only")]
    pub unread_only: bool,

    /// Default 50, cap 500.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,

    /// v1.0.0 #3470 (EPIC #3466) — block until a wake arrives, then read.
    ///
    /// Waits on the wake plane: the `ai-memory wake-hub` socket when one is
    /// configured, otherwise the bounded `<=60 s` backstop poll, which is the
    /// documented degraded mode and not an error. The read and its rendering
    /// are byte-identical to a plain `ai-memory inbox` — waiting changes WHEN
    /// the read happens, never WHAT it returns.
    #[arg(long)]
    pub wait: bool,

    /// Longest time `--wait` will block, in seconds.
    ///
    /// Omitting it does NOT mean waiting forever: the backstop tick is itself
    /// a return, so a wait without `--timeout` lasts at most one poll interval
    /// (`<= 60 s`, `wake_sink::BACKSTOP_POLL_MAX`). Pass it to bound the wait
    /// tighter than that.
    ///
    /// On expiry the command still performs the read and prints the result,
    /// so a timeout is "nothing arrived in that window", never a failure and
    /// never a reason to skip the durable truth.
    #[arg(long, value_name = "SECS", requires = "wait")]
    pub timeout: Option<u64>,
}

/// `ai-memory inbox` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the listing.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_inbox(
    db_path: &std::path::Path,
    args: &InboxArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let mut params = json!({});
    if let Some(a) = &args.agent_id {
        params["agent_id"] = json!(a);
    }
    if args.unread_only {
        params[crate::models::field_names::UNREAD_ONLY] = json!(true);
    }
    if let Some(l) = args.limit {
        params["limit"] = json!(l);
    }

    // CLI is single-tenant (the operator runs it locally) → trust-all caller
    // (None), preserving the existing `--agent-id`-selects-inbox behavior. #1557.
    let envelope = crate::mcp::handle_inbox(&conn, &params, None, None)
        .map_err(|e| anyhow::anyhow!("inbox: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    let owner = envelope
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    writeln!(out.stdout, "inbox: {count} message(s) for {owner}")?;
    if let Some(arr) = envelope.get("messages").and_then(Value::as_array) {
        for m in arr {
            let id = m.get("id").and_then(Value::as_str).unwrap_or("?");
            let from = m.get("from").and_then(Value::as_str).unwrap_or("?");
            let title = m.get("title").and_then(Value::as_str).unwrap_or("");
            let read = m.get("read").and_then(Value::as_bool).unwrap_or(false);
            writeln!(out.stdout, "  {id}  from={from}  read={read}  {title}")?;
        }
    }
    Ok(())
}

/// `ai-memory inbox --wait` — block on the wake plane, then render exactly
/// what [`cmd_inbox`] renders.
///
/// Without `--wait` this is a straight delegate, so the non-waiting path is
/// byte-identical to pre-#3470.
///
/// A hub CREDENTIAL that will not load is deliberately NOT an error here: it
/// is logged once at WARN and the wait falls through to the bounded backstop
/// poll (see [`crate::cli::wake_listen::wait_for_wake_or_backstop`]). A
/// `--wait` that returned immediately on a missing bundle would turn the
/// documented `sleep 180; ai-memory inbox` replacement into a hot loop.
///
/// # Errors
///
/// Refusals from the wake-listener RESOLUTION — a missing agent id, an
/// unresolvable key directory, a poll interval over the normative bound —
/// plus every failure [`cmd_inbox`] can produce.
pub async fn cmd_inbox_waiting(
    db_path: &std::path::Path,
    args: &InboxArgs,
    app_config: &crate::config::AppConfig,
    cli_agent_id: Option<&str>,
) -> Result<()> {
    if args.wait {
        let listen = crate::cli::wake_listen::WakeListenArgs {
            agent_id: args.agent_id.clone(),
            socket: None,
            hub_id: None,
            key_dir: None,
            bundle: None,
            poll_secs: None,
            unread_only: args.unread_only,
            limit: args.limit,
            json: args.json,
            exec: None,
            once: true,
            // No hub configured is NOT an error: the bounded backstop poll
            // is then the delivery mechanism, which is exactly the contract
            // this plane advertises.
            no_hub: false,
        };
        let resolved = crate::cli::wake_listen::resolve(&listen, app_config, cli_agent_id)?;
        let timeout = args.timeout.map(std::time::Duration::from_secs);
        // `wait_for_wake_or_backstop`, never `wait_for_wake`: a host that
        // never ran `ai-memory identity delegate` — or whose bundle expired,
        // or was minted for another hub — must still WAIT on the bounded
        // poll. Returning the credential error here would make `--wait` read
        // immediately, and the fleet recipe that swaps `sleep 180;
        // ai-memory inbox` for this command would become a hot loop of
        // immediate reads with a warning per iteration.
        match crate::cli::wake_listen::wait_for_wake_or_backstop(&resolved, timeout).await {
            Ok(Some(signal)) => {
                tracing::debug!(reason = signal.reason.label(), "inbox --wait: woken");
            }
            Ok(None) => {
                tracing::debug!("inbox --wait: timed out; reading anyway");
            }
            Err(e) => {
                // Only an invalid poll interval or a missing runtime reaches
                // here, and neither is recoverable by waiting. Degrade, never
                // refuse: the durable rows are readable whether or not the
                // wake plane is, and refusing would make an inbox read depend
                // on a latency optimisation.
                tracing::warn!(
                    "inbox --wait: the wake plane could not be started ({e:#}); reading \
                     immediately"
                );
            }
        }
    }
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut so = stdout.lock();
    let mut se = stderr.lock();
    let mut out = CliOutput::from_std(&mut so, &mut se);
    cmd_inbox(db_path, args, &mut out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn inbox_cli_empty_db_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = InboxArgs {
            agent_id: Some("ai:alice".into()),
            unread_only: false,
            limit: None,
            json: true,
            wait: false,
            timeout: None,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    #[test]
    fn inbox_cli_text_output_lists_messages() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a message into _inbox/ai:bob (the inbox namespace).
        crate::cli::test_utils::seed_memory(&db, "_inbox/ai:bob", "hello bob", "message payload");
        let args = InboxArgs {
            agent_id: Some("ai:bob".into()),
            unread_only: false,
            limit: Some(10),
            json: false,
            wait: false,
            timeout: None,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("1 message(s) for ai:bob"), "got: {stdout}");
        assert!(stdout.contains("from=test-agent"), "got: {stdout}");
        assert!(stdout.contains("hello bob"), "got: {stdout}");
        assert!(stdout.contains("read=false"), "got: {stdout}");
    }

    #[test]
    fn inbox_cli_unread_only_filters() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        crate::cli::test_utils::seed_memory(&db, "_inbox/ai:carol", "msg", "body");
        let args = InboxArgs {
            agent_id: Some("ai:carol".into()),
            unread_only: true,
            limit: None,
            json: true,
            wait: false,
            timeout: None,
        };
        {
            let mut out = env.output();
            cmd_inbox(&db, &args, &mut out).expect("ok");
        }
        let envelope: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        // Freshly seeded row has access_count==0 → unread → still listed.
        assert_eq!(envelope["count"].as_u64(), Some(1));
    }
}
