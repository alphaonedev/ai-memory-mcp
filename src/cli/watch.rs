// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory watch` — CLI surface for the L3 substrate poll-based
//! filesystem watcher (issue [#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)).
//! The daemon is OPT-IN — it never runs unless an operator explicitly
//! invokes this subcommand. Mirrors the `ai-memory curator`
//! `--once` / `--daemon` split.
//!
//! # Wire shape
//!
//! ```bash
//! ai-memory watch --once                       # single poll tick, human report
//! ai-memory watch --once --json                # single poll tick, JSON report
//! ai-memory watch --daemon --interval-secs 10   # continuous poll loop until SIGINT
//! ai-memory watch --daemon --host claude-code --host codex
//! ```

use std::path::Path;

use anyhow::Result;
use clap::Args;

use crate::cli::CliOutput;
use crate::recover::HostKind;
use crate::recover::watcher::{self, WatchConfig};

#[derive(Args, Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct WatchArgs {
    /// Run exactly one poll tick against every configured host, print
    /// the report, and exit. Mutually exclusive with `--daemon`.
    #[arg(long, conflicts_with = "daemon")]
    pub once: bool,
    /// Loop forever, polling every `--interval-secs`. SIGINT / SIGTERM
    /// trigger a clean shutdown between ticks.
    #[arg(long)]
    pub daemon: bool,
    /// Poll interval in seconds. Clamped to
    /// `[watcher::MIN_POLL_INTERVAL_SECS, watcher::MAX_POLL_INTERVAL_SECS]`.
    #[arg(long, default_value_t = watcher::DEFAULT_POLL_INTERVAL_SECS)]
    pub interval_secs: u64,
    /// Restrict polling to specific hosts (`claude-code` | `codex` |
    /// `gemini`). Repeat the flag for multiple. Default: all three.
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,
    /// Namespace override for captured memories. Defaults to the
    /// resolved default namespace (matches `recover-previous-session`).
    #[arg(long)]
    pub namespace: Option<String>,
    /// Max lines atomised per host, per tick.
    #[arg(long, default_value_t = watcher::DEFAULT_WATCH_LIMIT)]
    pub limit: usize,
    /// Parse + report only, no writes.
    #[arg(long)]
    pub dry_run: bool,
    /// Emit machine-readable JSON instead of a human-readable summary.
    #[arg(long)]
    pub json: bool,
}

/// Parse a `--host` string into a [`HostKind`]. Unrecognized values are
/// rejected up front (fail-fast CLI validation) rather than silently
/// falling back to a default host.
///
/// Matches against [`HostKind::as_str`] (the SSOT for the host-tag
/// vocabulary) rather than embedding a second copy of the per-vendor
/// literal strings — vendor-identifier duplication outside the
/// allowlisted carve-out files (`scripts/check-vendor-literals.sh`) is
/// a lint-gated regression class this deliberately avoids.
fn parse_host(s: &str) -> Result<HostKind> {
    watcher::default_watch_hosts()
        .into_iter()
        .find(|h| h.as_str() == s)
        .ok_or_else(|| {
            let expected: Vec<&str> = watcher::default_watch_hosts()
                .iter()
                .map(|h| h.as_str())
                .collect();
            anyhow::anyhow!(
                "unrecognized --host '{s}' (expected one of: {})",
                expected.join(", ")
            )
        })
}

/// Build the watcher's runtime config from CLI args + the resolved
/// top-level `--agent-id` (mirrors every other daemon-style subcommand
/// that threads `cli_agent_id` through from `daemon_runtime::run`).
fn build_config(args: &WatchArgs, cli_agent_id: Option<&str>) -> Result<WatchConfig> {
    let agent_id = crate::identity::resolve_agent_id(cli_agent_id, None)?;
    let hosts = if args.hosts.is_empty() {
        watcher::default_watch_hosts()
    } else {
        args.hosts
            .iter()
            .map(|h| parse_host(h))
            .collect::<Result<Vec<_>>>()?
    };
    Ok(WatchConfig {
        hosts,
        poll_interval: watcher::clamp_poll_interval(args.interval_secs),
        agent_id,
        namespace: args.namespace.clone(),
        limit: args.limit.max(1),
        dry_run: args.dry_run,
    })
}

fn print_watch_report(r: &watcher::WatchReport, out: &mut CliOutput<'_>) -> Result<()> {
    writeln!(out.stdout, "L3 watch report")?;
    writeln!(out.stdout, "  ticks:             {}", r.ticks)?;
    writeln!(out.stdout, "  changes_detected:  {}", r.changes_detected)?;
    writeln!(out.stdout, "  memories_captured: {}", r.memories_captured)?;
    writeln!(out.stdout, "  errors_total:      {}", r.errors)?;
    for o in &r.last_tick {
        write!(
            out.stdout,
            "  host={} changed={}",
            o.host.as_str(),
            o.changed
        )?;
        if let Some(e) = &o.error {
            writeln!(out.stdout, " error={e}")?;
        } else {
            writeln!(out.stdout)?;
        }
    }
    Ok(())
}

/// `watch` handler. `--daemon` delegates to `daemon_runtime`.
///
/// # Errors
///
/// Returns an error when neither `--once` nor `--daemon` is passed, an
/// unrecognized `--host` value is supplied, or agent-id resolution
/// fails. Per-host recovery failures are NOT propagated — they surface
/// under the report's per-host `error` field so a single bad
/// transcript can never abort the tick for the remaining hosts.
pub async fn run(
    db_path: &Path,
    args: &WatchArgs,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if !args.once && !args.daemon {
        anyhow::bail!("watch requires --once or --daemon");
    }

    let cfg = build_config(args, cli_agent_id)?;

    if args.once {
        let mut states = std::collections::HashMap::new();
        let outcomes = watcher::poll_once(db_path, &cfg, &mut states);
        let mut report = watcher::WatchReport::default();
        report.absorb_tick(outcomes);
        if args.json {
            writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
        } else {
            print_watch_report(&report, out)?;
        }
        return Ok(());
    }

    // Daemon mode — delegate to daemon_runtime (same Notify->AtomicBool
    // bridge every other daemon-style CLI subcommand uses, e.g.
    // `cli::curator::run`'s `--daemon` arm).
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_for_signal = shutdown.clone();
    tokio::spawn(async move {
        // Honour BOTH SIGINT (ctrl_c, cross-platform) and — on unix —
        // SIGTERM, so `systemd stop` / `docker stop` / `kill` trigger the
        // same clean between-ticks shutdown the `--daemon` doc promises
        // (issue #2119). On non-unix targets only SIGINT is available.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).ok();
            let term_fut = async {
                match term.as_mut() {
                    Some(t) => {
                        t.recv().await;
                    }
                    // No SIGTERM handler could be installed — park
                    // forever so `select!` resolves on ctrl_c alone.
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                () = term_fut => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown_for_signal.notify_one();
    });

    crate::daemon_runtime::run_watch_daemon_with_primitives(db_path.to_path_buf(), cfg, shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    fn default_args() -> WatchArgs {
        WatchArgs {
            once: false,
            daemon: false,
            interval_secs: watcher::DEFAULT_POLL_INTERVAL_SECS,
            hosts: Vec::new(),
            namespace: Some("test-watch".to_string()),
            limit: watcher::DEFAULT_WATCH_LIMIT,
            dry_run: false,
            json: false,
        }
    }

    #[tokio::test]
    async fn requires_once_or_daemon() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = default_args();
        let mut out = env.output();
        let res = run(&db, &args, Some("ai:test:watch"), &mut out).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("--once or --daemon"));
    }

    #[tokio::test]
    async fn once_runs_single_tick_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        args.once = true;
        {
            let mut out = env.output();
            run(&db, &args, Some("ai:test:watch"), &mut out)
                .await
                .unwrap();
        }
        assert!(env.stdout_str().contains("L3 watch report"));
    }

    #[tokio::test]
    async fn once_json_format() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        args.once = true;
        args.json = true;
        {
            let mut out = env.output();
            run(&db, &args, Some("ai:test:watch"), &mut out)
                .await
                .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["ticks"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn once_restricted_to_single_host() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        args.once = true;
        args.json = true;
        args.hosts = vec!["codex".to_string()];
        {
            let mut out = env.output();
            run(&db, &args, Some("ai:test:watch"), &mut out)
                .await
                .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let last_tick = v["last_tick"].as_array().unwrap();
        assert_eq!(last_tick.len(), 1);
        assert_eq!(last_tick[0]["host"], "codex");
    }

    #[tokio::test]
    async fn unrecognized_host_is_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        args.once = true;
        args.hosts = vec!["cursor".to_string()];
        let mut out = env.output();
        let res = run(&db, &args, Some("ai:test:watch"), &mut out).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("unrecognized --host"));
    }

    #[test]
    fn parse_host_rejects_unknown() {
        assert!(parse_host("bogus").is_err());
        assert!(parse_host("claude-code").is_ok());
        assert!(parse_host("codex").is_ok());
        assert!(parse_host("gemini").is_ok());
    }
}
