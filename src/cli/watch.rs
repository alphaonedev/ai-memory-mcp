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
            write!(out.stdout, " error={e}")?;
        }
        // Surface errors EMBEDDED in an otherwise-successful
        // `RecoverReport` (parse failure returns `Ok(report)` with
        // `report.errors` set; per-turn write failures land there too).
        // Without this the human `--once` report printed
        // `errors_total: 0` on a parse-failed tick — the `--json` path
        // already embeds `last_tick`, so only this human path was blind
        // (issue #2136).
        let recover_errors = o
            .recover_report
            .as_ref()
            .map(|rr| rr.errors.as_slice())
            .unwrap_or_default();
        if !recover_errors.is_empty() {
            write!(out.stdout, " recover_errors={}", recover_errors.len())?;
        }
        writeln!(out.stdout)?;
        for e in recover_errors {
            writeln!(out.stdout, "    recover_error: {e}")?;
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

    run_watch_daemon_with_primitives(db_path.to_path_buf(), cfg, shutdown).await
}

/// `Command::Watch` dispatch entry (invoked from
/// [`crate::daemon_runtime::run`]). Owns the stdout-vs-sink output
/// routing: `--daemon` runs a blocking poll loop on a `spawn_blocking`
/// worker that itself logs via `tracing::info!`, so holding the
/// process-wide `Stdout::lock()` across it risks a cross-thread
/// `ReentrantMutex` deadlock — daemon output goes to [`std::io::sink`],
/// while `--once` (which actually emits a report) locks real
/// stdout/stderr. Extracted from `daemon_runtime` so the coverable watch
/// logic lives in this module (issue #1978 coverage; #2088 precedent).
///
/// # Errors
///
/// Propagates [`run`]'s errors (missing `--once`/`--daemon`, unknown
/// `--host`, agent-id resolution). Per-host recovery failures never
/// propagate — see [`run`].
pub async fn dispatch(db_path: &Path, args: &WatchArgs, cli_agent_id: Option<&str>) -> Result<()> {
    if args.daemon {
        let mut so = std::io::sink();
        let mut se = std::io::sink();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(db_path, args, cli_agent_id, &mut out).await
    } else {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut so = stdout.lock();
        let mut se = stderr.lock();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(db_path, args, cli_agent_id, &mut out).await
    }
}

/// Watch-daemon loop body (issue #1978 L3 substrate watcher). Bridges
/// the CLI's [`tokio::sync::Notify`] shutdown signal into the
/// `Arc<AtomicBool>` [`watcher::run_watch_daemon`] checks every 500 ms,
/// then drives the blocking poll loop via `spawn_blocking` — the
/// identical bridge pattern `run_curator_daemon_with_primitives` uses
/// for the curator daemon. Extracted from `daemon_runtime` (issue #1978
/// coverage; #2088 precedent).
///
/// # Errors
///
/// Returns an error only if the `spawn_blocking` join fails (the poll
/// loop itself never propagates a per-host failure — see
/// [`watcher::poll_once`]).
async fn run_watch_daemon_with_primitives(
    db_path: std::path::PathBuf,
    cfg: WatchConfig,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let shutdown_flag = std::sync::Arc::new(AtomicBool::new(false));
    let shutdown_flag_for_signal = shutdown_flag.clone();
    tokio::spawn(async move {
        shutdown.notified().await;
        shutdown_flag_for_signal.store(true, Ordering::Relaxed);
    });

    tokio::task::spawn_blocking(move || {
        watcher::run_watch_daemon(db_path, cfg, shutdown_flag);
    })
    .await
    .map_err(|e| anyhow::anyhow!("watch daemon join: {e}"))?;
    Ok(())
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

    /// `dispatch --once` routes through the stdout-locking (non-sink)
    /// branch and returns cleanly. Extracted from `daemon_runtime`'s
    /// `Command::Watch` arm (issue #1978 coverage; #2088 precedent).
    #[tokio::test]
    async fn dispatch_once_returns_ok() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        args.once = true;
        // Single host keeps the tick light; the report is written to the
        // real (cargo-captured) stdout by the dispatch else-branch.
        args.hosts = vec!["codex".to_string()];
        dispatch(&db, &args, Some("ai:test:watch")).await.unwrap();
    }

    /// Issue #2136 — the human `--once` report must render errors
    /// embedded in a successful `RecoverReport` (a parse-failed tick),
    /// not just the outcome-level `error`. Pre-fix it printed
    /// `errors_total: 0` with zero indication anything had failed.
    #[test]
    fn print_watch_report_surfaces_embedded_recover_errors_2136() {
        let mut env = TestEnv::fresh();
        let mut rr = crate::recover::RecoverReport::new(HostKind::ClaudeCode, 82);
        rr.errors = vec!["parse failed: bad json".to_string()];
        let mut report = watcher::WatchReport::default();
        report.absorb_tick(vec![watcher::HostTickOutcome {
            host: HostKind::ClaudeCode,
            changed: true,
            recover_report: Some(rr),
            error: None,
        }]);
        {
            let mut out = env.output();
            print_watch_report(&report, &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("errors_total:      1"), "cumulative count: {s}");
        assert!(s.contains("recover_errors=1"), "per-host count: {s}");
        assert!(s.contains("parse failed: bad json"), "detail line: {s}");
    }

    /// `dispatch` propagates [`run`]'s missing-mode error (neither
    /// `--once` nor `--daemon`) through the stdout branch.
    #[tokio::test]
    async fn dispatch_requires_once_or_daemon() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = default_args();
        let res = dispatch(&db, &args, Some("ai:test:watch")).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("--once or --daemon"));
    }

    /// The `Notify`→`AtomicBool` shutdown bridge returns cleanly once the
    /// signal fires. A pre-fired `Notify` stores one permit, so the
    /// bridge's spawned task observes shutdown immediately and flips the
    /// flag the blocking poll loop checks every 500 ms. An EMPTY host
    /// list makes the loop fully hermetic (zero resolver walks) so the
    /// test neither touches the real `$HOME` nor the DB. Extracted from
    /// `daemon_runtime` (issue #1978 coverage; #2088 precedent).
    #[tokio::test]
    async fn daemon_primitives_bridge_returns_on_shutdown() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = WatchConfig {
            hosts: Vec::new(),
            poll_interval: watcher::clamp_poll_interval(1),
            agent_id: "ai:test:watch".to_string(),
            namespace: Some("test-watch".to_string()),
            limit: watcher::DEFAULT_WATCH_LIMIT,
            dry_run: false,
        };
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        shutdown.notify_one();
        let res = run_watch_daemon_with_primitives(db, cfg, shutdown).await;
        assert!(res.is_ok());
    }
}
