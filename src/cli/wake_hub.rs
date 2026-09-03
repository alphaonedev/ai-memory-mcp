// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` — CLI surface for the same-host agent wake plane
//! (issue [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467),
//! EPIC [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # Wire shape
//!
//! ```bash
//! ai-memory wake-hub                      # bind and serve until SIGINT/SIGTERM
//! ai-memory wake-hub --socket /run/x.sock # explicit socket path
//! ai-memory wake-hub --posture            # print the resolved posture, bind nothing
//! ai-memory wake-hub --posture --json     # machine-readable posture
//! ```
//!
//! # There is no `--insecure` flag, and there never will be
//!
//! The shipped identity verifier
//! ([`crate::wake_hub::identity::DenyAllVerifier`]) REFUSES every hello until
//! the scoped `a2a-hub/join/v1` delegation lands in
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468). This
//! subcommand deliberately exposes NO way to substitute a permissive verifier:
//! a flag that disables identity verification is a flag that eventually gets
//! set in production. Tests inject their own verifier through the library API
//! ([`crate::wake_hub::WakeHub::bind`]), which the shipped binary never calls
//! with anything but the production gates.
//!
//! Running it today therefore gets you a hub that binds, asserts its start-up
//! invariants, serves metrics — and admits nobody. That is the intended,
//! fail-closed intermediate state, and `--posture` says so out loud.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::wake_hub::{HubConfig, HubDeps, WakeHub, startup};

#[derive(Args, Debug, Clone)]
pub struct WakeHubArgs {
    /// Unix socket to listen on. Overrides `[wake_hub].socket`. The parent
    /// directory must be owner-only (0700); the socket itself is forced to
    /// 0600 and the mode is verified after `chmod`.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Hub identifier bound into every handshake transcript. Overrides
    /// `[wake_hub].hub_id`.
    #[arg(long, value_name = "ID")]
    pub hub_id: Option<String>,
    /// Hard connection ceiling. Further clamped at start-up by the process's
    /// `RLIMIT_NOFILE`. Overrides `[wake_hub].max_connections`.
    #[arg(long, value_name = "N")]
    pub max_connections: Option<usize>,
    /// Print the resolved posture (socket path, limits, identity state) and
    /// exit WITHOUT binding. Safe to run against a host already serving a hub.
    #[arg(long)]
    pub posture: bool,
    /// Emit machine-readable JSON instead of a human-readable report.
    #[arg(long)]
    pub json: bool,
}

/// Resolve the effective hub configuration: CLI flag > `[wake_hub]` config >
/// compiled default.
///
/// # Errors
///
/// Fails when no socket path can be resolved from any of the three sources.
pub fn resolve_config(args: &WakeHubArgs, app_config: &AppConfig) -> Result<HubConfig> {
    let cfg_block = app_config.wake_hub.clone().unwrap_or_default();
    let socket = match args.socket.clone().or_else(|| cfg_block.socket.clone()) {
        Some(p) => p,
        None => HubConfig::default_socket_path()?,
    };
    let mut hub = HubConfig::with_socket_path(socket);
    if let Some(id) = args.hub_id.clone().or_else(|| cfg_block.hub_id.clone()) {
        hub.hub_id = id;
    }
    if let Some(n) = args.max_connections.or(cfg_block.max_connections) {
        hub.max_connections = n;
    }
    if let Some(n) = cfg_block.queue_bytes {
        hub.queue_bytes = n;
    }
    if let Some(n) = cfg_block.global_egress_bytes {
        hub.global_egress_bytes = n;
    }
    if let Some(n) = cfg_block.rate_per_sec {
        hub.rate_per_sec = n;
    }
    if let Some(n) = cfg_block.rate_burst {
        hub.rate_burst = n;
    }
    if let Some(n) = cfg_block.pending_max_agents {
        hub.pending_max_agents = n;
    }
    if let Some(n) = cfg_block.pending_max_ids {
        hub.pending_max_ids = n;
    }
    Ok(hub)
}

/// Render the resolved posture without binding anything.
///
/// # Errors
///
/// Propagates write failures from `out`.
pub fn print_posture(cfg: &HubConfig, args: &WakeHubArgs, out: &mut CliOutput<'_>) -> Result<()> {
    let peer_creds_ok = startup::assert_peer_credentials_available().is_ok();
    if args.json {
        let doc = serde_json::json!({
            "socket": cfg.socket_path.display().to_string(),
            "socket_mode": format!("{:04o}", startup::SOCKET_MODE),
            "socket_dir_mode": format!("{:04o}", startup::SOCKET_DIR_MODE),
            "hub_id": cfg.hub_id,
            "max_connections": cfg.max_connections,
            "queue_bytes_per_recipient": cfg.queue_bytes,
            "global_egress_bytes": cfg.global_egress_bytes,
            "rate_per_sec": cfg.rate_per_sec,
            "rate_burst": cfg.rate_burst,
            "preauth_rate_per_sec": cfg.preauth_rate_per_sec,
            "preauth_burst": cfg.preauth_burst,
            "pending_max_agents": cfg.pending_max_agents,
            "pending_max_ids_per_agent": cfg.pending_max_ids,
            "reconnect_base_ms": cfg.reconnect_base_ms,
            "reconnect_jitter_ms": cfg.reconnect_jitter_ms,
            "peer_credentials_available": peer_creds_ok,
            "carries_message_bodies": false,
            "identity_verifier": "deny-all",
            "identity_note": WAKE_HUB_IDENTITY_NOTE,
        });
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&doc)?)?;
        return Ok(());
    }
    writeln!(out.stdout, "ai-memory wake-hub posture")?;
    writeln!(
        out.stdout,
        "  socket:                {}",
        cfg.socket_path.display()
    )?;
    writeln!(
        out.stdout,
        "  socket mode:           {:04o} (dir {:04o})",
        startup::SOCKET_MODE,
        startup::SOCKET_DIR_MODE
    )?;
    writeln!(out.stdout, "  hub id:                {}", cfg.hub_id)?;
    writeln!(
        out.stdout,
        "  max connections:       {}",
        cfg.max_connections
    )?;
    writeln!(
        out.stdout,
        "  per-recipient queue:   {} bytes",
        cfg.queue_bytes
    )?;
    writeln!(
        out.stdout,
        "  global egress cap:     {} bytes",
        cfg.global_egress_bytes
    )?;
    writeln!(
        out.stdout,
        "  rate limit:            {}/s burst {} (pre-auth {}/s burst {})",
        cfg.rate_per_sec, cfg.rate_burst, cfg.preauth_rate_per_sec, cfg.preauth_burst
    )?;
    writeln!(
        out.stdout,
        "  offline coalescing:    {} agents x {} ids",
        cfg.pending_max_agents, cfg.pending_max_ids
    )?;
    writeln!(
        out.stdout,
        "  peer credentials:      {}",
        if peer_creds_ok {
            "available (uid + pid)"
        } else {
            "UNAVAILABLE — the hub will refuse to start"
        }
    )?;
    writeln!(out.stdout, "  carries message bodies: no (structurally)")?;
    writeln!(out.stdout, "  identity verifier:     deny-all")?;
    writeln!(out.stdout, "  {WAKE_HUB_IDENTITY_NOTE}")?;
    Ok(())
}

/// The one place the "identity is not wired yet" wording lives, so the JSON
/// posture, the human posture and the boot banner cannot drift apart.
pub const WAKE_HUB_IDENTITY_NOTE: &str = "every hello is REFUSED until the scoped \
     a2a-hub/join/v1 delegation lands (#3468); a wake is a hint and the <=60 s backstop \
     poll remains the guarantee, so this degrades wake latency and nothing else";

/// Bind and serve until SIGINT / SIGTERM.
///
/// # Errors
///
/// Propagates every start-up refusal from [`WakeHub::bind`].
pub async fn dispatch(args: &WakeHubArgs, app_config: &AppConfig) -> Result<()> {
    let cfg = resolve_config(args, app_config)?;
    if args.posture {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut so = stdout.lock();
        let mut se = stderr.lock();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        return print_posture(&cfg, args, &mut out);
    }

    let hub = WakeHub::bind(cfg, HubDeps::default())?;
    tracing::warn!("wake-hub: identity verification is NOT wired yet — {WAKE_HUB_IDENTITY_NOTE}");
    hub.serve(shutdown_signal()).await
}

/// Resolve on SIGINT or, on unix, SIGTERM — so `systemctl stop`, `docker stop`
/// and a plain `kill` all trigger the same bounded drain.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        let term_fut = async {
            match term.as_mut() {
                Some(t) => {
                    t.recv().await;
                }
                // No SIGTERM handler could be installed — park forever so the
                // select resolves on ctrl_c alone.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WakeHubConfig;
    use crate::wake_hub::limits::{DEFAULT_MAX_CONNECTIONS, DEFAULT_RATE_TOKENS_PER_SEC};

    fn args() -> WakeHubArgs {
        WakeHubArgs {
            socket: None,
            hub_id: None,
            max_connections: None,
            posture: false,
            json: false,
        }
    }

    #[test]
    fn a_cli_flag_beats_the_config_block() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/flag.sock"));
        a.max_connections = Some(9);
        let mut app = AppConfig::default();
        app.wake_hub = Some(WakeHubConfig {
            socket: Some(PathBuf::from("/tmp/config.sock")),
            max_connections: Some(77),
            ..WakeHubConfig::default()
        });
        let cfg = resolve_config(&a, &app).expect("resolve");
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/flag.sock"));
        assert_eq!(cfg.max_connections, 9);
    }

    #[test]
    fn the_config_block_beats_the_compiled_default() {
        let mut app = AppConfig::default();
        app.wake_hub = Some(WakeHubConfig {
            socket: Some(PathBuf::from("/tmp/config.sock")),
            hub_id: Some("hub-b".into()),
            rate_per_sec: Some(11),
            ..WakeHubConfig::default()
        });
        let cfg = resolve_config(&args(), &app).expect("resolve");
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/config.sock"));
        assert_eq!(cfg.hub_id, "hub-b");
        assert_eq!(cfg.rate_per_sec, 11);
        assert_eq!(
            cfg.max_connections, DEFAULT_MAX_CONNECTIONS,
            "an unset config key must fall through to the compiled default"
        );
    }

    #[test]
    fn an_absent_config_block_yields_the_compiled_defaults() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/x.sock"));
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        assert_eq!(cfg.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(cfg.rate_per_sec, DEFAULT_RATE_TOKENS_PER_SEC);
    }

    #[test]
    fn posture_reports_deny_all_and_never_binds() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/never-bound-3467.sock"));
        a.posture = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        print_posture(&cfg, &a, &mut out).expect("posture");
        let text = String::from_utf8(so).expect("utf8");
        assert!(text.contains("deny-all"));
        assert!(text.contains("carries message bodies: no"));
        assert!(text.contains("#3468"));
        assert!(
            !std::path::Path::new("/tmp/never-bound-3467.sock").exists(),
            "--posture must never create a socket"
        );
    }

    #[test]
    fn posture_json_is_machine_readable_and_declares_the_content_free_contract() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/x.sock"));
        a.posture = true;
        a.json = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        print_posture(&cfg, &a, &mut out).expect("posture");
        let doc: serde_json::Value =
            serde_json::from_slice(&so).expect("posture --json must be valid JSON");
        assert_eq!(doc["identity_verifier"], "deny-all");
        assert_eq!(doc["carries_message_bodies"], false);
        assert_eq!(doc["socket_mode"], "0600");
        assert_eq!(doc["socket_dir_mode"], "0700");
    }
}
