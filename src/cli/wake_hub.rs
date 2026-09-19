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
//! ai-memory wake-hub --health             # probe the socket; exit 0 / 2 (#3471)
//! ai-memory wake-hub --health --json      # machine-readable reachability
//! ```
//!
//! # The health probe is an ORDINARY client (#3471)
//!
//! `--health` connects to the configured socket, waits for the hub's opening
//! challenge, and closes. It is deliberately NOT a privileged side channel, NOT
//! a bypass of the peer-credential gate, and NOT an authenticated session: it
//! presents no identity and sends no frame, so it needs no credential and can
//! enumerate nothing. It proves liveness only because it takes the same road
//! every agent takes.
//!
//! # There is no `--insecure` flag, and there never will be
//!
//! Production uses a scoped delegation verifier over a refreshed public cache.
//! Without a configured cache it refuses every hello. Tests inject their own
//! verifier through the library API; the CLI exposes no permissive override.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::CliOutput;
use crate::config::AppConfig;
use std::sync::Arc;

use crate::wake_hub::allowlist_reload::{AdmitReadiness, SnapshotFreshness};
use crate::wake_hub::delegation_verifier::{
    AllowlistCache, ReloadingAllowlist, ScopedDelegationVerifier,
};
use crate::wake_hub::limits::{
    DESIRED_NOFILE, DRAIN_DEADLINE_MS, HEALTH_PROBE_TIMEOUT_MS, SLOW_CONSUMER_PERCENT,
};
use crate::wake_hub::metrics::MetricsSnapshot;
use crate::wake_hub::{HubConfig, HubDeps, WakeHub, health, startup};

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
    /// Derived allowlist cache: the agents permitted to join, with their
    /// ENROLLED public keys. Public material only, 0600, refreshed out of band
    /// from ai-memory. Without it the hub admits nobody.
    #[arg(long, value_name = "PATH")]
    pub allowlist: Option<PathBuf>,
    /// Print the resolved posture (socket path, limits, identity state) and
    /// exit WITHOUT binding. Safe to run against a host already serving a hub.
    #[arg(long)]
    pub posture: bool,
    /// Probe the configured socket as an ORDINARY client and report whether the
    /// hub is reachable. Binds nothing, presents no identity, sends no frame.
    /// Exits non-zero when the hub is unreachable, so it is usable as a systemd
    /// `ExecStartPost` / watchdog or a launchd health check.
    #[arg(long)]
    pub health: bool,
    /// With `--posture`: EXIT NON-ZERO when the resolved allowlist snapshot
    /// admits nobody (empty, aged-out, unreadable, or absent). The credential-
    /// free admit-readiness gate the pre-auth `--health` probe cannot be — usable
    /// as a systemd `ExecStartPost` so a hub that admits nobody goes RED honestly
    /// (#3643). Reports the same `admits` / `admits_nobody` the JSON posture
    /// carries; it only decides the exit code, never the output.
    #[arg(long)]
    pub require_admits: bool,
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
    hub.allowlist_path = args
        .allowlist
        .clone()
        .or_else(|| cfg_block.allowlist.clone());
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
            (health::KEY_SOCKET_MODE): format!("{:04o}", startup::SOCKET_MODE),
            (health::KEY_SOCKET_DIR_MODE): format!("{:04o}", startup::SOCKET_DIR_MODE),
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
            "identity_verifier": IdentityPosture::resolve(cfg).label(),
            "identity_note": IdentityPosture::resolve(cfg).note(),
            "allowlist": cfg
                .allowlist_path
                .as_ref()
                .map(|p| p.display().to_string()),
            // #3504 — the hub refuses every hello once the snapshot passes
            // MAX_CACHE_AGE_SECS, so the operator must be able to see the
            // refresher fall behind before the agents do.
            "allowlist_snapshot": SnapshotFreshness::observe(cfg.allowlist_path.as_deref())
                .to_json(),
            // #3643 — the credential-free ADMIT dimension the pre-auth `--health`
            // probe is structurally blind to: how many principals this snapshot
            // will admit RIGHT NOW, and whether that is nobody. Read from the same
            // parsed snapshot the runtime verifier admits against, gated by the
            // same freshness ceiling — a fresh-but-empty (REPLACE_AGENT_ID) or
            // aged-out snapshot reports `admits_nobody: true` here while `--health`
            // still reports the socket reachable.
            "admit_readiness": AdmitReadiness::observe(cfg.allowlist_path.as_deref())
                .to_json(),
            // #3471 ops surface.
            "drain_deadline_ms": DRAIN_DEADLINE_MS,
            "slow_consumer_percent": SLOW_CONSUMER_PERCENT,
            "health_probe_timeout_ms": HEALTH_PROBE_TIMEOUT_MS,
            "fd_budget": fd_budget_json(cfg),
            "socket_posture": health::SocketPosture::read(&cfg.socket_path).to_json(),
            // The STABLE metric shape, at rest. `--posture` binds nothing, so
            // there are no live counters to report — publishing the schema is
            // the honest thing a non-binding verb CAN offer, and it lets an
            // exporter be written against a documented contract instead of
            // against whatever a running hub happened to emit.
            "metrics_schema": MetricsSnapshot::default().to_json(),
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
    let posture = IdentityPosture::resolve(cfg);
    writeln!(out.stdout, "  identity verifier:     {}", posture.label())?;
    writeln!(
        out.stdout,
        "  allowlist:             {}",
        cfg.allowlist_path.as_ref().map_or_else(
            || "<none configured>".to_string(),
            |p| p.display().to_string()
        )
    )?;
    writeln!(
        out.stdout,
        "  allowlist snapshot:    {}",
        SnapshotFreshness::observe(cfg.allowlist_path.as_deref()).summary()
    )?;
    // #3643 admit dimension — the state `--health` cannot see.
    let admit = AdmitReadiness::observe(cfg.allowlist_path.as_deref());
    writeln!(
        out.stdout,
        "  admits:                {}{}",
        admit.admits,
        if admit.admits_nobody {
            " — ADMITS NOBODY (empty / aged-out / absent allowlist; `--health` cannot see this)"
        } else {
            " principal(s)"
        }
    )?;
    // #3471 ops block.
    let fd = fd_budget_facts(cfg);
    writeln!(
        out.stdout,
        "  fd budget:             soft {} / hard {} (wants {DESIRED_NOFILE}, needs >= {}){}",
        fd.soft,
        fd.hard,
        startup::FdBudget::minimum_soft_nofile(),
        if fd.soft >= DESIRED_NOFILE {
            ""
        } else {
            " — BELOW the desired budget; set LimitNOFILE= / NumberOfFiles"
        }
    )?;
    writeln!(
        out.stdout,
        "  drain deadline:        {DRAIN_DEADLINE_MS} ms (SIGTERM/SIGINT; nothing content-bearing is emitted)"
    )?;
    writeln!(
        out.stdout,
        "  slow-consumer mark:    {SLOW_CONSUMER_PERCENT}% of the per-recipient byte cap"
    )?;
    writeln!(
        out.stdout,
        "  health probe budget:   {HEALTH_PROBE_TIMEOUT_MS} ms (ai-memory wake-hub --health)"
    )?;
    let on_disk = health::SocketPosture::read(&cfg.socket_path);
    writeln!(
        out.stdout,
        "  socket on disk:        {}",
        describe_socket_posture(&on_disk)
    )?;
    writeln!(out.stdout, "  {}", posture.note())?;
    Ok(())
}

/// One-line human summary of what is actually on disk at the socket path.
fn describe_socket_posture(p: &health::SocketPosture) -> String {
    match (p.socket_mode, p.dir_mode) {
        (None, _) => "absent (the hub is not running, or binds elsewhere)".to_string(),
        (Some(sock), dir) => format!(
            "mode {} (dir {}){}",
            health::fmt_mode(sock),
            dir.map_or_else(|| "?".to_string(), health::fmt_mode),
            if p.is_hardened() {
                ", owner-only"
            } else {
                " — NOT owner-only; run `ai-memory doctor`"
            }
        ),
    }
}

/// The process's current `RLIMIT_NOFILE`, read WITHOUT raising it.
///
/// `--posture` binds nothing and must change nothing, so it reports the
/// inherited limit rather than calling [`startup::configure_fd_limit`], which
/// would mutate the process it is describing.
fn fd_budget_facts(_cfg: &HubConfig) -> FdLimitFacts {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes into a fully-owned, correctly-typed local and
    // reads no pointer of ours. Same call shape as `startup::configure_fd_limit`.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) };
    if rc == 0 {
        FdLimitFacts {
            soft: u64::from(rl.rlim_cur),
            hard: u64::from(rl.rlim_max),
        }
    } else {
        FdLimitFacts { soft: 0, hard: 0 }
    }
}

/// The inherited file-descriptor limits, as reported by `--posture`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FdLimitFacts {
    soft: u64,
    hard: u64,
}

/// JSON view of [`fd_budget_facts`].
fn fd_budget_json(cfg: &HubConfig) -> serde_json::Value {
    let fd = fd_budget_facts(cfg);
    serde_json::json!({
        "soft": fd.soft,
        "hard": fd.hard,
        "desired": DESIRED_NOFILE,
        "minimum_to_bind": startup::FdBudget::minimum_soft_nofile(),
        "meets_desired": fd.soft >= DESIRED_NOFILE,
        "headroom_reserved": crate::wake_hub::limits::FD_HEADROOM,
    })
}

/// Run the `--health` probe and render it.
///
/// # Errors
///
/// Propagates write failures from `out`. A probe that could not reach the hub
/// is NOT an error — it is a report with a non-zero exit code, because a
/// supervisor needs the exit status and the reason, not a stack of context.
pub async fn run_health(cfg: &HubConfig, json: bool, out: &mut CliOutput<'_>) -> Result<i32> {
    let report = health::probe(&cfg.socket_path).await;
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string_pretty(&report.to_json())?
        )?;
        return Ok(report.exit_code());
    }
    writeln!(out.stdout, "ai-memory wake-hub health")?;
    writeln!(
        out.stdout,
        "  socket:                {}",
        report.socket.display()
    )?;
    writeln!(
        out.stdout,
        "  status:                {}",
        if report.status.is_reachable() {
            "REACHABLE"
        } else {
            "UNREACHABLE"
        }
    )?;
    writeln!(out.stdout, "  detail:                {}", report.status)?;
    if let Some(ms) = report.latency_ms {
        writeln!(out.stdout, "  challenge latency:     {ms} ms")?;
    }
    writeln!(
        out.stdout,
        "  socket on disk:        {}",
        describe_socket_posture(&report.posture)
    )?;
    if !report.status.is_reachable() {
        writeln!(out.stderr, "  fix: {}", report.status.remedy())?;
    }
    Ok(report.exit_code())
}

/// The one place the "identity is not wired yet" wording lives, so the JSON
/// posture, the human posture and the boot banner cannot drift apart.
pub const WAKE_HUB_IDENTITY_NOTE: &str = "every hello is REFUSED: no allowlist is \
     configured, so no agent can present a verifiable delegation. A wake is a hint and the \
     <=60 s backstop poll remains the guarantee, so this degrades wake latency and nothing else";

/// Which identity verifier a resolved configuration will actually install.
///
/// ONE definition, read by the JSON posture, the human posture and the runtime
/// wiring alike. The posture reporting a verifier the hub does not run is worse
/// than no posture at all — an operator would believe identity is enforced when
/// it is not — so the string cannot be written down in more than one place
/// (#3468, Fable ruling 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPosture {
    /// The scoped `a2a-hub/join/v1` delegation verifier is installed.
    Delegation,
    /// No allowlist is configured, so nothing can be admitted.
    DenyAll,
}

impl IdentityPosture {
    /// Resolve the posture the given configuration will produce.
    #[must_use]
    pub fn resolve(cfg: &HubConfig) -> Self {
        if cfg.allowlist_path.is_some() {
            Self::Delegation
        } else {
            Self::DenyAll
        }
    }

    /// The stable label the posture surfaces report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Delegation => "delegation/v1",
            Self::DenyAll => "deny-all",
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::Delegation => {
                "hellos are admitted only with a scoped a2a-hub/join/v1 \
                 delegation minted by an agent's ENROLLED key, bound to this hub and to the \
                 presented hello key, inside a bounded window"
            }
            Self::DenyAll => WAKE_HUB_IDENTITY_NOTE,
        }
    }
}

/// Process exit when `--posture --require-admits` finds the hub admits nobody.
///
/// Distinct from [`health::EXIT_UNREACHABLE`] (`2`) so a systemd journal can
/// tell "the socket did not answer" apart from "the socket answered but the
/// allowlist admits nobody" — the #3643 failure the pre-auth `--health` probe
/// is structurally blind to.
pub const EXIT_ADMITS_NOBODY: i32 = 3;

/// Bind and serve until SIGINT / SIGTERM, or run one of the non-binding
/// reporting modes.
///
/// Returns the process exit code: `0` for a clean serve or a healthy probe,
/// [`health::EXIT_UNREACHABLE`] when `--health` could not reach the hub.
///
/// # Errors
///
/// Propagates every start-up refusal from [`WakeHub::bind`], and write failures
/// from the reporting modes.
pub async fn dispatch(args: &WakeHubArgs, app_config: &AppConfig) -> Result<i32> {
    let cfg = resolve_config(args, app_config)?;
    if args.posture || args.health {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut so = stdout.lock();
        let mut se = stderr.lock();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        // `--posture` wins when both are given: it is the strictly
        // non-interacting one, and reporting the resolved configuration before
        // probing anything is the order an operator debugs in.
        if args.posture {
            print_posture(&cfg, args, &mut out)?;
            // #3643 admit-readiness gate. `--posture` alone is a non-interacting
            // INSPECTION and always exits 0; `--require-admits` turns the same
            // admit dimension the JSON already reported into an EXIT so a systemd
            // ExecStartPost can go RED on a hub that admits nobody. It reads the
            // same `admits_nobody` value print_posture just surfaced.
            if args.require_admits
                && AdmitReadiness::observe(cfg.allowlist_path.as_deref()).admits_nobody
            {
                return Ok(EXIT_ADMITS_NOBODY);
            }
            return Ok(0);
        }
        return run_health(&cfg, args.json, &mut out).await;
    }

    // Resolve the posture and BUILD THE VERIFIER before `cfg` is consumed, so
    // what the operator was told in `--posture` is what actually gets
    // installed. Any failure to load the allowlist is a refusal to start: a hub
    // that silently fell back to deny-all after being handed an allowlist would
    // be reporting one posture and running another.
    let posture = IdentityPosture::resolve(&cfg);
    let deps = match &cfg.allowlist_path {
        Some(path) => {
            let cache = AllowlistCache::load_from_file(path)?;
            tracing::info!(
                verifier = posture.label(),
                agents = cache.len(),
                allowlist = %path.display(),
                "wake-hub: scoped delegation verification is armed"
            );
            HubDeps {
                verifier: Arc::new(ScopedDelegationVerifier::new(ReloadingAllowlist::new(
                    path.clone(),
                )?)),
                ..HubDeps::default()
            }
        }
        None => {
            tracing::warn!(
                "wake-hub: no allowlist configured — {}",
                IdentityPosture::DenyAll.note()
            );
            HubDeps::default()
        }
    };
    let hub = WakeHub::bind(cfg, deps)?;
    // A completed drain is a SUCCESSFUL shutdown: exit 0, so `systemctl stop`
    // and `launchctl bootout` do not record a failure for the thing they asked
    // for (#3471).
    hub.serve(shutdown_signal()).await?;
    Ok(0)
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
            allowlist: None,
            posture: false,
            health: false,
            require_admits: false,
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

    /// Ruling 4 (#3468): the posture must report the verifier the hub will
    /// ACTUALLY install. JSON, human text and the config knob are pinned
    /// together in one test, because the failure mode is precisely the three
    /// drifting apart — an operator reading `deny-all` while a delegation
    /// verifier runs, or the reverse, is worse than no posture at all.
    #[test]
    fn posture_reports_the_configured_verifier_in_both_renderings() {
        for (allowlist, expected_label) in [
            (None, "deny-all"),
            (Some(PathBuf::from("/tmp/allow-3468.json")), "delegation/v1"),
        ] {
            let mut a = args();
            a.socket = Some(PathBuf::from("/tmp/never-bound-3468.sock"));
            a.allowlist = allowlist.clone();
            a.posture = true;
            let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
            assert_eq!(
                IdentityPosture::resolve(&cfg).label(),
                expected_label,
                "the knob decides the posture"
            );

            // Human rendering.
            let mut so = Vec::new();
            let mut se = Vec::new();
            let mut out = CliOutput::from_std(&mut so, &mut se);
            print_posture(&cfg, &a, &mut out).expect("posture");
            let text = String::from_utf8(so).expect("utf8");
            assert!(
                text.contains(expected_label),
                "human posture must name the verifier: {text}"
            );
            assert!(text.contains("carries message bodies: no"));

            // Machine rendering.
            let mut a_json = a.clone();
            a_json.json = true;
            let mut so = Vec::new();
            let mut se = Vec::new();
            let mut out = CliOutput::from_std(&mut so, &mut se);
            print_posture(&cfg, &a_json, &mut out).expect("posture");
            let doc: serde_json::Value = serde_json::from_slice(&so).expect("valid JSON");
            assert_eq!(doc["identity_verifier"], expected_label);
            assert_eq!(doc["carries_message_bodies"], false);
            assert_eq!(doc["socket_mode"], "0600");
            assert_eq!(doc["socket_dir_mode"], "0700");
            assert_eq!(
                doc["identity_note"],
                IdentityPosture::resolve(&cfg).note(),
                "the note must come from the same SSOT as the label"
            );

            assert!(
                !std::path::Path::new("/tmp/never-bound-3468.sock").exists(),
                "--posture must never create a socket"
            );
        }
    }

    #[test]
    fn an_absent_allowlist_resolves_to_deny_all() {
        // The fail-closed default is a property of the CONFIG, not of a code
        // path somebody remembered to take.
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/x.sock"));
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        assert!(cfg.allowlist_path.is_none());
        assert_eq!(IdentityPosture::resolve(&cfg), IdentityPosture::DenyAll);
    }

    #[test]
    fn the_allowlist_flag_beats_the_config_block() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/x.sock"));
        a.allowlist = Some(PathBuf::from("/tmp/from-flag.json"));
        let mut app = AppConfig::default();
        app.wake_hub = Some(WakeHubConfig {
            allowlist: Some(PathBuf::from("/tmp/from-config.json")),
            ..WakeHubConfig::default()
        });
        let cfg = resolve_config(&a, &app).expect("resolve");
        assert_eq!(
            cfg.allowlist_path,
            Some(PathBuf::from("/tmp/from-flag.json"))
        );
    }

    /// #3471 — the ops facts are part of the posture contract: an operator who
    /// cannot see the fd budget, the drain deadline and the metric schema from
    /// `--posture` has to read the source to write an alert rule.
    #[test]
    fn the_posture_reports_the_ops_budgets_and_the_metric_schema() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/never-bound-3471.sock"));
        a.posture = true;
        a.json = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        print_posture(&cfg, &a, &mut out).expect("posture");
        let doc: serde_json::Value = serde_json::from_slice(&so).expect("valid JSON");

        assert_eq!(doc["drain_deadline_ms"], DRAIN_DEADLINE_MS);
        assert_eq!(doc["slow_consumer_percent"], SLOW_CONSUMER_PERCENT);
        assert_eq!(doc["health_probe_timeout_ms"], HEALTH_PROBE_TIMEOUT_MS);
        assert_eq!(doc["fd_budget"]["desired"], DESIRED_NOFILE);
        assert_eq!(
            doc["fd_budget"]["minimum_to_bind"],
            startup::FdBudget::minimum_soft_nofile()
        );
        assert!(doc["fd_budget"]["soft"].as_u64().is_some());
        // The metric schema is present and shaped, and reads as "no traffic"
        // rather than as "everything is instantaneous".
        assert_eq!(doc["metrics_schema"]["connections_current"], 0);
        assert!(doc["metrics_schema"]["queue"].is_object());
        assert!(doc["metrics_schema"]["drops"].is_object());
        assert!(doc["metrics_schema"]["fanout_latency_us"]["p99"].is_null());
        // A posture run binds NOTHING.
        assert!(!std::path::Path::new("/tmp/never-bound-3471.sock").exists());
    }

    #[test]
    fn the_human_posture_names_the_drain_and_the_fd_budget() {
        let mut a = args();
        a.socket = Some(PathBuf::from("/tmp/never-bound-3471b.sock"));
        a.posture = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        print_posture(&cfg, &a, &mut out).expect("posture");
        let text = String::from_utf8(so).expect("utf8");
        assert!(text.contains("drain deadline"), "{text}");
        assert!(text.contains("fd budget"), "{text}");
        assert!(text.contains("slow-consumer mark"), "{text}");
        assert!(text.contains("socket on disk"), "{text}");
    }

    /// #3471 — the DENIED half of the health probe: an unreachable hub exits
    /// non-zero and says why. This is the property a supervisor depends on.
    #[tokio::test]
    async fn the_health_probe_exits_non_zero_when_the_hub_is_unreachable() {
        let tmp = tempfile::tempdir().expect("tmp");
        let mut a = args();
        a.socket = Some(tmp.path().join("absent.sock"));
        a.health = true;
        a.json = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let code = run_health(&cfg, true, &mut out).await.expect("render");
        assert_eq!(code, health::EXIT_UNREACHABLE);
        let doc: serde_json::Value = serde_json::from_slice(&so).expect("valid JSON");
        assert_eq!(doc["reachable"], false);
        assert_eq!(doc["status"], "socket_missing");
        assert!(
            doc["remedy"].as_str().is_some_and(|s| !s.is_empty()),
            "an unreachable report must carry a remedy"
        );
    }

    #[tokio::test]
    async fn the_human_health_report_names_the_socket_and_the_fix() {
        let tmp = tempfile::tempdir().expect("tmp");
        let mut a = args();
        a.socket = Some(tmp.path().join("absent.sock"));
        a.health = true;
        let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
        let mut so = Vec::new();
        let mut se = Vec::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let code = run_health(&cfg, false, &mut out).await.expect("render");
        assert_eq!(code, health::EXIT_UNREACHABLE);
        let text = String::from_utf8(so).expect("utf8");
        let err = String::from_utf8(se).expect("utf8");
        assert!(text.contains("UNREACHABLE"), "{text}");
        assert!(err.contains("fix:"), "{err}");
    }
    /// #3643 write a 0600 snapshot naming exactly `n` agents, stamped fresh —
    /// the shape the hub loader demands. `n == 0` is the shipped
    /// REPLACE_AGENT_ID shape (`identity hub-cache` omits the placeholder,
    /// publishing a valid, fresh, ZERO-entry snapshot).
    fn write_snapshot(path: &std::path::Path, n: usize) {
        let proven = crate::identity::pubkey_bind::BindAuthority::PossessionProof.as_str();
        let entries: Vec<(String, &str)> = (0..n)
            .map(|i| (format!("agent-3643-cli-{i}"), proven))
            .collect();
        let borrowed: Vec<(&str, &str)> = entries.iter().map(|(a, b)| (a.as_str(), *b)).collect();
        write_snapshot_entries(path, &borrowed);
    }

    /// #3643 (R2) — the same 0600 fresh snapshot, but with each entry's
    /// `(agent_id, bind_authority)` chosen by the cell, so a pin can name
    /// entries the hub REFUSES at hello (legacy-unproven, `daemon_key_dir` on a
    /// name that is not the reserved producer) next to ones it admits.
    fn write_snapshot_entries(path: &std::path::Path, entries: &[(&str, &str)]) {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let agents: Vec<serde_json::Value> = entries
            .iter()
            .enumerate()
            .map(|(i, (agent_id, authority))| {
                let key = ed25519_dalek::SigningKey::from_bytes(&[0xC0u8 + i as u8; 32]);
                serde_json::json!({
                    "agent_id": agent_id,
                    "pubkey_b64": crate::identity::keypair::encode_public_base64(
                        &key.verifying_key()
                    ),
                    "bind_authority": authority,
                    "bound_at": "2026-09-01T00:00:00Z",
                })
            })
            .collect();
        let body = serde_json::json!({
            "version": crate::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
            "refreshed_at": chrono::Utc::now().to_rfc3339(),
            "agents": agents,
        });
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .expect("create snapshot");
        f.write_all(&serde_json::to_vec(&body).expect("encode"))
            .expect("write snapshot");
        drop(f);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    /// #3643 THE PIN — the admit dimension `--health` is structurally blind to
    /// must be VISIBLE on `--posture --json` AND must drive a non-zero EXIT
    /// under `--require-admits`, so a systemd ExecStartPost can go RED honestly.
    ///
    /// RED LEG: the shipped REPLACE_AGENT_ID shape — a fresh, valid, ZERO-entry
    /// snapshot — reports `admits_nobody: true` / `admits: 0` and exits non-zero.
    /// The "pin that cannot fail" is now ABLE to fail on exactly the state it
    /// exists to catch. ALLOWED-PATH CONTROL: a fresh snapshot naming N > 0
    /// principals reports `admits: N` / `admits_nobody: false` and exits ZERO on
    /// the SAME sink and the SAME gate. Both admit fields are read off
    /// `--posture --json`; both exits off `--posture --require-admits`.
    #[tokio::test]
    async fn require_admits_reds_on_empty_and_greens_on_populated_3643() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let empty = dir.path().join("empty-allow.json");
        write_snapshot(&empty, 0);
        let full = dir.path().join("full-allow.json");
        write_snapshot(&full, 3);

        // Both legs read `admits` / `admits_nobody` off the SAME `--posture --json`
        // sink the operator would read.
        let admit_doc = |path: &std::path::Path| -> serde_json::Value {
            let mut a = args();
            a.socket = Some(dir.path().join("never-bound-3643.sock"));
            a.allowlist = Some(path.to_path_buf());
            a.posture = true;
            a.json = true;
            let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
            let mut so = Vec::new();
            let mut se = Vec::new();
            let mut out = CliOutput::from_std(&mut so, &mut se);
            print_posture(&cfg, &a, &mut out).expect("posture");
            serde_json::from_slice(&so).expect("valid JSON")
        };

        let red = admit_doc(&empty);
        assert_eq!(red["admit_readiness"]["admits"], 0, "empty admits nobody");
        assert_eq!(red["admit_readiness"]["admits_nobody"], true);

        let green = admit_doc(&full);
        assert_eq!(green["admit_readiness"]["admits"], 3, "populated admits N");
        assert_eq!(green["admit_readiness"]["admits_nobody"], false);

        // The EXIT the ExecStartPost consumes — same admit dimension, same gate.
        let mut a_red = args();
        a_red.socket = Some(dir.path().join("never-bound-red.sock"));
        a_red.allowlist = Some(empty.clone());
        a_red.posture = true;
        a_red.require_admits = true;
        let red_exit = dispatch(&a_red, &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(
            red_exit, EXIT_ADMITS_NOBODY,
            "the empty snapshot must go RED under --require-admits"
        );
        assert_ne!(red_exit, 0, "RED means a non-zero exit for ExecStartPost");

        let mut a_green = a_red.clone();
        a_green.allowlist = Some(full.clone());
        let green_exit = dispatch(&a_green, &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(
            green_exit, 0,
            "a snapshot with N > 0 entries must exit ZERO on the same assertion"
        );

        // Plain `--posture` stays an INSPECTION: exit 0 even when it admits
        // nobody, so the gate is opt-in and does not surprise an operator
        // debugging by hand.
        let mut a_plain = a_red.clone();
        a_plain.require_admits = false;
        let plain_exit = dispatch(&a_plain, &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(
            plain_exit, 0,
            "plain --posture is inspection-only and never gates the exit"
        );
    }

    /// #3643 R2 — `admits` is an ADMISSION count, not an ENTRY count. The hello
    /// path admits an entry only if
    /// `RootBindAuthority::from_column(bind_authority).may_delegate_for(agent_id)`
    /// (`delegation_verifier.rs`, the `may_delegate_for` gate); a snapshot whose
    /// entries the hub would refuse must report `admits: 0` / `admits_nobody:
    /// true` and RED the `--require-admits` exit, on the SAME `--posture --json`
    /// sink as the empty/populated pin above. Both halves in one cell:
    /// (absent) N legacy-unproven entries and a `daemon_key_dir` entry on a name
    /// that is not the reserved producer count ZERO; (present) the reserved
    /// `wake-hub-producer` entry with `daemon_key_dir` counts ONE — the one
    /// `daemon_key_dir` name the hub DOES admit, so the fix cannot be "ignore
    /// `daemon_key_dir`" — and a mixed snapshot counts only its admissible entry.
    #[tokio::test]
    async fn require_admits_counts_admissions_not_entries_3643() {
        use crate::identity::pubkey_bind::BindAuthority;
        use crate::identity::sentinels::WAKE_HUB_PRODUCER;
        use crate::wake_hub::delegation_verifier::{
            DAEMON_KEY_DIR_AUTHORITY, LEGACY_UNPROVEN_AUTHORITY,
        };
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let proven = BindAuthority::PossessionProof.as_str();

        let legacy = dir.path().join("legacy-allow.json");
        write_snapshot_entries(
            &legacy,
            &[
                ("agent-3643-legacy-0", LEGACY_UNPROVEN_AUTHORITY),
                ("agent-3643-legacy-1", LEGACY_UNPROVEN_AUTHORITY),
                ("agent-3643-legacy-2", LEGACY_UNPROVEN_AUTHORITY),
            ],
        );
        let impostor = dir.path().join("impostor-allow.json");
        write_snapshot_entries(
            &impostor,
            &[("agent-3643-not-the-producer", DAEMON_KEY_DIR_AUTHORITY)],
        );
        let producer = dir.path().join("producer-allow.json");
        write_snapshot_entries(&producer, &[(WAKE_HUB_PRODUCER, DAEMON_KEY_DIR_AUTHORITY)]);
        let mixed = dir.path().join("mixed-allow.json");
        write_snapshot_entries(
            &mixed,
            &[
                ("agent-3643-legacy-0", LEGACY_UNPROVEN_AUTHORITY),
                ("agent-3643-proven-0", proven),
                ("agent-3643-legacy-1", LEGACY_UNPROVEN_AUTHORITY),
            ],
        );

        let admit_doc = |path: &std::path::Path| -> serde_json::Value {
            let mut a = args();
            a.socket = Some(dir.path().join("never-bound-3643-r2.sock"));
            a.allowlist = Some(path.to_path_buf());
            a.posture = true;
            a.json = true;
            let cfg = resolve_config(&a, &AppConfig::default()).expect("resolve");
            let mut so = Vec::new();
            let mut se = Vec::new();
            let mut out = CliOutput::from_std(&mut so, &mut se);
            print_posture(&cfg, &a, &mut out).expect("posture");
            serde_json::from_slice(&so).expect("valid JSON")
        };
        let gate_args = |path: &std::path::Path| -> WakeHubArgs {
            let mut a = args();
            a.socket = Some(dir.path().join("never-bound-3643-r2.sock"));
            a.allowlist = Some(path.to_path_buf());
            a.posture = true;
            a.require_admits = true;
            a
        };

        // ABSENT — three entries, zero admissions: the hub refuses every one.
        let doc = admit_doc(&legacy);
        assert_eq!(
            doc["admit_readiness"]["admits"], 0,
            "legacy-unproven entries are not admissions: {doc}"
        );
        assert_eq!(doc["admit_readiness"]["admits_nobody"], true);
        let exit = dispatch(&gate_args(&legacy), &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(exit, EXIT_ADMITS_NOBODY);

        // ABSENT — `daemon_key_dir` on a name that is not the reserved producer.
        let doc = admit_doc(&impostor);
        assert_eq!(doc["admit_readiness"]["admits"], 0, "{doc}");
        assert_eq!(doc["admit_readiness"]["admits_nobody"], true);
        let exit = dispatch(&gate_args(&impostor), &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(exit, EXIT_ADMITS_NOBODY);

        // PRESENT — the reserved producer under `daemon_key_dir` IS admitted.
        let doc = admit_doc(&producer);
        assert_eq!(
            doc["admit_readiness"]["admits"], 1,
            "the reserved wake-hub-producer entry is the one daemon_key_dir admission: {doc}"
        );
        assert_eq!(doc["admit_readiness"]["admits_nobody"], false);
        let exit = dispatch(&gate_args(&producer), &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(exit, 0, "the producer entry must green the gate");

        // MIXED — only the admissible entry counts.
        let doc = admit_doc(&mixed);
        assert_eq!(doc["admit_readiness"]["admits"], 1, "{doc}");
        assert_eq!(doc["admit_readiness"]["admits_nobody"], false);
        let exit = dispatch(&gate_args(&mixed), &AppConfig::default())
            .await
            .expect("dispatch");
        assert_eq!(exit, 0);
    }
}
