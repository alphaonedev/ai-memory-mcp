// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-listen` — the long-lived wake-hub CLIENT (issue
//! [#3470](https://github.com/alphaonedev/ai-memory-mcp/issues/3470),
//! EPIC [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # What replaces what
//!
//! The fleet's prior shape was a cron-ish `ai-memory inbox` every three
//! minutes: one process boot per poll, three minutes of worst-case latency,
//! and a database read whether or not anything happened. This keeps ONE
//! session on the hub's socket and reads the inbox when there is something to
//! read — plus a bounded `<= 60 s` poll so a lost hub costs latency and
//! nothing else.
//!
//! # Wire shape
//!
//! ```bash
//! ai-memory wake-listen --agent-id ai:alice --json
//! ai-memory wake-listen --agent-id ai:alice --exec 'notify-send "$AI_MEMORY_WAKE_SENDER"'
//! ai-memory wake-listen --agent-id ai:alice --once          # exit after one catch-up
//! ai-memory inbox --wait --timeout 300 --agent-id ai:alice  # block, then print
//! ```
//!
//! # The exec hook gets METADATA, never a body
//!
//! `--exec` runs `sh -c <cmd>` with the wake hint in the environment. The hub
//! carries no message body — structurally, not by policy — so neither does
//! this: the hook receives the row ID it should read and the SHA-256 digest it
//! can verify what it read against. Passing the metadata through the
//! ENVIRONMENT rather than through the command line keeps wire-sourced values
//! off `ps` output and out of shell word-splitting.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `AI_MEMORY_WAKE_REASON` | `welcome` \| `lagged` \| `wake` \| `gap` \| `backstop` |
//! | `AI_MEMORY_WAKE_AGENT_ID` | the listening agent |
//! | `AI_MEMORY_WAKE_HUB_ID` | the hub this session joined |
//! | `AI_MEMORY_WAKE_INBOX_ROW_ID` | the durable row the hint names (empty when none) |
//! | `AI_MEMORY_WAKE_NAMESPACE` | namespace the row landed in |
//! | `AI_MEMORY_WAKE_SENDER` | agent that wrote the row |
//! | `AI_MEMORY_WAKE_DIGEST` | lowercase hex SHA-256 OF THE BODY — never the body |
//! | `AI_MEMORY_WAKE_SEQ` | the producer's wake watermark at mint time |
//! | `AI_MEMORY_WAKE_MISSED` | wakes this listener demonstrably did not see |
//! | `AI_MEMORY_WAKE_PENDING` | wakes the hub coalesced while offline |
//! | `AI_MEMORY_WAKE_INBOX_COUNT` | messages the catch-up read returned |
//!
//! A hook is bounded by [`EXEC_HOOK_TIMEOUT`] and killed past it: a hung hook
//! must not become a listener that stops reading its inbox.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::identity::keypair;
use crate::wake_client::{
    HubJoinBundle, SessionConfig, WakeClientConfig, WakeReason, WakeSignal, WakeStream,
};
use crate::wake_hub::DEFAULT_HUB_ID;
use crate::wake_sink::BACKSTOP_POLL_MAX;

/// How long an `--exec` hook may run before it is killed.
///
/// Not an operator knob on purpose: the value that matters is that SOME bound
/// exists, and a hook allowed to outlive the backstop interval would turn one
/// slow notifier into a listener that stops reading its inbox.
pub const EXEC_HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Shell used to run an `--exec` hook, so operators can write pipelines.
pub const EXEC_HOOK_SHELL: &str = "/bin/sh";

/// `ai-memory wake-listen` arguments.
#[derive(Args, Debug, Clone)]
pub struct WakeListenArgs {
    /// Agent whose inbox this listener watches. Defaults to the resolved
    /// caller identity.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,
    /// Hub socket to connect to. Overrides `[wake_hub].socket`.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Hub identifier bound into the handshake transcript. Overrides
    /// `[wake_hub].hub_id`.
    #[arg(long, value_name = "ID")]
    pub hub_id: Option<String>,
    /// Directory holding the agent's keys and its `a2a-hub` delegation
    /// bundle. Defaults to `AI_MEMORY_KEY_DIR` then the platform key dir.
    #[arg(long, value_name = "PATH")]
    pub key_dir: Option<PathBuf>,
    /// Explicit delegation bundle. Defaults to
    /// `<key-dir>/<agent-id>.a2a-hub.json`, which is where
    /// `ai-memory identity delegate --scope a2a-hub` writes it.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,
    /// Longest gap between inbox reads, in seconds. Refused above the
    /// normative 60 s wake-plane maximum.
    #[arg(long = "poll-secs", value_name = "SECS")]
    pub poll_secs: Option<u64>,
    /// Only count messages with `access_count == 0` on each catch-up read.
    #[arg(long = "unread-only")]
    pub unread_only: bool,
    /// Catch-up read page size. Default 50, cap 500.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Emit one JSON line per wake.
    #[arg(long)]
    pub json: bool,
    /// Run this command on each wake with the metadata in the environment.
    #[arg(long, value_name = "CMD")]
    pub exec: Option<String>,
    /// Exit after the first catch-up read instead of listening forever.
    #[arg(long)]
    pub once: bool,
    /// Run without a hub: the bounded backstop poll IS the delivery
    /// mechanism. Useful on a host where no hub is deployed yet.
    #[arg(long = "no-hub")]
    pub no_hub: bool,
}

/// The resolved listener posture: everything a session needs, plus how to
/// shape the catch-up read.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Agent whose inbox is watched.
    pub agent_id: String,
    /// Hub socket, when a hub is configured.
    pub socket: Option<PathBuf>,
    /// Hub identifier.
    pub hub_id: String,
    /// Key directory holding the delegation bundle.
    pub key_dir: PathBuf,
    /// Bundle path.
    pub bundle: PathBuf,
    /// Client tuning.
    pub client: WakeClientConfig,
}

/// Resolve the listener posture: CLI flag > `[wake_hub]` config > compiled
/// default.
///
/// # Errors
///
/// When no agent id can be resolved, when the key directory cannot be
/// resolved, or when the poll interval breaks the normative bound.
pub fn resolve(
    args: &WakeListenArgs,
    app_config: &AppConfig,
    cli_agent_id: Option<&str>,
) -> Result<Resolved> {
    let cfg_block = app_config.wake_hub.clone().unwrap_or_default();
    let agent_id = args
        .agent_id
        .clone()
        .or_else(|| cli_agent_id.map(ToOwned::to_owned))
        .or_else(crate::identity::resolve_read_visibility_caller)
        .filter(|id| !id.trim().is_empty())
        .context(
            "wake-listen: no agent id. Pass --agent-id, or set AI_MEMORY_AGENT_ID — a listener \
             must know whose inbox it is watching before it can present a delegation for it.",
        )?;
    crate::validate::validate_agent_id(&agent_id)?;

    let key_dir = match args.key_dir.clone() {
        Some(dir) => dir,
        None => keypair::default_key_dir()?,
    };
    let bundle = args
        .bundle
        .clone()
        .unwrap_or_else(|| HubJoinBundle::default_path(&key_dir, &agent_id));

    let hub_id = args
        .hub_id
        .clone()
        .or(cfg_block.hub_id)
        .unwrap_or_else(|| DEFAULT_HUB_ID.to_owned());
    let socket = if args.no_hub {
        None
    } else {
        Some(match args.socket.clone().or(cfg_block.socket) {
            Some(p) => p,
            None => crate::wake_hub::HubConfig::default_socket_path()?,
        })
    };

    let mut client = WakeClientConfig::default();
    if let Some(secs) = args.poll_secs {
        client.poll_interval = Duration::from_secs(secs);
    }
    client.validate()?;

    Ok(Resolved {
        agent_id,
        socket,
        hub_id,
        key_dir,
        bundle,
        client,
    })
}

/// Start the listener stream for a resolved posture.
///
/// # Errors
///
/// Every bundle refusal (when a hub is configured), plus a missing Tokio
/// runtime.
pub fn start_stream(resolved: &Resolved) -> Result<WakeStream> {
    let hub = match resolved.socket.clone() {
        Some(socket) => {
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let bundle =
                HubJoinBundle::load(&resolved.bundle, &resolved.hub_id, &resolved.key_dir, &now)?;
            if bundle.agent_id() != resolved.agent_id {
                bail!(
                    "the delegation bundle {} speaks for {:?}, but this listener watches {:?}. \
                     A listener may only join as the agent whose inbox it reads.",
                    resolved.bundle.display(),
                    bundle.agent_id(),
                    resolved.agent_id
                );
            }
            Some((
                SessionConfig::new(socket, resolved.hub_id.clone()),
                Arc::new(bundle),
            ))
        }
        None => None,
    };
    WakeStream::start(resolved.client.clone(), hub)
}

/// Perform ONE catch-up inbox read through the existing inbox path.
///
/// Reuses [`crate::mcp::handle_inbox`] — the same funnel `ai-memory inbox`,
/// the `memory_inbox` tool and `GET /api/v1/inbox` all resolve to — rather
/// than issuing its own SQL. One read per signal, never a read per queued
/// hint.
///
/// # Errors
///
/// A database open failure, or a refusal from the inbox surface.
pub async fn catch_up_read(
    db_path: &Path,
    agent_id: &str,
    unread_only: bool,
    limit: Option<u32>,
) -> Result<Value> {
    let db_path = db_path.to_path_buf();
    let agent_id = agent_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let conn = crate::db::open(&db_path)?;
        let mut params = json!({ "agent_id": agent_id });
        if unread_only {
            params[crate::models::field_names::UNREAD_ONLY] = json!(true);
        }
        if let Some(l) = limit {
            params["limit"] = json!(l);
        }
        crate::mcp::handle_inbox(&conn, &params, None, None)
            .map_err(|e| anyhow::anyhow!("inbox: {e}"))
    })
    .await
    .context("the catch-up inbox read task failed")?
}

/// Render one wake as a single JSON line.
///
/// The hint's fields are reported verbatim; the body is not present because
/// the plane never carried one.
#[must_use]
pub fn wake_line(resolved: &Resolved, signal: &WakeSignal, count: u64) -> Value {
    let meta = signal.meta.as_ref();
    json!({
        "reason": signal.reason.label(),
        "hub_driven": signal.reason.is_hub_driven(),
        "agent_id": resolved.agent_id,
        "hub_id": resolved.hub_id,
        "inbox_row_id": meta.map_or("", |m| m.inbox_row_id.as_str()),
        "namespace": meta.map_or("", |m| m.namespace.as_str()),
        "sender": meta.map_or("", |m| m.sender.as_str()),
        "digest": meta.map_or_else(String::new, |m| hex_digest(&m.digest)),
        "seq_high_watermark": meta.map_or(0, |m| m.seq_high_watermark),
        "missed": signal.missed,
        "pending_count": signal.pending_count,
        "inbox_count": count,
    })
}

/// Lowercase hex, so a hook can compare it against `sha256sum` output.
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        // `write!` to a String is infallible; the result is discarded
        // deliberately rather than unwrapped (ERRORS-19).
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Run the `--exec` hook for one wake, bounded by [`EXEC_HOOK_TIMEOUT`].
///
/// # Errors
///
/// A spawn failure. A non-zero exit or a timeout is LOGGED, not propagated:
/// a broken hook must not stop the listener from reading its inbox.
pub async fn run_exec_hook(
    cmd: &str,
    resolved: &Resolved,
    signal: &WakeSignal,
    count: u64,
) -> Result<()> {
    let meta = signal.meta.as_ref();
    let mut child = tokio::process::Command::new(EXEC_HOOK_SHELL)
        .arg("-c")
        .arg(cmd)
        .env("AI_MEMORY_WAKE_REASON", signal.reason.label())
        .env("AI_MEMORY_WAKE_AGENT_ID", &resolved.agent_id)
        .env("AI_MEMORY_WAKE_HUB_ID", &resolved.hub_id)
        .env(
            "AI_MEMORY_WAKE_INBOX_ROW_ID",
            meta.map_or("", |m| m.inbox_row_id.as_str()),
        )
        .env(
            "AI_MEMORY_WAKE_NAMESPACE",
            meta.map_or("", |m| m.namespace.as_str()),
        )
        .env(
            "AI_MEMORY_WAKE_SENDER",
            meta.map_or("", |m| m.sender.as_str()),
        )
        .env(
            "AI_MEMORY_WAKE_DIGEST",
            meta.map_or_else(String::new, |m| hex_digest(&m.digest)),
        )
        .env(
            "AI_MEMORY_WAKE_SEQ",
            meta.map_or(0, |m| m.seq_high_watermark).to_string(),
        )
        .env("AI_MEMORY_WAKE_MISSED", signal.missed.to_string())
        .env("AI_MEMORY_WAKE_PENDING", signal.pending_count.to_string())
        .env("AI_MEMORY_WAKE_INBOX_COUNT", count.to_string())
        .spawn()
        .with_context(|| format!("spawning the wake hook via {EXEC_HOOK_SHELL}"))?;

    match tokio::time::timeout(EXEC_HOOK_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => {}
        Ok(Ok(status)) => {
            tracing::warn!(
                reason = signal.reason.label(),
                "wake listener: the --exec hook exited {status}; the durable row is unaffected"
            );
        }
        Ok(Err(e)) => {
            tracing::warn!("wake listener: could not wait on the --exec hook ({e})");
        }
        Err(_) => {
            // Kill rather than leak: a hook that outlives the backstop
            // interval would make this listener stop reading its inbox.
            let _ = child.kill().await;
            tracing::error!(
                timeout_secs = EXEC_HOOK_TIMEOUT.as_secs(),
                "wake listener: the --exec hook exceeded its bound and was killed"
            );
        }
    }
    Ok(())
}

/// Block until a wake is due, then return the signal.
///
/// A `Welcome` that carries NO offline backlog is deliberately NOT returned:
/// on a healthy hub every session is welcomed immediately, and returning on
/// that would make a wait an alias for a plain read. A welcome that reports
/// coalesced wakes, or one flagged `lagged`, DOES return — there is mail
/// waiting.
///
/// `None` means the caller's timeout expired, or every producer stopped —
/// a bounded, honest "nothing arrived".
async fn wait_on(stream: &mut WakeStream, timeout: Option<Duration>) -> Option<WakeSignal> {
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    loop {
        let signal = match deadline {
            Some(at) => match tokio::time::timeout_at(at, stream.next()).await {
                Ok(next) => next,
                Err(_) => return None,
            },
            None => stream.next().await,
        };
        let signal = signal?;
        if signal.reason == WakeReason::Welcome && signal.pending_count == 0 {
            // An empty welcome is "you are attached", not "you have mail".
            stream.note_read();
            continue;
        }
        return Some(signal);
    }
}

/// Block until a wake is due, refusing if the hub credential will not load.
///
/// The shape `ai-memory wake-listen` wants: an operator who ran the listener
/// explicitly asked for a hub session, so a bundle that is missing, expired or
/// minted for another hub is an error they need to see, not something to work
/// around.
///
/// # Errors
///
/// Every start-up refusal from [`start_stream`].
pub async fn wait_for_wake(
    resolved: &Resolved,
    timeout: Option<Duration>,
) -> Result<Option<WakeSignal>> {
    let mut stream = start_stream(resolved)?;
    Ok(wait_on(&mut stream, timeout).await)
}

/// Block until a wake is due, DEGRADING to the bounded poll when the hub
/// credential will not load.
///
/// The shape `ai-memory inbox --wait` wants, and the one the plane's own
/// contract requires. `--wait` promises "the hub when one is configured,
/// otherwise the bounded backstop poll", and the fleet conversion recipe
/// swaps `sleep 180; ai-memory inbox` for `ai-memory inbox --wait --timeout
/// 180`. On a host that never ran `ai-memory identity delegate` — or whose
/// bundle expired, or was minted for another hub — [`start_stream`] fails
/// BEFORE any stream exists, and returning that error would make the caller
/// read immediately. In a loop that is a hot loop: one process boot per
/// iteration, a warning each time, and none of the pacing the recipe it
/// replaced provided.
///
/// A hub that is merely DOWN never had this problem — the bundle loads, the
/// session loop backs off, and the always-armed backstop returns on schedule.
/// This closes the case where the CREDENTIAL, not the hub, is what is
/// missing: the refusal is logged once at WARN with its full cause chain (so
/// the operator sees the re-mint remediation), and the wait then runs on a
/// hub-less stream, staying bounded by `min(timeout, poll_interval)`.
///
/// # Errors
///
/// Only a failure to start the hub-LESS stream — an invalid poll interval or
/// no Tokio runtime. Neither is recoverable by waiting.
pub async fn wait_for_wake_or_backstop(
    resolved: &Resolved,
    timeout: Option<Duration>,
) -> Result<Option<WakeSignal>> {
    let mut stream = match start_stream(resolved) {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(
                "inbox --wait: the wake-hub credential could not be loaded ({e:#}); waiting on \
                 the bounded backstop poll instead (at most {:?})",
                resolved.client.poll_interval
            );
            WakeStream::start(resolved.client.clone(), None)?
        }
    };
    Ok(wait_on(&mut stream, timeout).await)
}

/// Serve `ai-memory wake-listen` until SIGINT / SIGTERM.
///
/// # Errors
///
/// Every resolution and start-up refusal. A per-wake failure (a read error, a
/// broken hook) is logged and the listener continues: the durable inbox row
/// is unaffected and the next signal will read it again.
pub async fn dispatch(
    db_path: &Path,
    args: &WakeListenArgs,
    app_config: &AppConfig,
    cli_agent_id: Option<&str>,
) -> Result<()> {
    let resolved = resolve(args, app_config, cli_agent_id)?;
    let mut stream = start_stream(&resolved)?;
    tracing::info!(
        agent = resolved.agent_id,
        hub = resolved.hub_id,
        socket = resolved.socket.as_ref().map(|p| p.display().to_string()),
        backstop_secs = resolved.client.poll_interval.as_secs(),
        "wake listener: started; the inbox row remains the durable record and the poll \
         remains the guarantee"
    );

    loop {
        let signal = tokio::select! {
            () = shutdown_signal() => {
                tracing::info!("wake listener: stopping on signal");
                return Ok(());
            }
            next = stream.next() => match next {
                Some(s) => s,
                None => {
                    tracing::warn!("wake listener: every producer stopped; exiting");
                    return Ok(());
                }
            },
        };

        let envelope =
            match catch_up_read(db_path, &resolved.agent_id, args.unread_only, args.limit).await {
                Ok(v) => v,
                Err(e) => {
                    // Degrade, never corrupt: the row is committed and the next
                    // signal (at worst the backstop) reads it again.
                    tracing::error!(
                        "wake listener: catch-up inbox read failed ({e:#}); will retry"
                    );
                    stream.note_read();
                    continue;
                }
            };
        stream.note_read();
        let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);

        emit(&resolved, args, &signal, count).await?;

        if args.once {
            return Ok(());
        }
    }
}

/// Report one wake, in whichever shape the operator asked for.
async fn emit(
    resolved: &Resolved,
    args: &WakeListenArgs,
    signal: &WakeSignal,
    count: u64,
) -> Result<()> {
    if let Some(cmd) = args.exec.as_deref() {
        run_exec_hook(cmd, resolved, signal, count).await?;
    }
    if args.json || args.exec.is_none() {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut so = stdout.lock();
        let mut se = stderr.lock();
        let out = CliOutput::from_std(&mut so, &mut se);
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&wake_line(resolved, signal, count))?
            )?;
        } else {
            let meta = signal.meta.as_ref();
            writeln!(
                out.stdout,
                "wake[{}] {} message(s) for {}{}",
                signal.reason.label(),
                count,
                resolved.agent_id,
                meta.map_or_else(String::new, |m| format!(
                    "  from={} ns={} row={}",
                    m.sender, m.namespace, m.inbox_row_id
                ))
            )?;
        }
        out.stdout.flush()?;
    }
    Ok(())
}

/// Resolve on SIGINT or, on unix, SIGTERM.
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

/// The listener's own normative bound, re-exported so the CLI reference and
/// the docs cite ONE number.
#[must_use]
pub const fn backstop_max() -> Duration {
    BACKSTOP_POLL_MAX
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WakeHubConfig;
    use crate::wake_hub::frame::WakeMeta;

    fn args() -> WakeListenArgs {
        WakeListenArgs {
            agent_id: Some("ai:listener-3470".into()),
            socket: None,
            hub_id: None,
            key_dir: Some(PathBuf::from("/nonexistent-key-dir-3470")),
            bundle: None,
            poll_secs: None,
            unread_only: false,
            limit: None,
            json: false,
            exec: None,
            once: false,
            no_hub: true,
        }
    }

    /// A CLI flag beats the `[wake_hub]` block, which beats the compiled
    /// default — the same ladder `ai-memory wake-hub` resolves on, so a
    /// listener and its hub cannot disagree about which socket they mean.
    #[test]
    fn the_resolution_ladder_matches_the_hub_3470() {
        let mut a = args();
        a.no_hub = false;
        a.socket = Some(PathBuf::from("/tmp/flag-3470.sock"));
        let mut app = AppConfig::default();
        app.wake_hub = Some(WakeHubConfig {
            socket: Some(PathBuf::from("/tmp/config-3470.sock")),
            hub_id: Some("hub-from-config".into()),
            ..WakeHubConfig::default()
        });
        let r = resolve(&a, &app, None).expect("resolve");
        assert_eq!(r.socket, Some(PathBuf::from("/tmp/flag-3470.sock")));
        assert_eq!(r.hub_id, "hub-from-config");

        // No config block at all falls through to the compiled hub id.
        let mut bare = args();
        bare.no_hub = false;
        bare.socket = Some(PathBuf::from("/tmp/x-3470.sock"));
        let r = resolve(&bare, &AppConfig::default(), None).expect("resolve");
        assert_eq!(r.hub_id, DEFAULT_HUB_ID);
        assert_eq!(
            r.bundle,
            PathBuf::from("/nonexistent-key-dir-3470/ai:listener-3470.a2a-hub.json"),
            "the default bundle path must be the one `identity delegate` writes"
        );
    }

    /// A listener with no agent id cannot know whose inbox it watches, and
    /// refusing is the only honest answer.
    #[test]
    fn a_listener_without_an_agent_id_is_refused_3470() {
        let mut a = args();
        a.agent_id = None;
        let err = resolve(&a, &AppConfig::default(), None)
            .expect_err("a listener must know whose inbox it watches");
        assert!(format!("{err:#}").contains("--agent-id"), "{err:#}");

        // The global caller identity supplies it when the flag does not.
        let r = resolve(&a, &AppConfig::default(), Some("ai:from-cli")).expect("resolve");
        assert_eq!(r.agent_id, "ai:from-cli");
    }

    /// A poll interval over the normative maximum is refused at the CLI
    /// boundary, so an operator learns immediately rather than running a
    /// listener that quietly breaks the plane's contract.
    #[test]
    fn a_poll_interval_over_the_backstop_is_refused_at_the_cli_3470() {
        let mut a = args();
        a.poll_secs = Some(backstop_max().as_secs() + 1);
        let err = resolve(&a, &AppConfig::default(), None).expect_err("over the bound");
        assert!(format!("{err:#}").contains("normative maximum"), "{err:#}");

        a.poll_secs = Some(5);
        let r = resolve(&a, &AppConfig::default(), None).expect("a tighter poll is fine");
        assert_eq!(r.client.poll_interval, Duration::from_secs(5));
    }

    /// The JSON line carries the hint and the DIGEST — never a body, because
    /// the plane never carried one.
    #[test]
    fn the_json_line_carries_metadata_and_a_digest_never_a_body_3470() {
        let a = args();
        let resolved = resolve(&a, &AppConfig::default(), None).expect("resolve");
        let signal = WakeSignal {
            reason: WakeReason::Gap,
            meta: Some(WakeMeta {
                inbox_row_id: "row-3470".into(),
                namespace: "_inbox/ai:listener-3470".into(),
                sender: "ai:alice".into(),
                digest: vec![0xab; 32],
                seq_high_watermark: 42,
            }),
            pending_count: 0,
            missed: 3,
        };
        let line = wake_line(&resolved, &signal, 2);
        assert_eq!(line["reason"], "gap");
        assert_eq!(line["hub_driven"], true);
        assert_eq!(line["inbox_row_id"], "row-3470");
        assert_eq!(line["sender"], "ai:alice");
        assert_eq!(line["seq_high_watermark"], 42);
        assert_eq!(line["missed"], 3);
        assert_eq!(line["inbox_count"], 2);
        assert_eq!(line["digest"], "ab".repeat(32));
        let rendered = serde_json::to_string(&line).expect("json");
        for forbidden in ["body", "payload", "content", "title"] {
            assert!(
                !rendered.contains(forbidden),
                "a wake line must never carry a body field: {rendered}"
            );
        }

        // A signal that names no row renders empty strings, never nulls a
        // shell hook would print as the four characters `null`.
        let bare = WakeSignal::bare(WakeReason::Backstop);
        let line = wake_line(&resolved, &bare, 0);
        assert_eq!(line["inbox_row_id"], "");
        assert_eq!(line["digest"], "");
        assert_eq!(line["hub_driven"], false);
    }

    /// The hook bound exists and is inside the backstop window, so a hung
    /// hook can never cost more than one poll interval of inbox latency.
    #[test]
    fn the_exec_hook_bound_is_inside_the_backstop_3470() {
        assert!(!EXEC_HOOK_TIMEOUT.is_zero());
        assert!(
            EXEC_HOOK_TIMEOUT <= backstop_max(),
            "a hook allowed to outlive the backstop would stop the listener reading"
        );
    }

    #[test]
    fn hex_digest_is_lowercase_and_pairs_bytes_3470() {
        assert_eq!(hex_digest(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_digest(&[]), "");
    }
}
