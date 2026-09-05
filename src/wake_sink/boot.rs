// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the `serve` boot decision for the wake sink.
//!
//! One small module rather than more glue in `daemon_runtime`, so the whole
//! "does this daemon push wakes, and if not exactly why not" decision is in one
//! readable place with its own tests.
//!
//! # The decision, in order
//!
//! 1. `[wake_hub].sink_socket` unset -> [`WakeSinkBoot::NotConfigured`]. No
//!    socket, no identity load, no task. Opening a socket and joining an
//!    identity plane is an operator decision, never one a daemon infers.
//! 2. Set -> load the daemon's enrolled key
//!    ([`super::producer_identity::DaemonIssuedCredential`]). Absent or
//!    public-only is a REFUSAL naming the remediation, not a silent skip.
//! 3. Install the forwarder ([`super::uds::install_uds`]).
//!
//! # Why a refusal here does not abort `serve`
//!
//! The wake plane is a LATENCY optimisation over a durable inbox row: the row
//! is the record, the wake is a hint, and the `<=60 s` backstop poll
//! ([`super::BACKSTOP_POLL_MAX`]) is the guarantee. Aborting the daemon —
//! taking down the durable substrate every agent depends on — because a hint
//! cannot be pushed would be a self-inflicted outage, and it would trade
//! availability for nothing: no data is at risk either way. So the FORWARDER
//! fails closed (it does not start, and no socket is opened) while `serve`
//! continues, and the refusal is logged at ERROR with its full cause chain so
//! it cannot be the #2444 "reports success while doing nothing" shape. The
//! caller gets the `Result` either way, which is what the regression test
//! asserts against.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};

use super::producer_identity::DaemonIssuedCredential;
use super::uds::{JoinCredential as _, UdsSinkConfig, install_uds};
use crate::config::AppConfig;

/// What the boot decision did. Returned rather than only logged so a test can
/// assert the exact branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeSinkBoot {
    /// `[wake_hub].sink_socket` is unset: this daemon pushes no wakes and its
    /// recipients rely on their backstop poll. The default.
    NotConfigured,
    /// A forwarder is running against this socket.
    Installed {
        /// The hub socket wakes are forwarded to.
        socket: PathBuf,
        /// The hub id bound into the handshake transcript.
        hub_id: String,
    },
}

/// Resolve `[wake_hub]` into the forwarder inputs. `Ok(None)` = not configured.
///
/// Split out so the resolution, the identity refusal and the bus attachment
/// are three separately observable steps rather than one opaque call.
fn resolve(
    app_config: &AppConfig,
    key_dir: &Path,
) -> Result<Option<(UdsSinkConfig, DaemonIssuedCredential)>> {
    let Some(wake_hub) = app_config.wake_hub.as_ref() else {
        return Ok(None);
    };
    let Some(socket) = wake_hub.sink_socket.clone() else {
        return Ok(None);
    };
    let hub_id = wake_hub
        .hub_id
        .clone()
        .unwrap_or_else(|| crate::wake_hub::DEFAULT_HUB_ID.to_owned());
    let credential = DaemonIssuedCredential::from_key_dir(key_dir, hub_id.clone())?;
    tracing::info!(
        socket = %socket.display(),
        hub_id = %hub_id,
        "wake sink: issuing `{}` sessions under the daemon\'s enrolled key (public key \
         {}); the hub must carry an allowlist row binding that name to this key",
        credential.agent_id(),
        credential.enrolled_public_base64()
    );
    let mut cfg = UdsSinkConfig::with_socket_path(socket);
    cfg.hub_id = hub_id;
    Ok(Some((cfg, credential)))
}

/// Start the configured forwarder WITHOUT attaching it to the wake bus.
///
/// The half a caller wants when it intends to own the sink itself — and the
/// half the end-to-end test drives, so proving the real credential against a
/// real hub does not consume the ONE process-wide sink installation.
/// `Ok(None)` means no sink is configured.
///
/// # Errors
///
/// Every refusal in [`install_with_key_dir`] except the already-installed one.
pub fn spawn_forwarder(
    app_config: &AppConfig,
    key_dir: &Path,
) -> Result<Option<super::uds::UdsWakeSink>> {
    let Some((cfg, credential)) = resolve(app_config, key_dir)? else {
        return Ok(None);
    };
    Ok(Some(super::uds::UdsWakeSink::spawn(
        cfg,
        Arc::new(credential),
    )?))
}

/// Resolve `[wake_hub]` and install the daemon-side wake forwarder, taking the
/// enrolled key from `key_dir`.
///
/// # Errors
///
/// Returns the refusal when a sink IS configured but cannot be started: no
/// enrolled daemon key, a public-only one, a forwarder that refuses to spawn,
/// or a wake sink already installed on this process. Every one of these means
/// "configured but not running", which an operator must be told about
/// explicitly. Never returns an error for the unconfigured case — that is a
/// valid posture, not a fault.
pub fn install_with_key_dir(app_config: &AppConfig, key_dir: &Path) -> Result<WakeSinkBoot> {
    let Some((cfg, credential)) = resolve(app_config, key_dir)? else {
        return Ok(WakeSinkBoot::NotConfigured);
    };
    let socket = cfg.socket_path.clone();
    let hub_id = cfg.hub_id.clone();
    install_uds(cfg, Arc::new(credential))?;
    Ok(WakeSinkBoot::Installed { socket, hub_id })
}

/// Resolve `[wake_hub]` and install the daemon-side wake forwarder.
///
/// Call once, from inside the `serve` Tokio runtime, after the store is up —
/// the forwarder must not be attached to the bus before the surface that
/// publishes on it exists.
///
/// # Errors
///
/// Every refusal in [`install_with_key_dir`], plus an unusable key directory.
/// The key directory is resolved ONLY when a sink is actually configured, so
/// the default posture never touches it.
pub fn install_from_config(app_config: &AppConfig) -> Result<WakeSinkBoot> {
    let configured = app_config
        .wake_hub
        .as_ref()
        .is_some_and(|w| w.sink_socket.is_some());
    if !configured {
        return Ok(WakeSinkBoot::NotConfigured);
    }
    let key_dir = crate::identity::keypair::default_key_dir().context(
        "wake sink: no usable key directory, so this daemon cannot issue a wake-hub \
         producer session. Fix the key directory (it must be owner-only) or unset \
         `[wake_hub].sink_socket`.",
    )?;
    install_with_key_dir(app_config, &key_dir)
}

/// [`install_from_config`], with the refusal already logged.
///
/// The shape `serve` calls: a misconfigured wake plane must be LOUD but must
/// not take the durable substrate down with it (see the module docs).
pub fn install_from_config_logged(app_config: &AppConfig) -> WakeSinkBoot {
    match install_from_config(app_config) {
        Ok(WakeSinkBoot::NotConfigured) => {
            tracing::debug!(
                "wake sink: `[wake_hub].sink_socket` is unset; no wake forwarder started \
                 (recipients rely on their backstop poll)"
            );
            WakeSinkBoot::NotConfigured
        }
        Ok(installed) => {
            tracing::info!("wake sink: {installed:?}");
            installed
        }
        Err(e) => {
            tracing::error!(
                "wake sink: `[wake_hub].sink_socket` IS configured but the forwarder was \
                 REFUSED, so this daemon is pushing no wakes and its recipients are \
                 relying on their backstop poll: {e:#}"
            );
            WakeSinkBoot::NotConfigured
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WakeHubConfig;

    fn config(sink_socket: Option<PathBuf>) -> AppConfig {
        AppConfig {
            wake_hub: Some(WakeHubConfig {
                sink_socket,
                ..WakeHubConfig::default()
            }),
            ..AppConfig::default()
        }
    }

    /// The DEFAULT posture: no `[wake_hub]` block at all, and no `sink_socket`
    /// inside one, both mean no forwarder — and neither is an error.
    #[test]
    fn an_unconfigured_sink_starts_nothing_and_is_not_a_fault_3469() {
        assert_eq!(
            install_from_config(&AppConfig::default()).expect("no block is a valid posture"),
            WakeSinkBoot::NotConfigured
        );
        assert_eq!(
            install_from_config(&config(None)).expect("no sink_socket is a valid posture"),
            WakeSinkBoot::NotConfigured
        );
        // The logged shape agrees.
        assert_eq!(
            install_from_config_logged(&AppConfig::default()),
            WakeSinkBoot::NotConfigured
        );
    }

    /// DENIED, and the regression the amendment asks for at unit level: a
    /// configured sink with NO credential material in the key directory
    /// REFUSES to start the forwarder, names the remediation, and never
    /// resolves to "not configured" — the shape that would let a daemon report
    /// success while pushing nothing.
    #[test]
    fn a_configured_sink_with_no_credential_material_refuses_3469() {
        let empty = tempfile::tempdir().expect("tempdir");
        let cfg = config(Some(PathBuf::from("/tmp/wake-sink-never-opened-3469.sock")));
        let err =
            install_with_key_dir(&cfg, empty.path()).expect_err("no enrolled key, no forwarder");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("wake sink:"), "{rendered}");
        assert!(
            rendered.contains(crate::identity::sentinels::WAKE_HUB_PRODUCER),
            "the refusal must name the principal the operator has to enrol: {rendered}"
        );
        assert!(
            rendered.contains("hub-cache"),
            "and the allowlist step they must not forget: {rendered}"
        );
        // Nothing was spawned either.
        assert!(spawn_forwarder(&cfg, empty.path()).is_err());
    }

    /// The unconfigured posture never touches the key directory, so a daemon
    /// with no wake plane cannot fail to boot over one.
    #[test]
    fn an_unconfigured_sink_never_consults_the_key_directory_3469() {
        let missing = PathBuf::from("/nonexistent-key-dir-3469");
        assert_eq!(
            install_with_key_dir(&AppConfig::default(), &missing).expect("valid posture"),
            WakeSinkBoot::NotConfigured
        );
        assert!(
            spawn_forwarder(&config(None), &missing)
                .expect("valid posture")
                .is_none()
        );
    }
}
