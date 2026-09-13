// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3700 — the deployment SHAPE decides the default security posture.
//!
//! ai-memory already carries the machinery that stops one agent's wrong
//! conclusion from becoming a swarm's shared truth: the `asi-hard` posture
//! ([`crate::security_profile`]) pins `REQUIRE_WITNESS` (corroboration),
//! `REQUIRE_AGENT_ATTESTATION`, `FED_QUARANTINE_UNATTRIBUTED`, the four
//! `FED_REQUIRE_*_SIG` gates, cause binding, identity lineage, rollback
//! check, role separation, `CID_ENFORCE` and `DB_SYNCHRONOUS`, and refuses to
//! loosen any of them. Before #3700 every one of those shipped OFF: the
//! compiled default was [`SecurityPosture::Standard`], and nothing connected
//! the deployment's SHAPE to its posture, so a federated, multi-agent fleet
//! — exactly the swarm case where a single bad shared memory becomes
//! thousands of correlated wrong actions — booted unprotected and silent.
//!
//! ## The shape is the discriminator
//!
//! A deployment is **fleet-shaped** when any of these content-free signals
//! is present, and **singleton** otherwise:
//!
//! | signal | source | meaning |
//! |---|---|---|
//! | `outbound_peers` | argv | `serve --quorum-peers` / `sync-daemon --peers` |
//! | `inbound_bindings` | env | peer fingerprints, cert↔peer-id bindings or a trust bundle |
//! | `listener_mtls` | argv | `serve --mtls-allowlist` |
//! | `peer_allowlist` | env | `AI_MEMORY_FED_PEER_ATTESTATION` is set (even `{}`, even invalid) |
//! | `mcp_federation_forward_url` | config | `mcp_federation_forward_url` (MCP writes fan out to a mesh) |
//! | `wake_hub` | config | `[wake_hub]` (the multi-agent wake plane) |
//! | `agent_registry` | store | at least [`FLEET_REGISTRY_MIN_AGENTS`] registered agents |
//!
//! A signal a process cannot observe (argv from `doctor`, the store before
//! it is open) is reported as `unobservable`, never as absent (ERRORS-09).
//!
//! ## Resolution
//!
//! 1. An explicit `AI_MEMORY_SECURITY_PROFILE` always wins
//!    ([`PostureOrigin::Explicit`]).
//! 2. Unset on a fleet shape → `asi-hard`, [`PostureOrigin::DerivedFromShape`].
//! 3. Unset on a singleton → `standard`, [`PostureOrigin::CompiledDefault`]
//!    — a single-agent developer install boots byte-identically.
//!
//! ## Enforcement
//!
//! - **Derived `asi-hard`** pins every unset protection exactly like the
//!   explicit posture does (the derivation runs in the synchronous
//!   pre-runtime phase of `fn main()` and writes the profile selector into
//!   the environment, the same #1889/#2386 contract every other boot-time
//!   env write honours). A fleet-shaped deployment that has any pinned knob
//!   set BELOW its floor REFUSES to boot, and the refusal names EVERY
//!   disabled knob plus the one-line deliberate override.
//! - **Explicit `standard` on a fleet shape** boots, warns ONCE and is
//!   recorded (the boot snapshot, capabilities, the forensic audit stream).
//! - **A fleet shape learned only after the store opens** (the agent
//!   registry) cannot be pinned from the async runtime, so a posture that is
//!   `standard` by OMISSION refuses there too, naming every protection that
//!   is off and both one-line choices.
//! - `doctor` never refuses; it reports the shape, the posture, its origin
//!   and whether they match, at the top of the DEFAULT report — so a
//!   deployment that boots today learns exactly what will refuse after the
//!   upgrade BEFORE it upgrades.

use std::path::Path;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::federation::peer_posture::{self, Allowlist, Observation};
use crate::security_profile::{
    self, ASI_HARD_REFUSAL_PREFIX, ENV_SECURITY_PROFILE, SecurityPosture,
};

/// The issue tag every #3700 boot line, refusal and doctor note carries, so an
/// operator can grep one token for "the deployment shape stopped my boot".
pub const ISSUE_TAG: &str = "#3700";

/// Tracing target for the shape/posture boot lines.
pub const TRACING_TARGET: &str = "security.deployment_shape";

/// The registry count at which a store is multi-agent by declaration. One
/// registered agent is a singleton that named itself; two are a fleet.
pub const FLEET_REGISTRY_MIN_AGENTS: usize = 2;

/// The ONE spelling of the deliberate override an operator states to run a
/// fleet-shaped deployment under `standard`.
pub const EXPLICIT_STANDARD_OVERRIDE: &str = "AI_MEMORY_SECURITY_PROFILE=standard";

/// The ONE spelling of the recommended fix for a fleet-shaped deployment
/// whose posture could not be derived (registry learned after open).
pub const EXPLICIT_ASI_HARD_SELECTOR: &str = "AI_MEMORY_SECURITY_PROFILE=asi-hard";

/// Forensic-audit `kind` of the recorded explicit-standard exception.
pub const AUDIT_KIND_POSTURE_EXCEPTION: &str = "deployment_shape.posture_exception";

pub const SIGNAL_OUTBOUND_PEERS: &str = "outbound_peers";
pub const SIGNAL_INBOUND_BINDINGS: &str = "inbound_bindings";
pub const SIGNAL_LISTENER_MTLS: &str = "listener_mtls";
pub const SIGNAL_PEER_ALLOWLIST: &str = "peer_allowlist";
pub const SIGNAL_MCP_FEDERATION_FORWARD: &str = "mcp_federation_forward_url";
pub const SIGNAL_WAKE_HUB: &str = "wake_hub";
pub const SIGNAL_AGENT_REGISTRY: &str = "agent_registry";

const SOURCE_ARGV: &str = "argv";
const SOURCE_ENV: &str = "env";
const SOURCE_CONFIG: &str = "config";
const SOURCE_STORE: &str = "store";

/// Singleton (one agent, one node) or fleet (federated and/or multi-agent).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    Singleton,
    Fleet,
}

impl Shape {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Singleton => "singleton",
            Self::Fleet => "fleet",
        }
    }
}

/// Whether one signal was observed present, observed absent, or could not be
/// observed from this process at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalState {
    Present,
    Absent,
    Unobservable,
}

impl SignalState {
    fn from_present(present: bool) -> Self {
        if present { Self::Present } else { Self::Absent }
    }

    fn from_observation(o: Observation) -> Self {
        match o {
            Observation::Present => Self::Present,
            Observation::Absent => Self::Absent,
            Observation::Unobservable => Self::Unobservable,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unobservable => "unobservable",
        }
    }
}

/// One content-free shape signal. Carries no peer URL, path, id or key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    pub source: String,
    pub state: SignalState,
}

impl Signal {
    fn new(name: &str, source: &str, state: SignalState) -> Self {
        Self {
            name: name.to_string(),
            source: source.to_string(),
            state,
        }
    }
}

/// The observed deployment shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeReport {
    pub shape: Shape,
    pub signals: Vec<Signal>,
    /// `None` until the store has been opened (or when this process never
    /// opens it).
    pub registered_agents: Option<usize>,
}

impl ShapeReport {
    fn from_signals(signals: Vec<Signal>, registered_agents: Option<usize>) -> Self {
        let mut report = Self {
            shape: Shape::Singleton,
            signals,
            registered_agents,
        };
        report.recompute();
        report
    }

    fn recompute(&mut self) {
        let fleet = self.signals.iter().any(|s| s.state == SignalState::Present);
        self.shape = if fleet {
            Shape::Fleet
        } else {
            Shape::Singleton
        };
    }

    /// Names of the signals observed present.
    #[must_use]
    pub fn present(&self) -> Vec<&str> {
        self.signals
            .iter()
            .filter(|s| s.state == SignalState::Present)
            .map(|s| s.name.as_str())
            .collect()
    }

    /// Names of the signals this process could not observe.
    #[must_use]
    pub fn unobservable(&self) -> Vec<&str> {
        self.signals
            .iter()
            .filter(|s| s.state == SignalState::Unobservable)
            .map(|s| s.name.as_str())
            .collect()
    }

    /// The fleet shape rests on the store-derived registry signal ALONE — the
    /// one signal the pre-runtime derivation cannot see, so nothing was
    /// pinned for it.
    #[must_use]
    pub fn fleet_by_registry_only(&self) -> bool {
        self.shape == Shape::Fleet
            && self
                .present()
                .iter()
                .all(|name| *name == SIGNAL_AGENT_REGISTRY)
    }

    /// Fold in the store-derived registry signal (only observable after the
    /// store is open).
    #[must_use]
    pub fn with_registry(mut self, registered_agents: usize) -> Self {
        let state = SignalState::from_present(registered_agents >= FLEET_REGISTRY_MIN_AGENTS);
        match self
            .signals
            .iter_mut()
            .find(|s| s.name == SIGNAL_AGENT_REGISTRY)
        {
            Some(s) => s.state = state,
            None => self
                .signals
                .push(Signal::new(SIGNAL_AGENT_REGISTRY, SOURCE_STORE, state)),
        }
        self.registered_agents = Some(registered_agents);
        self.recompute();
        self
    }
}

/// How the effective posture came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureOrigin {
    /// `AI_MEMORY_SECURITY_PROFILE` was set by the operator.
    Explicit,
    /// Unset, fleet-shaped → `asi-hard` (#3700).
    DerivedFromShape,
    /// Unset, singleton → the compiled `standard` default.
    CompiledDefault,
}

impl PostureOrigin {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::DerivedFromShape => "derived_from_shape",
            Self::CompiledDefault => "compiled_default",
        }
    }
}

/// The posture this deployment runs under, and why. Content-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureResolution {
    /// `standard` / `asi-hard` (the [`SecurityPosture`] wire token).
    pub posture: String,
    pub origin: PostureOrigin,
    pub shape: ShapeReport,
    /// `false` exactly when a fleet shape runs under `standard`.
    pub shape_matches_posture: bool,
    /// The explicit-standard-on-a-fleet exception was recorded (warned once
    /// and written to the forensic audit stream) by this process.
    pub exception_recorded: bool,
}

impl PostureResolution {
    #[must_use]
    pub fn posture(&self) -> SecurityPosture {
        SecurityPosture::parse(&self.posture).unwrap_or(SecurityPosture::AsiHard)
    }

    /// The deliberate `standard`-on-a-fleet exception.
    #[must_use]
    pub fn is_explicit_exception(&self) -> bool {
        !self.shape_matches_posture && self.origin == PostureOrigin::Explicit
    }

    /// A fleet shape running `standard` because nobody chose — the state the
    /// #3700 refusal exists for.
    #[must_use]
    pub fn is_unprotected_by_omission(&self) -> bool {
        !self.shape_matches_posture && self.origin == PostureOrigin::CompiledDefault
    }
}

/// Observe the shape of this process's configuration. Read-only: no store,
/// no private key, no environment mutation. `argv` is `Some((outbound_peers,
/// mtls_allowlist))` when the caller is the daemon or the sync daemon and
/// `None` when argv is unobservable (`doctor`, MCP, one-shot verbs).
#[must_use]
pub fn observe(app_config: Option<&AppConfig>, argv: Option<(bool, Option<&Path>)>) -> ShapeReport {
    let peers = peer_posture::observe(argv);
    let allowlist = match peers.peer_allowlist {
        // `{}` and a malformed map both mean an operator CONFIGURED federation.
        Allowlist::Configured | Allowlist::ConfiguredEmpty | Allowlist::Invalid => {
            SignalState::Present
        }
        Allowlist::Absent => SignalState::Absent,
    };
    let cfg_signal = |present: Option<bool>| match present {
        Some(p) => SignalState::from_present(p),
        None => SignalState::Unobservable,
    };
    let signals = vec![
        Signal::new(
            SIGNAL_OUTBOUND_PEERS,
            SOURCE_ARGV,
            SignalState::from_observation(peers.outbound_peers),
        ),
        Signal::new(
            SIGNAL_INBOUND_BINDINGS,
            SOURCE_ENV,
            SignalState::from_observation(peers.inbound_bindings),
        ),
        Signal::new(
            SIGNAL_LISTENER_MTLS,
            SOURCE_ARGV,
            SignalState::from_observation(peers.listener_mtls),
        ),
        Signal::new(SIGNAL_PEER_ALLOWLIST, SOURCE_ENV, allowlist),
        Signal::new(
            SIGNAL_MCP_FEDERATION_FORWARD,
            SOURCE_CONFIG,
            cfg_signal(app_config.map(|c| c.mcp_federation_forward_url.is_some())),
        ),
        Signal::new(
            SIGNAL_WAKE_HUB,
            SOURCE_CONFIG,
            cfg_signal(app_config.map(|c| c.wake_hub.is_some())),
        ),
        Signal::new(
            SIGNAL_AGENT_REGISTRY,
            SOURCE_STORE,
            SignalState::Unobservable,
        ),
    ];
    ShapeReport::from_signals(signals, None)
}

/// Pure resolution: the explicit selector (if any) and the shape → posture +
/// origin. No environment read; the matrix the four #3700 states pin.
#[must_use]
pub fn resolve_with(explicit: Option<SecurityPosture>, shape: ShapeReport) -> PostureResolution {
    let (posture, origin) = match (explicit, shape.shape) {
        (Some(p), _) => (p, PostureOrigin::Explicit),
        // A fleet known only from the agent registry is learned AFTER the
        // store opens, where nothing can be pinned: with no selector the
        // process runs `standard` by omission — the refusal state.
        (None, Shape::Fleet) if shape.fleet_by_registry_only() => {
            (SecurityPosture::Standard, PostureOrigin::CompiledDefault)
        }
        (None, Shape::Fleet) => (SecurityPosture::AsiHard, PostureOrigin::DerivedFromShape),
        (None, Shape::Singleton) => (SecurityPosture::Standard, PostureOrigin::CompiledDefault),
    };
    let shape_matches_posture =
        !(shape.shape == Shape::Fleet && posture == SecurityPosture::Standard);
    PostureResolution {
        posture: posture.as_str().to_string(),
        origin,
        shape,
        shape_matches_posture,
        exception_recorded: false,
    }
}

/// Resolve against the live `AI_MEMORY_SECURITY_PROFILE` (read-only).
///
/// # Errors
/// An unrecognised explicit posture token (fail-loud, as before #3700).
pub fn resolve(shape: ShapeReport) -> Result<PostureResolution> {
    let explicit = match std::env::var(ENV_SECURITY_PROFILE) {
        Ok(v) => Some(SecurityPosture::parse(&v)?),
        Err(_) => None,
    };
    Ok(resolve_with(explicit, shape))
}

/// The refusal for a fleet-shaped deployment whose protections are off.
/// Names EVERY disabled knob — those set below the floor and, when they
/// could not be pinned, those unset — and the one-line choices.
#[must_use]
pub fn refusal_message(
    shape: &ShapeReport,
    below_floor: &[(&str, String, &str)],
    unpinned: &[(&str, &str)],
    derived: bool,
) -> String {
    let signals = shape.present().join(", ");
    let mut disabled: Vec<String> = below_floor
        .iter()
        .map(|(env, current, hard)| format!("{env}={current:?} (below the hard floor {hard:?})"))
        .collect();
    disabled.extend(
        unpinned
            .iter()
            .map(|(env, hard)| format!("{env} unset (off; hard floor {hard:?})")),
    );
    let count = disabled.len();
    let listed = disabled.join("; ");
    if derived {
        format!(
            "{ASI_HARD_REFUSAL_PREFIX} (derived from the deployment shape, {ISSUE_TAG}): this \
             deployment is FLEET-shaped (signals: {signals}), so the hardened anti-cascade \
             posture is its default — but {count} protection(s) are DISABLED: {listed}. Raise \
             each to its floor (or unset it so the posture pins it), or state the exception \
             deliberately on ONE line: {EXPLICIT_STANDARD_OVERRIDE} (boots, warns once, is \
             recorded). `ai-memory doctor` lists every protection and its state."
        )
    } else {
        format!(
            "{ISSUE_TAG}: this deployment is FLEET-shaped (signals: {signals}) but runs the \
             `standard` posture by OMISSION, and the shape was learned only after the store \
             opened, where protections cannot be pinned — {count} protection(s) are DISABLED: \
             {listed}. Choose on ONE line: {EXPLICIT_ASI_HARD_SELECTOR} (recommended: pins every \
             protection at boot) or {EXPLICIT_STANDARD_OVERRIDE} (deliberate exception: boots, \
             warns once, is recorded). `ai-memory doctor` lists every protection and its state."
        )
    }
}

/// The refusal for a direct library caller (no `fn main()` pre-runtime
/// phase ran) on a fleet shape whose posture nobody chose: the protections
/// cannot be pinned from the live runtime, so the caller states the posture.
#[must_use]
pub fn library_caller_refusal(
    shape: &ShapeReport,
    below_floor: &[(&str, String, &str)],
    unpinned: &[(&str, &str)],
) -> String {
    let signals = shape.present().join(", ");
    let count = below_floor.len() + unpinned.len();
    format!(
        "{ISSUE_TAG}: this deployment is FLEET-shaped (signals: {signals}) and no security \
         posture was chosen, but this process did not boot through the ai-memory binary (a \
         direct `daemon_runtime` caller), where the posture would have been derived and every \
         protection pinned; from the live runtime nothing can be pinned, so {count} \
         protection(s) stay OFF. Choose on ONE line before starting: \
         {EXPLICIT_ASI_HARD_SELECTOR} (with every pinned knob at its floor) or \
         {EXPLICIT_STANDARD_OVERRIDE} (deliberate exception: boots, warns once, is recorded)."
    )
}

/// Every pinned knob that is currently UNSET (off by its own default).
#[must_use]
pub fn unpinned_knobs() -> Vec<(&'static str, &'static str)> {
    security_profile::pinned_knobs()
        .into_iter()
        .filter(|(env, _)| std::env::var_os(env).is_none())
        .collect()
}

/// Snapshot of the last completed in-process evaluation, shared by boot,
/// capabilities and the recorded exception.
static BOOT_RESOLUTION: RwLock<Option<PostureResolution>> = RwLock::new(None);

/// The boot snapshot, if this process evaluated its shape.
#[must_use]
pub fn boot_resolution() -> Option<PostureResolution> {
    BOOT_RESOLUTION
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn stash(resolution: &PostureResolution) {
    *BOOT_RESOLUTION.write().unwrap_or_else(|e| e.into_inner()) = Some(resolution.clone());
}

static EXCEPTION_WARNED: AtomicBool = AtomicBool::new(false);

/// The ONE-time operator warning for a deliberate `standard` on a fleet.
/// Returns whether this call emitted it.
fn warn_exception_once(shape: &ShapeReport) -> bool {
    if EXCEPTION_WARNED.swap(true, Ordering::SeqCst) {
        return false;
    }
    // stderr also works in the pre-tracing main entry point.
    eprintln!(
        "ai-memory: WARN {ISSUE_TAG}: {EXPLICIT_STANDARD_OVERRIDE} is set on a FLEET-shaped \
         deployment (signals: {}); the anti-cascade protections are OFF by the operator's \
         deliberate choice. This exception is recorded. Remove the override to derive asi-hard.",
        shape.present().join(", ")
    );
    true
}

/// Derive the posture in the synchronous pre-runtime phase of `fn main()`.
///
/// MUST run before the tracing appender worker or any tokio runtime thread
/// exists: a derived `asi-hard` is written into `AI_MEMORY_SECURITY_PROFILE`
/// so [`crate::security_profile::enforce_at_boot_pre_runtime`] (called right
/// after) pins the protections exactly as an explicit selection would, and
/// every downstream `SecurityPosture::resolve()` sees the derived posture.
///
/// `announce` prints the derivation / exception line to stderr (the daemon
/// and sync-daemon entry points); one-shot verbs derive silently so hooks
/// and pipelines that capture stderr stay byte-identical.
///
/// # Errors
/// - An unrecognised explicit posture token.
/// - A fleet-shaped deployment with `AI_MEMORY_SECURITY_PROFILE` unset and
///   any pinned knob set below its hard floor: the #3700 refusal, naming
///   every disabled knob and the deliberate override.
pub fn derive_pre_runtime(
    app_config: &AppConfig,
    argv: Option<(bool, Option<&Path>)>,
    announce: bool,
) -> Result<PostureResolution> {
    let resolution = resolve(observe(Some(app_config), argv))?;
    match resolution.origin {
        PostureOrigin::DerivedFromShape => {
            let below = security_profile::asi_hard_below_floor();
            if !below.is_empty() {
                bail!(refusal_message(&resolution.shape, &below, &[], true));
            }
            // SAFETY: the synchronous single-threaded pre-runtime phase of
            // `fn main()` — the same #1889/#2386 contract as
            // `security_profile::enforce_at_boot`, which runs next and pins
            // the individual knobs the same way.
            unsafe {
                std::env::set_var(ENV_SECURITY_PROFILE, SecurityPosture::AsiHard.as_str());
            }
            if announce {
                eprintln!(
                    "ai-memory: {ISSUE_TAG}: security posture asi-hard DERIVED from the \
                     FLEET-shaped deployment (signals: {}); every anti-cascade protection is \
                     pinned ON. Set {EXPLICIT_STANDARD_OVERRIDE} deliberately to run without \
                     them (recorded).",
                    resolution.shape.present().join(", ")
                );
            }
        }
        PostureOrigin::Explicit if resolution.is_explicit_exception() && announce => {
            // Warned here (pre-tracing); RECORDED once the daemon body runs
            // (`enforce_pre_open`), where the forensic audit writer exists.
            warn_exception_once(&resolution.shape);
        }
        PostureOrigin::Explicit | PostureOrigin::CompiledDefault => {}
    }
    stash(&resolution);
    Ok(resolution)
}

/// Record the deliberate exception in the forensic audit stream (best
/// effort: the audit writer is initialised by the daemon boot; a process
/// without one logs the failure through the audit module's own path).
fn record_exception(resolution: &PostureResolution) {
    crate::governance::audit::record_decision(
        "ai-memory",
        "boot",
        AUDIT_KIND_POSTURE_EXCEPTION,
        ISSUE_TAG,
        serde_json::json!({
            "posture": resolution.posture,
            "origin": resolution.origin.as_str(),
            "shape": resolution.shape.shape.as_str(),
            "signals": resolution.shape.present(),
            "registered_agents": resolution.shape.registered_agents,
            "override": EXPLICIT_STANDARD_OVERRIDE,
        }),
    );
    tracing::warn!(
        target: TRACING_TARGET,
        shape = resolution.shape.shape.as_str(),
        signals = ?resolution.shape.present(),
        posture = %resolution.posture,
        origin = resolution.origin.as_str(),
        "{ISSUE_TAG}: deliberate `standard` posture on a fleet-shaped deployment — \
         anti-cascade protections OFF by operator choice (recorded)"
    );
}

/// The gate for the daemon and sync-daemon bodies, BEFORE the store opens.
/// Read-only and safe on the live runtime. Uses the pre-runtime snapshot
/// when the process booted through the binary; for a direct library caller
/// it re-derives read-only and fails CLOSED on a fleet shape whose posture
/// nobody chose, because the protections cannot be pinned from here
/// (the #2386 contract).
///
/// # Errors
/// - An unrecognised explicit posture token.
/// - A fleet shape with `AI_MEMORY_SECURITY_PROFILE` unset when no
///   pre-runtime derivation ran.
pub fn enforce_pre_open(
    app_config: Option<&AppConfig>,
    argv: Option<(bool, Option<&Path>)>,
) -> Result<PostureResolution> {
    let mut resolution = match boot_resolution() {
        Some(r) => r,
        None => {
            let r = resolve(observe(app_config, argv))?;
            if r.origin == PostureOrigin::DerivedFromShape {
                let below = security_profile::asi_hard_below_floor();
                let unpinned = unpinned_knobs();
                bail!(library_caller_refusal(&r.shape, &below, &unpinned));
            }
            r
        }
    };
    if resolution.is_explicit_exception() && !resolution.exception_recorded {
        warn_exception_once(&resolution.shape);
        record_exception(&resolution);
        resolution.exception_recorded = true;
    } else if resolution.origin == PostureOrigin::DerivedFromShape {
        tracing::warn!(
            target: TRACING_TARGET,
            signals = ?resolution.shape.present(),
            "{ISSUE_TAG}: security posture asi-hard derived from the fleet-shaped deployment"
        );
    }
    stash(&resolution);
    Ok(resolution)
}

/// The gate AFTER the store opens: fold in the agent-registry signal. A shape
/// that becomes fleet only here cannot be pinned any more, so a posture that
/// is `standard` by omission refuses, naming every protection that is off
/// and both one-line choices. An explicit `standard` records the exception.
///
/// # Errors
/// The registry makes the deployment fleet-shaped and no posture was chosen.
pub fn enforce_post_open(registered_agents: usize) -> Result<PostureResolution> {
    let previous = boot_resolution().unwrap_or_else(|| resolve_with(None, observe(None, None)));
    let shape = previous.shape.clone().with_registry(registered_agents);
    // What is in force NOW: an explicit selector, or the asi-hard the
    // pre-runtime derivation already wrote into the environment.
    let selected = match previous.origin {
        PostureOrigin::Explicit => Some(previous.posture()),
        PostureOrigin::DerivedFromShape => Some(SecurityPosture::AsiHard),
        PostureOrigin::CompiledDefault => None,
    };
    let mut resolution = resolve_with(selected, shape);
    resolution.exception_recorded = previous.exception_recorded;
    if selected.is_some() {
        resolution.origin = previous.origin;
    } else if resolution.is_unprotected_by_omission() {
        // The registry made this a fleet only now, nobody chose a posture,
        // and the protections cannot be pinned from the live runtime: the
        // process IS running `standard` by omission. Refuse, naming every
        // protection that is off and both one-line choices.
        stash(&resolution);
        let below = security_profile::asi_hard_below_floor();
        let unpinned = unpinned_knobs();
        bail!(refusal_message(&resolution.shape, &below, &unpinned, false));
    }
    if resolution.is_explicit_exception() && !resolution.exception_recorded {
        warn_exception_once(&resolution.shape);
        record_exception(&resolution);
        resolution.exception_recorded = true;
    }
    stash(&resolution);
    Ok(resolution)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(present: &[&str]) -> ShapeReport {
        let names = [
            SIGNAL_OUTBOUND_PEERS,
            SIGNAL_INBOUND_BINDINGS,
            SIGNAL_LISTENER_MTLS,
            SIGNAL_PEER_ALLOWLIST,
            SIGNAL_MCP_FEDERATION_FORWARD,
            SIGNAL_WAKE_HUB,
        ];
        let signals = names
            .iter()
            .map(|n| {
                Signal::new(
                    n,
                    SOURCE_ENV,
                    SignalState::from_present(present.contains(n)),
                )
            })
            .collect();
        ShapeReport::from_signals(signals, None)
    }

    /// The four #3700 states, as a pure matrix (no environment).
    #[test]
    fn posture_resolution_matrix_3700() {
        // 1. fleet + unset → asi-hard derived, shape matches.
        let r = resolve_with(None, report(&[SIGNAL_OUTBOUND_PEERS]));
        assert_eq!(r.posture(), SecurityPosture::AsiHard);
        assert_eq!(r.origin, PostureOrigin::DerivedFromShape);
        assert!(r.shape_matches_posture);
        // 2. singleton + unset → standard by compiled default, unchanged.
        let r = resolve_with(None, report(&[]));
        assert_eq!(r.posture(), SecurityPosture::Standard);
        assert_eq!(r.origin, PostureOrigin::CompiledDefault);
        assert!(r.shape_matches_posture);
        assert!(!r.is_unprotected_by_omission());
        // 3. fleet + explicit standard → the deliberate exception.
        let r = resolve_with(Some(SecurityPosture::Standard), report(&[SIGNAL_WAKE_HUB]));
        assert_eq!(r.posture(), SecurityPosture::Standard);
        assert!(!r.shape_matches_posture);
        assert!(r.is_explicit_exception());
        assert!(!r.is_unprotected_by_omission());
        // 4. fleet + explicit asi-hard → matches, explicit.
        let r = resolve_with(
            Some(SecurityPosture::AsiHard),
            report(&[SIGNAL_PEER_ALLOWLIST]),
        );
        assert!(r.shape_matches_posture);
        assert_eq!(r.origin, PostureOrigin::Explicit);
    }

    #[test]
    fn every_signal_alone_makes_a_fleet_3700() {
        for name in [
            SIGNAL_OUTBOUND_PEERS,
            SIGNAL_INBOUND_BINDINGS,
            SIGNAL_LISTENER_MTLS,
            SIGNAL_PEER_ALLOWLIST,
            SIGNAL_MCP_FEDERATION_FORWARD,
            SIGNAL_WAKE_HUB,
        ] {
            assert_eq!(report(&[name]).shape, Shape::Fleet, "{name}");
        }
        assert_eq!(report(&[]).shape, Shape::Singleton);
    }

    #[test]
    fn registry_threshold_is_two_agents_3700() {
        let one = report(&[]).with_registry(1);
        assert_eq!(one.shape, Shape::Singleton);
        assert_eq!(one.registered_agents, Some(1));
        let two = report(&[]).with_registry(FLEET_REGISTRY_MIN_AGENTS);
        assert_eq!(two.shape, Shape::Fleet);
        assert_eq!(two.present(), vec![SIGNAL_AGENT_REGISTRY]);
        // A registry learned after open on a posture nobody chose is the
        // refusal state; on an explicit standard it is the exception.
        assert!(two.fleet_by_registry_only());
        let by_omission = resolve_with(None, two.clone());
        assert_eq!(by_omission.origin, PostureOrigin::CompiledDefault);
        assert!(by_omission.is_unprotected_by_omission());
        assert!(resolve_with(Some(SecurityPosture::Standard), two.clone()).is_explicit_exception());
        // With a pre-open signal beside the registry the posture derives.
        let mixed = report(&[SIGNAL_WAKE_HUB]).with_registry(2);
        assert!(!mixed.fleet_by_registry_only());
        assert_eq!(
            resolve_with(None, mixed).origin,
            PostureOrigin::DerivedFromShape
        );
    }

    #[test]
    fn unobservable_is_never_absent_3700() {
        let r = observe(None, None);
        for name in [
            SIGNAL_OUTBOUND_PEERS,
            SIGNAL_LISTENER_MTLS,
            SIGNAL_MCP_FEDERATION_FORWARD,
            SIGNAL_WAKE_HUB,
            SIGNAL_AGENT_REGISTRY,
        ] {
            let s = r.signals.iter().find(|s| s.name == name).unwrap();
            assert_eq!(s.state, SignalState::Unobservable, "{name}");
        }
        assert!(r.unobservable().contains(&SIGNAL_AGENT_REGISTRY));
    }

    #[test]
    fn refusal_names_every_disabled_knob_and_the_override_3700() {
        let shape = report(&[SIGNAL_OUTBOUND_PEERS, SIGNAL_PEER_ALLOWLIST]);
        let below = vec![
            ("AI_MEMORY_REQUIRE_WITNESS", "0".to_string(), "1"),
            ("AI_MEMORY_CID_ENFORCE", "0".to_string(), "1"),
        ];
        let msg = refusal_message(&shape, &below, &[], true);
        assert!(msg.starts_with(ASI_HARD_REFUSAL_PREFIX));
        assert!(msg.contains(ISSUE_TAG));
        assert!(msg.contains("outbound_peers, peer_allowlist"));
        assert!(msg.contains("2 protection(s) are DISABLED"));
        assert!(msg.contains("AI_MEMORY_REQUIRE_WITNESS=\"0\""));
        assert!(msg.contains("AI_MEMORY_CID_ENFORCE=\"0\""));
        assert!(msg.contains(EXPLICIT_STANDARD_OVERRIDE));
        // The post-open form names the unset knobs too and offers both lines.
        let unpinned = vec![
            ("AI_MEMORY_REQUIRE_WITNESS", "1"),
            ("AI_MEMORY_DB_SYNCHRONOUS", "FULL"),
        ];
        let msg = refusal_message(&shape.with_registry(3), &[], &unpinned, false);
        assert!(msg.contains("agent_registry"));
        assert!(msg.contains("AI_MEMORY_REQUIRE_WITNESS unset"));
        assert!(msg.contains("AI_MEMORY_DB_SYNCHRONOUS unset"));
        assert!(msg.contains(EXPLICIT_ASI_HARD_SELECTOR));
        assert!(msg.contains(EXPLICIT_STANDARD_OVERRIDE));
    }

    #[test]
    fn snapshot_round_trips_through_json_3700() {
        let r = resolve_with(Some(SecurityPosture::Standard), report(&[SIGNAL_WAKE_HUB]));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["posture"], "standard");
        assert_eq!(json["origin"], "explicit");
        assert_eq!(json["shape"]["shape"], "fleet");
        assert_eq!(json["shape_matches_posture"], false);
        let back: PostureResolution = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
    }
}
