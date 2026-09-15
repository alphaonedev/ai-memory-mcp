// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3700 — the deployment-shape DETECTOR: what the configuration
//! and the store OBSERVE about a node, held against the shape the operator
//! DECLARED (`[deployment] shape`, [`DeploymentShape`]
//! — the ONE definition, #3714).
//!
//! ai-memory already carries the machinery that stops one agent's wrong
//! conclusion from becoming a swarm's shared truth: the `asi-hard` posture
//! pins `REQUIRE_WITNESS` (corroboration), agent attestation, quarantine of
//! unattributed federated writes, the `FED_REQUIRE_*_SIG` gates, cause
//! binding, identity lineage, rollback check, role separation,
//! `CID_ENFORCE` and `DB_SYNCHRONOUS`. Since #3714 the DECLARED shape
//! derives that posture: `production` / `federated` / `hive` pin `asi-hard`
//! as a FLOOR before any other boot check runs, and an override below the
//! floor refuses. What was still missing — the #3700 defect — is that a
//! customer can configure federation and a multi-agent fleet WITHOUT
//! declaring the shape, and boot a `singleton` with every protection off,
//! silently. This module makes that state loud:
//!
//! - it observes content-free **signals** (peer lists, inbound bindings,
//!   the peer allowlist, the MCP forward URL, the wake hub, monitoring
//!   peer scopes, the agent registry) and derives the **observed floor**:
//!   the least demanding shape those signals are consistent with;
//! - when the observed floor exceeds the declared shape it WARNs at boot,
//!   records the mismatch on the forensic audit stream, reports it in the
//!   DEFAULT `doctor` report with the exact config line to declare, and
//!   exposes it through capabilities — it never re-postures the node.
//!   **Promotion is an operator act** (the #3714 2→3 rule, Conductor ruling
//!   (b)): detection may warn, it may not silently harden a running node;
//! - under a hardened DECLARED shape it refuses a boot whose pinned knobs
//!   sit below the floor, naming EVERY disabled knob (the per-knob
//!   `security_profile` refusal names only the first) and the way out
//!   (raise the knobs, or declare a shape whose posture is a default).
//!
//! Zero-config local-CA minting (#3709 item 1) consumes the DECLARED shape
//! too: it is for `singleton` only — every other shape brings enterprise
//! PKI (3x7 audit ruling).

use std::path::Path;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::DeploymentShape;
use crate::config::AppConfig;
use crate::federation::peer_posture::{self, Allowlist, Observation};
use crate::governance::audit::ForensicPayload;
use crate::security_profile::{
    self, ASI_HARD_REFUSAL_PREFIX, ENV_SECURITY_PROFILE, SecurityPosture,
};

/// The issue tag every #3700 boot line, refusal and doctor note carries.
pub const ISSUE_TAG: &str = "#3700";

/// Tracing target for the shape detector's boot lines.
pub const TRACING_TARGET: &str = "security.deployment_shape";

/// The registry count at which a store is multi-agent by declaration. One
/// registered agent is a singleton that named itself; two are a team.
pub const FLEET_REGISTRY_MIN_AGENTS: usize = 2;

/// Forensic-audit `kind` of a recorded undeclared-shape mismatch.
pub const AUDIT_KIND_UNDECLARED_SHAPE: &str = "deployment_shape.undeclared_signals";

pub const SIGNAL_OUTBOUND_PEERS: &str = "outbound_peers";
pub const SIGNAL_INBOUND_BINDINGS: &str = "inbound_bindings";
pub const SIGNAL_LISTENER_MTLS: &str = "listener_mtls";
pub const SIGNAL_PEER_ALLOWLIST: &str = "peer_allowlist";
pub const SIGNAL_MCP_FEDERATION_FORWARD: &str = "mcp_federation_forward_url";
pub const SIGNAL_WAKE_HUB: &str = "wake_hub";
pub const SIGNAL_MONITORING_PEERS: &str = "monitoring_peer_scopes";
pub const SIGNAL_AGENT_REGISTRY: &str = "agent_registry";

const SOURCE_ARGV: &str = "argv";
const SOURCE_ENV: &str = "env";
const SOURCE_CONFIG: &str = "config";
const SOURCE_STORE: &str = "store";

/// Whether one signal was observed present, observed absent, or could not be
/// observed from this process at all (never reported as absent, ERRORS-09).
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

/// What a present signal implies about the least demanding consistent
/// shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalClass {
    /// Several agents share this node (wake hub, agent registry).
    MultiAgent,
    /// Peers are configured (federation).
    Federation,
}

/// One content-free shape signal. Carries no peer URL, path, id or key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    pub source: String,
    pub class: SignalClass,
    pub state: SignalState,
}

impl Signal {
    fn new(name: &str, source: &str, class: SignalClass, state: SignalState) -> Self {
        Self {
            name: name.to_string(),
            source: source.to_string(),
            class,
            state,
        }
    }
}

/// The observed signals and the least demanding shape consistent with them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeReport {
    /// The least demanding [`DeploymentShape`] the present signals allow:
    /// `singleton` with no signal, `team` with multi-agent signals only,
    /// `federated` with any federation signal.
    pub observed_floor: DeploymentShape,
    pub signals: Vec<Signal>,
    /// `None` until the store has been opened (or when this process never
    /// opens it).
    pub registered_agents: Option<usize>,
}

impl ShapeReport {
    fn from_signals(signals: Vec<Signal>, registered_agents: Option<usize>) -> Self {
        let mut report = Self {
            observed_floor: DeploymentShape::Singleton,
            signals,
            registered_agents,
        };
        report.recompute();
        report
    }

    fn recompute(&mut self) {
        let present = |class: SignalClass| {
            self.signals
                .iter()
                .any(|s| s.class == class && s.state == SignalState::Present)
        };
        self.observed_floor = if present(SignalClass::Federation) {
            DeploymentShape::Federated
        } else if present(SignalClass::MultiAgent) {
            DeploymentShape::Team
        } else {
            DeploymentShape::Singleton
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
            None => self.signals.push(Signal::new(
                SIGNAL_AGENT_REGISTRY,
                SOURCE_STORE,
                SignalClass::MultiAgent,
                state,
            )),
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
    /// The declared shape's floor pinned it (#3714).
    ShapeFloor,
    /// Unset under a shape whose posture is a default: the compiled
    /// `standard`.
    CompiledDefault,
}

impl PostureOrigin {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::ShapeFloor => "shape_floor",
            Self::CompiledDefault => "compiled_default",
        }
    }
}

/// The detector's verdict. Content-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeAssessment {
    /// The shape the operator declared (`[deployment] shape`; absent =
    /// `singleton`, never promoted).
    pub declared: DeploymentShape,
    pub observed: ShapeReport,
    /// `true` when the observed floor exceeds the declared shape: the node
    /// is configured like a stricter shape than it declares. Promotion is
    /// the operator's act; this is the WARN, never a re-posture.
    pub undeclared_promotion: bool,
    /// `standard` / `asi-hard` (the [`SecurityPosture`] wire token) in force.
    pub posture: String,
    pub origin: PostureOrigin,
    /// The mismatch was recorded (forensic audit) by this process.
    pub mismatch_recorded: bool,
}

impl ShapeAssessment {
    #[must_use]
    pub fn posture(&self) -> SecurityPosture {
        SecurityPosture::parse(&self.posture).unwrap_or(SecurityPosture::AsiHard)
    }

    /// The config line that would declare what the signals show.
    #[must_use]
    pub fn promotion_line(&self) -> String {
        self.observed.observed_floor.config_line()
    }

    /// The node runs every anti-cascade protection OFF while its
    /// configuration looks like a fleet: the state the #3700 detector
    /// exists to make loud.
    #[must_use]
    pub fn unprotected_fleet(&self) -> bool {
        self.undeclared_promotion && self.posture() == SecurityPosture::Standard
    }
}

fn rank(shape: DeploymentShape) -> u8 {
    match shape {
        DeploymentShape::Singleton => 0,
        DeploymentShape::Team => 1,
        DeploymentShape::Production => 2,
        DeploymentShape::Federated => 3,
        DeploymentShape::Hive => 4,
    }
}

/// Observe the signals of this process's configuration. Read-only: no
/// store, no private key, no environment mutation. `argv` is
/// `Some((outbound_peers, mtls_allowlist))` for the daemon / sync daemon
/// and `None` when argv is unobservable (`doctor`, MCP, one-shot verbs).
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
            SignalClass::Federation,
            SignalState::from_observation(peers.outbound_peers),
        ),
        Signal::new(
            SIGNAL_INBOUND_BINDINGS,
            SOURCE_ENV,
            SignalClass::Federation,
            SignalState::from_observation(peers.inbound_bindings),
        ),
        Signal::new(
            SIGNAL_LISTENER_MTLS,
            SOURCE_ARGV,
            SignalClass::Federation,
            SignalState::from_observation(peers.listener_mtls),
        ),
        Signal::new(
            SIGNAL_PEER_ALLOWLIST,
            SOURCE_ENV,
            SignalClass::Federation,
            allowlist,
        ),
        Signal::new(
            SIGNAL_MCP_FEDERATION_FORWARD,
            SOURCE_CONFIG,
            SignalClass::Federation,
            cfg_signal(app_config.map(|c| c.mcp_federation_forward_url.is_some())),
        ),
        Signal::new(
            SIGNAL_MONITORING_PEERS,
            SOURCE_CONFIG,
            SignalClass::Federation,
            cfg_signal(app_config.map(|c| {
                c.monitoring
                    .as_ref()
                    .is_some_and(|m| !m.peer_ids.is_empty())
            })),
        ),
        Signal::new(
            SIGNAL_WAKE_HUB,
            SOURCE_CONFIG,
            SignalClass::MultiAgent,
            cfg_signal(app_config.map(|c| c.wake_hub.is_some())),
        ),
        Signal::new(
            SIGNAL_AGENT_REGISTRY,
            SOURCE_STORE,
            SignalClass::MultiAgent,
            SignalState::Unobservable,
        ),
    ];
    ShapeReport::from_signals(signals, None)
}

/// Pure assessment: the declared shape, the observed signals and the
/// explicit selector (if any) → posture, origin and the mismatch flag. No
/// environment read; the matrix the #3700 states pin.
#[must_use]
pub fn assess_with(
    declared: DeploymentShape,
    observed: ShapeReport,
    explicit: Option<SecurityPosture>,
) -> ShapeAssessment {
    let floor = declared.derive().security_posture;
    let (posture, origin) = match explicit {
        Some(p) => (p, PostureOrigin::Explicit),
        None if floor.is_floor() => (floor.value(), PostureOrigin::ShapeFloor),
        None => (floor.value(), PostureOrigin::CompiledDefault),
    };
    let undeclared_promotion = rank(observed.observed_floor) > rank(declared);
    ShapeAssessment {
        declared,
        observed,
        undeclared_promotion,
        posture: posture.as_str().to_string(),
        origin,
        mismatch_recorded: false,
    }
}

/// Assess against the live `AI_MEMORY_SECURITY_PROFILE` (read-only; the
/// #3714 pin has already been applied when this runs in the binary).
///
/// # Errors
/// An unrecognised explicit posture token (fail-loud).
pub fn assess(app_config: &AppConfig, observed: ShapeReport) -> Result<ShapeAssessment> {
    let explicit = match std::env::var(ENV_SECURITY_PROFILE) {
        Ok(v) => Some(SecurityPosture::parse(&v)?),
        Err(_) => None,
    };
    Ok(assess_with(
        app_config.effective_shape(),
        observed,
        explicit,
    ))
}

/// The refusal for a hardened DECLARED shape whose pinned knobs sit below
/// the floor. Names EVERY disabled knob and both ways out.
#[must_use]
pub fn hardened_shape_refusal(
    declared: DeploymentShape,
    below_floor: &[(&str, String, &str)],
) -> String {
    let listed: Vec<String> = below_floor
        .iter()
        .map(|(env, current, hard)| format!("{env}={current:?} (below the hard floor {hard:?})"))
        .collect();
    let count = listed.len();
    let line = declared.config_line();
    format!(
        "{ASI_HARD_REFUSAL_PREFIX} ({line} pins it as a FLOOR, {ISSUE_TAG}): {count} \
         protection(s) are set BELOW the floor: {}. Raise each to its floor (or unset it so the \
         posture pins it), or declare a shape whose posture is a default (`singleton`, `team`) \
         — promotion and demotion are both operator acts. `ai-memory doctor` lists every \
         protection and its state.",
        listed.join("; ")
    )
}

/// The one-time boot WARN for an undeclared promotion.
#[must_use]
pub fn undeclared_promotion_warning(assessment: &ShapeAssessment) -> String {
    let posture_note = if assessment.unprotected_fleet() {
        " — every anti-cascade protection (witness corroboration, attestation, quarantine of \
         unattributed federated writes, cause binding, lineage, rollback check, role separation, \
         CID enforcement, durable sync) is OFF"
    } else {
        ""
    };
    format!(
        "WARN {ISSUE_TAG}: this node declares [deployment] shape = \"{}\" but its configuration \
         looks like `{}` (signals: {}){posture_note}. Promotion is an operator act: nothing was \
         re-postured. To run it as what it is, declare `{}` (the shape then pins the hardened \
         posture); `ai-memory doctor` reports this until it is declared.",
        assessment.declared,
        assessment.observed.observed_floor,
        assessment.observed.present().join(", "),
        assessment.promotion_line(),
    )
}

/// Snapshot of the last completed in-process assessment, shared by boot,
/// capabilities and the recorded mismatch.
static BOOT_ASSESSMENT: RwLock<Option<ShapeAssessment>> = RwLock::new(None);

/// The boot snapshot, if this process assessed its shape.
#[must_use]
pub fn boot_assessment() -> Option<ShapeAssessment> {
    BOOT_ASSESSMENT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn stash(assessment: &ShapeAssessment) {
    *BOOT_ASSESSMENT.write().unwrap_or_else(|e| e.into_inner()) = Some(assessment.clone());
}

static PROMOTION_WARNED: AtomicBool = AtomicBool::new(false);

/// Print the undeclared-promotion WARN once per process (stderr works in
/// the pre-tracing main entry point). Returns whether this call printed it.
fn warn_promotion_once(assessment: &ShapeAssessment) -> bool {
    if PROMOTION_WARNED.swap(true, Ordering::SeqCst) {
        return false;
    }
    eprintln!("ai-memory: {}", undeclared_promotion_warning(assessment));
    true
}

fn record_mismatch(assessment: &ShapeAssessment) {
    crate::governance::audit::record_decision(
        "ai-memory",
        "boot",
        AUDIT_KIND_UNDECLARED_SHAPE,
        ISSUE_TAG,
        // #3647 — every field is classified by WHAT IT IS, because the
        // payload type decides what a row discloses and what it commits to.
        // `declared` / `observed_floor` / `origin` are compile-time tokens
        // from closed vocabularies (`label`). `signals` are the `SIGNAL_*`
        // tokens, identifier-shaped and borrowed from the report's owned
        // names (`idents`: verbatim). `registered_agents` is a count. `posture`
        // is a `SecurityPosture` token carried as a `String` on the
        // assessment (`ident`: verbatim, the same bytes a label would write).
        // `promotion_line` is RENDERED free text — the operator's config line,
        // derivable from `observed_floor` — so it is a commitment, never
        // verbatim (`commit`).
        ForensicPayload::new()
            .label("declared", assessment.declared.as_str())
            .label(
                "observed_floor",
                assessment.observed.observed_floor.as_str(),
            )
            .idents("signals", assessment.observed.present())
            .opt_number("registered_agents", assessment.observed.registered_agents)
            .ident("posture", &assessment.posture)
            .label("origin", assessment.origin.as_str())
            .commit("promotion_line", &assessment.promotion_line()),
    );
    tracing::warn!(
        target: TRACING_TARGET,
        declared = assessment.declared.as_str(),
        observed_floor = assessment.observed.observed_floor.as_str(),
        signals = ?assessment.observed.present(),
        posture = %assessment.posture,
        "{ISSUE_TAG}: configuration looks like a stricter shape than declared — not \
         re-postured (promotion is an operator act); recorded"
    );
}

/// Pre-runtime assessment in the synchronous phase of `fn main()`, AFTER
/// [`crate::config::shape::enforce_at_boot_pre_runtime`] (which pins the
/// declared shape's posture floor) and BEFORE
/// [`crate::security_profile::enforce_at_boot_pre_runtime`]. Read-only: it
/// writes nothing into the environment.
///
/// `announce` prints the undeclared-promotion WARN to stderr (the daemon
/// and sync-daemon entry points); one-shot verbs stay quiet.
///
/// # Errors
/// - An unrecognised explicit posture token.
/// - A hardened declared shape with any pinned knob set below its floor:
///   the refusal names every disabled knob.
pub fn assess_pre_runtime(
    app_config: &AppConfig,
    argv: Option<(bool, Option<&Path>)>,
    announce: bool,
) -> Result<ShapeAssessment> {
    let assessment = assess(app_config, observe(Some(app_config), argv))?;
    if assessment.declared.is_hardened() {
        let below = security_profile::asi_hard_below_floor();
        if !below.is_empty() {
            bail!(hardened_shape_refusal(assessment.declared, &below));
        }
    }
    if assessment.undeclared_promotion && announce {
        warn_promotion_once(&assessment);
    }
    stash(&assessment);
    Ok(assessment)
}

/// The daemon-body gate BEFORE the store opens (read-only, safe on the live
/// runtime). Uses the pre-runtime snapshot when the process booted through
/// the binary; a direct library caller is assessed here. An undeclared
/// promotion is warned once and recorded — never re-postured.
///
/// # Errors
/// - An unrecognised explicit posture token.
/// - A hardened declared shape with a pinned knob below its floor (library
///   callers get the same refusal the binary gives).
pub fn enforce_pre_open(
    app_config: Option<&AppConfig>,
    argv: Option<(bool, Option<&Path>)>,
) -> Result<ShapeAssessment> {
    let mut assessment = match boot_assessment() {
        Some(a) => a,
        None => {
            // A library caller without a config (the sync-daemon body) is
            // assessed as the compiled default: an absent `[deployment]`
            // block is `singleton` (the #3714 2→3 rule).
            let default_cfg;
            let cfg = match app_config {
                Some(c) => c,
                None => {
                    default_cfg = AppConfig::default();
                    &default_cfg
                }
            };
            let a = assess(cfg, observe(Some(cfg), argv))?;
            if a.declared.is_hardened() {
                let below = security_profile::asi_hard_below_floor();
                if !below.is_empty() {
                    bail!(hardened_shape_refusal(a.declared, &below));
                }
            }
            a
        }
    };
    if assessment.undeclared_promotion && !assessment.mismatch_recorded {
        warn_promotion_once(&assessment);
        record_mismatch(&assessment);
        assessment.mismatch_recorded = true;
    }
    stash(&assessment);
    Ok(assessment)
}

/// The gate AFTER the store opens: fold in the agent-registry signal. A
/// registry that raises the observed floor above the declared shape is a
/// WARN and a recorded mismatch — never a refusal and never a re-posture:
/// what a node learns at runtime cannot promote it.
pub fn assess_post_open(registered_agents: usize) -> ShapeAssessment {
    let previous = boot_assessment()
        .unwrap_or_else(|| assess_with(DeploymentShape::Singleton, observe(None, None), None));
    let observed = previous.observed.clone().with_registry(registered_agents);
    let explicit = (previous.origin == PostureOrigin::Explicit).then(|| previous.posture());
    let mut assessment = assess_with(previous.declared, observed, explicit);
    if previous.origin == PostureOrigin::ShapeFloor {
        assessment.origin = PostureOrigin::ShapeFloor;
    }
    assessment.mismatch_recorded = previous.mismatch_recorded;
    if assessment.undeclared_promotion && !assessment.mismatch_recorded {
        warn_promotion_once(&assessment);
        record_mismatch(&assessment);
        assessment.mismatch_recorded = true;
    }
    stash(&assessment);
    assessment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(present: &[&str]) -> ShapeReport {
        let table: [(&str, SignalClass); 7] = [
            (SIGNAL_OUTBOUND_PEERS, SignalClass::Federation),
            (SIGNAL_INBOUND_BINDINGS, SignalClass::Federation),
            (SIGNAL_LISTENER_MTLS, SignalClass::Federation),
            (SIGNAL_PEER_ALLOWLIST, SignalClass::Federation),
            (SIGNAL_MCP_FEDERATION_FORWARD, SignalClass::Federation),
            (SIGNAL_MONITORING_PEERS, SignalClass::Federation),
            (SIGNAL_WAKE_HUB, SignalClass::MultiAgent),
        ];
        let signals = table
            .iter()
            .map(|(n, class)| {
                Signal::new(
                    n,
                    SOURCE_ENV,
                    *class,
                    SignalState::from_present(present.contains(n)),
                )
            })
            .collect();
        ShapeReport::from_signals(signals, None)
    }

    #[test]
    fn observed_floor_follows_the_signal_classes_3700() {
        assert_eq!(report(&[]).observed_floor, DeploymentShape::Singleton);
        assert_eq!(
            report(&[SIGNAL_WAKE_HUB]).observed_floor,
            DeploymentShape::Team
        );
        for name in [
            SIGNAL_OUTBOUND_PEERS,
            SIGNAL_INBOUND_BINDINGS,
            SIGNAL_LISTENER_MTLS,
            SIGNAL_PEER_ALLOWLIST,
            SIGNAL_MCP_FEDERATION_FORWARD,
            SIGNAL_MONITORING_PEERS,
        ] {
            assert_eq!(
                report(&[name]).observed_floor,
                DeploymentShape::Federated,
                "{name}"
            );
        }
        let registry = report(&[]).with_registry(FLEET_REGISTRY_MIN_AGENTS);
        assert_eq!(registry.observed_floor, DeploymentShape::Team);
        assert_eq!(registry.present(), vec![SIGNAL_AGENT_REGISTRY]);
        assert_eq!(
            report(&[]).with_registry(1).observed_floor,
            DeploymentShape::Singleton
        );
    }

    /// The #3700 states as a pure matrix (no environment).
    #[test]
    fn assessment_matrix_3700() {
        // Declared singleton, federation configured, nothing chosen: the
        // unprotected fleet — WARN state, posture stays standard (never
        // re-postured).
        let a = assess_with(
            DeploymentShape::Singleton,
            report(&[SIGNAL_OUTBOUND_PEERS]),
            None,
        );
        assert!(a.undeclared_promotion);
        assert!(a.unprotected_fleet());
        assert_eq!(a.posture(), SecurityPosture::Standard);
        assert_eq!(a.origin, PostureOrigin::CompiledDefault);
        assert_eq!(a.promotion_line(), "[deployment] shape = \"federated\"");
        // Declared singleton, no signals: unchanged developer install.
        let a = assess_with(DeploymentShape::Singleton, report(&[]), None);
        assert!(!a.undeclared_promotion && !a.unprotected_fleet());
        // Declared federated: the floor pins asi-hard; signals match.
        let a = assess_with(
            DeploymentShape::Federated,
            report(&[SIGNAL_OUTBOUND_PEERS]),
            None,
        );
        assert!(!a.undeclared_promotion);
        assert_eq!(a.posture(), SecurityPosture::AsiHard);
        assert_eq!(a.origin, PostureOrigin::ShapeFloor);
        // Declared singleton hardened explicitly by the operator: federation
        // signals still exceed the declaration (WARN), but nothing is off.
        let a = assess_with(
            DeploymentShape::Singleton,
            report(&[SIGNAL_PEER_ALLOWLIST]),
            Some(SecurityPosture::AsiHard),
        );
        assert!(a.undeclared_promotion && !a.unprotected_fleet());
        assert_eq!(a.origin, PostureOrigin::Explicit);
        // A declared hive is never "promoted" by federation signals.
        let a = assess_with(
            DeploymentShape::Hive,
            report(&[SIGNAL_OUTBOUND_PEERS]),
            None,
        );
        assert!(!a.undeclared_promotion);
    }

    #[test]
    fn unobservable_is_never_absent_3700() {
        let r = observe(None, None);
        for name in [
            SIGNAL_OUTBOUND_PEERS,
            SIGNAL_LISTENER_MTLS,
            SIGNAL_MCP_FEDERATION_FORWARD,
            SIGNAL_MONITORING_PEERS,
            SIGNAL_WAKE_HUB,
            SIGNAL_AGENT_REGISTRY,
        ] {
            let s = r.signals.iter().find(|s| s.name == name).unwrap();
            assert_eq!(s.state, SignalState::Unobservable, "{name}");
        }
        assert!(r.unobservable().contains(&SIGNAL_AGENT_REGISTRY));
    }

    #[test]
    fn hardened_refusal_names_every_disabled_knob_3700() {
        let below = vec![
            ("AI_MEMORY_REQUIRE_WITNESS", "0".to_string(), "1"),
            ("AI_MEMORY_CID_ENFORCE", "0".to_string(), "1"),
        ];
        let msg = hardened_shape_refusal(DeploymentShape::Federated, &below);
        assert!(msg.starts_with(ASI_HARD_REFUSAL_PREFIX));
        assert!(msg.contains(ISSUE_TAG));
        assert!(msg.contains("[deployment] shape = \"federated\""));
        assert!(msg.contains("2 protection(s)"));
        assert!(msg.contains("AI_MEMORY_REQUIRE_WITNESS=\"0\""));
        assert!(msg.contains("AI_MEMORY_CID_ENFORCE=\"0\""));
        assert!(msg.contains("operator acts"));
    }

    #[test]
    fn promotion_warning_names_the_config_line_and_the_protections_3700() {
        let a = assess_with(
            DeploymentShape::Singleton,
            report(&[SIGNAL_OUTBOUND_PEERS, SIGNAL_WAKE_HUB]),
            None,
        );
        let w = undeclared_promotion_warning(&a);
        assert!(w.contains(ISSUE_TAG));
        assert!(w.contains("[deployment] shape = \"federated\""));
        assert!(w.contains("outbound_peers, wake_hub"));
        assert!(w.contains("witness corroboration"));
        assert!(w.contains("nothing was re-postured"));
    }

    #[test]
    fn snapshot_round_trips_through_json_3700() {
        let a = assess_with(
            DeploymentShape::Team,
            report(&[SIGNAL_OUTBOUND_PEERS]).with_registry(3),
            Some(SecurityPosture::Standard),
        );
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["declared"], "team");
        assert_eq!(json["observed"]["observed_floor"], "federated");
        assert_eq!(json["undeclared_promotion"], true);
        assert_eq!(json["origin"], "explicit");
        let back: ShapeAssessment = serde_json::from_value(json).unwrap();
        assert_eq!(back, a);
    }

    /// #3700 x #3647 — the recorded mismatch row is a `ForensicPayload`
    /// whose every field is classified by what it is: the closed-vocabulary
    /// tokens (`declared`, `observed_floor`, `origin`, `posture`) and the
    /// `SIGNAL_*` names render VERBATIM, the registry count is a number
    /// (`null` when the store was never opened), and the RENDERED promotion
    /// line — free text — is a keyed commitment that never reaches the row
    /// in the clear. A conversion that merely compiles could misclassify a
    /// field and quietly change what an audit row reveals; this pins the
    /// disclosure of each one.
    #[test]
    fn recorded_mismatch_row_classifies_every_field_3700_3647() {
        use crate::governance::audit::{self, ForensicDecision, forensic_commitment};
        let _g = audit::forensic_sink_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        audit::shutdown();
        let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        audit::init(tmp.path(), Some(key.clone())).unwrap();
        let explicit = assess_with(
            DeploymentShape::Singleton,
            report(&[SIGNAL_OUTBOUND_PEERS, SIGNAL_WAKE_HUB]).with_registry(3),
            Some(SecurityPosture::AsiHard),
        );
        let pre_open = assess_with(
            DeploymentShape::Team,
            report(&[SIGNAL_INBOUND_BINDINGS]),
            None,
        );
        record_mismatch(&explicit);
        record_mismatch(&pre_open);
        audit::shutdown();

        let mut text = String::new();
        for e in std::fs::read_dir(tmp.path()).unwrap().flatten() {
            text.push_str(&std::fs::read_to_string(e.path()).unwrap());
        }
        let rows: Vec<ForensicDecision> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("forensic row"))
            .collect();
        assert_eq!(rows.len(), 2, "{text}");
        let row = &rows[0];
        assert_eq!(row.kind, AUDIT_KIND_UNDECLARED_SHAPE);
        assert_eq!(row.rule_id, ISSUE_TAG);
        let p = &row.payload;
        assert_eq!(p["declared"], "singleton");
        assert_eq!(p["observed_floor"], "federated");
        assert_eq!(p["origin"], "explicit");
        assert_eq!(p["posture"], "asi-hard");
        assert_eq!(
            p["signals"],
            serde_json::json!([
                SIGNAL_OUTBOUND_PEERS,
                SIGNAL_WAKE_HUB,
                SIGNAL_AGENT_REGISTRY
            ])
        );
        assert_eq!(p["registered_agents"], 3);
        assert_eq!(
            p["promotion_line"],
            forensic_commitment(&key, b"[deployment] shape = \"federated\"")
        );
        let p = &rows[1].payload;
        assert_eq!(p["declared"], "team");
        assert_eq!(p["origin"], "compiled_default");
        assert_eq!(p["posture"], "standard");
        assert!(
            p.get("registered_agents").is_some(),
            "the key renders even pre-open: {p}"
        );
        assert_eq!(p["registered_agents"], serde_json::Value::Null);
        assert!(
            !text.contains("[deployment] shape = "),
            "free text never reaches the audit row verbatim: {text}"
        );
    }
}
