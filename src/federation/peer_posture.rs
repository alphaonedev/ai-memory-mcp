// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3582: read-only peer observation shared by boot, doctor and capabilities.
//! Enrollment establishes identity; namespace authorization requires a separate
//! nonempty peer allowlist. No database or private key is read by this module.

use std::path::Path;
use std::sync::RwLock;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::security_profile::SecurityPosture;

/// A diagnostic cannot infer another process's command-line arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    Absent,
    Present,
    Unobservable,
}

impl Observation {
    fn from_present(present: bool) -> Self {
        if present { Self::Present } else { Self::Absent }
    }

    /// Plain-language value used by ordinary doctor.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Present => "present",
            Self::Unobservable => "unobservable from this process",
        }
    }
}

/// Valid empty maps declare no authorized peers; malformed maps are errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Allowlist {
    Absent,
    ConfiguredEmpty,
    Invalid,
    Configured,
}

/// Missing observation is distinct from an observed absence (ERRORS-09).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    NoPeersObserved,
    Allowed,
    Warning,
    Refused,
    Unobservable,
}

/// Public, content-free boot facts. Contains no peer IDs, paths or key material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub security_posture: String,
    pub outbound_peers: Observation,
    pub inbound_bindings: Observation,
    pub inbound_enrollment: Observation,
    pub listener_mtls: Observation,
    pub peer_allowlist: Allowlist,
    pub verdict: Verdict,
    pub key_enrollment_required: bool,
    pub require_push_namespace_scope: bool,
    pub observation_errors: Vec<String>,
}

impl Report {
    /// Boot and diagnostics share the refusal for incomplete asi-hard
    /// observations, including when a usable allowlist itself is present.
    #[must_use]
    pub(crate) fn refuses_boot(&self) -> bool {
        self.verdict == Verdict::Refused
            || (self.security_posture == SecurityPosture::AsiHard.as_str()
                && !self.observation_errors.is_empty())
    }
}

/// Evaluate supplied facts without reading or changing process state.
#[must_use]
pub fn evaluate(
    posture: SecurityPosture,
    outbound_peers: Observation,
    inbound_bindings: Observation,
    inbound_enrollment: Observation,
    listener_mtls: Observation,
    peer_allowlist: Allowlist,
) -> Report {
    let observations = [outbound_peers, inbound_bindings, listener_mtls];
    let present = observations.contains(&Observation::Present);
    let unknown = observations.contains(&Observation::Unobservable);
    let verdict = if peer_allowlist == Allowlist::Invalid
        || (peer_allowlist == Allowlist::Absent && present)
    {
        if posture == SecurityPosture::AsiHard {
            Verdict::Refused
        } else {
            Verdict::Warning
        }
    } else if peer_allowlist == Allowlist::Absent && inbound_enrollment != Observation::Absent {
        // Shared identity keys may belong entirely to local agents. Neither
        // their presence nor a read error establishes federation configuration.
        Verdict::Warning
    } else if matches!(
        peer_allowlist,
        Allowlist::Configured | Allowlist::ConfiguredEmpty
    ) {
        Verdict::Allowed
    } else if unknown {
        Verdict::Unobservable
    } else {
        Verdict::NoPeersObserved
    };
    Report {
        security_posture: posture.as_str().into(),
        outbound_peers,
        inbound_bindings,
        inbound_enrollment,
        listener_mtls,
        peer_allowlist,
        verdict,
        key_enrollment_required: true,
        require_push_namespace_scope: true,
        observation_errors: Vec::new(),
    }
}

/// Read public enrollment recursively, including slashed agent IDs (#1514).
/// Directory cycles are refused, not silently treated as an empty enrollment.
fn has_enrolled_public_key(root: &Path) -> Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = std::collections::HashSet::new();
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && dir == root => {
                return Ok(false);
            }
            Err(e) => return Err(e).context("reading public enrollment directory"),
        };
        anyhow::ensure!(
            visited.insert(std::fs::canonicalize(&dir)?),
            "public enrollment directory cycle"
        );
        crate::identity::keypair::enforce_key_dir_secure(&dir)?;
        for entry in entries {
            let path = entry?.path();
            if std::fs::metadata(&path)?.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path.strip_prefix(root)?;
            let Some(agent_id) = relative.to_str().and_then(|s| s.strip_suffix(".pub")) else {
                continue;
            };
            if crate::validate::validate_agent_id(agent_id).is_ok() {
                // Only public material is inspected. The receiver also accepts
                // public-only enrollment; private keys confer no extra scope.
                crate::identity::keypair::load_public(agent_id, root)?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn inbound_configured() -> Result<bool> {
    let fingerprints = crate::tls::peer_fingerprint_map_from_env()?;
    let bindings = crate::tls::cert_peer_binding_map_from_env()?;
    let trust = super::identity::trust_bundle::TrustBundle::load_from_env()?;
    Ok(fingerprints.is_some_and(|m| !m.is_empty())
        || bindings.is_some_and(|m| !m.is_empty())
        || !trust.is_empty())
}

/// Observe this process's configuration. `None` means argv is unavailable,
/// as in local doctor; `Some((false, None))` is an observed peerless listener.
#[must_use]
pub fn observe(argv: Option<(bool, Option<&Path>)>) -> Report {
    let mut errors = Vec::new();
    let posture = match SecurityPosture::resolve() {
        Ok(posture) => posture,
        Err(_) => {
            errors.push("security posture could not be resolved".into());
            SecurityPosture::AsiHard
        }
    };
    let inbound = match inbound_configured() {
        Ok(present) => Observation::from_present(present),
        Err(_) => {
            errors.push("inbound certificate configuration could not be read".into());
            Observation::Unobservable
        }
    };
    let enrollment = match crate::identity::keypair::default_key_dir()
        .and_then(|dir| has_enrolled_public_key(&dir))
    {
        Ok(present) => Observation::from_present(present),
        // Keep this separate from errors that refuse hardened boot: the shared
        // key directory cannot tell us whether a federation peer is configured.
        Err(_) => Observation::Unobservable,
    };
    let (outbound, mtls) = match argv {
        // An explicit inbound fingerprint-file argument configures peers.
        // The existing async TLS loader validates the file before listening;
        // this synchronous pre-runtime observation never starts a runtime.
        Some((peers, path)) => (
            Observation::from_present(peers),
            Observation::from_present(path.is_some()),
        ),
        None => (Observation::Unobservable, Observation::Unobservable),
    };
    let cfg = super::peer_attestation::PeerAttestationConfig::from_env();
    let allowlist = if !cfg.has_allowlist() {
        Allowlist::Absent
    } else if cfg.is_broken() {
        Allowlist::Invalid
    } else if cfg.is_configured_empty() {
        Allowlist::ConfiguredEmpty
    } else {
        Allowlist::Configured
    };
    let mut report = evaluate(posture, outbound, inbound, enrollment, mtls, allowlist);
    report.key_enrollment_required =
        crate::handlers::federation_signing_check::require_peer_enrollment_enabled()
            && !crate::handlers::federation_signing_check::allow_unenrolled_peers_enabled();
    report.require_push_namespace_scope =
        super::receive_auth::require_push_namespace_scope_enabled();
    report.observation_errors = errors;
    report
}

/// Snapshot of the last completed in-process boot evaluation. Capabilities
/// reports this snapshot, never guesses another process's argv or re-scans keys.
static BOOT_REPORT: RwLock<Option<Report>> = RwLock::new(None);

#[must_use]
pub fn boot_report() -> Option<Report> {
    BOOT_REPORT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Refuse asi-hard before starting workers or opening a database. Standard
/// retains a loud warning. Shared key enrollment only warns in either posture.
///
/// # Errors
/// Missing authorization with configured peers, invalid authorization, or
/// unreadable explicit federation configuration under asi-hard.
pub fn enforce_at_boot(outbound_peers: bool, mtls: Option<&Path>) -> Result<()> {
    let report = observe(Some((outbound_peers, mtls)));
    enforce_report(&report)?;
    *BOOT_REPORT.write().unwrap_or_else(|e| e.into_inner()) = Some(report);
    Ok(())
}

fn enforce_report(report: &Report) -> Result<()> {
    if report.refuses_boot() {
        anyhow::bail!(
            "{} #3582: peers configured without an allowlist or federation configuration invalid; \
             require valid AI_MEMORY_FED_PEER_ATTESTATION ({{}} explicitly denies all peers) \
             and readable federation bindings. \
             Key enrollment alone grants no namespace scope. Run `ai-memory doctor`.",
            crate::security_profile::ASI_HARD_REFUSAL_PREFIX
        );
    }
    if report.verdict == Verdict::Warning || !report.observation_errors.is_empty() {
        // stderr also works in the pre-tracing main entry point.
        eprintln!(
            "ai-memory: WARN #3582: peer authorization needs attention or shared key enrollment \
             is present/unobservable; configure AI_MEMORY_FED_PEER_ATTESTATION. Key enrollment alone \
             grants no namespace scope; required push scope refuses unscoped writes. \
             Run `ai-memory doctor`."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_configured_peer_source_requires_allowlist_3582() {
        for posture in [SecurityPosture::Standard, SecurityPosture::AsiHard] {
            for source in 0..3 {
                for allowlist in [
                    Allowlist::Absent,
                    Allowlist::ConfiguredEmpty,
                    Allowlist::Invalid,
                    Allowlist::Configured,
                ] {
                    let mut facts = [Observation::Absent; 3];
                    facts[source] = Observation::Present;
                    let report = evaluate(
                        posture,
                        facts[0],
                        facts[1],
                        Observation::Absent,
                        facts[2],
                        allowlist,
                    );
                    let expected = if matches!(
                        allowlist,
                        Allowlist::Configured | Allowlist::ConfiguredEmpty
                    ) {
                        Verdict::Allowed
                    } else if posture == SecurityPosture::AsiHard {
                        Verdict::Refused
                    } else {
                        Verdict::Warning
                    };
                    assert_eq!(report.verdict, expected);
                    assert_eq!(
                        enforce_report(&report).is_err(),
                        expected == Verdict::Refused
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_is_not_absent_and_known_inbound_still_finds_gap_3582() {
        for posture in [SecurityPosture::Standard, SecurityPosture::AsiHard] {
            let unknown = evaluate(
                posture,
                Observation::Unobservable,
                Observation::Absent,
                Observation::Absent,
                Observation::Unobservable,
                Allowlist::Absent,
            );
            assert_eq!(unknown.verdict, Verdict::Unobservable);
            let mut broken = unknown.clone();
            broken.observation_errors.push("unreadable bindings".into());
            assert_eq!(
                enforce_report(&broken).is_err(),
                posture == SecurityPosture::AsiHard
            );
            let local = evaluate(
                posture,
                Observation::Unobservable,
                Observation::Present,
                Observation::Absent,
                Observation::Unobservable,
                Allowlist::Absent,
            );
            assert!(matches!(local.verdict, Verdict::Warning | Verdict::Refused));
            let absent = evaluate(
                posture,
                Observation::Absent,
                Observation::Absent,
                Observation::Absent,
                Observation::Absent,
                Allowlist::Absent,
            );
            assert_eq!(absent.verdict, Verdict::NoPeersObserved);
            assert!(enforce_report(&absent).is_ok());
        }
    }

    #[test]
    fn shared_enrollment_only_warns_in_both_postures_3582() {
        for posture in [SecurityPosture::Standard, SecurityPosture::AsiHard] {
            for enrollment in [Observation::Present, Observation::Unobservable] {
                for allowlist in [
                    Allowlist::Absent,
                    Allowlist::ConfiguredEmpty,
                    Allowlist::Configured,
                ] {
                    let report = evaluate(
                        posture,
                        Observation::Absent,
                        Observation::Absent,
                        enrollment,
                        Observation::Absent,
                        allowlist,
                    );
                    let expected = if allowlist == Allowlist::Absent {
                        Verdict::Warning
                    } else {
                        Verdict::Allowed
                    };
                    assert_eq!(report.verdict, expected);
                    assert!(enforce_report(&report).is_ok());
                }
            }
            let invalid = evaluate(
                posture,
                Observation::Absent,
                Observation::Absent,
                Observation::Absent,
                Observation::Absent,
                Allowlist::Invalid,
            );
            assert_eq!(
                enforce_report(&invalid).is_err(),
                posture == SecurityPosture::AsiHard
            );
        }
    }

    #[test]
    fn recursive_public_enrollment_never_reads_private_material_3582() {
        let temp = tempfile::tempdir().unwrap();
        assert!(!has_enrolled_public_key(temp.path()).unwrap());
        let key = crate::identity::keypair::generate("region/node").unwrap();
        crate::identity::keypair::save_public_only(&key, temp.path()).unwrap();
        std::fs::write(
            temp.path().join("region/node.priv"),
            b"invalid private bytes",
        )
        .unwrap();
        assert!(has_enrolled_public_key(temp.path()).unwrap());
        assert!(!has_enrolled_public_key(&temp.path().join("missing")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_directory_cycles_are_unobservable_3582() {
        let temp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(temp.path(), temp.path().join("cycle")).unwrap();
        assert!(has_enrolled_public_key(temp.path()).is_err());
    }
}
