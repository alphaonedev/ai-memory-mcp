// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Schema-v97 authority selection for scoped wake-hub delegations.

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::VerifyingKey;

use crate::storage::AgentPubkeyVersion;

/// Select the proven, current root from one durable history snapshot.
///
/// Uses the strict timestamp eligibility and ledger validation of
/// `agent_pubkey_at`, then requires the eligible key to be
/// the current open version. Historical attestation eligibility alone must
/// never reauthorize a retired key for a live hub session (ERRORS-09).
///
/// # Errors
/// Refuses missing, malformed, unproven, closed, or timestamp-ineligible history.
pub fn current_issuer(
    agent_id: &str,
    versions: &[AgentPubkeyVersion],
    issued_at: &str,
) -> Result<VerifyingKey> {
    if agent_id.is_empty()
        || agent_id.len() > super::hub_delegation::MAX_PRINCIPAL_BYTES
        || versions.iter().any(|version| version.agent_id != agent_id)
    {
        bail!("invalid delegation principal or key history");
    }
    let eligible = crate::storage::select_agent_pubkey_version_at(versions, issued_at)?;
    let current = versions
        .last()
        .context("delegation issuer has no key history")?;
    if current.superseded_at.is_some()
        || !eligible.is_some_and(|version| version.version == current.version)
        || ![
            super::pubkey_bind::BindAuthority::PossessionProof.as_str(),
            super::pubkey_bind::BindAuthority::LineageSuccession.as_str(),
            super::pubkey_bind::BindAuthority::GuardianRecovery.as_str(),
        ]
        .contains(&current.bind_authority.as_str())
    {
        bail!("delegation issuer is not a proven current open history key");
    }
    super::keypair::decode_public_base64(&current.pubkey_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;

    const AGENT: &str = "agent-3468";
    const ISSUED: &str = "2026-09-04T12:00:00Z";

    fn version() -> AgentPubkeyVersion {
        AgentPubkeyVersion {
            agent_id: AGENT.to_owned(),
            version: 1,
            pubkey_b64: URL_SAFE_NO_PAD
                .encode(SigningKey::from_bytes(&[46; 32]).verifying_key().to_bytes()),
            bind_authority: "possession_proof".to_owned(),
            proof_nonce: Some("fixture".to_owned()),
            bound_at: "2026-09-04T11:00:00Z".to_owned(),
            superseded_at: None,
        }
    }

    #[test]
    fn allowed_each_proven_current_authority() {
        for authority in [
            "possession_proof",
            "lineage_succession",
            "guardian_recovery",
        ] {
            let mut row = version();
            row.bind_authority = authority.to_owned();
            assert!(current_issuer(AGENT, &[row], ISSUED).is_ok(), "{authority}");
        }
    }

    #[test]
    fn denied_missing_unproven_closed_and_ineligible_roots() {
        assert!(current_issuer(AGENT, &[], ISSUED).is_err());
        for authority in ["legacy_unproven", "unknown"] {
            let mut row = version();
            row.bind_authority = authority.to_owned();
            assert!(current_issuer(AGENT, &[row], ISSUED).is_err());
        }
        let mut row = version();
        row.superseded_at = Some("2026-09-04T11:59:59Z".to_owned());
        assert!(current_issuer(AGENT, &[row], ISSUED).is_err());
        assert!(current_issuer(AGENT, &[version()], "2026-09-03T00:00:00Z").is_err());
    }

    #[test]
    fn denied_malformed_ids_and_cross_agent_history() {
        for id in ["", &"x".repeat(129), "another-agent"] {
            assert!(current_issuer(id, &[version()], ISSUED).is_err());
        }
    }
}
