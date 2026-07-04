// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S1 (D3-012, #1870) — `ai-memory model-attest` CLI.
//!
//! Operator surface over the `model_attestations` substrate:
//!
//! - `model-attest list` — read-only dump of every attestation row.
//! - `model-attest enroll --agent-id <id> --provider <p> --model <m>
//!   --family <f> --sign` — land an `operator_signed` row binding a model
//!   family to an operator-controlled `agent_id`, Ed25519-signed with the
//!   operator key on disk.
//!
//! `loader_observed` rows are NOT written here — the substrate stamps
//! those at the LLM-client boundary (only substrate-invoked generation is
//! attestable; ~40% hard cap, ROADMAP.md:1229).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::Signer;

use crate::cli::CliOutput;
use crate::cli::rules::{OPERATOR_KEY_ID, load_operator_signing_key_from_dir, resolve_key_dir};
use crate::storage::model_attest;

/// Domain separator for the operator-enrollment signature pre-image.
const ENROLL_DOMAIN: &[u8] = b"model-attest-enroll-v1\x00";

#[derive(Args)]
pub struct ModelAttestArgs {
    /// Override the default key storage directory.
    /// Honors `AI_MEMORY_KEY_DIR` env var when this flag is omitted.
    #[arg(long, value_name = "PATH", global = true)]
    pub key_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: ModelAttestAction,
}

#[derive(Subcommand)]
pub enum ModelAttestAction {
    /// List every model-attestation row (loader-observed + operator-signed).
    /// Read-only, no key required.
    List,
    /// Enroll an operator-signed model-family attestation. Requires the
    /// operator keypair on disk; signs the canonical enrollment bytes.
    Enroll {
        /// Operator-controlled agent id this enrollment binds to.
        #[arg(long)]
        agent_id: String,
        /// Resolved provider/backend selector (e.g. `ollama`, `xai`).
        #[arg(long)]
        provider: String,
        /// Verbatim resolved model string (e.g. `grok-4`).
        #[arg(long)]
        model: String,
        /// Normalized family token (e.g. `grok`, `llama`).
        #[arg(long)]
        family: String,
        /// Sign the enrollment with the operator keypair on disk.
        #[arg(long)]
        sign: bool,
    },
}

/// Canonical, domain-tagged signing pre-image for an operator enrollment.
fn enroll_signable_bytes(provider: &str, model: &str, family: &str, agent_id: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        ENROLL_DOMAIN.len() + provider.len() + model.len() + family.len() + agent_id.len() + 4,
    );
    bytes.extend_from_slice(ENROLL_DOMAIN);
    for field in [provider, model, family, agent_id] {
        bytes.extend_from_slice(field.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn attestation_to_json(a: &model_attest::ModelAttestation) -> serde_json::Value {
    use crate::models::field_names;
    serde_json::json!({
        "id": a.id,
        "provider": a.provider,
        "model_ref": a.model_ref,
        "model_digest": a.model_digest,
        "model_family": a.model_family,
        "attest_level": a.attest_level,
        "agent_id": a.agent_id,
        "signed": a.signature.is_some(),
        (field_names::CREATED_AT): a.created_at,
    })
}

/// Entry point for `ai-memory model-attest`.
///
/// # Errors
///
/// Propagates db-open, key-load, signing, and SQLite errors.
pub fn run(
    db_path: &std::path::Path,
    args: ModelAttestArgs,
    json: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // Open via the migrating path so the `model_attestations` table (v78)
    // exists on a fresh db — same discipline as `cli::rules::run`.
    let conn = crate::db::open(db_path)
        .with_context(|| format!("model-attest: open db at {}", db_path.display()))?;

    match args.action {
        ModelAttestAction::List => {
            let rows = model_attest::list(&conn)?;
            let payload = serde_json::Value::Array(rows.iter().map(attestation_to_json).collect());
            crate::cli::rules::emit_ok(json, out, "model-attest.list", &payload)?;
            Ok(())
        }
        ModelAttestAction::Enroll {
            agent_id,
            provider,
            model,
            family,
            sign,
        } => {
            if !sign {
                bail!("model-attest.no_operator_key: `model-attest enroll` requires --sign");
            }
            let key_dir = resolve_key_dir(args.key_dir.as_deref())?;
            let signing_key = load_operator_signing_key_from_dir(&key_dir)?;
            let signable = enroll_signable_bytes(&provider, &model, &family, &agent_id);
            let sig = signing_key.sign(&signable);
            let inserted = model_attest::enroll_operator_signed(
                &conn,
                &provider,
                &model,
                &family,
                &agent_id,
                &sig.to_bytes(),
            )?;
            let payload = serde_json::json!({
                "agent_id": agent_id,
                "provider": provider,
                "model_ref": model,
                "model_family": family,
                "operator": OPERATOR_KEY_ID,
                "inserted": inserted,
            });
            crate::cli::rules::emit_ok(json, out, "model-attest.enroll", &payload)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_signable_bytes_are_domain_tagged_and_field_separated() {
        let a = enroll_signable_bytes("ollama", "llama3", "llama", "ai:op");
        assert!(a.starts_with(ENROLL_DOMAIN), "domain-tagged");
        // Deterministic + order-pinned.
        assert_eq!(
            a,
            enroll_signable_bytes("ollama", "llama3", "llama", "ai:op")
        );
        // Any field change flips the bytes.
        assert_ne!(a, enroll_signable_bytes("xai", "llama3", "llama", "ai:op"));
        assert_ne!(a, enroll_signable_bytes("ollama", "grok", "llama", "ai:op"));
        assert_ne!(
            a,
            enroll_signable_bytes("ollama", "llama3", "grok", "ai:op")
        );
        assert_ne!(
            a,
            enroll_signable_bytes("ollama", "llama3", "llama", "ai:other")
        );
        // Contains a NUL after each field.
        assert_eq!(
            a.iter().filter(|b| **b == 0).count(),
            ENROLL_DOMAIN.iter().filter(|b| **b == 0).count() + 4
        );
    }

    #[test]
    fn attestation_to_json_shape() {
        let a = model_attest::ModelAttestation {
            id: "id1".into(),
            provider: "ollama".into(),
            model_ref: "llama3".into(),
            model_digest: None,
            model_family: "llama".into(),
            attest_level: "loader_observed".into(),
            agent_id: String::new(),
            signature: Some(vec![1, 2, 3]),
            created_at: "2026-07-04T00:00:00Z".into(),
        };
        let j = attestation_to_json(&a);
        assert_eq!(j["provider"], "ollama");
        assert_eq!(j["model_family"], "llama");
        assert_eq!(j["attest_level"], "loader_observed");
        assert_eq!(j["signed"], true, "signature presence surfaced as `signed`");
        assert_eq!(j["model_digest"], serde_json::Value::Null);
    }
}
