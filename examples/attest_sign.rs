// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `attest_sign` — repo-linked Ed25519 signer for the store-path agent
//! attestation gate (#626 Layer-3).
//!
//! The maximum-secure fleet runs with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`,
//! so an UNSIGNED `POST /api/v1/memories` is refused `403 ATTESTATION_FAILED`.
//! A positive functional write must present a detached Ed25519 `signature`
//! (standard base64) plus the `created_at` (RFC3339) it signed, so the daemon
//! re-derives the exact [`SignableWrite`] envelope and verifies it against the
//! agent's bound public key.
//!
//! This tool exists so the canonical byte serialisation the signature commits
//! to is computed by the **same crate code the verifier runs** — there is no
//! re-implementation of the RFC 8949 deterministic-CBOR encoding or the SHA-256
//! content commitment in bash. It calls
//! [`ai_memory::identity::sign::sign_write`] over the
//! [`ai_memory::identity::sign::SignableWrite`] envelope built by
//! [`ai_memory::identity::attest::sign_memory_write`]'s exact field contract:
//!
//! ```text
//! SignableWrite { agent_id, namespace, title, kind, created_at,
//!                 content_sha256 = sha256(content) }
//! ```
//!
//! and prints the resulting 64-byte signature as **standard base64** — the
//! encoding [`ai_memory::identity::attest::prepare_signed_store`] decodes on the
//! receive path. The private key is read as the raw 32-byte Ed25519 seed the
//! `keypair` module writes to `<agent_id>.priv`; it is never echoed.
//!
//! Usage (the harness `attested_write` helper drives this):
//!
//! ```bash
//! attest_sign \
//!   --agent-id   ai:harness@do-1461 \
//!   --namespace  _test \
//!   --title      reg-... \
//!   --kind       observation \
//!   --created-at 2026-06-08T12:00:00+00:00 \
//!   --content    'regression probe sentinel ...' \
//!   --priv-file  /path/to/ai:harness@do-1461.priv
//! ```
//!
//! `--content-file -` reads the content body from stdin so a payload with shell
//! metacharacters never lands on a command line.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::Parser;
use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

use ai_memory::identity::attest::content_sha256;
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::identity::sign::{SignableWrite, sign_write};

#[derive(Parser)]
#[command(
    name = "attest_sign",
    about = "Sign the store-path SignableWrite envelope and print the standard-base64 Ed25519 signature"
)]
struct Cli {
    /// The claiming agent id (the field the attestation gate binds). MUST be
    /// the same id the request authenticates as (X-Agent-Id) AND the id whose
    /// public key is bound on the peer.
    #[arg(long)]
    agent_id: String,
    /// Namespace the write targets.
    #[arg(long)]
    namespace: String,
    /// Memory title (`(title, namespace)` is the upsert key — identity-bearing).
    #[arg(long)]
    title: String,
    /// Memory kind discriminant. The default-kind path lands `observation`, so
    /// the signer pins the same value the row will carry. One of the Form-6
    /// vocabulary strings (observation/reflection/persona/concept/entity/claim/
    /// relation/event/conversation/decision).
    #[arg(long, default_value = "observation")]
    kind: String,
    /// RFC3339 creation timestamp the signature commits to. The caller MUST
    /// send this SAME value as the request body `created_at`; the server adopts
    /// it verbatim (within the ±300s freshness window) before re-deriving the
    /// envelope.
    #[arg(long)]
    created_at: String,
    /// Memory content. Mutually exclusive with `--content-file`.
    #[arg(long, conflicts_with = "content_file")]
    content: Option<String>,
    /// Read the content body from this file (or `-` for stdin). Keeps payloads
    /// with shell metacharacters off the command line.
    #[arg(long)]
    content_file: Option<PathBuf>,
    /// Path to the agent's raw 32-byte Ed25519 private seed (`<agent_id>.priv`).
    #[arg(long)]
    priv_file: PathBuf,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(sig_b64) => {
            // The signature is the ONLY thing on stdout so the harness can
            // capture it with a bare command substitution.
            println!("{sig_b64}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("attest_sign: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<String> {
    let content = resolve_content(cli)?;

    // Load the raw 32-byte Ed25519 seed and build a sign-capable AgentKeypair.
    let keypair = load_signing_keypair(&cli.agent_id, &cli.priv_file)?;

    // Build the SAME envelope the verifier re-derives — the field contract is
    // pinned by `attest::sign_memory_write` / `attest::stamp_attestation`.
    let content_hash = content_sha256(&content);
    let write = SignableWrite {
        agent_id: &cli.agent_id,
        namespace: &cli.namespace,
        title: &cli.title,
        kind: &cli.kind,
        created_at: &cli.created_at,
        content_sha256: &content_hash,
    };

    let sig = sign_write(&keypair, &write).context("signing the write envelope")?;
    // STANDARD base64 (NOT url-safe): `attest::prepare_signed_store` decodes the
    // wire `signature` with the standard alphabet.
    Ok(base64::engine::general_purpose::STANDARD.encode(sig))
}

/// Resolve the content body from `--content`, `--content-file <path>`, or
/// `--content-file -` (stdin). Exactly one source must be present.
fn resolve_content(cli: &Cli) -> Result<String> {
    match (&cli.content, &cli.content_file) {
        (Some(c), None) => Ok(c.clone()),
        (None, Some(path)) => {
            if path.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .context("reading content from stdin")?;
                Ok(buf)
            } else {
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading content file {}", path.display()))
            }
        }
        (None, None) => bail!("one of --content or --content-file is required"),
        (Some(_), Some(_)) => {
            // clap `conflicts_with` already guards this; belt-and-suspenders.
            bail!("--content and --content-file are mutually exclusive")
        }
    }
}

/// Read the raw 32-byte Ed25519 seed at `priv_file` and build a sign-capable
/// [`AgentKeypair`] for `agent_id`. The seed format matches the `.priv` files
/// `keypair::save` writes (`SigningKey::to_bytes()`); the secret never lands on
/// stdout/stderr.
fn load_signing_keypair(agent_id: &str, priv_file: &std::path::Path) -> Result<AgentKeypair> {
    let bytes = std::fs::read(priv_file)
        .with_context(|| format!("reading private key {}", priv_file.display()))?;
    let seed: [u8; SECRET_KEY_LENGTH] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "private key {} is {} bytes, expected {SECRET_KEY_LENGTH} raw Ed25519 seed bytes",
            priv_file.display(),
            bytes.len()
        )
    })?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    Ok(AgentKeypair {
        agent_id: agent_id.to_string(),
        public,
        private: Some(signing),
    })
}
