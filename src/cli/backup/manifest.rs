// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3199 — operator-signed backup manifests.
//!
//! Before #3199 a manifest was a sha256 of its snapshot, written next to it.
//! Anyone who can write the backup directory can replace BOTH files, so the
//! checksum only proved that the two files agree with each other. This module
//! binds the manifest to the OPERATOR key (5-agent vote `51c21dfd`, protocol
//! `4d3ea1c5`):
//!
//! * `backup` signs the JSON bytes of a [`SignedPayload`] with the operator
//!   key and stores those exact bytes (base64) beside the signature. The
//!   verifier never re-encodes anything: the stored bytes ARE what was signed.
//! * `restore` verifies the stored bytes against the operator public key it
//!   resolves OUT OF BAND
//!   ([`crate::governance::rules_store::resolve_operator_pubkey`]: the env pin,
//!   then the key directory) and only then parses them. It never trusts a key
//!   the manifest carries; [`BackupManifest::signer`] is a fingerprint for
//!   diagnostics only.
//! * A signature that is present but does not verify is refused with no
//!   override. A manifest with no signature is [`ManifestVerdict::Unverified`]
//!   and the caller decides (refused unless `--allow-unsigned-manifest` under
//!   the standard posture).

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::BackupManifest;

/// Domain / version discriminator committed INSIDE the signed bytes, so a
/// signature the operator key made over some other JSON document cannot be
/// replayed as a backup manifest.
pub(super) const MANIFEST_DOMAIN: &str = "ai-memory/backup-manifest/v1";

/// Version of the [`SignedPayload`] shape.
pub(super) const PAYLOAD_VERSION: i64 = 1;

/// `manifest_version` stamped on a signed manifest. A legacy (pre-#3199)
/// manifest carries no `manifest_version` at all.
pub(super) const MANIFEST_VERSION_SIGNED: i64 = 2;

/// Number of hex characters of the key digest kept in
/// [`BackupManifest::signer`].
const FINGERPRINT_HEX_LEN: usize = 16;

/// The signed half of a manifest: every field `restore` makes a decision on,
/// including the snapshot's FILE NAME, so a signed pair renamed to look like a
/// different backup is refused.
///
/// Field order is the encoding order (`serde_json::to_vec` follows
/// declaration order); the golden-bytes test pins it. Changing a field is a
/// new [`PAYLOAD_VERSION`], never an edit in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SignedPayload {
    /// Always [`MANIFEST_DOMAIN`].
    pub dst: String,
    /// Always [`PAYLOAD_VERSION`].
    pub v: i64,
    /// File name of the snapshot (`ai-memory-<ts>.db`), not a path.
    pub snapshot: String,
    /// Lowercase hex SHA-256 of the snapshot bytes.
    pub sha256: String,
    /// Snapshot size in bytes.
    pub bytes: u64,
    /// Source database path at capture time (provenance only).
    pub source_db: String,
    /// `ai-memory` version that took the snapshot.
    pub version: String,
    /// RFC 3339 capture time; `--latest` orders by this, never by mtime.
    pub created_at: String,
    /// Backend that produced the snapshot (always `sqlite` today).
    pub backend: String,
    /// Applied schema version of the captured database.
    pub schema_version: i64,
    /// Live `memories` row count at capture time.
    pub memory_count: i64,
}

/// Diagnostic fingerprint of a public key: `sha256:<16 hex>`. Never used for
/// a trust decision.
pub(super) fn fingerprint(key: &VerifyingKey) -> String {
    use sha2::Digest;
    let hex = crate::signed_events::hex_lower(&sha2::Sha256::digest(key.as_bytes()));
    format!("sha256:{}", &hex[..FINGERPRINT_HEX_LEN])
}

/// Sign `payload` with `key` and record the result on `manifest`.
///
/// # Errors
/// The payload cannot be encoded (a serialization bug in practice).
pub(super) fn sign_into(
    manifest: &mut BackupManifest,
    payload: &SignedPayload,
    key: &SigningKey,
) -> Result<()> {
    let bytes = serde_json::to_vec(payload).context("encoding the signed manifest payload")?;
    let signature = key.sign(&bytes);
    manifest.manifest_version = Some(MANIFEST_VERSION_SIGNED);
    manifest.signed_payload = Some(B64.encode(&bytes));
    manifest.signature = Some(B64.encode(signature.to_bytes()));
    manifest.signer = Some(fingerprint(&key.verifying_key()));
    Ok(())
}

/// Why a manifest could not be verified (it was not REFUSED; the caller
/// decides what an unverified manifest is worth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnverifiedReason {
    /// The manifest carries no signature: a pre-#3199 manifest, or one taken
    /// on a host with no operator signing key.
    NoSignature,
    /// The manifest is signed but no operator public key resolves on this
    /// host, so there is nothing to verify it against.
    NoAnchor,
}

impl UnverifiedReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::NoSignature => "unsigned",
            Self::NoAnchor => "no_operator_pubkey",
        }
    }
}

/// What a manifest turned out to be.
#[derive(Debug)]
pub(super) enum ManifestVerdict {
    /// The stored payload verified under the operator key; decide ONLY from
    /// it, never from the manifest's plain fields.
    Signed(SignedPayload),
    /// Nothing verified. `manifest` is the plain, unauthenticated content.
    Unverified {
        manifest: BackupManifest,
        reason: UnverifiedReason,
    },
}

/// Read a manifest and verify its signature against `anchor`.
///
/// # Errors
/// A REFUSAL with no override: the text is not a manifest, it carries half a
/// signature, the signature does not verify under `anchor`, or the verified
/// payload is not a backup manifest of a version this build understands.
pub(super) fn verify(text: &str, anchor: Option<&VerifyingKey>) -> Result<ManifestVerdict> {
    let manifest: BackupManifest =
        serde_json::from_str(text).context("the manifest is not valid manifest JSON")?;
    let (payload_b64, signature_b64) =
        match (manifest.signed_payload.as_deref(), manifest.signature.as_deref()) {
            (None, None) => {
                return Ok(ManifestVerdict::Unverified {
                    manifest,
                    reason: UnverifiedReason::NoSignature,
                });
            }
            (Some(p), Some(s)) => (p.to_owned(), s.to_owned()),
            _ => anyhow::bail!(
                "the manifest carries half a signature (signed_payload without signature, \
                 or the reverse) — refusing it (#3199)"
            ),
        };
    let Some(anchor) = anchor else {
        return Ok(ManifestVerdict::Unverified {
            manifest,
            reason: UnverifiedReason::NoAnchor,
        });
    };
    let bytes = B64
        .decode(payload_b64.as_bytes())
        .context("the manifest's signed_payload is not base64 — refusing it (#3199)")?;
    let signature_bytes = B64
        .decode(signature_b64.as_bytes())
        .context("the manifest's signature is not base64 — refusing it (#3199)")?;
    let signature = Signature::from_slice(&signature_bytes)
        .context("the manifest's signature is not an Ed25519 signature — refusing it (#3199)")?;
    anchor.verify_strict(&bytes, &signature).map_err(|_| {
        anyhow::anyhow!(
            "the manifest's signature does NOT verify under the operator public key \
             ({}) — the snapshot or its manifest was altered, or signed by another key. \
             Refusing it; there is no flag that accepts an invalid signature (#3199)",
            fingerprint(anchor)
        )
    })?;
    let payload: SignedPayload = serde_json::from_slice(&bytes)
        .context("the manifest's signed payload is not a backup manifest — refusing it (#3199)")?;
    if payload.dst != MANIFEST_DOMAIN || payload.v != PAYLOAD_VERSION {
        anyhow::bail!(
            "the manifest's signed payload is `{}` v{}, not `{MANIFEST_DOMAIN}` \
             v{PAYLOAD_VERSION} — refusing it (#3199)",
            payload.dst,
            payload.v
        );
    }
    Ok(ManifestVerdict::Signed(payload))
}
