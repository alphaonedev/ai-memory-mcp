// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Live v2 write-attestation path (crypto-core stage 3, #1942/#1941,
//! epic #1940, spec §2.2/§2.3/§2.4).
//!
//! Stage 1 landed the pinned CBOR-array encoder + [`SignableWriteV2`];
//! stage 2 landed the [`SubkeyCert`] chain and the suite-binding rule.
//! This module WIRES them into the live store path: when a store write
//! **presents a v2 envelope** (the `write_v2` presentation channel — see
//! [`PresentedWriteV2`]), the ingest runs the mandatory §2.3 order and, on
//! success, stamps `attest_level = agent_attested`; on any failure it
//! REJECTS unconditionally on every surface. When no v2 envelope is
//! presented the path is a no-op and the write follows exactly today's
//! v1/claimed behaviour (see [`crate::identity::attest`]).
//!
//! # Presentation channel (additive, opt-in)
//!
//! v1 arrives as a detached base64 `signature` + the signed `created_at`
//! (#626). v2 needs the whole certified envelope, so it arrives as a single
//! `write_v2` JSON object (a params key on MCP, a body field on HTTP, a
//! `--write-v2 <file>` payload on CLI) distinguished purely by presence.
//! The object is self-contained and offline-verifiable (the spec §5.2 /
//! R24 ethos): it carries the [`SubkeyCert`] fields, the cert + write
//! Ed25519 signatures, the advisory `suite_tag`, the optional presence-
//! encoded `session_id`, the content-digest codec, and the signed
//! `created_at`. The write's `instance_key_id` + `model_version_ref` are
//! taken FROM the (root-signed) cert, so the caller cannot present a write
//! bound to an instance the root never certified.
//!
//! # Mandatory ingest order (spec §2.3 / §7 step 3)
//!
//! 1. verify the [`SubkeyCert`] under the **principal root** (the agent's
//!    C3 bound pubkey), THEN
//! 2. verify the write under the **certified sub-key**, THEN
//! 3. cross-check the advisory `suite_tag` against the ENROLLED suite
//!    ([`verify_suite_binding`] — never dispatch on the wire tag), with the
//!    validity window checked between (2) and (3).
//!
//! A self-declared instance stamp with no root-signed cert is rejected at
//! step 1 ([`SubkeyCertError::CertInvalid`]).

use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use crate::identity::cbor_array::{
    HashCodec, MULTIHASH_DIGEST_LEN, Multihash, SignableWriteV2, canonical_cbor_write_v2,
};
use crate::identity::subkey_cert::{
    SubkeyCert, SubkeyCertError, check_validity, verify_write_under_certified_subkey,
};
use crate::identity::suite::{SuiteError, SuiteId, verify_suite_binding};
use crate::identity::verify::AttestLevel;
use crate::secret_screen::{ScreenOutcome, screen};

/// Presentation-channel JSON key that distinguishes a v2 store from a v1
/// (or unsigned) one. Its presence — and only its presence — routes a
/// write through the [`stamp_v2_sync`] gate.
pub const WRITE_V2_PARAM: &str = "write_v2";

/// Content-digest codec token accepted in the presented envelope — the
/// default, matching the v1 `content_sha256` + `cid` genesis digest.
const CODEC_SHA2_256: &str = "sha2-256";
/// BLAKE3 content-digest codec token (spec Appendix A.2).
const CODEC_BLAKE3: &str = "blake3";

/// Fold a field through [`crate::secret_screen::screen`] mode-independently
/// — byte-identical to [`crate::identity::cid`]'s genesis screening, so the
/// v2 preimage never carries a recoverable credential and a signer/verifier
/// on different `AI_MEMORY_SECRET_SCREEN_MODE` settings converge.
fn screened(field: &str) -> String {
    match screen(field) {
        ScreenOutcome::Clean => field.to_string(),
        ScreenOutcome::Hit { redacted, .. } => redacted,
    }
}

/// The certificate half of a presented v2 envelope (the [`SubkeyCert`]
/// bound fields, spec §2.3), decoded from base64.
#[derive(Debug, Clone)]
struct PresentedCert {
    principal: String,
    instance_key_id: Vec<u8>,
    model_version_ref: Vec<u8>,
    not_before: String,
    not_after: String,
}

/// A caller-presented v2 write envelope (the `write_v2` channel).
///
/// Self-contained + offline-verifiable: everything the §2.3 chain needs
/// except the enrolled principal-root key (resolved server-side from the
/// agent's C3 binding — an unauthenticated field can never become a trust
/// input).
#[derive(Debug, Clone)]
pub struct PresentedWriteV2 {
    cert: PresentedCert,
    cert_signature: Vec<u8>,
    write_signature: Vec<u8>,
    session_id: Option<String>,
    suite_tag: u64,
    codec: HashCodec,
    /// The RFC3339 `created_at` the caller committed inside the signed
    /// write bytes; the server adopts it verbatim (bounded by the v1
    /// freshness window) so the verifier re-derives identical bytes.
    pub created_at: String,
}

/// Errors from the live v2 ingest gate. Every variant is a hard REJECT on
/// every surface; the distinct variants are for logs / audit envelopes,
/// not for leaking which check failed (the [`SubkeyCertError`] precedent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestV2Error {
    /// The `write_v2` object was present but structurally malformed
    /// (missing field, bad base64, non-string where a string is required).
    Malformed(String),
    /// The presenting agent has no C3-bound principal-root key, so a
    /// presented v2 envelope cannot be verified — fail-closed reject
    /// (a presented-but-unverifiable envelope is never downgraded).
    NoRootKey,
    /// The bound principal-root key could not be decoded.
    BadRootKey,
    /// The cert certifies a different principal than the writing agent.
    PrincipalMismatch,
    /// The sub-key certification chain (cert-under-root → write-under-
    /// subkey) failed. Wraps the precise [`SubkeyCertError`].
    Chain(SubkeyCertError),
    /// The advisory `suite_tag` cross-check failed (unknown tag or a
    /// downgrade mismatch against the enrolled suite).
    Suite(SuiteError),
}

impl std::fmt::Display for AttestV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "malformed write_v2 envelope: {d}"),
            Self::NoRootKey => f.write_str(
                "v2 attestation presented but the agent has no bound principal-root key \
                 (bind one with `ai-memory agents bind-key`)",
            ),
            Self::BadRootKey => f.write_str("the agent's bound principal-root key is malformed"),
            Self::PrincipalMismatch => {
                f.write_str("the presented SubkeyCert certifies a different principal")
            }
            Self::Chain(e) => write!(f, "v2 subkey-certification chain failed: {e}"),
            Self::Suite(e) => write!(f, "v2 suite-binding cross-check failed: {e}"),
        }
    }
}

impl std::error::Error for AttestV2Error {}

impl AttestV2Error {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "write_v2_malformed",
            Self::NoRootKey => "write_v2_no_root_key",
            Self::BadRootKey => "write_v2_bad_root_key",
            Self::PrincipalMismatch => "write_v2_principal_mismatch",
            Self::Chain(_) => "write_v2_chain_invalid",
            Self::Suite(_) => "write_v2_suite_mismatch",
        }
    }
}

/// Standard-base64 decode a required string field of the `write_v2` object.
fn field_b64(obj: &Value, key: &str) -> Result<Vec<u8>, AttestV2Error> {
    use base64::Engine as _;
    let s = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AttestV2Error::Malformed(format!("missing string field `{key}`")))?;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| AttestV2Error::Malformed(format!("field `{key}` is not base64: {e}")))
}

/// Required string field of the `write_v2` object.
fn field_str<'a>(obj: &'a Value, key: &str) -> Result<&'a str, AttestV2Error> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AttestV2Error::Malformed(format!("missing string field `{key}`")))
}

/// Parse the presentation channel: return `Ok(None)` when no `write_v2`
/// object is present (the write follows today's v1/claimed path), `Ok(Some)`
/// when a well-formed envelope is presented, and `Err` when a `write_v2`
/// object is present but structurally invalid (a hard reject — a presented
/// v2 envelope is never silently ignored).
///
/// # Errors
///
/// [`AttestV2Error::Malformed`] when the object is present but a field is
/// missing / mis-typed / not base64.
pub fn parse_presented(params: &Value) -> Result<Option<PresentedWriteV2>, AttestV2Error> {
    let Some(obj) = params.get(WRITE_V2_PARAM) else {
        return Ok(None);
    };
    if obj.is_null() {
        return Ok(None);
    }
    if !obj.is_object() {
        return Err(AttestV2Error::Malformed(
            "`write_v2` must be an object".to_string(),
        ));
    }
    use crate::models::field_names as fk;
    let cert_obj = obj
        .get(fk::CERT)
        .filter(|v| v.is_object())
        .ok_or_else(|| AttestV2Error::Malformed("missing object field `cert`".to_string()))?;
    let cert = PresentedCert {
        principal: field_str(cert_obj, fk::PRINCIPAL)?.to_string(),
        instance_key_id: field_b64(cert_obj, fk::INSTANCE_KEY_ID)?,
        model_version_ref: field_b64(cert_obj, fk::MODEL_VERSION_REF)?,
        not_before: field_str(cert_obj, fk::NOT_BEFORE)?.to_string(),
        not_after: field_str(cert_obj, fk::NOT_AFTER)?.to_string(),
    };
    let suite_tag = obj
        .get(fk::SUITE_TAG)
        .and_then(Value::as_u64)
        .ok_or_else(|| AttestV2Error::Malformed("missing uint field `suite_tag`".to_string()))?;
    let codec = match obj.get(fk::CONTENT_CODEC).and_then(Value::as_str) {
        None | Some(CODEC_SHA2_256) => HashCodec::Sha2_256,
        Some(CODEC_BLAKE3) => HashCodec::Blake3,
        Some(other) => {
            return Err(AttestV2Error::Malformed(format!(
                "unknown content_codec `{other}`"
            )));
        }
    };
    let session_id = obj
        .get(fk::SESSION_ID)
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Some(PresentedWriteV2 {
        cert,
        cert_signature: field_b64(obj, fk::CERT_SIGNATURE)?,
        write_signature: field_b64(obj, fk::WRITE_SIGNATURE)?,
        session_id,
        suite_tag,
        codec,
        created_at: field_str(obj, fk::CREATED_AT)?.to_string(),
    }))
}

/// Compute the self-describing multihash content digest for the v2 preimage
/// over the (mode-independently screened) content.
fn content_multihash(codec: HashCodec, content: &str) -> Multihash {
    let screened_content = screened(content);
    let digest: [u8; MULTIHASH_DIGEST_LEN] = match codec {
        HashCodec::Sha2_256 => {
            use sha2::{Digest, Sha256};
            Sha256::digest(screened_content.as_bytes()).into()
        }
        HashCodec::Blake3 => blake3::hash(screened_content.as_bytes()).into(),
    };
    Multihash::new(codec, digest)
}

/// Run the full §2.3/§2.4 v2 ingest chain for a presented envelope over the
/// write's identity-bearing fields, returning [`AttestLevel::AgentAttested`]
/// on success.
///
/// `root_pubkey` is the writing agent's C3-bound principal-root verifying
/// key (the sole trust authority). `title` + `content` are the RAW row
/// fields; they are screened here to reconstruct the exact signed preimage.
/// `created_at` MUST already be the caller's adopted signed timestamp.
///
/// # Errors
///
/// The first failing [`AttestV2Error`] in mandatory chain order — the walk
/// is fail-closed and never falls back to a partially-verified state.
#[allow(clippy::too_many_arguments)]
pub fn verify_v2_write(
    root_pubkey: &VerifyingKey,
    agent_id: &str,
    namespace: &str,
    title: &str,
    kind: &str,
    created_at: &str,
    content: &str,
    presented: &PresentedWriteV2,
    now_rfc3339: &str,
) -> Result<AttestLevel, AttestV2Error> {
    // The cert's principal MUST be the writing agent (the write cannot
    // borrow a cert minted for someone else).
    if presented.cert.principal != agent_id {
        return Err(AttestV2Error::PrincipalMismatch);
    }

    let cert = SubkeyCert {
        principal: &presented.cert.principal,
        instance_key_id: &presented.cert.instance_key_id,
        model_version_ref: &presented.cert.model_version_ref,
        not_before: &presented.cert.not_before,
        not_after: &presented.cert.not_after,
    };

    // Reconstruct the exact signed v2 write pre-image. The instance +
    // model refs come FROM the (root-signed) cert, so a write can only
    // bind an instance the root certified.
    let digest = content_multihash(presented.codec, content);
    let screened_title = screened(title);
    let write = SignableWriteV2 {
        agent_id,
        namespace,
        title: &screened_title,
        kind,
        created_at,
        content_digest: digest,
        instance_key_id: &presented.cert.instance_key_id,
        model_version_ref: &presented.cert.model_version_ref,
        session_id: presented.session_id.as_deref(),
        suite_tag: presented.suite_tag,
    };
    let write_bytes = canonical_cbor_write_v2(&write);

    // Step 1+2 (mandatory order): cert-under-root FIRST, then write-under-
    // subkey. `verify_write_under_certified_subkey` enforces the order.
    verify_write_under_certified_subkey(
        root_pubkey,
        &cert,
        &presented.cert_signature,
        &presented.cert.instance_key_id,
        &write_bytes,
        &presented.write_signature,
    )
    .map_err(AttestV2Error::Chain)?;

    // Validity window (clock supplied by the live path, kept out of the
    // R24 offline core).
    check_validity(&cert, now_rfc3339).map_err(AttestV2Error::Chain)?;

    // Step 3: advisory suite cross-check against the ENROLLED authority —
    // never dispatched on the wire tag (JWS alg-confusion is unrepresentable
    // in `verify_suite_binding`'s shape). v1.0 enrolls exactly one suite.
    verify_suite_binding(SuiteId::Ed25519Sha256, presented.suite_tag)
        .map_err(AttestV2Error::Suite)?;

    Ok(AttestLevel::AgentAttested)
}

/// The audit copy of a verified [`SubkeyCert`] for TOFU-persistence into
/// the v79 `agent_subkey_certs` table (spec §2.3). Only ever written AFTER
/// [`verify_v2_write`] accepts the presentation, so the row is guaranteed
/// root-signed — an unauthenticated caller can never seed a trusted row.
#[derive(Debug, Clone)]
pub struct SubkeyCertRecord {
    /// Stable row id (`b3`-cid of the canonical cert bytes).
    pub id: String,
    /// Certified principal (== the writing agent).
    pub principal: String,
    /// Certified per-instance sub-key id (raw Ed25519 verifying-key bytes).
    pub instance_key_id: Vec<u8>,
    /// Bound model-version reference.
    pub model_version_ref: Vec<u8>,
    /// Validity window start (RFC3339).
    pub not_before: String,
    /// Validity window end (RFC3339).
    pub not_after: String,
    /// The principal root's Ed25519 signature over the canonical cert bytes.
    pub signature: Vec<u8>,
    /// The exact canonical signed CBOR (the audit copy).
    pub cert_bytes: Vec<u8>,
}

impl PresentedWriteV2 {
    /// Build the [`SubkeyCertRecord`] audit copy for the just-verified
    /// presentation. Call ONLY after [`verify_v2_write`] succeeded.
    #[must_use]
    pub fn to_record(&self) -> SubkeyCertRecord {
        use crate::identity::subkey_cert::canonical_cbor_subkey_cert;
        let cert = SubkeyCert {
            principal: &self.cert.principal,
            instance_key_id: &self.cert.instance_key_id,
            model_version_ref: &self.cert.model_version_ref,
            not_before: &self.cert.not_before,
            not_after: &self.cert.not_after,
        };
        let cert_bytes = canonical_cbor_subkey_cert(&cert);
        let id = format!("b3:{}", blake3::hash(&cert_bytes).to_hex());
        SubkeyCertRecord {
            id,
            principal: self.cert.principal.clone(),
            instance_key_id: self.cert.instance_key_id.clone(),
            model_version_ref: self.cert.model_version_ref.clone(),
            not_before: self.cert.not_before.clone(),
            not_after: self.cert.not_after.clone(),
            signature: self.cert_signature.clone(),
            cert_bytes,
        }
    }
}

/// Freshness-bound (replay / post-date guard) and adopt the presented v2
/// `created_at` onto `mem`, mirroring the v1 signed path so the verifier
/// re-derives identical bytes.
///
/// # Errors
///
/// When `created_at` is not RFC3339 or is outside the
/// [`crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS`] window; the
/// message is wire-suitable (QUAL-7: typed `anyhow`, not `String`).
fn adopt_created_at(
    mem: &mut crate::models::Memory,
    presented: &PresentedWriteV2,
) -> anyhow::Result<()> {
    let parsed = chrono::DateTime::parse_from_rfc3339(&presented.created_at)
        .map_err(|e| anyhow::anyhow!("invalid v2 `created_at` (expected RFC3339): {e}"))?;
    let skew = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs();
    if skew > crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS {
        anyhow::bail!(
            "v2 `created_at` is outside the ±{}s attestation freshness window (skew {skew}s)",
            crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS
        );
    }
    mem.created_at = presented.created_at.clone();
    Ok(())
}

/// Stamp `metadata.attest_level = agent_attested` on a verified v2 write.
fn stamp_agent_attested(mem: &mut crate::models::Memory) {
    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.insert(
            "attest_level".to_string(),
            serde_json::Value::String(AttestLevel::AgentAttested.as_str().to_string()),
        );
    }
}

/// Run the full live v2 ingest for a presented envelope on a direct
/// `rusqlite::Connection` surface (MCP `memory_store`, CLI `store`): adopt +
/// freshness-check `created_at`, resolve the principal-root key from the C3
/// binding, run the mandatory §2.3 chain, stamp `agent_attested`, and
/// TOFU-persist the (root-signed) cert. Any failure is a hard REJECT.
///
/// # Errors
///
/// On any verification, key-resolution, or freshness failure; the rendered
/// message is suitable for a 4xx / MCP error envelope (QUAL-7: typed
/// `anyhow`, not `String`). A presented-but-unverifiable envelope is NEVER
/// silently downgraded.
pub fn stamp_v2_sync(
    conn: &rusqlite::Connection,
    mem: &mut crate::models::Memory,
    agent_id: &str,
    presented: &PresentedWriteV2,
) -> anyhow::Result<()> {
    adopt_created_at(mem, presented)?;
    let root_b64 = crate::db::agent_pubkey(conn, agent_id)?
        .ok_or_else(|| anyhow::anyhow!(AttestV2Error::NoRootKey))?;
    let root = crate::identity::keypair::decode_public_base64(&root_b64)
        .map_err(|_| anyhow::anyhow!(AttestV2Error::BadRootKey))?;
    let now = chrono::Utc::now().to_rfc3339();
    verify_v2_write(
        &root,
        agent_id,
        &mem.namespace,
        &mem.title,
        mem.memory_kind.as_str(),
        &mem.created_at,
        &mem.content,
        presented,
        &now,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    stamp_agent_attested(mem);
    if let Err(e) = crate::db::insert_subkey_cert(conn, &presented.to_record()) {
        tracing::warn!(error = %e, "v2 subkey-cert TOFU persist failed (write still attested)");
    }
    Ok(())
}

/// Verify a stand-alone [`SubkeyCert`] under the principal `root` and, on
/// success, build its [`SubkeyCertRecord`] audit copy — the pre-enrollment
/// path for `ai-memory agents enroll-subkey-cert` (spec §2.3).
///
/// This is the operator/pre-enrollment complement of the inline TOFU path in
/// [`verify_v2_write`]: it certifies a sub-key ahead of any write, following
/// the `bind-key` pattern (the enrolled root is the sole trust authority).
///
/// # Errors
///
/// - [`AttestV2Error::Chain`] — the cert did not verify under `root`.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_record_cert(
    root: &VerifyingKey,
    principal: &str,
    instance_key_id: &[u8],
    model_version_ref: &[u8],
    not_before: &str,
    not_after: &str,
    cert_signature: &[u8],
) -> Result<SubkeyCertRecord, AttestV2Error> {
    use crate::identity::subkey_cert::{canonical_cbor_subkey_cert, verify_subkey_cert};
    let cert = SubkeyCert {
        principal,
        instance_key_id,
        model_version_ref,
        not_before,
        not_after,
    };
    verify_subkey_cert(root, &cert, cert_signature).map_err(AttestV2Error::Chain)?;
    let cert_bytes = canonical_cbor_subkey_cert(&cert);
    let id = format!("b3:{}", blake3::hash(&cert_bytes).to_hex());
    Ok(SubkeyCertRecord {
        id,
        principal: principal.to_string(),
        instance_key_id: instance_key_id.to_vec(),
        model_version_ref: model_version_ref.to_vec(),
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        signature: cert_signature.to_vec(),
        cert_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::cbor_array::SUITE_ED25519_SHA256;
    use crate::identity::subkey_cert::{SubkeyCert, sign_subkey_cert};
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }
    fn sub_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    const AGENT: &str = "ai:example-agent@host.example";
    const NS: &str = "global";
    const TITLE: &str = "t";
    const KIND: &str = "instruction";
    const CREATED: &str = "2026-07-11T00:00:00Z";
    const CONTENT: &str = "hello world";
    const NOW: &str = "2026-07-11T00:05:00Z";

    /// Build a fully-valid presented envelope + its principal-root key.
    fn valid_presentation() -> (VerifyingKey, PresentedWriteV2) {
        let root = root_key();
        let sub = sub_key();
        let instance_key_id = sub.verifying_key().to_bytes().to_vec();
        let model_version_ref = vec![0xab; 32];
        let not_before = "2026-07-11T00:00:00Z".to_string();
        let not_after = "2027-07-11T00:00:00Z".to_string();

        let cert = SubkeyCert {
            principal: AGENT,
            instance_key_id: &instance_key_id,
            model_version_ref: &model_version_ref,
            not_before: &not_before,
            not_after: &not_after,
        };
        let cert_sig = sign_subkey_cert(&root, &cert);

        // The write pre-image the sub-key signs — identical construction to
        // `verify_v2_write`.
        let digest = content_multihash(HashCodec::Sha2_256, CONTENT);
        let screened_title = screened(TITLE);
        let write = SignableWriteV2 {
            agent_id: AGENT,
            namespace: NS,
            title: &screened_title,
            kind: KIND,
            created_at: CREATED,
            content_digest: digest,
            instance_key_id: &instance_key_id,
            model_version_ref: &model_version_ref,
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
        };
        let write_bytes = canonical_cbor_write_v2(&write);
        let write_sig = sub.sign(&write_bytes).to_bytes();

        let presented = PresentedWriteV2 {
            cert: PresentedCert {
                principal: AGENT.to_string(),
                instance_key_id,
                model_version_ref,
                not_before,
                not_after,
            },
            cert_signature: cert_sig.to_vec(),
            write_signature: write_sig.to_vec(),
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
            codec: HashCodec::Sha2_256,
            created_at: CREATED.to_string(),
        };
        (root.verifying_key(), presented)
    }

    fn run(root: &VerifyingKey, p: &PresentedWriteV2) -> Result<AttestLevel, AttestV2Error> {
        verify_v2_write(root, AGENT, NS, TITLE, KIND, &p.created_at, CONTENT, p, NOW)
    }

    #[test]
    fn valid_v2_presentation_is_agent_attested() {
        let (root, p) = valid_presentation();
        assert_eq!(run(&root, &p).unwrap(), AttestLevel::AgentAttested);
    }

    #[test]
    fn forged_cert_under_wrong_root_is_rejected() {
        let (_root, p) = valid_presentation();
        // Verify against an unrelated root → cert-under-root (step 1) fails.
        let attacker_root = SigningKey::from_bytes(&[0x99; 32]).verifying_key();
        assert_eq!(
            run(&attacker_root, &p),
            Err(AttestV2Error::Chain(SubkeyCertError::CertInvalid)),
        );
    }

    #[test]
    fn forged_write_sig_under_valid_cert_is_rejected() {
        let (root, mut p) = valid_presentation();
        // Flip a write-signature byte: cert still verifies, write (step 2)
        // does not.
        p.write_signature[0] ^= 0x01;
        assert_eq!(
            run(&root, &p),
            Err(AttestV2Error::Chain(SubkeyCertError::WriteInvalid)),
        );
    }

    #[test]
    fn tampered_content_breaks_write_sig() {
        let (root, p) = valid_presentation();
        // Same envelope, a DIFFERENT persisted content → re-derived preimage
        // diverges → write verify fails.
        let err = verify_v2_write(
            &root,
            AGENT,
            NS,
            TITLE,
            KIND,
            &p.created_at,
            "TAMPERED",
            &p,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, AttestV2Error::Chain(SubkeyCertError::WriteInvalid));
    }

    #[test]
    fn suite_tag_mismatch_is_rejected() {
        let (root, mut p) = valid_presentation();
        // An unknown wire suite tag → the write sig also breaks (tag is in
        // the signed bytes), so the chain rejects first — proving a
        // downgraded tag can never attest. We assert a hard reject.
        p.suite_tag = 7;
        assert!(run(&root, &p).is_err());
    }

    #[test]
    fn principal_mismatch_is_rejected() {
        let (root, mut p) = valid_presentation();
        p.cert.principal = "ai:evil@host.example".to_string();
        assert_eq!(run(&root, &p), Err(AttestV2Error::PrincipalMismatch));
    }

    #[test]
    fn outside_validity_window_is_rejected() {
        let (root, p) = valid_presentation();
        // `now` before not_before → OutsideValidity.
        let err = verify_v2_write(
            &root,
            AGENT,
            NS,
            TITLE,
            KIND,
            &p.created_at,
            CONTENT,
            &p,
            "2020-01-01T00:00:00Z",
        )
        .unwrap_err();
        assert_eq!(err, AttestV2Error::Chain(SubkeyCertError::OutsideValidity));
    }

    #[test]
    fn parse_absent_is_none() {
        let params = serde_json::json!({"content": "x"});
        assert!(parse_presented(&params).unwrap().is_none());
    }

    #[test]
    fn parse_present_but_malformed_is_error() {
        let params = serde_json::json!({ WRITE_V2_PARAM: {"cert": {}} });
        assert!(matches!(
            parse_presented(&params),
            Err(AttestV2Error::Malformed(_))
        ));
    }

    #[test]
    fn parse_roundtrip_reconstructs_envelope() {
        let (root, p) = valid_presentation();
        let params = serde_json::json!({
            WRITE_V2_PARAM: {
                "cert": {
                    "principal": p.cert.principal,
                    "instance_key_id": B64.encode(&p.cert.instance_key_id),
                    "model_version_ref": B64.encode(&p.cert.model_version_ref),
                    "not_before": p.cert.not_before,
                    "not_after": p.cert.not_after,
                },
                "cert_signature": B64.encode(&p.cert_signature),
                "write_signature": B64.encode(&p.write_signature),
                "suite_tag": p.suite_tag,
                "content_codec": "sha2-256",
                "created_at": p.created_at,
            }
        });
        let parsed = parse_presented(&params).unwrap().expect("present");
        assert_eq!(run(&root, &parsed).unwrap(), AttestLevel::AgentAttested);
    }

    #[test]
    fn record_id_is_deterministic_b3() {
        let (_root, p) = valid_presentation();
        let r1 = p.to_record();
        let r2 = p.to_record();
        assert_eq!(r1.id, r2.id);
        assert!(r1.id.starts_with("b3:"));
        assert_eq!(r1.principal, AGENT);
    }

    // -- WIRED path: stamp_v2_sync + db round-trip -----------------------

    use crate::identity::keypair;
    use crate::models::{KindProvenance, Memory, MemoryKind};

    /// Build a valid `write_v2` presentation JSON `Value` (the object the
    /// presentation channel carries) for a registered agent whose bound
    /// principal-root is `root_kp`.
    fn valid_write_v2_json(root_kp: &keypair::AgentKeypair) -> serde_json::Value {
        let root = root_kp.private.as_ref().expect("root has private key");
        let sub = sub_key();
        let instance_key_id = sub.verifying_key().to_bytes().to_vec();
        let model_version_ref = vec![0xab; 32];
        // Wide window so the real-clock validity check passes on any run date.
        let not_before = "2020-01-01T00:00:00Z";
        let not_after = "2030-01-01T00:00:00Z";
        let cert = SubkeyCert {
            principal: AGENT,
            instance_key_id: &instance_key_id,
            model_version_ref: &model_version_ref,
            not_before,
            not_after,
        };
        let cert_sig = sign_subkey_cert(root, &cert);
        let digest = content_multihash(HashCodec::Sha2_256, CONTENT);
        let screened_title = screened(TITLE);
        // The wired `stamp_v2_sync` freshness-checks `created_at` against the
        // real clock, so sign over `now` (not a fixed fixture instant).
        let fresh = chrono::Utc::now().to_rfc3339();
        let write = SignableWriteV2 {
            agent_id: AGENT,
            namespace: NS,
            title: &screened_title,
            kind: KIND,
            created_at: &fresh,
            content_digest: digest,
            instance_key_id: &instance_key_id,
            model_version_ref: &model_version_ref,
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
        };
        let write_sig = sub.sign(&canonical_cbor_write_v2(&write)).to_bytes();
        serde_json::json!({
            "cert": {
                "principal": AGENT,
                "instance_key_id": B64.encode(&instance_key_id),
                "model_version_ref": B64.encode(&model_version_ref),
                "not_before": not_before,
                "not_after": not_after,
            },
            "cert_signature": B64.encode(cert_sig),
            "write_signature": B64.encode(write_sig),
            "suite_tag": SUITE_ED25519_SHA256,
            "content_codec": "sha2-256",
            "created_at": fresh,
        })
    }

    fn mem_fixture() -> Memory {
        Memory {
            namespace: NS.to_string(),
            title: TITLE.to_string(),
            content: CONTENT.to_string(),
            created_at: CREATED.to_string(),
            updated_at: CREATED.to_string(),
            memory_kind: MemoryKind::Instruction,
            metadata: serde_json::json!({ "agent_id": AGENT }),
            ..Memory::default()
        }
    }

    /// Register `AGENT` and bind its generated root pubkey; return the root
    /// keypair so a test can mint certs under it.
    fn registered_agent(conn: &rusqlite::Connection) -> keypair::AgentKeypair {
        crate::db::register_agent(conn, AGENT, "ai:generic", &[]).expect("register");
        let root_kp = keypair::generate(AGENT).expect("gen root");
        crate::db::bind_agent_pubkey(conn, AGENT, &root_kp.public_base64()).expect("bind");
        root_kp
    }

    #[test]
    fn wired_valid_v2_stamps_agent_attested_and_persists_cert() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        let root_kp = registered_agent(&conn);
        let params = serde_json::json!({ WRITE_V2_PARAM: valid_write_v2_json(&root_kp) });
        let presented = parse_presented(&params).unwrap().expect("present");

        let mut mem = mem_fixture();
        stamp_v2_sync(&conn, &mut mem, AGENT, &presented).expect("valid v2 must attest");
        assert_eq!(
            mem.metadata.get("attest_level").and_then(|v| v.as_str()),
            Some("agent_attested")
        );
        // Cert was TOFU-persisted (idempotent — one row).
        let certs = crate::db::list_subkey_certs(&conn, Some(AGENT)).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].principal, AGENT);
    }

    #[test]
    fn wired_forged_write_sig_is_rejected_and_not_persisted() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        let root_kp = registered_agent(&conn);
        let mut json = valid_write_v2_json(&root_kp);
        // Corrupt the write signature (still valid base64, wrong bytes).
        let mut sig = B64
            .decode(json["write_signature"].as_str().unwrap())
            .unwrap();
        sig[0] ^= 0x01;
        json["write_signature"] = serde_json::Value::String(B64.encode(&sig));
        let params = serde_json::json!({ WRITE_V2_PARAM: json });
        let presented = parse_presented(&params).unwrap().expect("present");

        let mut mem = mem_fixture();
        assert!(stamp_v2_sync(&conn, &mut mem, AGENT, &presented).is_err());
        assert!(mem.metadata.get("attest_level").is_none());
        // A rejected presentation must NOT persist a cert.
        assert!(
            crate::db::list_subkey_certs(&conn, Some(AGENT))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn wired_no_bound_root_key_is_rejected() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        // Register but do NOT bind a root key.
        crate::db::register_agent(&conn, AGENT, "ai:generic", &[]).unwrap();
        let root_kp = keypair::generate(AGENT).unwrap();
        let params = serde_json::json!({ WRITE_V2_PARAM: valid_write_v2_json(&root_kp) });
        let presented = parse_presented(&params).unwrap().expect("present");
        let mut mem = mem_fixture();
        let err = stamp_v2_sync(&conn, &mut mem, AGENT, &presented).unwrap_err();
        assert!(
            err.to_string().contains("no bound principal-root key"),
            "got: {err}"
        );
    }

    // -- kind_provenance column denormalisation (#1945) ------------------

    fn kind_provenance_col(conn: &rusqlite::Connection, id: &str) -> Option<String> {
        conn.query_row(
            "SELECT kind_provenance FROM memories WHERE id = ?1",
            [id],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap()
    }

    #[test]
    fn kind_provenance_stamped_metadata_denormalises_to_column() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        let mut mem = mem_fixture();
        mem.id = uuid::Uuid::new_v4().to_string();
        KindProvenance::Declared.stamp(&mut mem.metadata);
        let id = crate::db::insert(&conn, &mem).unwrap();
        assert_eq!(kind_provenance_col(&conn, &id).as_deref(), Some("declared"));
    }

    #[test]
    fn kind_provenance_unstamped_write_leaves_column_null() {
        // v1 regression pin: a write with no provenance carrier leaves the
        // v79 column NULL (legacy-legal), byte-for-byte the prior behaviour.
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        let mut mem = mem_fixture();
        mem.id = uuid::Uuid::new_v4().to_string();
        mem.title = "untyped".to_string();
        let id = crate::db::insert(&conn, &mem).unwrap();
        assert_eq!(kind_provenance_col(&conn, &id), None);
    }
}
