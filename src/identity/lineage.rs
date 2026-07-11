// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G13 (#1828) — identity lineage: signed key-succession chains
//! (single-node ROTATION-survival core).
//!
//! Today an identity IS `metadata.agent_pubkey` — one key. Rotating it
//! leaves the new key with no cryptographic tie to the old, so every
//! `signed_events` row and attested write authored under `K_old` is
//! orphaned. This module adds an **opt-in, additive signed lineage
//! chain** so `agent_id A` names a *sequence of keys* `K0 → K1 → … →
//! Kn` linked by succession records signed by each predecessor: a
//! verifier walks **genesis → head** and trusts `Kn` via an unbroken
//! Ed25519 chain rooted at `K0`.
//!
//! # Honest scope (C7 — read before citing this module)
//!
//! - **Single-node key-ROTATION survival only.** This is NOT key-LOSS
//!   resilience: losing `K_current` with no chance to sign a handoff
//!   still orphans the identity this train. The record format carries
//!   `recovery_pubkey` for forward-compat, but the recovery VERIFY
//!   path (and its same-epoch fork tie-break) lands in v1.0 —
//!   [`verify_lineage`] fail-closes on any `reason = recovery` record.
//! - **Invisible cross-host.** Federation peers resolve identities via
//!   the on-disk key store
//!   ([`crate::identity::verify::lookup_peer_public_key`]), NOT the
//!   `_agents` registry this chain hangs off, so a rotation survived
//!   locally is still a fresh unknown key to a peer until re-enrolled.
//!   Lineage federation is deferred.
//! - **Advisory / verdict-only (C6).** [`current_authoritative_key`
//!   ](crate::storage::current_authoritative_key) feeds the
//!   [`LineageCheck`] verdict surface and the CLI — the `attest_write`
//!   enforcement hot path is UNTOUCHED and keeps reading the flat
//!   `metadata.agent_pubkey` (which every lineage append keeps in
//!   sync). Gap G13 stays OPEN until the v1.0 recovery path lands.
//!
//! # Trust anchoring (C1/C3 — why the walk beats the flat key)
//!
//! The `_agents` registration row is mutable, crypto-unauthenticated
//! metadata (`bind_agent_pubkey` ignores `CallerContext`), so a
//! self-signed chain stored there alone would be forgeable by
//! wholesale substitution under an attacker `K0'`. The verifier
//! therefore cross-anchors every record to the **append-only
//! `signed_events` witness** written in the same transaction as the
//! record body (C4):
//!
//! - each record's witness `payload_hash` = SHA-256 over the exact
//!   domain-tagged bytes the predecessor signed
//!   ([`LineageRecord::witness_payload_hash`]); a record with no
//!   matching witness is [`LineageError::WitnessMismatch`] (C1 — this
//!   pins genesis at enroll-time);
//! - the witness rows for an agent must correspond 1:1 with the stored
//!   records; leftover witnesses mean the newest record(s) were rolled
//!   back → [`LineageError::Truncated`] (C3 — the table carries no
//!   head/length commitment of its own).
//!
//! Every design element mirrors a shipped v0.9.0 gate: the
//! [`LineageCheck`] verdict enum clones `RoleSeparationCheck` (G9),
//! the [`LINEAGE_DOMAIN`](crate::identity::sign::LINEAGE_DOMAIN)
//! prefix clones `CID_DOMAIN` (G8), and the single-transaction append
//! clones `capture_turn_idempotent` (L4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::identity::keypair;
use crate::identity::sign::{SignableSuccession, canonical_cbor_succession, lineage_signing_input};
use crate::identity::verify::SIGNATURE_LEN;

/// `prev_record_hash` of the genesis record — 32 zero bytes (the chain
/// has no predecessor to hash). Mirrors `signed_events::ZERO_HASH`.
pub const ZERO_PREV_HASH: [u8; 32] = [0u8; 32];

/// Env flag (`AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`) that flips the
/// [`LineageCheck`] verdict to FAIL-CLOSED require-mode: with no
/// enrolled lineage the verdict becomes [`LineageCheck::Missing`]
/// (dirty) instead of withholding ([`LineageCheck::Unknown`]).
/// Default off ⇒ `Unknown` ⇒ byte-identical legacy posture. Mirrors
/// `AI_MEMORY_REQUIRE_ROLE_SEPARATION` / `AI_MEMORY_REQUIRE_WITNESS`.
pub const REQUIRE_IDENTITY_LINEAGE_ENV: &str = "AI_MEMORY_REQUIRE_IDENTITY_LINEAGE";

/// `true` when [`REQUIRE_IDENTITY_LINEAGE_ENV`] is set truthy
/// (`1`/`true`/`yes`/`on`). Clone of the
/// `governance::audit::env_flag_enabled` truthy set so require-mode
/// spelling is uniform across the K2-style gates.
#[must_use]
pub fn require_identity_lineage_enabled() -> bool {
    std::env::var(REQUIRE_IDENTITY_LINEAGE_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

/// Why a lineage record exists. Wire slugs are the lowercase names
/// (`"genesis"` / `"rotation"` / `"recovery"`), stored in the
/// `agent_lineage.reason` column and committed inside the signed bytes
/// (so a rotation signature can never be replayed as a recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageReason {
    /// Epoch-0 self-signed anchor: `predecessor == successor == K0`.
    Genesis,
    /// `K_old` hands off to `K_new`; signed by `K_old`.
    Rotation,
    /// Pre-registered cold recovery key mints a fresh head. The wire
    /// slug + witness event type exist NOW for forward-compat, but the
    /// VERIFY path is deferred to v1.0 (same-epoch fork tie-break is
    /// under-specified) — [`verify_lineage`] fail-closes on it and the
    /// append paths refuse to mint it.
    Recovery,
    /// v1.0.0 #1949 (R13) — the current head signs a record at epoch
    /// N+1 that REVOKES the chain from a suspected-compromise witness
    /// SEQUENCE high-water mark ([`LineageRecord::suspected_compromise_from_seq`]).
    /// Rides the same chain (`LINEAGE_DOMAIN`, C1/C3/C5, single
    /// [`verify_lineage`] walk) as a rotation — the successor is the
    /// fresh post-revocation head. Entries in
    /// `[suspected_compromise_from_seq, S_rev)` are DOWNGRADED to a
    /// Suspect verdict (never cryptographically un-verified — R13).
    /// **Verdict-surface-only this train** (no write-path teeth).
    Revocation,
}

impl LineageReason {
    /// Canonical wire slug (also the `agent_lineage.reason` column
    /// value and the CBOR `reason` field).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Genesis => LINEAGE_REASON_GENESIS,
            Self::Rotation => LINEAGE_REASON_ROTATION,
            Self::Recovery => LINEAGE_REASON_RECOVERY,
            Self::Revocation => LINEAGE_REASON_REVOCATION,
        }
    }

    /// Parse the stored column form. `None` for unknown slugs so the
    /// reader fail-closes rather than guessing.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            LINEAGE_REASON_GENESIS => Some(Self::Genesis),
            LINEAGE_REASON_ROTATION => Some(Self::Rotation),
            LINEAGE_REASON_RECOVERY => Some(Self::Recovery),
            LINEAGE_REASON_REVOCATION => Some(Self::Revocation),
            _ => None,
        }
    }
}

/// Wire slug for [`LineageReason::Genesis`] — the `agent_lineage.reason`
/// column value and the committed CBOR `reason` field.
pub const LINEAGE_REASON_GENESIS: &str = "genesis";
/// Wire slug for [`LineageReason::Rotation`].
pub const LINEAGE_REASON_ROTATION: &str = "rotation";
/// Wire slug for [`LineageReason::Recovery`].
pub const LINEAGE_REASON_RECOVERY: &str = "recovery";
/// Wire slug for [`LineageReason::Revocation`] (v1.0.0 #1949).
pub const LINEAGE_REASON_REVOCATION: &str = "revocation";

/// Wire slug for [`CustodyClass::SoftwareFile`] — the ONLY class the OSS
/// build will mint. It is the frozen DEFAULT: a record whose custody is
/// `software-file` omits the field from the signed CBOR entirely, so
/// every legacy v76 succession record (which predates the field) stays
/// byte-identical and its Ed25519 signature keeps verifying.
pub const CUSTODY_CLASS_SOFTWARE_FILE: &str = "software-file";
/// Wire slug for [`CustodyClass::Tpm2`] (RESERVED — never OSS-mintable).
pub const CUSTODY_CLASS_TPM2: &str = "tpm2";
/// Wire slug for [`CustodyClass::Pkcs11Hsm`] (RESERVED — never OSS-mintable).
pub const CUSTODY_CLASS_PKCS11_HSM: &str = "pkcs11-hsm";
/// Wire slug for [`CustodyClass::SecureEnclave`] (RESERVED — never OSS-mintable).
pub const CUSTODY_CLASS_SECURE_ENCLAVE: &str = "secure-enclave";
/// Wire slug for [`CustodyClass::Kms`] (RESERVED — never OSS-mintable).
pub const CUSTODY_CLASS_KMS: &str = "kms";

/// v1.0.0 #1949 (spec §3, `da9eeb26`) — the custody environment a
/// lineage key is held in, committed INSIDE the predecessor-signed
/// [`SignableSuccession`](crate::identity::sign::SignableSuccession)
/// bytes (never a bare crypto-unauthenticated column).
///
/// A CLOSED named-const value set: [`SoftwareFile`](Self::SoftwareFile)
/// is the only class the OSS build mints; `{tpm2, pkcs11-hsm,
/// secure-enclave, kms}` are RESERVED for a future commercial /
/// hardware-attesting build. [`from_str`](Self::from_str) fail-closes
/// (`None`) on any unknown slug, and [`ensure_oss_mintable`
/// ](Self::ensure_oss_mintable) is the CODE refuse-guard (not docs)
/// that structurally refuses to mint any non-`software-file` slug.
///
/// # ⚠️ ESTIMABLE, not ATTESTABLE (spec §3 verbatim)
///
/// `custody_class` is **attested-by-OSS-refusal-and-custody-separation,
/// NOT attested-by-hardware.** It **MUST NOT be a cross-host trust
/// input** — a peer never grants a `tpm2`-claiming key more authority
/// than `software-file` — until a reserved inner hardware-attestation
/// blob (TPM quote / PKCS#11 cert chain) lands. Local provenance marker
/// + refuse-guard only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CustodyClass {
    /// Key material is an on-disk software file. The frozen DEFAULT and
    /// the ONLY OSS-mintable class. Omitted from the signed CBOR for
    /// legacy byte-compat.
    #[default]
    SoftwareFile,
    /// RESERVED — TPM 2.0. Verifiable-only this train (never minted).
    Tpm2,
    /// RESERVED — PKCS#11 HSM. Verifiable-only this train.
    Pkcs11Hsm,
    /// RESERVED — secure enclave. Verifiable-only this train.
    SecureEnclave,
    /// RESERVED — cloud KMS. Verifiable-only this train.
    Kms,
}

/// Returned by [`CustodyClass::ensure_oss_mintable`] when a mint path is
/// asked to stamp a non-`software-file` custody class in the OSS build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyMintRefused {
    /// The refused (non-`software-file`) slug.
    pub slug: &'static str,
}

impl std::fmt::Display for CustodyMintRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "custody_class '{}' cannot be minted by the OSS build — only '{}' is mintable \
             (hardware-attesting custody classes are RESERVED for a future build)",
            self.slug, CUSTODY_CLASS_SOFTWARE_FILE
        )
    }
}

impl std::error::Error for CustodyMintRefused {}

impl CustodyClass {
    /// Canonical wire slug (the `agent_lineage.custody_class` column
    /// value and the committed CBOR field).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftwareFile => CUSTODY_CLASS_SOFTWARE_FILE,
            Self::Tpm2 => CUSTODY_CLASS_TPM2,
            Self::Pkcs11Hsm => CUSTODY_CLASS_PKCS11_HSM,
            Self::SecureEnclave => CUSTODY_CLASS_SECURE_ENCLAVE,
            Self::Kms => CUSTODY_CLASS_KMS,
        }
    }

    /// Parse the stored / wire slug. `None` (FAIL-CLOSED) on any unknown
    /// slug so a forged or future value is never silently trusted.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            CUSTODY_CLASS_SOFTWARE_FILE => Some(Self::SoftwareFile),
            CUSTODY_CLASS_TPM2 => Some(Self::Tpm2),
            CUSTODY_CLASS_PKCS11_HSM => Some(Self::Pkcs11Hsm),
            CUSTODY_CLASS_SECURE_ENCLAVE => Some(Self::SecureEnclave),
            CUSTODY_CLASS_KMS => Some(Self::Kms),
            _ => None,
        }
    }

    /// Resolve a nullable stored column into a class — a NULL / absent
    /// value is a legacy row that predates the field, which is
    /// definitionally [`SoftwareFile`](Self::SoftwareFile). `None` (the
    /// input `Option`) → default; `Some(unknown_slug)` → `None` return
    /// (fail-closed, surfaced by the caller).
    #[must_use]
    pub fn from_stored(slug: Option<&str>) -> Option<Self> {
        match slug {
            None => Some(Self::default()),
            Some(s) => Self::from_str(s),
        }
    }

    /// `true` for the sole OSS-mintable class.
    #[must_use]
    pub const fn is_software_file(self) -> bool {
        matches!(self, Self::SoftwareFile)
    }

    /// The CODE refuse-guard (spec §3: "the refuse-guard is code, not
    /// docs"). The OSS build STRUCTURALLY REFUSES to mint any
    /// non-`software-file` custody class — every mint path
    /// ([`crate::storage::append_lineage_record`] and its postgres twin)
    /// calls this before persisting.
    ///
    /// # Errors
    ///
    /// [`CustodyMintRefused`] for every RESERVED (hardware) class.
    pub fn ensure_oss_mintable(self) -> Result<Self, CustodyMintRefused> {
        if self.is_software_file() {
            Ok(self)
        } else {
            Err(CustodyMintRefused {
                slug: self.as_str(),
            })
        }
    }
}

/// One signed identity-lineage record (the owned storage shape backing
/// one `agent_lineage` row). The Ed25519 signature by
/// `predecessor_pubkey_b64` is stored ALONGSIDE (not signed-in) — see
/// [`crate::identity::sign::sign_succession`] for the exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageRecord {
    /// The identity that persists across key handoffs.
    pub agent_id: String,
    /// Genesis = 0, +1 per record (total order, anti-reorder).
    pub epoch: u64,
    /// Genesis / Rotation / Recovery.
    pub reason: LineageReason,
    /// base64 (URL-safe-no-pad) of the key that SIGNS this record.
    pub predecessor_pubkey_b64: String,
    /// base64 of the key handed off; == predecessor for genesis.
    pub successor_pubkey_b64: String,
    /// Optional pre-registered cold recovery key (v1.0 verify path).
    pub recovery_pubkey_b64: Option<String>,
    /// RFC3339; monotonic non-decreasing up the chain.
    pub not_before: String,
    /// SHA-256 over the canonical bytes of the prior record;
    /// [`ZERO_PREV_HASH`] for genesis.
    pub prev_record_hash: Vec<u8>,
    /// v1.0.0 #1949 — custody environment of `successor_pubkey_b64`.
    /// Committed inside the signed bytes; [`CustodyClass::SoftwareFile`]
    /// (the default) is OMITTED from the canonical CBOR so legacy v76
    /// records stay byte-identical and keep verifying.
    pub custody_class: CustodyClass,
    /// v1.0.0 #1949 — for a [`LineageReason::Revocation`] record ONLY,
    /// the `signed_events` witness SEQUENCE high-water mark from which a
    /// suspected key compromise is dated. `None` for genesis/rotation
    /// (omitted from the canonical CBOR → legacy byte-compat). The
    /// ordering authority for the Suspect window (never wall-clock).
    pub suspected_compromise_from_seq: Option<u64>,
}

impl LineageRecord {
    /// Mint the epoch-0 self-signed genesis shape for `k0_pub_b64`
    /// (the currently-bound key). `predecessor == successor == K0`,
    /// `prev_record_hash == ZERO`.
    #[must_use]
    pub fn genesis(
        agent_id: &str,
        k0_pub_b64: &str,
        recovery_pubkey_b64: Option<String>,
        not_before: &str,
    ) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            epoch: 0,
            reason: LineageReason::Genesis,
            predecessor_pubkey_b64: k0_pub_b64.to_string(),
            successor_pubkey_b64: k0_pub_b64.to_string(),
            recovery_pubkey_b64,
            not_before: not_before.to_string(),
            prev_record_hash: ZERO_PREV_HASH.to_vec(),
            custody_class: CustodyClass::SoftwareFile,
            suspected_compromise_from_seq: None,
        }
    }

    /// Mint the rotation shape that succeeds `prev` with
    /// `successor_pubkey_b64`. Epoch increments, the predecessor is
    /// pinned to `prev`'s successor, and `prev_record_hash` links to
    /// `prev`'s canonical bytes. `not_before` is clamped to be
    /// non-decreasing against `prev.not_before` so a slewed clock can
    /// never mint a record the verifier's monotonicity check rejects.
    ///
    /// # Errors
    ///
    /// Propagates the (in practice unreachable) CBOR-encode failure
    /// from hashing `prev`.
    pub fn rotation(
        prev: &LineageRecord,
        successor_pubkey_b64: &str,
        recovery_pubkey_b64: Option<String>,
        not_before: &str,
    ) -> anyhow::Result<Self> {
        let clamped = if not_before < prev.not_before.as_str() {
            prev.not_before.clone()
        } else {
            not_before.to_string()
        };
        Ok(Self {
            agent_id: prev.agent_id.clone(),
            epoch: prev.epoch + 1,
            reason: LineageReason::Rotation,
            predecessor_pubkey_b64: prev.successor_pubkey_b64.clone(),
            successor_pubkey_b64: successor_pubkey_b64.to_string(),
            recovery_pubkey_b64,
            not_before: clamped,
            prev_record_hash: prev.record_hash()?.to_vec(),
            custody_class: CustodyClass::SoftwareFile,
            suspected_compromise_from_seq: None,
        })
    }

    /// v1.0.0 #1949 — mint a [`LineageReason::Revocation`] record that
    /// succeeds `prev` and hands off to `successor_pubkey_b64` (the fresh
    /// post-revocation head), committing `suspected_compromise_from_seq`
    /// (the `signed_events` witness SEQUENCE high-water from which the
    /// compromise is dated — the ordering authority, never wall-clock)
    /// inside the signed bytes. Chains exactly like a rotation
    /// (epoch +1, `predecessor == prev.successor`, hash-linked, clamped
    /// monotonic `not_before`) so the single [`verify_lineage`] walk
    /// carries it. **Verdict-surface-only** — no write-path teeth.
    ///
    /// # Errors
    ///
    /// Propagates the (in practice unreachable) CBOR-encode failure from
    /// hashing `prev`.
    pub fn revocation(
        prev: &LineageRecord,
        successor_pubkey_b64: &str,
        suspected_compromise_from_seq: u64,
        recovery_pubkey_b64: Option<String>,
        not_before: &str,
    ) -> anyhow::Result<Self> {
        let clamped = if not_before < prev.not_before.as_str() {
            prev.not_before.clone()
        } else {
            not_before.to_string()
        };
        Ok(Self {
            agent_id: prev.agent_id.clone(),
            epoch: prev.epoch + 1,
            reason: LineageReason::Revocation,
            predecessor_pubkey_b64: prev.successor_pubkey_b64.clone(),
            successor_pubkey_b64: successor_pubkey_b64.to_string(),
            recovery_pubkey_b64,
            not_before: clamped,
            prev_record_hash: prev.record_hash()?.to_vec(),
            custody_class: CustodyClass::SoftwareFile,
            suspected_compromise_from_seq: Some(suspected_compromise_from_seq),
        })
    }

    /// Borrowed signable view — the audited canonical-encoder surface.
    #[must_use]
    pub fn to_signable(&self) -> SignableSuccession<'_> {
        SignableSuccession {
            agent_id: &self.agent_id,
            epoch: self.epoch,
            reason: self.reason.as_str(),
            predecessor_pubkey: &self.predecessor_pubkey_b64,
            successor_pubkey: &self.successor_pubkey_b64,
            recovery_pubkey: self.recovery_pubkey_b64.as_deref(),
            not_before: &self.not_before,
            prev_record_hash: &self.prev_record_hash,
            custody_class: self.custody_class.as_str(),
            suspected_compromise_from_seq: self.suspected_compromise_from_seq,
        }
    }

    /// Canonical RFC 8949 body bytes (WITHOUT the domain tag).
    ///
    /// # Errors
    /// CBOR-encode failure (in practice unreachable).
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        canonical_cbor_succession(&self.to_signable())
    }

    /// The exact bytes the predecessor signs:
    /// `LINEAGE_DOMAIN ∥ canonical_bytes`.
    ///
    /// # Errors
    /// CBOR-encode failure (in practice unreachable).
    pub fn signing_input(&self) -> anyhow::Result<Vec<u8>> {
        Ok(lineage_signing_input(&self.canonical_bytes()?))
    }

    /// SHA-256 over the canonical body bytes — the value the NEXT
    /// record's `prev_record_hash` must carry (anti-splice link).
    ///
    /// # Errors
    /// CBOR-encode failure (in practice unreachable).
    pub fn record_hash(&self) -> anyhow::Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes()?);
        Ok(hasher.finalize().into())
    }

    /// SHA-256 over the domain-tagged signing input — the
    /// `signed_events` witness `payload_hash` for this record (C1).
    ///
    /// # Errors
    /// CBOR-encode failure (in practice unreachable).
    pub fn witness_payload_hash(&self) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_input()?);
        Ok(hasher.finalize().to_vec())
    }
}

/// Why a lineage chain failed verification. Hand-rolled `Display` +
/// `Error` (no `thiserror`) per the repo convention
/// ([`crate::identity::verify::VerifyError`] precedent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageError {
    /// Empty chain, or record 0 is not a well-formed self-anchored
    /// genesis (`epoch 0`, `reason genesis`, `predecessor == successor`,
    /// zero `prev_record_hash`).
    NoGenesis,
    /// `epoch != prior_epoch + 1` — a record was reordered, dropped,
    /// or duplicated.
    EpochGap {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// The record's claimed predecessor is not the key the prior
    /// record handed off to (or the record is an unverifiable-this-train
    /// `recovery`). No path exists for a key outside the chain to
    /// become head.
    PredecessorMismatch {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// `prev_record_hash` does not match SHA-256 over the prior
    /// record's canonical bytes — anti-splice link broken.
    BrokenLink {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// The Ed25519 signature does not `verify_strict` under the
    /// record's predecessor key over the domain-tagged bytes (or the
    /// predecessor key / signature blob is malformed).
    SignatureInvalid {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// `not_before` decreased relative to the prior record (or is not
    /// parseable RFC3339).
    NonMonotonicTime {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// The chain verified but its head successor is not the key bound
    /// at `metadata.agent_pubkey` — the flat binding was tampered or
    /// desynced.
    HeadKeyMismatch,
    /// C1 — the record has no matching append-only `signed_events`
    /// witness (`payload_hash` over its exact signed bytes). A chain
    /// substituted/rewritten in the mutable table cannot fabricate the
    /// witness row, so this is the anchor that makes the walk add
    /// trust over the flat key.
    WitnessMismatch {
        /// Epoch of the offending record.
        epoch: u64,
    },
    /// C3 — more lineage witnesses exist in `signed_events` than
    /// records in the table: the newest record(s) were rolled back to
    /// resurrect a burned key.
    Truncated {
        /// Records present in the `agent_lineage` table.
        records: u64,
        /// Lineage witness rows present in `signed_events`.
        witnesses: u64,
    },
}

impl std::fmt::Display for LineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoGenesis => {
                f.write_str("lineage has no well-formed epoch-0 self-signed genesis record")
            }
            Self::EpochGap { epoch } => {
                write!(f, "epoch {epoch} is not contiguous with its predecessor")
            }
            Self::PredecessorMismatch { epoch } => write!(
                f,
                "record at epoch {epoch} claims a predecessor the chain never authorized \
                 (or is a recovery record, whose verify path lands in v1.0)"
            ),
            Self::BrokenLink { epoch } => write!(
                f,
                "record at epoch {epoch} does not hash-link to its predecessor (tampered body)"
            ),
            Self::SignatureInvalid { epoch } => write!(
                f,
                "record at epoch {epoch} signature does not verify under its predecessor key"
            ),
            Self::NonMonotonicTime { epoch } => write!(
                f,
                "record at epoch {epoch} not_before precedes its predecessor's (or is malformed)"
            ),
            Self::HeadKeyMismatch => {
                f.write_str("verified head key does not match the bound metadata.agent_pubkey")
            }
            Self::WitnessMismatch { epoch } => write!(
                f,
                "record at epoch {epoch} has no matching append-only signed_events witness (C1)"
            ),
            Self::Truncated { records, witnesses } => write!(
                f,
                "lineage truncation/rollback: {records} stored record(s) but {witnesses} \
                 append-only witness row(s) (C3)"
            ),
        }
    }
}

impl std::error::Error for LineageError {}

/// Successful outcome of a genesis→head walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLineage {
    /// The authoritative head key (highest-epoch successor).
    pub head_key: VerifyingKey,
    /// Epoch of the head record.
    pub epoch: u64,
    /// Records the walk verified (== chain length).
    pub records_checked: u64,
    /// v1.0.0 #1949 — custody class of the head key (surfaced in the
    /// verdict; ESTIMABLE, never a cross-host trust input).
    pub head_custody_class: CustodyClass,
    /// v1.0.0 #1949 — `suspected_compromise_from_seq` of the most-recent
    /// [`LineageReason::Revocation`] on the chain, or `None` if the chain
    /// carries no revocation. When `Some(from_seq)`, entries in
    /// `[from_seq, revocation)` are SUSPECT (R13) — surfaced as
    /// [`LineageCheck::Revoked`], the chain itself still verifies.
    pub revoked_from_seq: Option<u64>,
}

/// Verify ONE succession record's Ed25519 signature under
/// `predecessor` over the domain-tagged canonical bytes.
///
/// # Errors
///
/// [`LineageError::SignatureInvalid`] on a malformed (non-64-byte)
/// signature blob, an unencodable record, or a failed `verify_strict`.
pub fn verify_succession(
    record: &LineageRecord,
    signature: &[u8],
    predecessor: &VerifyingKey,
) -> Result<(), LineageError> {
    let invalid = || LineageError::SignatureInvalid {
        epoch: record.epoch,
    };
    let sig_arr: [u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| invalid())?;
    let sig = Signature::from_bytes(&sig_arr);
    let input = record.signing_input().map_err(|_| invalid())?;
    // #1808 — strict verification rejects malleable / non-canonical
    // signatures, matching every other v0.9.0 verifier.
    predecessor
        .verify_strict(&input, &sig)
        .map_err(|_| invalid())
}

/// Walk genesis → head and return the authoritative head key.
///
/// `records` are `(record, signature)` pairs in ascending-epoch order
/// (the `read_lineage` contract). `witness_hashes` are the
/// `signed_events` `payload_hash` blobs of every `identity.lineage.*`
/// row for this agent — the C1/C3 append-only anchor. `bound_pubkey_b64`
/// is the flat `metadata.agent_pubkey` the head is cross-checked
/// against.
///
/// The walk enforces, per record: epoch contiguity, the
/// `prev_record_hash` anti-splice link, `not_before` monotonicity,
/// authorized-predecessor (rotation: `predecessor == prior.successor`;
/// recovery: fail-closed this train), the per-record witness anchor
/// (C1), and a strict Ed25519 signature under the predecessor key.
/// After the walk: leftover witnesses → [`LineageError::Truncated`]
/// (C3), then head vs bound-key ([`LineageError::HeadKeyMismatch`]).
///
/// # Errors
///
/// The first [`LineageError`] encountered — the walk is fail-closed
/// and never "falls back" to a partially-verified head.
pub fn verify_lineage(
    records: &[(LineageRecord, Vec<u8>)],
    witness_hashes: &[Vec<u8>],
    bound_pubkey_b64: Option<&str>,
) -> Result<VerifiedLineage, LineageError> {
    // Genesis shape — epoch 0, self-anchored, zero prev-hash.
    let Some((genesis, _)) = records.first() else {
        return Err(LineageError::NoGenesis);
    };
    if genesis.epoch != 0
        || genesis.reason != LineageReason::Genesis
        || genesis.predecessor_pubkey_b64 != genesis.successor_pubkey_b64
        || genesis.prev_record_hash != ZERO_PREV_HASH
    {
        return Err(LineageError::NoGenesis);
    }

    // C1/C3 witness multiset — consumed one entry per verified record.
    let mut witnesses: std::collections::HashMap<&[u8], u64> = std::collections::HashMap::new();
    for w in witness_hashes {
        *witnesses.entry(w.as_slice()).or_insert(0) += 1;
    }
    let mut consume_witness = |record: &LineageRecord| -> Result<(), LineageError> {
        let mismatch = || LineageError::WitnessMismatch {
            epoch: record.epoch,
        };
        let hash = record.witness_payload_hash().map_err(|_| mismatch())?;
        match witnesses.get_mut(hash.as_slice()) {
            Some(count) if *count > 0 => {
                *count -= 1;
                Ok(())
            }
            _ => Err(mismatch()),
        }
    };

    let mut prev: Option<&LineageRecord> = None;
    // v1.0.0 #1949 — the newest revocation's compromise-from sequence
    // (verdict-surface-only; the chain still verifies past a revocation).
    let mut revoked_from_seq: Option<u64> = None;
    for (record, signature) in records {
        if let Some(prior) = prev {
            // Contiguity (anti-reorder / anti-drop).
            if record.epoch != prior.epoch + 1 {
                return Err(LineageError::EpochGap {
                    epoch: record.epoch,
                });
            }
            // Anti-splice hash link to the prior record's exact bytes.
            let expected = prior.record_hash().map_err(|_| LineageError::BrokenLink {
                epoch: record.epoch,
            })?;
            if record.prev_record_hash != expected {
                return Err(LineageError::BrokenLink {
                    epoch: record.epoch,
                });
            }
            // Monotonic not_before (parse-validated RFC3339).
            let parse = |s: &str| chrono::DateTime::parse_from_rfc3339(s);
            match (parse(&prior.not_before), parse(&record.not_before)) {
                (Ok(a), Ok(b)) if b >= a => {}
                _ => {
                    return Err(LineageError::NonMonotonicTime {
                        epoch: record.epoch,
                    });
                }
            }
            // Authorized predecessor. Rotation AND Revocation (#1949)
            // both hand off from the prior head key; Recovery stays
            // fail-closed this train (verify path + fork tie-break land
            // in v1.0).
            let hands_off_from_head = record.predecessor_pubkey_b64 == prior.successor_pubkey_b64;
            let authorized = matches!(
                record.reason,
                LineageReason::Rotation | LineageReason::Revocation
            ) && hands_off_from_head;
            if !authorized {
                return Err(LineageError::PredecessorMismatch {
                    epoch: record.epoch,
                });
            }
        }

        // v1.0.0 #1949 — a revocation carries the compromise-from
        // witness sequence forward; the newest revocation on the chain
        // wins the Suspect-window report.
        if record.reason == LineageReason::Revocation {
            if let Some(from_seq) = record.suspected_compromise_from_seq {
                revoked_from_seq = Some(from_seq);
            }
        }

        // C1 — every record (genesis included) must be anchored to its
        // append-only witness before its signature buys any trust.
        consume_witness(record)?;

        // Strict Ed25519 under the (chain-authorized) predecessor key.
        let predecessor =
            keypair::decode_public_base64(&record.predecessor_pubkey_b64).map_err(|_| {
                LineageError::SignatureInvalid {
                    epoch: record.epoch,
                }
            })?;
        verify_succession(record, signature, &predecessor)?;

        prev = Some(record);
    }

    // C3 — leftover witnesses mean the table lost its newest record(s).
    let leftover: u64 = witnesses.values().sum();
    if leftover > 0 {
        return Err(LineageError::Truncated {
            records: u64::try_from(records.len()).unwrap_or(u64::MAX),
            witnesses: u64::try_from(witness_hashes.len()).unwrap_or(u64::MAX),
        });
    }

    // prev is Some — records is non-empty past the genesis gate.
    let head = prev.ok_or(LineageError::NoGenesis)?;

    // Head cross-check against the flat binding (tamper indicator).
    let head_b64 = &head.successor_pubkey_b64;
    let matches_bound = bound_pubkey_b64.is_some_and(|bound| {
        // Compare decoded key BYTES, not strings, so padded-vs-unpadded
        // base64 spellings of the same key never false-mismatch.
        match (
            keypair::decode_public_base64(bound),
            keypair::decode_public_base64(head_b64),
        ) {
            (Ok(b), Ok(h)) => b.to_bytes() == h.to_bytes(),
            _ => false,
        }
    });
    if !matches_bound {
        return Err(LineageError::HeadKeyMismatch);
    }

    let head_key = keypair::decode_public_base64(head_b64)
        .map_err(|_| LineageError::SignatureInvalid { epoch: head.epoch })?;
    Ok(VerifiedLineage {
        head_key,
        epoch: head.epoch,
        records_checked: u64::try_from(records.len()).unwrap_or(u64::MAX),
        head_custody_class: head.custody_class,
        revoked_from_seq,
    })
}

/// Convenience: URL-safe-no-pad base64 of a verifying key (the wire
/// form every pubkey column in this module uses).
#[must_use]
pub fn pubkey_b64(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

/// v0.9.0 G13 (#1828) — verdict of the identity-lineage check, surfaced
/// by `verify-audit-trail` on BOTH backends. Mirrors
/// [`crate::signed_events::RoleSeparationCheck`] (G9): additive/opt-in,
/// withhold-by-default, require-flag to fail closed.
///
/// - [`Unknown`](LineageCheck::Unknown) — no agent has an enrolled
///   lineage (default posture): verdict withheld, byte-identical
///   legacy report.
/// - [`NotDetected`](LineageCheck::NotDetected) — every enrolled
///   lineage walks genesis→head cleanly.
/// - [`Forged`](LineageCheck::Forged) — an enrolled chain failed
///   [`verify_lineage`] (any [`LineageError`]). Hard-dirty.
/// - [`Revoked`](LineageCheck::Revoked) — an enrolled chain VERIFIES but
///   carries a [`LineageReason::Revocation`] (v1.0.0 #1949). NOT dirty —
///   the head key is authoritative; entries in the Suspect window are
///   surfaced, never cryptographically un-verified (R13).
/// - [`Missing`](LineageCheck::Missing) — require-mode
///   (`AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`) is on but no lineage is
///   enrolled: fail-closed (dirty).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LineageCheck {
    /// No lineage enrolled — verdict withheld (default posture).
    Unknown,
    /// Every enrolled chain holds genesis→head.
    NotDetected,
    /// An enrolled chain failed verification.
    Forged {
        /// Human-readable reason (for the CLI/JSON surface).
        detail: String,
    },
    /// v1.0.0 #1949 — an enrolled chain verifies but has been revoked.
    /// Chain integrity holds (NOT dirty); the readout names the Suspect
    /// window + head custody class.
    Revoked {
        /// The `signed_events` witness SEQUENCE the compromise is dated
        /// from — entries in `[from_seq, revocation)` are SUSPECT.
        from_seq: u64,
        /// Human-readable readout (agent, Suspect window, custody).
        detail: String,
    },
    /// Require-mode on but no enrolled lineage (fail-closed).
    Missing,
}

/// v1.0.0 #1949 — one enrolled agent's genesis→head walk outcome, fed to
/// [`compute_lineage_check`]. An owned struct (not a tuple) so both
/// backends' verdict assemblies stay legible as the readout grows.
/// SHARED by the sqlite + postgres `verify_audit_trail` twins so the
/// verdict is IDENTICAL (K3 parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageWalkOutcome {
    /// The agent whose chain this outcome describes.
    pub agent_id: String,
    /// `Some(detail)` = the walk's first failure (a rendered
    /// [`LineageError`], or an infra read failure — both fail-closed once
    /// lineage is known to exist); `None` = a clean walk.
    pub failure: Option<String>,
    /// `Some(from_seq)` = the clean chain carries a revocation dated from
    /// this witness sequence; `None` = no revocation.
    pub revoked_from_seq: Option<u64>,
    /// Custody class of the verified head key (surfaced in the verdict;
    /// ESTIMABLE — never a cross-host trust input). Ignored when
    /// [`failure`](Self::failure) is `Some`.
    pub head_custody_class: CustodyClass,
}

/// Compute the [`LineageCheck`] verdict from per-agent walk outcomes.
///
/// `outcomes` carries one [`LineageWalkOutcome`] per agent that HAS
/// lineage records. Verdict precedence (fail-closed / dirty first):
/// any failed walk → [`Forged`](LineageCheck::Forged); else any clean
/// chain carrying a revocation → [`Revoked`](LineageCheck::Revoked)
/// (verdict-surface, NOT dirty — #1949 R13); else
/// [`NotDetected`](LineageCheck::NotDetected). An empty set → `Unknown`
/// (or `Missing` under require-mode). SHARED by both backends
/// (`verify_audit_trail` sqlite + postgres twins) so the verdict is
/// IDENTICAL — the K3-parity discipline of G5b/G9.
#[must_use]
pub fn compute_lineage_check(outcomes: &[LineageWalkOutcome], require: bool) -> LineageCheck {
    if outcomes.is_empty() {
        return if require {
            LineageCheck::Missing
        } else {
            LineageCheck::Unknown
        };
    }
    // Forged (dirty) has precedence over Revoked (verdict-surface).
    for o in outcomes {
        if let Some(detail) = &o.failure {
            return LineageCheck::Forged {
                detail: format!("agent '{}': {detail}", o.agent_id),
            };
        }
    }
    for o in outcomes {
        if let Some(from_seq) = o.revoked_from_seq {
            return LineageCheck::Revoked {
                from_seq,
                detail: format!(
                    "agent '{}': chain revoked — entries from witness sequence {from_seq} \
                     are SUSPECT (custody: {})",
                    o.agent_id,
                    o.head_custody_class.as_str()
                ),
            };
        }
    }
    LineageCheck::NotDetected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair::AgentKeypair;
    use crate::identity::sign::sign_succession;

    fn kp(label: &str) -> AgentKeypair {
        crate::identity::keypair::generate(label).expect("generate")
    }

    fn signed(record: &LineageRecord, signer: &AgentKeypair) -> (LineageRecord, Vec<u8>) {
        let sig = sign_succession(signer, &record.to_signable()).expect("sign");
        (record.clone(), sig)
    }

    /// A verified 3-key chain K0 → K1 → K2 with matching witnesses.
    fn chain_fixture() -> (
        Vec<(LineageRecord, Vec<u8>)>,
        Vec<Vec<u8>>,
        AgentKeypair,
        AgentKeypair,
        AgentKeypair,
    ) {
        let k0 = kp("agent-a");
        let k1 = kp("agent-a");
        let k2 = kp("agent-a");
        let genesis = LineageRecord::genesis(
            "agent-a",
            &k0.public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        );
        let r1 = LineageRecord::rotation(
            &genesis,
            &k1.public_base64(),
            None,
            "2026-06-02T00:00:00+00:00",
        )
        .expect("rotation r1");
        let r2 =
            LineageRecord::rotation(&r1, &k2.public_base64(), None, "2026-06-03T00:00:00+00:00")
                .expect("rotation r2");
        let records = vec![signed(&genesis, &k0), signed(&r1, &k0), signed(&r2, &k1)];
        let witnesses = records
            .iter()
            .map(|(r, _)| r.witness_payload_hash().expect("hash"))
            .collect();
        (records, witnesses, k0, k1, k2)
    }

    #[test]
    fn clean_three_key_chain_verifies_to_head() {
        let (records, witnesses, _k0, _k1, k2) = chain_fixture();
        let v = verify_lineage(&records, &witnesses, Some(&k2.public_base64()))
            .expect("clean chain verifies");
        assert_eq!(v.head_key.to_bytes(), k2.public.to_bytes());
        assert_eq!(v.epoch, 2);
        assert_eq!(v.records_checked, 3);
    }

    #[test]
    fn empty_chain_is_no_genesis() {
        assert_eq!(
            verify_lineage(&[], &[], None).unwrap_err(),
            LineageError::NoGenesis
        );
    }

    #[test]
    fn genesis_shape_violations_are_no_genesis() {
        let k0 = kp("agent-a");
        let base = LineageRecord::genesis(
            "agent-a",
            &k0.public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        );
        // Wrong epoch.
        let mut wrong_epoch = base.clone();
        wrong_epoch.epoch = 1;
        // predecessor != successor.
        let mut split_keys = base.clone();
        split_keys.successor_pubkey_b64 = kp("agent-a").public_base64();
        // Non-zero prev hash.
        let mut nonzero_prev = base.clone();
        nonzero_prev.prev_record_hash = vec![0xAA; 32];
        // Wrong reason.
        let mut wrong_reason = base.clone();
        wrong_reason.reason = LineageReason::Rotation;
        for record in [wrong_epoch, split_keys, nonzero_prev, wrong_reason] {
            let signed_rec = signed(&record, &k0);
            let w = vec![record.witness_payload_hash().unwrap()];
            assert_eq!(
                verify_lineage(&[signed_rec], &w, Some(&k0.public_base64())).unwrap_err(),
                LineageError::NoGenesis
            );
        }
    }

    #[test]
    fn epoch_gap_detected() {
        let (mut records, witnesses, _k0, _k1, k2) = chain_fixture();
        records[2].0.epoch = 5;
        let err = verify_lineage(&records, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::EpochGap { epoch: 5 });
    }

    #[test]
    fn tampered_body_is_broken_link() {
        // Corrupt the head record's prev_record_hash: the anti-splice
        // link to its predecessor's exact bytes no longer holds. (The
        // link check runs BEFORE the record's witness/signature checks,
        // so this isolates BrokenLink specifically.)
        let (mut records, witnesses, _k0, _k1, k2) = chain_fixture();
        records[2].0.prev_record_hash = vec![0xAA; 32];
        let err = verify_lineage(&records, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::BrokenLink { epoch: 2 });
    }

    #[test]
    fn tampered_middle_record_is_witness_mismatch() {
        // Tampering a record's CONTENT changes its canonical bytes, so
        // its append-only witness anchor no longer matches — C1 fires
        // before the (also-broken) downstream link/signature checks.
        let (mut records, witnesses, _k0, _k1, k2) = chain_fixture();
        records[1].0.successor_pubkey_b64 = kp("agent-a").public_base64();
        let err = verify_lineage(&records, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::WitnessMismatch { epoch: 1 });
    }

    #[test]
    fn non_monotonic_not_before_rejected() {
        let (records, _w, k0, k1, k2) = chain_fixture();
        // Rebuild r2 with a not_before EARLIER than r1's, bypassing the
        // constructor clamp (attacker-authored record).
        let r1 = &records[1].0;
        let mut r2 =
            LineageRecord::rotation(r1, &k2.public_base64(), None, "2026-06-03T00:00:00+00:00")
                .unwrap();
        r2.not_before = "2026-05-01T00:00:00+00:00".to_string();
        let rebuilt = vec![records[0].clone(), records[1].clone(), signed(&r2, &k1)];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let err = verify_lineage(&rebuilt, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::NonMonotonicTime { epoch: 2 });
        drop(k0);
    }

    #[test]
    fn malformed_not_before_rejected() {
        let (records, _w, _k0, k1, k2) = chain_fixture();
        let r1 = &records[1].0;
        let mut r2 =
            LineageRecord::rotation(r1, &k2.public_base64(), None, "2026-06-03T00:00:00+00:00")
                .unwrap();
        r2.not_before = "not-a-timestamp".to_string();
        let rebuilt = vec![records[0].clone(), records[1].clone(), signed(&r2, &k1)];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let err = verify_lineage(&rebuilt, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::NonMonotonicTime { epoch: 2 });
    }

    #[test]
    fn forged_succession_wrong_predecessor_rejected() {
        // K_x (never attested by the chain) claims to hand off to
        // itself at epoch 2 with a self-consistent hash link but a
        // predecessor that is NOT r1's successor.
        let (records, _w, _k0, _k1, _k2) = chain_fixture();
        let kx = kp("agent-a");
        let r1 = &records[1].0;
        let mut forged =
            LineageRecord::rotation(r1, &kx.public_base64(), None, "2026-06-04T00:00:00+00:00")
                .unwrap();
        forged.predecessor_pubkey_b64 = kx.public_base64();
        let rebuilt = vec![records[0].clone(), records[1].clone(), signed(&forged, &kx)];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let err = verify_lineage(&rebuilt, &witnesses, Some(&kx.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::PredecessorMismatch { epoch: 2 });
    }

    #[test]
    fn forged_succession_wrong_signature_rejected() {
        // The record claims the RIGHT predecessor (r1's successor K1)
        // but is signed by K_x — verify_strict under K1 fails.
        let (records, _w, _k0, _k1, k2) = chain_fixture();
        let kx = kp("agent-a");
        let r1 = &records[1].0;
        let forged =
            LineageRecord::rotation(r1, &k2.public_base64(), None, "2026-06-04T00:00:00+00:00")
                .unwrap();
        let rebuilt = vec![
            records[0].clone(),
            records[1].clone(),
            signed(&forged, &kx), // signed by the WRONG key
        ];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let err = verify_lineage(&rebuilt, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::SignatureInvalid { epoch: 2 });
    }

    #[test]
    fn malformed_signature_blob_rejected() {
        let (mut records, witnesses, _k0, _k1, k2) = chain_fixture();
        records[2].1 = vec![0u8; 12]; // not 64 bytes
        let err = verify_lineage(&records, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::SignatureInvalid { epoch: 2 });
    }

    #[test]
    fn recovery_record_fail_closes_this_train() {
        // The recovery VERIFY path is v1.0 — a reason=recovery record
        // in the chain must be rejected, never trusted.
        let (records, _w, _k0, k1, k2) = chain_fixture();
        let r1 = &records[1].0;
        let mut rec =
            LineageRecord::rotation(r1, &k2.public_base64(), None, "2026-06-04T00:00:00+00:00")
                .unwrap();
        rec.reason = LineageReason::Recovery;
        let rebuilt = vec![records[0].clone(), records[1].clone(), signed(&rec, &k1)];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let err = verify_lineage(&rebuilt, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::PredecessorMismatch { epoch: 2 });
    }

    #[test]
    fn missing_witness_is_witness_mismatch_c1() {
        // Drop the genesis witness — a wholesale chain-substitution
        // under attacker K0' cannot fabricate the append-only anchor,
        // so verification must fail at the un-anchored record.
        let (records, mut witnesses, _k0, _k1, k2) = chain_fixture();
        witnesses.remove(0);
        let err = verify_lineage(&records, &witnesses, Some(&k2.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::WitnessMismatch { epoch: 0 });
    }

    #[test]
    fn leftover_witnesses_are_truncation_c3() {
        // Roll back the newest record from the table while its witness
        // survives in the append-only chain → Truncated.
        let (mut records, witnesses, _k0, k1, _k2) = chain_fixture();
        records.pop();
        let err = verify_lineage(&records, &witnesses, Some(&k1.public_base64())).unwrap_err();
        assert_eq!(
            err,
            LineageError::Truncated {
                records: 2,
                witnesses: 3
            }
        );
    }

    #[test]
    fn head_key_mismatch_detected() {
        let (records, witnesses, k0, _k1, _k2) = chain_fixture();
        // Bound key desynced to K0 while the verified head is K2.
        let err = verify_lineage(&records, &witnesses, Some(&k0.public_base64())).unwrap_err();
        assert_eq!(err, LineageError::HeadKeyMismatch);
        // No bound key at all is also a mismatch (metadata cleared).
        let err = verify_lineage(&records, &witnesses, None).unwrap_err();
        assert_eq!(err, LineageError::HeadKeyMismatch);
    }

    #[test]
    fn head_key_comparison_is_byte_level_not_string_level() {
        // A padded-base64 spelling of the SAME head key must not
        // false-trip HeadKeyMismatch.
        let (records, witnesses, _k0, _k1, k2) = chain_fixture();
        let padded = base64::engine::general_purpose::STANDARD.encode(k2.public.to_bytes());
        let v = verify_lineage(&records, &witnesses, Some(&padded))
            .expect("padded spelling of the same key must verify");
        assert_eq!(v.head_key.to_bytes(), k2.public.to_bytes());
    }

    #[test]
    fn reason_slugs_round_trip() {
        for reason in [
            LineageReason::Genesis,
            LineageReason::Rotation,
            LineageReason::Recovery,
        ] {
            assert_eq!(LineageReason::from_str(reason.as_str()), Some(reason));
        }
        assert_eq!(LineageReason::from_str("bogus"), None);
    }

    #[test]
    fn rotation_constructor_links_and_clamps() {
        let k0 = kp("agent-a");
        let k1 = kp("agent-a");
        let genesis = LineageRecord::genesis(
            "agent-a",
            &k0.public_base64(),
            Some("recovery-key-b64".to_string()),
            "2026-06-02T00:00:00+00:00",
        );
        // A not_before EARLIER than the predecessor's is clamped up so
        // a slewed clock can't mint an unverifiable record.
        let r1 = LineageRecord::rotation(
            &genesis,
            &k1.public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        )
        .unwrap();
        assert_eq!(r1.not_before, genesis.not_before);
        assert_eq!(r1.epoch, 1);
        assert_eq!(r1.predecessor_pubkey_b64, genesis.successor_pubkey_b64);
        assert_eq!(r1.prev_record_hash, genesis.record_hash().unwrap().to_vec());
    }

    #[test]
    fn witness_payload_hash_binds_the_domain_tagged_bytes() {
        let k0 = kp("agent-a");
        let genesis = LineageRecord::genesis(
            "agent-a",
            &k0.public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        );
        let mut hasher = Sha256::new();
        hasher.update(genesis.signing_input().unwrap());
        assert_eq!(
            genesis.witness_payload_hash().unwrap(),
            hasher.finalize().to_vec()
        );
        // And it differs from the record_hash (body-only) domain.
        assert_ne!(
            genesis.witness_payload_hash().unwrap(),
            genesis.record_hash().unwrap().to_vec()
        );
    }

    #[test]
    fn verify_succession_accepts_valid_and_rejects_cross_key() {
        let k0 = kp("agent-a");
        let genesis = LineageRecord::genesis(
            "agent-a",
            &k0.public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        );
        let (_, sig) = signed(&genesis, &k0);
        verify_succession(&genesis, &sig, &k0.public).expect("valid succession verifies");
        let other = kp("agent-a");
        assert_eq!(
            verify_succession(&genesis, &sig, &other.public).unwrap_err(),
            LineageError::SignatureInvalid { epoch: 0 }
        );
    }

    fn clean_outcome(agent: &str) -> LineageWalkOutcome {
        LineageWalkOutcome {
            agent_id: agent.to_string(),
            failure: None,
            revoked_from_seq: None,
            head_custody_class: CustodyClass::SoftwareFile,
        }
    }

    #[test]
    fn lineage_check_verdicts() {
        // No lineage: withhold by default, fail-closed under require.
        assert_eq!(compute_lineage_check(&[], false), LineageCheck::Unknown);
        assert_eq!(compute_lineage_check(&[], true), LineageCheck::Missing);
        // Clean chains: NotDetected.
        let clean = vec![clean_outcome("agent-a")];
        assert_eq!(
            compute_lineage_check(&clean, false),
            LineageCheck::NotDetected
        );
        assert_eq!(
            compute_lineage_check(&clean, true),
            LineageCheck::NotDetected
        );
        // Any failure: Forged with the agent + error in the detail.
        let dirty = vec![
            clean_outcome("agent-a"),
            LineageWalkOutcome {
                agent_id: "agent-b".to_string(),
                failure: Some(LineageError::HeadKeyMismatch.to_string()),
                revoked_from_seq: None,
                head_custody_class: CustodyClass::default(),
            },
        ];
        match compute_lineage_check(&dirty, false) {
            LineageCheck::Forged { detail } => {
                assert!(detail.contains("agent-b"), "got: {detail}");
                assert!(detail.contains("agent_pubkey"), "got: {detail}");
            }
            other => panic!("expected Forged, got {other:?}"),
        }
    }

    #[test]
    fn revoked_chain_yields_revoked_verdict_but_forged_wins() {
        // v1.0.0 #1949 — a clean-but-revoked chain surfaces Revoked (NOT
        // dirty); the from_seq + custody are in the detail.
        let revoked = vec![LineageWalkOutcome {
            agent_id: "agent-r".to_string(),
            failure: None,
            revoked_from_seq: Some(42),
            head_custody_class: CustodyClass::SoftwareFile,
        }];
        match compute_lineage_check(&revoked, false) {
            LineageCheck::Revoked { from_seq, detail } => {
                assert_eq!(from_seq, 42);
                assert!(detail.contains("agent-r"), "got: {detail}");
                assert!(detail.contains("42"), "got: {detail}");
                assert!(
                    detail.contains(CUSTODY_CLASS_SOFTWARE_FILE),
                    "got: {detail}"
                );
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
        // Forged (dirty) has precedence over Revoked (verdict-surface).
        let mixed = vec![
            LineageWalkOutcome {
                agent_id: "agent-r".to_string(),
                failure: None,
                revoked_from_seq: Some(7),
                head_custody_class: CustodyClass::SoftwareFile,
            },
            LineageWalkOutcome {
                agent_id: "agent-f".to_string(),
                failure: Some(LineageError::HeadKeyMismatch.to_string()),
                revoked_from_seq: None,
                head_custody_class: CustodyClass::default(),
            },
        ];
        assert!(matches!(
            compute_lineage_check(&mixed, false),
            LineageCheck::Forged { .. }
        ));
    }

    #[test]
    fn custody_class_slugs_round_trip_and_fail_closed() {
        for class in [
            CustodyClass::SoftwareFile,
            CustodyClass::Tpm2,
            CustodyClass::Pkcs11Hsm,
            CustodyClass::SecureEnclave,
            CustodyClass::Kms,
        ] {
            assert_eq!(CustodyClass::from_str(class.as_str()), Some(class));
        }
        // Unknown slug fail-closes to None (never guessed).
        assert_eq!(CustodyClass::from_str("hsm-of-the-future"), None);
        // NULL legacy column → software-file default; unknown → None.
        assert_eq!(
            CustodyClass::from_stored(None),
            Some(CustodyClass::SoftwareFile)
        );
        assert_eq!(CustodyClass::from_stored(Some("bogus")), None);
        assert!(CustodyClass::default().is_software_file());
    }

    #[test]
    fn custody_refuse_guard_only_mints_software_file() {
        // The OSS refuse-guard is CODE: software-file passes, every
        // reserved hardware class is refused.
        assert_eq!(
            CustodyClass::SoftwareFile.ensure_oss_mintable(),
            Ok(CustodyClass::SoftwareFile)
        );
        for class in [
            CustodyClass::Tpm2,
            CustodyClass::Pkcs11Hsm,
            CustodyClass::SecureEnclave,
            CustodyClass::Kms,
        ] {
            let err = class.ensure_oss_mintable().expect_err("must refuse");
            assert_eq!(err.slug, class.as_str());
        }
    }

    #[test]
    fn revocation_record_verifies_and_surfaces_the_window() {
        // A revocation record rides the chain like a rotation, and the
        // walk surfaces its suspected_compromise_from_seq + head custody.
        let (records, _w, _k0, k1, k2) = chain_fixture();
        let r1 = &records[1].0;
        let revocation = LineageRecord::revocation(
            r1,
            &k2.public_base64(),
            99,
            None,
            "2026-06-04T00:00:00+00:00",
        )
        .expect("build revocation");
        assert_eq!(revocation.reason, LineageReason::Revocation);
        assert_eq!(revocation.suspected_compromise_from_seq, Some(99));
        let rebuilt = vec![
            records[0].clone(),
            records[1].clone(),
            signed(&revocation, &k1),
        ];
        let witnesses: Vec<Vec<u8>> = rebuilt
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let v = verify_lineage(&rebuilt, &witnesses, Some(&k2.public_base64()))
            .expect("revoked chain still verifies (R13)");
        assert_eq!(v.epoch, 2);
        assert_eq!(v.revoked_from_seq, Some(99));
        assert_eq!(v.head_custody_class, CustodyClass::SoftwareFile);
        assert_eq!(v.head_key.to_bytes(), k2.public.to_bytes());
    }

    #[test]
    fn legacy_software_file_record_bytes_are_unchanged() {
        // v1.0.0 #1949 back-compat pin: a software-file / no-revocation
        // record's canonical signing bytes are byte-identical to a
        // record with the additive fields at their omitted defaults — so
        // legacy v76 signatures keep verifying.
        let (records, _w, _k0, _k1, _k2) = chain_fixture();
        let genesis = &records[0].0;
        let mut with_defaults = genesis.clone();
        with_defaults.custody_class = CustodyClass::SoftwareFile;
        with_defaults.suspected_compromise_from_seq = None;
        assert_eq!(
            genesis.canonical_bytes().unwrap(),
            with_defaults.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn lineage_check_serializes_with_status_tag() {
        // Mirrors the RoleSeparationCheck JSON shape so the
        // verify-audit-trail --json surface is uniform across verdicts.
        let json = serde_json::to_string(&LineageCheck::Forged {
            detail: "x".to_string(),
        })
        .unwrap();
        assert!(json.contains("\"status\":\"forged\""), "got: {json}");
        let json = serde_json::to_string(&LineageCheck::Unknown).unwrap();
        assert!(json.contains("\"status\":\"unknown\""), "got: {json}");
    }

    #[test]
    fn require_flag_parses_truthy_spellings() {
        // Env-var mutation: serialise via the keypair test lock (shared
        // process-global env discipline).
        let _guard = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (val, expected) in [
            ("1", true),
            ("true", true),
            ("YES", true),
            ("on", true),
            ("0", false),
            ("off", false),
            ("", false),
        ] {
            // SAFETY: test-only env mutation serialised by the lock above.
            unsafe { std::env::set_var(REQUIRE_IDENTITY_LINEAGE_ENV, val) };
            assert_eq!(
                require_identity_lineage_enabled(),
                expected,
                "value {val:?}"
            );
        }
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe { std::env::remove_var(REQUIRE_IDENTITY_LINEAGE_ENV) };
        assert!(!require_identity_lineage_enabled());
    }

    #[test]
    fn pubkey_b64_matches_keypair_encoding() {
        let k = kp("agent-a");
        assert_eq!(pubkey_b64(&k.public), k.public_base64());
    }

    #[test]
    fn lineage_error_display_is_operator_actionable() {
        // Every variant renders a non-empty, lowercase-start message
        // (err-lowercase-msg) that names the offending epoch where one
        // exists — these strings surface verbatim in the WARN log and
        // the Forged verdict detail.
        let cases: Vec<(LineageError, &str)> = vec![
            (LineageError::NoGenesis, "genesis"),
            (LineageError::EpochGap { epoch: 3 }, "3"),
            (LineageError::PredecessorMismatch { epoch: 4 }, "4"),
            (LineageError::BrokenLink { epoch: 5 }, "5"),
            (LineageError::SignatureInvalid { epoch: 6 }, "6"),
            (LineageError::NonMonotonicTime { epoch: 7 }, "7"),
            (LineageError::HeadKeyMismatch, "agent_pubkey"),
            (LineageError::WitnessMismatch { epoch: 8 }, "8"),
            (
                LineageError::Truncated {
                    records: 2,
                    witnesses: 3,
                },
                "rollback",
            ),
        ];
        for (err, needle) in cases {
            let rendered = err.to_string();
            assert!(
                rendered.contains(needle),
                "{err:?} rendered without its identifying detail: {rendered}"
            );
            assert!(
                rendered.chars().next().is_some_and(char::is_lowercase),
                "error messages start lowercase: {rendered}"
            );
        }
    }
}
