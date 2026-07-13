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
    /// v1.0.0 #1831 (G17) — for a [`LineageReason::Recovery`] record ONLY,
    /// the SHA-256 digest over the SORTED enrolled recovery-guardian public
    /// keys the quorum was minted against. Committed inside the signed
    /// bytes so the verifier re-checks against the guardian set AT MINT
    /// time (never its own current env). `None` for every non-recovery
    /// record (omitted from the canonical CBOR → legacy byte-compat).
    pub guardian_set_id: Option<Vec<u8>>,
    /// v1.0.0 #1831 (G17) — for a [`LineageReason::Recovery`] record ONLY,
    /// the M-of-N threshold the quorum was minted against, committed so
    /// verification enforces the threshold-at-mint (never a later-lowered
    /// env value). `None` for every non-recovery record (omitted → legacy
    /// byte-compat).
    pub recovery_threshold: Option<u64>,
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
            guardian_set_id: None,
            recovery_threshold: None,
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
            guardian_set_id: None,
            recovery_threshold: None,
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
            guardian_set_id: None,
            recovery_threshold: None,
        })
    }

    /// v1.0.0 #1831 (G17) — mint a [`LineageReason::Recovery`] record that
    /// succeeds `prev` and hands off to `successor_pubkey_b64` (a FRESH
    /// primary key), attested NOT by the prior head key (which is LOST)
    /// but by an M-of-N quorum of enrolled recovery guardians
    /// ([`RecoveryPolicy`]). This is the key-LOSS half of G13: losing the
    /// primary key no longer orphans the identity — a guardian quorum can
    /// mint a fresh head.
    ///
    /// `predecessor_pubkey` is pinned to `prev.successor` (the LOST head)
    /// so the record still names the key it recovers FROM and the single
    /// [`verify_lineage`] walk keeps its contiguity + hash-link
    /// invariants; the difference from a rotation is that the stored
    /// `signature` blob is a quorum attestation
    /// ([`encode_recovery_quorum`]) verified against the guardian set, not
    /// a single predecessor Ed25519 signature.
    ///
    /// `suspected_compromise_from_seq` doubles the recovery as a
    /// revocation — this is the OPT-IN "recovery signs both fresh head +
    /// revocation" path (#1831 ratification delta F): when `Some(seq)`,
    /// entries in `[seq, recovery)` are surfaced as SUSPECT (the lost key
    /// may have been stolen AND lost); when `None` the recovery is PURE and
    /// the predecessor's prior entries stay fully trusted. Callers that
    /// suspect the lost key was compromised MUST pass `Some(seq)`.
    ///
    /// `guardian_set_id` + `recovery_threshold` are the committed trust
    /// anchor (#1831 ratification delta A): the SHA-256 over the SORTED
    /// enrolled guardian pubkeys and the M-of-N threshold the quorum was
    /// minted against. They ride the signed CBOR body so a persisted
    /// recovery is re-verified against the guardian set + threshold AT MINT
    /// time, never the verifier's later env.
    ///
    /// # Errors
    ///
    /// Propagates the (in practice unreachable) CBOR-encode failure from
    /// hashing `prev`.
    pub fn recovery(
        prev: &LineageRecord,
        successor_pubkey_b64: &str,
        suspected_compromise_from_seq: Option<u64>,
        recovery_pubkey_b64: Option<String>,
        guardian_set_id: Vec<u8>,
        recovery_threshold: u64,
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
            reason: LineageReason::Recovery,
            predecessor_pubkey_b64: prev.successor_pubkey_b64.clone(),
            successor_pubkey_b64: successor_pubkey_b64.to_string(),
            recovery_pubkey_b64,
            not_before: clamped,
            prev_record_hash: prev.record_hash()?.to_vec(),
            custody_class: CustodyClass::SoftwareFile,
            suspected_compromise_from_seq,
            guardian_set_id: Some(guardian_set_id),
            recovery_threshold: Some(recovery_threshold),
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
            guardian_set_id: self.guardian_set_id.as_deref(),
            recovery_threshold: self.recovery_threshold,
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
    /// v1.0.0 #1831 (G17) — a [`LineageReason::Recovery`] record was
    /// encountered but no [`RecoveryPolicy`] was supplied (no recovery
    /// guardians enrolled), so the M-of-N recovery quorum can never be
    /// checked. Fail-closed: a recovery is trusted ONLY under an enrolled
    /// guardian set. (`verify_lineage` with no policy always lands here.)
    RecoveryNotEnrolled {
        /// Epoch of the offending recovery record.
        epoch: u64,
    },
    /// v1.0.0 #1831 (G17) — a [`LineageReason::Recovery`] record's stored
    /// quorum attestation is malformed / undecodable, or a presented
    /// guardian signature did not `verify_strict` (or the signer is not an
    /// enrolled guardian). The recovery is not cryptographically
    /// authorized.
    RecoveryQuorumInvalid {
        /// Epoch of the offending recovery record.
        epoch: u64,
    },
    /// v1.0.0 #1831 (G17) — a [`LineageReason::Recovery`] record's quorum
    /// carried fewer DISTINCT valid enrolled guardian signatures than the
    /// configured threshold `M`. The recovery is under-attested.
    RecoveryQuorumNotMet {
        /// Epoch of the offending recovery record.
        epoch: u64,
        /// Distinct valid enrolled guardian signers presented.
        distinct: usize,
        /// The M-of-N threshold in force.
        threshold: usize,
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
            Self::RecoveryNotEnrolled { epoch } => write!(
                f,
                "recovery record at epoch {epoch} cannot be verified — no recovery guardians \
                 are enrolled (set AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS)"
            ),
            Self::RecoveryQuorumInvalid { epoch } => write!(
                f,
                "recovery record at epoch {epoch} carries a malformed or unverifiable \
                 guardian-quorum attestation"
            ),
            Self::RecoveryQuorumNotMet {
                epoch,
                distinct,
                threshold,
            } => write!(
                f,
                "recovery record at epoch {epoch} met only {distinct} of {threshold} distinct \
                 enrolled recovery guardians"
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
    /// v1.0.0 #1831 (G17) — epoch of the most-recent
    /// [`LineageReason::Recovery`] record on the chain, or `None` if the
    /// chain carries no recovery. When `Some(epoch)`, the head at (or
    /// after) that epoch is authoritative BECAUSE a valid M-of-N recovery
    /// quorum ([`RecoveryPolicy`]) attested it — the key-LOSS half of G13
    /// (a lost primary key was replaced by a fresh one via a guardian
    /// quorum, not a predecessor signature).
    pub recovered_at_epoch: Option<u64>,
    /// v1.0.0 #1831 (G17) — `true` when a verified recovery on the chain
    /// was minted against a guardian set whose committed `guardian_set_id`
    /// differs from a digest over the verifier's CURRENTLY-enrolled set (the
    /// roster drifted since mint). Advisory only — the chain still verifies
    /// (the COMMITTED threshold was met by currently-enrolled valid
    /// signers); surfaced so an operator notices roster drift.
    pub recovery_guardian_set_drift: bool,
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

// ---------------------------------------------------------------------------
// v1.0.0 #1831 (G17) — M-of-N threshold key recovery.
//
// The key-LOSS half of gap G13 (v0.9.0 shipped only key-ROTATION survival).
// Losing the current head key no longer orphans the identity: a quorum of
// M-of-N enrolled recovery GUARDIAN keys can attest a `recovery` succession
// record that mints a FRESH primary key on the same v76 lineage chain, and
// `verify_lineage_with_recovery` accepts a head reachable via that valid
// quorum.
//
// # Honest scope boundary (label ATTESTABLE vs ESTIMABLE)
//
// - **ATTESTABLE** — the M-of-N recovery-quorum Ed25519 signatures over the
//   domain-tagged succession bytes ([`crate::identity::sign::LINEAGE_DOMAIN`])
//   + the append-only `signed_events` witness anchor (C1) + the hash-linked
//   chain (C3/C5). A recovery head that verifies is cryptographically bound
//   to a threshold of the enrolled guardian set.
// - **ESTIMABLE / operational** — WHO the guardians are (custody + enrollment
//   of `AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS`) is an operational trust input,
//   NOT a cryptographic one, exactly like the #1957 approver-quorum
//   (`AI_MEMORY_APPROVER_PUBKEYS`) and the operator-key custody. An adversary
//   who controls the guardian env AND holds M guardian private keys AND has
//   DB-write access can mint a recovery to a key they hold — a full
//   single-node custody compromise, out of scope for the single-node threat
//   model.
//
// SINGLE-NODE only: like the rest of the lineage layer, a recovery survived
// locally is invisible cross-host (federation peers resolve via
// `lookup_peer_public_key`, not this chain). Cross-host recovery propagation
// stays deferred.

/// Env var holding the comma-separated base64 (standard OR url-safe-no-pad)
/// Ed25519 PUBLIC keys enrolled as M-of-N recovery guardians (#1831 G17).
/// Mirrors the #1957 [`crate::approvals::signed::APPROVER_PUBKEYS_ENV`]
/// enrollment shape.
pub const RECOVERY_GUARDIAN_PUBKEYS_ENV: &str = "AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS";

/// Env var holding the M-of-N recovery threshold — the minimum count of
/// DISTINCT valid enrolled guardian signatures a recovery record must carry
/// (#1831 G17). Consulted ONLY when MINTING a recovery; it has NO default
/// (ratification delta C — a key-takeover primitive never silently defaults
/// to `M = 1`), so a mint with guardians enrolled but this var unset is
/// REFUSED. Verification uses the value COMMITTED in the record, never this.
pub const RECOVERY_THRESHOLD_ENV: &str = "AI_MEMORY_RECOVERY_THRESHOLD";

/// v1.0.0 #1831 (G17) — the leading integer version element of the
/// recovery-quorum CBOR blob (ratification delta B). Committed so the
/// attestation wire format can evolve past `2-of-N Ed25519` after records
/// exist on disk — a `decode` of an unknown version fails closed.
// M-DOCUMENTED-MAGIC: versioned so a future quorum-suite change is a
// distinct format rather than a silent reinterpretation.
pub const RECOVERY_QUORUM_FORMAT_V1: u64 = 1;

/// One guardian's detached attestation over a recovery record's signing
/// input (`LINEAGE_DOMAIN ∥ canonical_bytes`), stored inside the recovery
/// record's `signature` blob as a version-tagged CBOR array (#1831 G17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAttestation {
    /// URL-safe-no-pad base64 of the guardian's Ed25519 PUBLIC key.
    pub guardian_pubkey_b64: String,
    /// The 64-byte Ed25519 signature over the recovery signing input.
    pub signature: Vec<u8>,
}

/// The DISTINCT-signer count + guardian-set-drift flag returned by a
/// successful [`verify_recovery_record`] (#1831 G17 ratification delta A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryVerification {
    /// Distinct valid enrolled guardian signers that satisfied the
    /// COMMITTED threshold.
    pub distinct_signers: usize,
    /// `true` when the record's COMMITTED `guardian_set_id` differs from a
    /// digest over the verifier's CURRENTLY-enrolled guardian set — the
    /// guardian roster drifted since mint. The recovery still VERIFIES (the
    /// committed threshold was met by currently-enrolled valid signers);
    /// drift is surfaced as an advisory, never a silent re-derivation of
    /// the trust bar from the verifier's env.
    pub guardian_set_drift: bool,
}

/// The resolved M-of-N recovery policy: the enrolled guardian KEY MATERIAL
/// and the MINT-time threshold (#1831 G17). A pure carrier so
/// [`verify_lineage_with_recovery`] stays env-free and unit-testable;
/// [`RecoveryPolicy::from_env`] resolves it at the storage boundary.
///
/// The guardians here are the verifier's KEY-MATERIAL source (used to
/// verify each attestation signature); the TRUST BAR (threshold +
/// guardian-set identity) a persisted recovery is judged against is the
/// value COMMITTED in the signed record, NOT `threshold` here — `threshold`
/// is consulted ONLY when MINTING (ratification delta A/C).
#[derive(Debug, Clone)]
pub struct RecoveryPolicy {
    /// The enrolled recovery guardian PUBLIC keys (verification key
    /// material + the mint-time `guardian_set_id` pre-image).
    pub guardians: Vec<VerifyingKey>,
    /// The M-of-N threshold to MINT with — `None` when
    /// [`RECOVERY_THRESHOLD_ENV`] is unset (a mint is then REFUSED; a
    /// key-takeover primitive never silently defaults to `M = 1`,
    /// ratification delta C). Ignored at verification time (the committed
    /// threshold rules there).
    pub threshold: Option<usize>,
}

impl RecoveryPolicy {
    /// Resolve the recovery policy from the environment (#1831 G17):
    /// [`RECOVERY_GUARDIAN_PUBKEYS_ENV`] (key material) +
    /// [`RECOVERY_THRESHOLD_ENV`] (mint threshold; `None` when unset).
    ///
    /// Returns `None` when NO guardians are enrolled — the fail-closed
    /// signal that a recovery record cannot be verified (there is no
    /// key material to check its quorum against).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let guardians = enrolled_recovery_guardians();
        if guardians.is_empty() {
            return None;
        }
        Some(Self {
            guardians,
            threshold: recovery_threshold_explicit(),
        })
    }

    /// The SHA-256 digest over this policy's SORTED guardian public keys —
    /// the value a recovery mints into `guardian_set_id`, and the value a
    /// verifier compares the committed digest against to detect drift.
    #[must_use]
    pub fn guardian_set_id(&self) -> Vec<u8> {
        guardian_set_id_digest(&self.guardians)
    }
}

/// SHA-256 over the SORTED raw bytes of `guardians` (#1831 G17). Sorting
/// makes the digest order-independent so the same guardian SET always mints
/// the same id regardless of enrollment order.
// M-STRONG-TYPES-GUARD: the digest is the committed trust anchor that guards
// "this recovery was minted against exactly this guardian set".
#[must_use]
pub fn guardian_set_id_digest(guardians: &[VerifyingKey]) -> Vec<u8> {
    let mut keys: Vec<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> =
        guardians.iter().map(VerifyingKey::to_bytes).collect();
    keys.sort_unstable();
    let mut hasher = Sha256::new();
    for k in &keys {
        hasher.update(k);
    }
    hasher.finalize().to_vec()
}

/// Resolve the enrolled recovery-guardian key set from
/// [`RECOVERY_GUARDIAN_PUBKEYS_ENV`] (#1831 G17). Duplicate keys collapse;
/// un-decodable tokens are skipped with a WARN. Mirrors
/// [`crate::approvals::signed::enrolled_approver_keys`].
#[must_use]
pub fn enrolled_recovery_guardians() -> Vec<VerifyingKey> {
    let mut keys: Vec<VerifyingKey> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> =
        std::collections::HashSet::new();
    if let Ok(v) = std::env::var(RECOVERY_GUARDIAN_PUBKEYS_ENV) {
        for tok in v.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            match keypair::decode_public_base64(tok) {
                Ok(pk) => {
                    if seen.insert(pk.to_bytes()) {
                        keys.push(pk);
                    }
                }
                Err(_) => tracing::warn!(
                    target: "identity.lineage.recovery",
                    "ignoring un-decodable recovery guardian pubkey in {RECOVERY_GUARDIAN_PUBKEYS_ENV}"
                ),
            }
        }
    }
    keys
}

/// Resolve the EXPLICIT M-of-N recovery threshold from
/// [`RECOVERY_THRESHOLD_ENV`] (#1831 G17 ratification delta C). Returns
/// `None` when the var is unset / unparseable / below `1` — a recovery mint
/// then REFUSES rather than silently defaulting a key-takeover primitive to
/// `M = 1`. (Verification never consults this — the committed threshold
/// rules there.)
#[must_use]
pub fn recovery_threshold_explicit() -> Option<usize> {
    std::env::var(RECOVERY_THRESHOLD_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
}

/// Encode an M-of-N recovery quorum as the version-tagged CBOR blob stored
/// in a recovery record's `signature` column (#1831 G17): the CBOR array
/// `[RECOVERY_QUORUM_FORMAT_V1, [[guardian_pubkey_b64, signature_bytes], …]]`.
///
/// # Errors
/// CBOR-encode failure (in practice unreachable for the fixed shape).
pub fn encode_recovery_quorum(quorum: &[RecoveryAttestation]) -> anyhow::Result<Vec<u8>> {
    let pairs = ciborium::Value::Array(
        quorum
            .iter()
            .map(|att| {
                ciborium::Value::Array(vec![
                    ciborium::Value::Text(att.guardian_pubkey_b64.clone()),
                    ciborium::Value::Bytes(att.signature.clone()),
                ])
            })
            .collect(),
    );
    let value = ciborium::Value::Array(vec![
        ciborium::Value::Integer(ciborium::value::Integer::from(RECOVERY_QUORUM_FORMAT_V1)),
        pairs,
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(128 * quorum.len().max(1));
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|e| anyhow::anyhow!("CBOR encode recovery quorum: {e}"))?;
    Ok(out)
}

/// Decode the version-tagged recovery-quorum CBOR blob (#1831 G17). `None`
/// on any malformed shape OR an unrecognised leading format version
/// (fail-closed so a future format is never mis-read as v1).
#[must_use]
pub fn decode_recovery_quorum(blob: &[u8]) -> Option<Vec<RecoveryAttestation>> {
    let value: ciborium::Value = ciborium::de::from_reader(blob).ok()?;
    let mut outer = value.into_array().ok()?;
    if outer.len() != 2 {
        return None;
    }
    let pairs = outer.pop()?.into_array().ok()?;
    let version = u64::try_from(outer.pop()?.into_integer().ok()?).ok()?;
    if version != RECOVERY_QUORUM_FORMAT_V1 {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for entry in pairs {
        let mut pair = entry.into_array().ok()?;
        if pair.len() != 2 {
            return None;
        }
        // pair = [Text pubkey_b64, Bytes signature]
        let sig = pair.pop()?.into_bytes().ok()?;
        let pubkey_b64 = pair.pop()?.into_text().ok()?;
        out.push(RecoveryAttestation {
            guardian_pubkey_b64: pubkey_b64,
            signature: sig,
        });
    }
    Some(out)
}

/// Verify ONE recovery record against its COMMITTED trust bar (#1831 G17
/// ratification delta A). Shared by the storage append pre-flight and the
/// [`verify_lineage_with_recovery`] walk so the two can never drift.
///
/// The threshold + guardian-set identity are read from the record's SIGNED
/// body (`recovery_threshold` + `guardian_set_id`), NOT re-derived from
/// `policy` — so rotating a guardian env or lowering the env threshold can
/// never retroactively re-judge a persisted recovery's trust bar. `policy`
/// supplies only the guardian KEY MATERIAL used to verify each signature; a
/// mismatch between the committed `guardian_set_id` and a digest over the
/// currently-enrolled set is FLAGGED (`guardian_set_drift`), not silently
/// substituted.
///
/// Signature counting is skip-tolerant (aligns with the #1957 approver
/// discipline): an attestation whose signer is not currently enrolled, or
/// whose signature does not verify, is SKIPPED (not a hard failure) — only
/// DISTINCT enrolled-and-valid signers count toward the committed threshold.
///
/// # Errors
///
/// [`LineageError::RecoveryQuorumInvalid`] (malformed / unversioned blob, or
/// a recovery record missing its committed threshold / guardian-set id) or
/// [`LineageError::RecoveryQuorumNotMet`] (fewer distinct enrolled-valid
/// signers than the COMMITTED threshold).
pub fn verify_recovery_record(
    record: &LineageRecord,
    quorum_blob: &[u8],
    policy: &RecoveryPolicy,
) -> Result<RecoveryVerification, LineageError> {
    let epoch = record.epoch;
    let invalid = || LineageError::RecoveryQuorumInvalid { epoch };

    // The trust bar comes from the SIGNED body, never the verifier's env.
    let committed_threshold =
        usize::try_from(record.recovery_threshold.ok_or_else(invalid)?).map_err(|_| invalid())?;
    if committed_threshold < 1 {
        return Err(invalid());
    }
    let committed_gid = record.guardian_set_id.as_deref().ok_or_else(invalid)?;
    let current_gid = policy.guardian_set_id();
    let guardian_set_drift = committed_gid != current_gid.as_slice();

    let quorum = decode_recovery_quorum(quorum_blob).ok_or_else(invalid)?;
    let signing_input = record.signing_input().map_err(|_| invalid())?;
    let enrolled: std::collections::HashSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> = policy
        .guardians
        .iter()
        .map(VerifyingKey::to_bytes)
        .collect();
    let mut distinct: std::collections::BTreeSet<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> =
        std::collections::BTreeSet::new();
    for att in &quorum {
        // Skip-tolerant: an un-decodable / unenrolled / non-verifying
        // attestation simply does not count (it never hard-fails the walk).
        let Ok(pk) = keypair::decode_public_base64(&att.guardian_pubkey_b64) else {
            continue;
        };
        if !enrolled.contains(&pk.to_bytes()) {
            continue;
        }
        let Ok(sig_arr) = <[u8; SIGNATURE_LEN]>::try_from(att.signature.as_slice()) else {
            continue;
        };
        let sig = Signature::from_bytes(&sig_arr);
        if pk.verify_strict(&signing_input, &sig).is_ok() {
            distinct.insert(pk.to_bytes());
        }
    }
    if distinct.len() < committed_threshold {
        return Err(LineageError::RecoveryQuorumNotMet {
            epoch,
            distinct: distinct.len(),
            threshold: committed_threshold,
        });
    }
    Ok(RecoveryVerification {
        distinct_signers: distinct.len(),
        guardian_set_drift,
    })
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
    // No recovery policy → a `recovery` record is fail-closed (its quorum
    // can never be checked). The OBSERVABLE verdict is preserved vs v0.9.0
    // (a recovery chain is rejected, an enrolled non-recovery chain verifies
    // identically) — NOT byte-identical output: the no-policy recovery
    // rejection is now the specific `RecoveryNotEnrolled` where v0.9.0
    // produced `PredecessorMismatch` (its unit test was updated). That
    // difference is unobservable in practice only because v0.9.0 could never
    // PERSIST a recovery record (`append_lineage_record` bailed on it), so no
    // v0.9.0 chain carries one to re-verify.
    verify_lineage_with_recovery(records, witness_hashes, bound_pubkey_b64, None)
}

/// v1.0.0 #1831 (G17) — the recovery-aware genesis → head walk.
///
/// Identical to [`verify_lineage`] for genesis / rotation / revocation
/// records; additionally, when `recovery_policy` is `Some`, a
/// [`LineageReason::Recovery`] record verifies iff a valid M-of-N recovery
/// quorum ([`verify_recovery_record`]) attests it (the key-LOSS half of
/// G13). When `recovery_policy` is `None`, a recovery record is
/// [`LineageError::RecoveryNotEnrolled`] (fail-closed — no guardian set to
/// check against), preserving the v0.9.0 behaviour.
///
/// # Errors
///
/// The first [`LineageError`] encountered — fail-closed, never a fallback
/// to a partially-verified head.
pub fn verify_lineage_with_recovery(
    records: &[(LineageRecord, Vec<u8>)],
    witness_hashes: &[Vec<u8>],
    bound_pubkey_b64: Option<&str>,
    recovery_policy: Option<&RecoveryPolicy>,
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
    // A #1831 recovery that carries `suspected_compromise_from_seq` doubles
    // as a revocation and feeds this window too.
    let mut revoked_from_seq: Option<u64> = None;
    // v1.0.0 #1831 — epoch of the newest recovery on the chain + whether any
    // verified recovery was minted against a since-drifted guardian roster.
    let mut recovered_at_epoch: Option<u64> = None;
    let mut recovery_guardian_set_drift = false;
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
            // Authorized predecessor. Rotation AND Revocation (#1949) both
            // hand off from the prior head key under a single predecessor
            // signature. Recovery (#1831 G17) also names the prior head as
            // `predecessor` (the LOST key it recovers FROM) but is attested
            // by the M-of-N guardian quorum instead — its cryptographic
            // check runs in the signature branch below.
            let hands_off_from_head = record.predecessor_pubkey_b64 == prior.successor_pubkey_b64;
            match record.reason {
                LineageReason::Rotation | LineageReason::Revocation => {
                    if !hands_off_from_head {
                        return Err(LineageError::PredecessorMismatch {
                            epoch: record.epoch,
                        });
                    }
                }
                LineageReason::Recovery => {
                    if !hands_off_from_head {
                        return Err(LineageError::PredecessorMismatch {
                            epoch: record.epoch,
                        });
                    }
                    // Fail-closed with no enrolled guardian set — the
                    // v0.9.0 posture is preserved when no policy is passed.
                    if recovery_policy.is_none() {
                        return Err(LineageError::RecoveryNotEnrolled {
                            epoch: record.epoch,
                        });
                    }
                }
                // Genesis is only valid at epoch 0 (the prev == None path).
                LineageReason::Genesis => {
                    return Err(LineageError::PredecessorMismatch {
                        epoch: record.epoch,
                    });
                }
            }
        }

        // v1.0.0 #1949/#1831 — a revocation OR a recovery may carry the
        // compromise-from witness sequence forward; the newest wins the
        // Suspect-window report.
        if matches!(
            record.reason,
            LineageReason::Revocation | LineageReason::Recovery
        ) {
            if let Some(from_seq) = record.suspected_compromise_from_seq {
                revoked_from_seq = Some(from_seq);
            }
        }

        // C1 — every record (genesis included) must be anchored to its
        // append-only witness before its signature buys any trust.
        consume_witness(record)?;

        // Cryptographic authorization — branch on reason.
        match record.reason {
            LineageReason::Recovery => {
                // The M-of-N guardian quorum (against the COMMITTED threshold
                // + guardian-set id) authorizes the fresh head. `prev` is
                // Some here: a recovery is never the genesis record (genesis
                // fixes epoch 0 / reason Genesis above).
                let policy = recovery_policy.ok_or(LineageError::RecoveryNotEnrolled {
                    epoch: record.epoch,
                })?;
                let verified = verify_recovery_record(record, signature, policy)?;
                recovered_at_epoch = Some(record.epoch);
                recovery_guardian_set_drift |= verified.guardian_set_drift;
            }
            _ => {
                // Strict Ed25519 under the (chain-authorized) predecessor
                // key — genesis self-signs, rotation/revocation are signed
                // by the prior head.
                let predecessor = keypair::decode_public_base64(&record.predecessor_pubkey_b64)
                    .map_err(|_| LineageError::SignatureInvalid {
                        epoch: record.epoch,
                    })?;
                verify_succession(record, signature, &predecessor)?;
            }
        }

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
        recovered_at_epoch,
        recovery_guardian_set_drift,
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
    fn recovery_record_fail_closes_without_policy() {
        // v1.0.0 #1831 — with NO enrolled recovery guardians (the plain
        // `verify_lineage` no-policy path, byte-identical to v0.9.0's
        // posture), a reason=recovery record must be rejected — never
        // trusted. The verdict is the specific RecoveryNotEnrolled (a
        // recovery cannot be checked without a guardian set to check it
        // against).
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
        assert_eq!(err, LineageError::RecoveryNotEnrolled { epoch: 2 });
    }

    // ------------------------------------------------------------------
    // v1.0.0 #1831 (G17) — M-of-N threshold key recovery.
    // ------------------------------------------------------------------

    /// A guardian signs a recovery record's signing input.
    fn guardian_sign(record: &LineageRecord, guardian: &AgentKeypair) -> RecoveryAttestation {
        use ed25519_dalek::Signer;
        let input = record.signing_input().expect("signing input");
        let sig = guardian
            .private
            .as_ref()
            .expect("guardian can sign")
            .sign(&input);
        RecoveryAttestation {
            guardian_pubkey_b64: guardian.public_base64(),
            signature: sig.to_bytes().to_vec(),
        }
    }

    fn policy(guardians: &[&AgentKeypair], threshold: usize) -> RecoveryPolicy {
        RecoveryPolicy {
            guardians: guardians.iter().map(|g| g.public).collect(),
            threshold: Some(threshold),
        }
    }

    /// Build a K0→K1 (rotation) chain whose head is then RECOVERED to a
    /// fresh key `k_new` via an M-of-N guardian quorum. The recovery record
    /// COMMITS `guardian_set_id` (digest over the 3-guardian set) +
    /// `recovery_threshold` into its signed body (#1831 ratification delta
    /// A). Returns the signed records + witnesses + the fresh head + the
    /// guardian keypairs + a matching (no-drift) policy.
    fn recovery_fixture(
        committed_threshold: u64,
        signers: usize,
    ) -> (
        Vec<(LineageRecord, Vec<u8>)>,
        Vec<Vec<u8>>,
        AgentKeypair,
        Vec<AgentKeypair>,
        RecoveryPolicy,
    ) {
        let k0 = kp("agent-a");
        let k1 = kp("agent-a");
        let k_new = kp("agent-a");
        let guardians: Vec<AgentKeypair> = (0..3).map(|_| kp("guardian")).collect();
        let guardian_keys: Vec<VerifyingKey> = guardians.iter().map(|g| g.public).collect();
        let gid = guardian_set_id_digest(&guardian_keys);
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
        // K1 is LOST — recover to k_new via the guardian quorum, committing
        // the guardian-set id + threshold into the signed body.
        let recovery = LineageRecord::recovery(
            &r1,
            &k_new.public_base64(),
            None,
            None,
            gid,
            committed_threshold,
            "2026-06-10T00:00:00+00:00",
        )
        .expect("recovery record");
        let quorum: Vec<RecoveryAttestation> = guardians
            .iter()
            .take(signers)
            .map(|g| guardian_sign(&recovery, g))
            .collect();
        let quorum_blob = encode_recovery_quorum(&quorum).expect("encode quorum");
        let records = vec![
            signed(&genesis, &k0),
            signed(&r1, &k0),
            (recovery, quorum_blob),
        ];
        let witnesses = records
            .iter()
            .map(|(r, _)| r.witness_payload_hash().expect("hash"))
            .collect();
        // The verify policy's env threshold is deliberately DIFFERENT from
        // the committed one (7) to prove verification ignores it.
        let pol = policy(&guardians.iter().collect::<Vec<_>>(), 7);
        (records, witnesses, k_new, guardians, pol)
    }

    #[test]
    fn m_of_n_recovery_verifies_to_fresh_head() {
        // 2-of-3 guardians recover a LOST head key to a fresh primary; the
        // guardian roster matches the committed set → no drift.
        let (records, witnesses, k_new, _guardians, pol) = recovery_fixture(2, 2);
        let v = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .expect("m-of-n recovery verifies");
        assert_eq!(v.epoch, 2);
        assert_eq!(v.head_key.to_bytes(), k_new.public.to_bytes());
        assert_eq!(v.recovered_at_epoch, Some(2));
        assert!(
            !v.recovery_guardian_set_drift,
            "roster matches committed set"
        );
    }

    #[test]
    fn recovery_verify_uses_committed_threshold_not_env() {
        // The record COMMITS threshold 2 but only 1 signer is presented;
        // the env policy's threshold is 7 (fixture) — verification enforces
        // the COMMITTED 2 (never the env), so 1 < 2 is under-attested. This
        // proves a lowered env threshold can never retroactively re-judge a
        // persisted recovery (#1831 ratification delta A killer-finding).
        let (records, witnesses, k_new, _guardians, pol) = recovery_fixture(2, 1);
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
        assert_eq!(
            err,
            LineageError::RecoveryQuorumNotMet {
                epoch: 2,
                distinct: 1,
                threshold: 2, // the COMMITTED value, not the env's 7
            }
        );
    }

    #[test]
    fn recovery_duplicate_signer_collapses_to_one() {
        // Present the SAME guardian twice — distinct count is 1, below the
        // committed threshold of 2 (a duplicate never inflates the quorum).
        let (mut records, mut witnesses, k_new, guardians, pol) = recovery_fixture(2, 0);
        let recovery = &records[2].0;
        let att = guardian_sign(recovery, &guardians[0]);
        let quorum = vec![att.clone(), att];
        records[2].1 = encode_recovery_quorum(&quorum).unwrap();
        witnesses[2] = records[2].0.witness_payload_hash().unwrap();
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
        assert_eq!(
            err,
            LineageError::RecoveryQuorumNotMet {
                epoch: 2,
                distinct: 1,
                threshold: 2,
            }
        );
    }

    #[test]
    fn recovery_unenrolled_signer_is_skipped_not_counted() {
        // Skip-tolerant (aligns with #1957): a signer NOT in the enrolled
        // set does not count and does not hard-fail — the quorum simply
        // falls short of the committed threshold (distinct 0 of 1).
        let (mut records, mut witnesses, k_new, _guardians, pol) = recovery_fixture(1, 0);
        let stranger = kp("stranger");
        let recovery = &records[2].0;
        let quorum = vec![guardian_sign(recovery, &stranger)];
        records[2].1 = encode_recovery_quorum(&quorum).unwrap();
        witnesses[2] = records[2].0.witness_payload_hash().unwrap();
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
        assert_eq!(
            err,
            LineageError::RecoveryQuorumNotMet {
                epoch: 2,
                distinct: 0,
                threshold: 1,
            }
        );
    }

    #[test]
    fn recovery_forged_signature_is_skipped_not_counted() {
        // An ENROLLED guardian's slot carries a signature that does not
        // verify (the bytes were tampered) — skipped, not counted, so the
        // committed threshold is not met.
        let (mut records, mut witnesses, k_new, guardians, pol) = recovery_fixture(1, 0);
        let recovery = &records[2].0;
        let mut att = guardian_sign(recovery, &guardians[0]);
        att.signature[0] ^= 0xFF; // corrupt one byte
        records[2].1 = encode_recovery_quorum(&[att]).unwrap();
        witnesses[2] = records[2].0.witness_payload_hash().unwrap();
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
        assert_eq!(
            err,
            LineageError::RecoveryQuorumNotMet {
                epoch: 2,
                distinct: 0,
                threshold: 1,
            }
        );
    }

    #[test]
    fn recovery_malformed_or_unversioned_blob_is_invalid() {
        // A blob that does not decode (wrong CBOR shape / unknown version)
        // is a hard RecoveryQuorumInvalid.
        let (mut records, mut witnesses, k_new, _guardians, pol) = recovery_fixture(1, 1);
        records[2].1 = vec![0xFF, 0x00, 0x13]; // garbage
        witnesses[2] = records[2].0.witness_payload_hash().unwrap();
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
        assert_eq!(err, LineageError::RecoveryQuorumInvalid { epoch: 2 });
    }

    #[test]
    fn recovery_guardian_set_drift_is_flagged_but_still_verifies() {
        // The recovery commits guardian_set_id = digest{g0,g1,g2}; the
        // verifier's enrolled set adds a 4th guardian, so the digest drifts.
        // g0+g1 are still enrolled+valid → committed threshold 2 is met, so
        // the chain VERIFIES with the drift ADVISORY flagged (never a silent
        // re-derivation of the trust bar).
        let (records, witnesses, k_new, guardians, _pol) = recovery_fixture(2, 2);
        let extra = kp("guardian-4");
        let mut drifted: Vec<VerifyingKey> = guardians.iter().map(|g| g.public).collect();
        drifted.push(extra.public);
        let pol = RecoveryPolicy {
            guardians: drifted,
            threshold: Some(2),
        };
        let v = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .expect("recovery still verifies under a drifted (superset) roster");
        assert_eq!(v.recovered_at_epoch, Some(2));
        assert!(
            v.recovery_guardian_set_drift,
            "an added guardian must flag guardian-set drift"
        );
    }

    #[test]
    fn recovery_carries_compromise_window_like_a_revocation_opt_in() {
        // OPT-IN "recovery signs both fresh head + revocation" — a recovery
        // with a suspected_compromise_from_seq surfaces the Suspect window;
        // a pure recovery (None) leaves the predecessor's entries trusted.
        let (records, witnesses, k_new, _guardians, pol) = recovery_fixture(2, 2);
        // The fixture minted a PURE recovery (None) → no Suspect window.
        let v = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap();
        assert_eq!(v.revoked_from_seq, None, "a pure recovery revokes nothing");

        // Now mint the compromise-windowed variant.
        let k0 = kp("agent-a");
        let k1 = kp("agent-a");
        let k_new2 = kp("agent-a");
        let guardians: Vec<AgentKeypair> = (0..2).map(|_| kp("guardian")).collect();
        let gid = guardian_set_id_digest(&guardians.iter().map(|g| g.public).collect::<Vec<_>>());
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
        .unwrap();
        let recovery = LineageRecord::recovery(
            &r1,
            &k_new2.public_base64(),
            Some(77),
            None,
            gid,
            2,
            "2026-06-10T00:00:00+00:00",
        )
        .unwrap();
        assert_eq!(recovery.suspected_compromise_from_seq, Some(77));
        let quorum: Vec<RecoveryAttestation> = guardians
            .iter()
            .map(|g| guardian_sign(&recovery, g))
            .collect();
        let records = vec![
            signed(&genesis, &k0),
            signed(&r1, &k0),
            (recovery, encode_recovery_quorum(&quorum).unwrap()),
        ];
        let witnesses: Vec<Vec<u8>> = records
            .iter()
            .map(|(r, _)| r.witness_payload_hash().unwrap())
            .collect();
        let pol = policy(&guardians.iter().collect::<Vec<_>>(), 2);
        let v = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new2.public_base64()),
            Some(&pol),
        )
        .unwrap();
        assert_eq!(v.recovered_at_epoch, Some(2));
        assert_eq!(v.revoked_from_seq, Some(77));
    }

    #[test]
    fn recovery_quorum_blob_version_tag_round_trips() {
        let g = kp("guardian");
        let genesis = LineageRecord::genesis(
            "agent-a",
            &kp("agent-a").public_base64(),
            None,
            "2026-06-01T00:00:00+00:00",
        );
        let att = guardian_sign(&genesis, &g);
        let blob = encode_recovery_quorum(std::slice::from_ref(&att)).unwrap();
        let decoded = decode_recovery_quorum(&blob).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], att);

        // A blob carrying an UNKNOWN leading version fails closed.
        let wrong_version = ciborium::Value::Array(vec![
            ciborium::Value::Integer(ciborium::value::Integer::from(99u64)),
            ciborium::Value::Array(vec![]),
        ]);
        let mut wv = Vec::new();
        ciborium::ser::into_writer(&wrong_version, &mut wv).unwrap();
        assert!(
            decode_recovery_quorum(&wv).is_none(),
            "an unrecognised quorum format version must fail closed"
        );

        // A garbage blob decodes to None (fail-closed).
        assert!(decode_recovery_quorum(&[0xFF, 0x00, 0x13]).is_none());
    }

    #[test]
    fn recovery_threshold_explicit_is_none_when_unset() {
        // Ratification delta C — a mint refuses to default M to 1; the
        // resolver returns None when the var is unset / below 1.
        let _guard = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe { std::env::remove_var(RECOVERY_THRESHOLD_ENV) };
        assert_eq!(recovery_threshold_explicit(), None);
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe { std::env::set_var(RECOVERY_THRESHOLD_ENV, "0") };
        assert_eq!(recovery_threshold_explicit(), None, "0 is below the floor");
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe { std::env::set_var(RECOVERY_THRESHOLD_ENV, "3") };
        assert_eq!(recovery_threshold_explicit(), Some(3));
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe { std::env::remove_var(RECOVERY_THRESHOLD_ENV) };
    }

    #[test]
    fn recovery_wrong_predecessor_is_predecessor_mismatch() {
        // A recovery record that does NOT name the prior head as its
        // predecessor is rejected on the chain-shape check BEFORE the
        // quorum is consulted (a recovery still recovers FROM the head).
        let (mut records, mut witnesses, k_new, guardians, pol) = recovery_fixture(2, 0);
        records[2].0.predecessor_pubkey_b64 = kp("agent-a").public_base64();
        let quorum: Vec<RecoveryAttestation> = guardians
            .iter()
            .take(2)
            .map(|g| guardian_sign(&records[2].0, g))
            .collect();
        records[2].1 = encode_recovery_quorum(&quorum).unwrap();
        witnesses[2] = records[2].0.witness_payload_hash().unwrap();
        let err = verify_lineage_with_recovery(
            &records,
            &witnesses,
            Some(&k_new.public_base64()),
            Some(&pol),
        )
        .unwrap_err();
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
