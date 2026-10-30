// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — scope-key records, the [`ScopeKeyStore`] contract and the
//! file-backed store.
//!
//! One [`ScopeKeyRecord`] per `(namespace, epoch)`. It carries the key id,
//! the half-open validity window (`created_at` inclusive, `superseded_at`
//! exclusive, the `agent_pubkey_history` ledger shape), one recipient stanza
//! per reader node (the scope key sealed to that node's X25519 KEK through
//! the existing `0x02` ECIES path) and one escrow stanza sealed to the
//! deployment recovery public key. Every stanza plaintext is id-bound
//! (`0x05 || key_id || epoch || len16(namespace) || namespace || key`), so a
//! stanza copied from another record or namespace is refused on unwrap. A
//! `key_check` value (an HKDF commitment to the key) lets any holder verify a
//! candidate key without revealing it, so a stanza and the escrow can never
//! silently disagree.
//!
//! The file store keeps `<key_dir>/scope-keys/<slug>.scope.<epoch>.json`,
//! mode `0o600`, written stage-then-rename, and one append-only, hash-chained
//! audit log `<slug>.audit.jsonl` per namespace ([`ledger`]). `slug` is the
//! hex of the first 16 bytes of SHA-256(namespace): path-safe for any
//! namespace text, and the namespace itself is stored in the record and
//! verified on every load.
//!
//! [`ScopeKeyStore`] is a synchronous `Send + Sync` cache contract (ruling
//! R11, vote `6def5ab6`, option B). Lookups are pure memory behind an
//! `RwLock`. The files are the cold store: loaded at construction
//! ([`FileScopeKeyStore::open`]), reloaded by
//! [`ScopeKeyStore::refresh_from_ledger`], and written through by every
//! mutator in the same call, so there is no window where the cache and the
//! files disagree for this process. The cache records each namespace's
//! [`LedgerHead`]; a lookup that must be at least as fresh as a head a peer
//! advertised refuses with [`ScopeKeyStoreError::SealedForeign`] until a
//! refresh catches up. Mutations take an exclusive `flock` on
//! `scope-keys/.scope-keys.lock` (loads take it shared), which serialises
//! threads (each opens its own descriptor) and processes. Lock order is
//! always `flock` first, cache `RwLock` second. The async ledger methods on
//! `MemoryStore` (load, append, refresh) for both backends arrive in E2 with
//! the Codex SAL slice.

pub mod ledger;

pub use ledger::{AuditAction, AuditEntry, LedgerHead};

use super::{
    ISSUE_TAG, SCOPE_ENVELOPE_VERSION, SCOPE_KEY_ID_LEN, SCOPE_KEY_LEN, ScopeKey, ScopeKeyId,
    ScopeKeyRef,
};
use crate::encryption::{
    Envelope, Keypair, decrypt_bytes, encrypt_bytes, escrow, fingerprint_public_bytes,
};
use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use ledger::{Change, NamespaceLedger};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

/// Sub-directory of the key directory holding scope-key records.
pub const SCOPE_KEY_SUBDIR: &str = "scope-keys";
/// Lock file serialising record mutations.
pub const SCOPE_KEY_LOCK_FILE: &str = ".scope-keys.lock";
/// Infix between the namespace slug and the epoch in a record file name.
const RECORD_INFIX: &str = ".scope.";
/// Suffix of a record file name.
const RECORD_SUFFIX: &str = ".json";
/// Suffix of a namespace's audit log (after the slug).
const AUDIT_SUFFIX: &str = ".audit.jsonl";
/// On-disk record format version.
pub const SCOPE_KEY_RECORD_FORMAT: u32 = 1;
/// Mode of record and lock files.
const MODE_PRIVATE: u32 = 0o600;
/// Bytes of SHA-256(namespace) rendered into the file slug.
const SLUG_BYTES: usize = 16;
/// Length of the key-check commitment.
const KEY_CHECK_LEN: usize = 16;
/// HKDF `info` label of the key-check commitment.
const KEY_CHECK_INFO: &[u8] = b"ai-memory/v1.0.0/e2e-scope/key-check/v5";

/// A reader node's KEK public key (its X25519 agent key) and agent id.
#[derive(Clone, Debug)]
pub struct ReaderKek {
    /// Agent id of the reader node (readability; the fingerprint is the key).
    pub agent_id: String,
    /// The reader's X25519 public key.
    pub public: PublicKey,
}

impl ReaderKek {
    /// The reader view of a local keypair.
    #[must_use]
    pub fn from_keypair(kp: &Keypair) -> Self {
        Self {
            agent_id: kp.agent_id.clone(),
            public: kp.public,
        }
    }

    /// Fingerprint of the KEK public key (SHA-256, first 16 bytes, hex).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_public_bytes(self.public.as_bytes())
    }
}

/// One reader's copy of the scope key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientStanza {
    /// Agent id of the reader node.
    pub agent_id: String,
    /// Fingerprint of the reader's KEK public key.
    pub kek_fingerprint: String,
    /// The id-bound scope key sealed to the reader KEK (`0x02` envelope,
    /// base64url without padding).
    pub wrapped: String,
}

/// The recovery copy of the scope key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowStanza {
    /// Fingerprint of the deployment recovery public key.
    pub recovery_fingerprint: String,
    /// The id-bound scope key sealed to the recovery key.
    pub wrapped: String,
}

/// One scope-key generation of one namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeKeyRecord {
    /// Record format ([`SCOPE_KEY_RECORD_FORMAT`]).
    pub format: u32,
    /// The namespace this key seals.
    pub namespace: String,
    /// 1-based generation; dense per namespace.
    pub epoch: u32,
    /// Hex of the random key id.
    pub key_id: String,
    /// Hex of the key-check commitment.
    pub key_check: String,
    /// RFC 3339 start of validity (inclusive).
    pub created_at: String,
    /// RFC 3339 end of validity (exclusive); `None` while current.
    pub superseded_at: Option<String>,
    /// One stanza per reader node.
    pub recipients: Vec<RecipientStanza>,
    /// The recovery stanza (always present: a key is never minted without it).
    pub escrow: EscrowStanza,
}

/// Typed refusals of the scope-key store. Every one fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKeyStoreError {
    /// No deployment recovery key is enrolled, so a scope key cannot be
    /// escrowed and is not minted.
    EscrowUnavailable {
        /// Namespace whose mint was refused.
        namespace: String,
    },
    /// Mint or supersede was asked for with no reader.
    NoRecipients {
        /// Namespace concerned.
        namespace: String,
    },
    /// Removing this stanza would leave the key with no reader.
    LastRecipient {
        /// Namespace concerned.
        namespace: String,
        /// Epoch concerned.
        epoch: u32,
    },
    /// The caller's KEK holds no stanza for this key.
    NotAReader {
        /// Namespace concerned.
        namespace: String,
        /// Epoch concerned.
        epoch: u32,
        /// Fingerprint of the caller's KEK.
        kek_fingerprint: String,
    },
    /// The store has no record for this key.
    UnknownKey {
        /// Namespace concerned.
        namespace: String,
        /// Key named by the caller.
        key: String,
    },
    /// A record exists for this epoch with a different key id: two keys were
    /// minted for one generation (divergence), so neither is trusted here.
    KeyIdMismatch {
        /// Namespace concerned.
        namespace: String,
        /// Epoch concerned.
        epoch: u32,
    },
    /// An unwrapped stanza names another key or namespace, or does not match
    /// the record's key-check commitment.
    StanzaBindingMismatch {
        /// Namespace concerned.
        namespace: String,
        /// Epoch concerned.
        epoch: u32,
    },
    /// The recovery secret is not the key the escrow stanza was sealed to.
    RecoveryKeyMismatch {
        /// Namespace concerned.
        namespace: String,
        /// Epoch concerned.
        epoch: u32,
    },
    /// A record file is unreadable, malformed, inconsistent or insecure.
    RecordCorrupt {
        /// The file concerned.
        path: String,
        /// What is wrong.
        detail: String,
    },
    /// The namespace is too long for the stanza length prefix.
    NamespaceTooLong,
    /// The epoch counter would overflow.
    EpochExhausted {
        /// Namespace concerned.
        namespace: String,
    },
    /// The D4 partial-result signal: this node's ledger for the namespace is
    /// older than the head the caller requires (a head a peer advertised), so
    /// rows sealed under keys it may not hold yet stay sealed until a refresh
    /// (`/keys/scope` pull, E2) catches up. Never flattened to "not a reader".
    SealedForeign {
        /// Namespace concerned.
        namespace: String,
        /// Ledger head of the local cache.
        cached_head: u64,
        /// Ledger head the caller required.
        required_head: u64,
    },
    /// The audit log does not chain: a missing, reordered or edited entry, a
    /// previous-epoch pointer that is not the head, or records that disagree
    /// with the log.
    AuditChainMismatch {
        /// Namespace concerned.
        namespace: String,
        /// What is wrong.
        detail: String,
    },
    /// Supersede found a recovery key other than the one the current epoch is
    /// escrowed to; the escrow chain is not forked silently.
    RecoveryKeyChanged {
        /// Namespace concerned.
        namespace: String,
        /// Escrow fingerprint of the current epoch.
        previous: String,
        /// Fingerprint of the enrolled recovery key.
        current: String,
    },
}

impl ScopeKeyStoreError {
    /// Stable class name for logs and metrics.
    pub const CLASS: &'static str = "scope_key_store_refused";
}

impl std::fmt::Display for ScopeKeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EscrowUnavailable { namespace } => write!(
                f,
                "{ISSUE_TAG}: no recovery key is enrolled, so a scope key for namespace \
                 {namespace:?} cannot be escrowed and is not minted (run `{}`)",
                escrow::REMEDY_ENROLL_RECOVERY_KEY
            ),
            Self::NoRecipients { namespace } => write!(
                f,
                "{ISSUE_TAG}: a scope key for namespace {namespace:?} needs at least one reader"
            ),
            Self::LastRecipient { namespace, epoch } => write!(
                f,
                "{ISSUE_TAG}: refusing to remove the last reader of namespace {namespace:?} \
                 epoch {epoch}"
            ),
            Self::NotAReader {
                namespace,
                epoch,
                kek_fingerprint,
            } => write!(
                f,
                "{ISSUE_TAG}: KEK {kek_fingerprint} is not a reader of namespace {namespace:?} \
                 epoch {epoch}; the row stays sealed"
            ),
            Self::UnknownKey { namespace, key } => write!(
                f,
                "{ISSUE_TAG}: no scope key {key} is known for namespace {namespace:?}; the row \
                 stays sealed"
            ),
            Self::KeyIdMismatch { namespace, epoch } => write!(
                f,
                "{ISSUE_TAG}: namespace {namespace:?} epoch {epoch} is held under a different \
                 key id (two keys minted for one generation); refusing both"
            ),
            Self::StanzaBindingMismatch { namespace, epoch } => write!(
                f,
                "{ISSUE_TAG}: a stanza of namespace {namespace:?} epoch {epoch} does not match \
                 its record; refusing it"
            ),
            Self::RecoveryKeyMismatch { namespace, epoch } => write!(
                f,
                "{ISSUE_TAG}: the recovery key is not the one namespace {namespace:?} epoch \
                 {epoch} was escrowed to"
            ),
            Self::RecordCorrupt { path, detail } => {
                write!(f, "{ISSUE_TAG}: scope-key record {path} refused: {detail}")
            }
            Self::NamespaceTooLong => {
                write!(f, "{ISSUE_TAG}: namespace too long for a scope-key stanza")
            }
            Self::EpochExhausted { namespace } => write!(
                f,
                "{ISSUE_TAG}: namespace {namespace:?} has exhausted its epoch counter"
            ),
            Self::SealedForeign {
                namespace,
                cached_head,
                required_head,
            } => write!(
                f,
                "{ISSUE_TAG}: namespace {namespace:?} scope-key ledger is at head {cached_head}, \
                 {required_head} is required; rows under newer keys stay sealed until the \
                 ledger is refreshed"
            ),
            Self::AuditChainMismatch { namespace, detail } => write!(
                f,
                "{ISSUE_TAG}: scope-key audit log of namespace {namespace:?} refused: {detail}"
            ),
            Self::RecoveryKeyChanged {
                namespace,
                previous,
                current,
            } => write!(
                f,
                "{ISSUE_TAG}: namespace {namespace:?} is escrowed to recovery key {previous}, the \
                 enrolled recovery key is {current}; refusing to fork the escrow chain"
            ),
        }
    }
}

impl std::error::Error for ScopeKeyStoreError {}

/// Downcast an error chain to [`ScopeKeyStoreError`].
#[must_use]
pub fn scope_key_store_error(err: &anyhow::Error) -> Option<&ScopeKeyStoreError> {
    err.downcast_ref::<ScopeKeyStoreError>()
}

fn refuse(err: ScopeKeyStoreError) -> anyhow::Error {
    anyhow::Error::new(err)
}

/// The typed refusal for a key the store does not hold.
pub(crate) fn unknown_scope_key(namespace: &str, key: ScopeKeyRef) -> anyhow::Error {
    refuse(ScopeKeyStoreError::UnknownKey {
        namespace: namespace.to_string(),
        key: key.to_string(),
    })
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// The key-check commitment of `secret` at `key_ref` in `namespace`.
fn key_check(
    secret: &[u8; SCOPE_KEY_LEN],
    key_ref: ScopeKeyRef,
    namespace: &str,
) -> Result<[u8; KEY_CHECK_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut info =
        Vec::with_capacity(KEY_CHECK_INFO.len() + SCOPE_KEY_ID_LEN + 4 + namespace.len());
    info.extend_from_slice(KEY_CHECK_INFO);
    info.extend_from_slice(&key_ref.key_id.0);
    info.extend_from_slice(&key_ref.epoch.to_be_bytes());
    info.extend_from_slice(namespace.as_bytes());
    let mut out = [0u8; KEY_CHECK_LEN];
    hk.expand(&info, &mut out)
        .map_err(|e| anyhow!("HKDF expand of the scope key check failed: {e}"))?;
    Ok(out)
}

/// The id-bound stanza plaintext. The caller zeroizes the result.
fn stanza_plaintext(key: &ScopeKey) -> Result<Vec<u8>> {
    let ns = key.namespace().as_bytes();
    let ns_len =
        u16::try_from(ns.len()).map_err(|_| refuse(ScopeKeyStoreError::NamespaceTooLong))?;
    let key_ref = key.key_ref();
    let mut out = Vec::with_capacity(1 + SCOPE_KEY_ID_LEN + 4 + 2 + ns.len() + SCOPE_KEY_LEN);
    out.push(SCOPE_ENVELOPE_VERSION);
    out.extend_from_slice(&key_ref.key_id.0);
    out.extend_from_slice(&key_ref.epoch.to_be_bytes());
    out.extend_from_slice(&ns_len.to_be_bytes());
    out.extend_from_slice(ns);
    out.extend_from_slice(key.secret_bytes());
    Ok(out)
}

/// Seal `key` to `recipient` and render the stanza bytes.
fn wrap_scope_key(key: &ScopeKey, recipient: &PublicKey) -> Result<String> {
    let mut plaintext = stanza_plaintext(key)?;
    let sealed = encrypt_bytes(&plaintext, recipient);
    plaintext.zeroize();
    let envelope = sealed.context("sealing a scope key to a recipient")?;
    Ok(URL_SAFE_NO_PAD.encode(envelope.to_bytes()))
}

impl ScopeKeyRecord {
    /// The key this record holds.
    ///
    /// # Errors
    /// The stored key id is not 32 hex characters.
    pub fn key_ref(&self) -> Result<ScopeKeyRef> {
        Ok(ScopeKeyRef {
            key_id: ScopeKeyId::from_hex(&self.key_id)?,
            epoch: self.epoch,
        })
    }

    /// Whether the KEK with this fingerprint holds a stanza.
    #[must_use]
    pub fn is_reader(&self, kek_fingerprint: &str) -> bool {
        self.recipients
            .iter()
            .any(|s| s.kek_fingerprint == kek_fingerprint)
    }

    fn mismatch(&self) -> anyhow::Error {
        refuse(ScopeKeyStoreError::StanzaBindingMismatch {
            namespace: self.namespace.clone(),
            epoch: self.epoch,
        })
    }

    /// Unwrap one stanza with `secret`, then verify its binding and the
    /// key-check commitment.
    fn unwrap_stanza(&self, wrapped: &str, secret: &StaticSecret) -> Result<ScopeKey> {
        let key_ref = self.key_ref()?;
        let bytes = URL_SAFE_NO_PAD
            .decode(wrapped)
            .map_err(|_| self.mismatch())?;
        let envelope = Envelope::from_bytes(&bytes).map_err(|_| self.mismatch())?;
        let mut plaintext = decrypt_bytes(&envelope, secret)?;
        let parsed = parse_stanza_plaintext(&plaintext, key_ref, &self.namespace);
        plaintext.zeroize();
        let Some(secret_bytes) = parsed else {
            return Err(self.mismatch());
        };
        let key = ScopeKey::from_parts(&self.namespace, key_ref, *secret_bytes);
        self.verify_key_check(&key)?;
        Ok(key)
    }

    /// Verify a candidate key against this record's key-check commitment.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::StanzaBindingMismatch`] on any difference.
    pub fn verify_key_check(&self, key: &ScopeKey) -> Result<()> {
        let key_ref = self.key_ref()?;
        if key.key_ref() != key_ref || key.namespace() != self.namespace {
            return Err(self.mismatch());
        }
        let expected = hex::decode(&self.key_check).map_err(|_| self.mismatch())?;
        let actual = key_check(key.secret_bytes(), key_ref, &self.namespace)?;
        if bool::from(actual.as_slice().ct_eq(expected.as_slice())) {
            Ok(())
        } else {
            Err(self.mismatch())
        }
    }

    /// Unwrap this record's scope key with a reader's KEK.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::NotAReader`] when the KEK holds no stanza; an
    /// AEAD failure or [`ScopeKeyStoreError::StanzaBindingMismatch`] when the
    /// stanza does not unwrap to this record's key.
    pub fn unwrap_for(&self, reader: &Keypair) -> Result<ScopeKey> {
        let fingerprint = fingerprint_public_bytes(reader.public.as_bytes());
        let Some(stanza) = self
            .recipients
            .iter()
            .find(|s| s.kek_fingerprint == fingerprint)
        else {
            return Err(refuse(ScopeKeyStoreError::NotAReader {
                namespace: self.namespace.clone(),
                epoch: self.epoch,
                kek_fingerprint: fingerprint,
            }));
        };
        self.unwrap_stanza(&stanza.wrapped, &reader.secret)
    }

    /// Recover this record's scope key from its escrow stanza with the
    /// deployment recovery private key (the `keys recover` path).
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::RecoveryKeyMismatch`] when `recovery_secret` is
    /// not the escrow recipient; otherwise as [`Self::unwrap_for`].
    pub fn recover_with(&self, recovery_secret: &StaticSecret) -> Result<ScopeKey> {
        let public = PublicKey::from(recovery_secret);
        if fingerprint_public_bytes(public.as_bytes()) != self.escrow.recovery_fingerprint {
            return Err(refuse(ScopeKeyStoreError::RecoveryKeyMismatch {
                namespace: self.namespace.clone(),
                epoch: self.epoch,
            }));
        }
        self.unwrap_stanza(&self.escrow.wrapped, recovery_secret)
    }

    /// Structural checks every load of the record at `path` applies: the
    /// file name's slug and epoch must be the record's own.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::RecordCorrupt`] naming `path` and the defect.
    fn validate(
        &self,
        path: &Path,
        slug: &str,
        epoch: u32,
    ) -> std::result::Result<(), ScopeKeyStoreError> {
        let corrupt = |detail: String| ScopeKeyStoreError::RecordCorrupt {
            path: path.display().to_string(),
            detail,
        };
        if self.format != SCOPE_KEY_RECORD_FORMAT {
            return Err(corrupt(format!(
                "unsupported record format {}",
                self.format
            )));
        }
        if FileScopeKeyStore::slug(&self.namespace) != slug {
            return Err(corrupt(
                "record namespace does not match its file name".to_string(),
            ));
        }
        if self.epoch != epoch || epoch == 0 {
            return Err(corrupt(format!(
                "record epoch {} does not match its file name",
                self.epoch
            )));
        }
        ScopeKeyId::from_hex(&self.key_id).map_err(|e| corrupt(e.to_string()))?;
        if hex::decode(&self.key_check).map(|v| v.len()) != Ok(KEY_CHECK_LEN) {
            return Err(corrupt("key_check is not a 16-byte hex value".to_string()));
        }
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|e| corrupt(format!("created_at: {e}")))?;
        if let Some(end) = &self.superseded_at {
            chrono::DateTime::parse_from_rfc3339(end)
                .map_err(|e| corrupt(format!("superseded_at: {e}")))?;
        }
        if self.recipients.is_empty() {
            return Err(corrupt("record has no recipient stanza".to_string()));
        }
        Ok(())
    }
}

/// Parse an id-bound stanza plaintext; `None` on any mismatch. The secret
/// copy is zeroized when the caller drops it.
fn parse_stanza_plaintext(
    plaintext: &[u8],
    key_ref: ScopeKeyRef,
    namespace: &str,
) -> Option<Zeroizing<[u8; SCOPE_KEY_LEN]>> {
    let ns = namespace.as_bytes();
    let ns_len = u16::try_from(ns.len()).ok()?;
    let mut expected_head = Vec::with_capacity(1 + SCOPE_KEY_ID_LEN + 4 + 2 + ns.len());
    expected_head.push(SCOPE_ENVELOPE_VERSION);
    expected_head.extend_from_slice(&key_ref.key_id.0);
    expected_head.extend_from_slice(&key_ref.epoch.to_be_bytes());
    expected_head.extend_from_slice(&ns_len.to_be_bytes());
    expected_head.extend_from_slice(ns);
    if plaintext.len() != expected_head.len() + SCOPE_KEY_LEN
        || !plaintext.starts_with(&expected_head)
    {
        return None;
    }
    let secret: [u8; SCOPE_KEY_LEN] = plaintext[expected_head.len()..].try_into().ok()?;
    Some(Zeroizing::new(secret))
}

/// Build the record for a freshly generated key.
fn build_record(
    key: &ScopeKey,
    readers: &[ReaderKek],
    recovery: &PublicKey,
    created_at: String,
) -> Result<ScopeKeyRecord> {
    let key_ref = key.key_ref();
    let mut recipients = Vec::with_capacity(readers.len());
    for reader in readers {
        let fingerprint = reader.fingerprint();
        if recipients
            .iter()
            .any(|s: &RecipientStanza| s.kek_fingerprint == fingerprint)
        {
            continue;
        }
        recipients.push(RecipientStanza {
            agent_id: reader.agent_id.clone(),
            kek_fingerprint: fingerprint,
            wrapped: wrap_scope_key(key, &reader.public)?,
        });
    }
    Ok(ScopeKeyRecord {
        format: SCOPE_KEY_RECORD_FORMAT,
        namespace: key.namespace().to_string(),
        epoch: key_ref.epoch,
        key_id: key_ref.key_id.to_hex(),
        key_check: hex::encode(key_check(key.secret_bytes(), key_ref, key.namespace())?),
        created_at,
        superseded_at: None,
        recipients,
        escrow: EscrowStanza {
            recovery_fingerprint: fingerprint_public_bytes(recovery.as_bytes()),
            wrapped: wrap_scope_key(key, recovery)?,
        },
    })
}

/// What [`ScopeKeyStore::mint`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintOutcome {
    /// A new epoch-1 key was minted and escrowed.
    Minted(ScopeKeyRecord),
    /// The namespace already has a key; this is its current record.
    Existing(ScopeKeyRecord),
}

impl MintOutcome {
    /// The current record either way.
    #[must_use]
    pub fn record(&self) -> &ScopeKeyRecord {
        match self {
            Self::Minted(r) | Self::Existing(r) => r,
        }
    }
}

/// What a recipient change did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientChange {
    /// A stanza was added.
    Added,
    /// The reader already held a stanza; nothing written.
    AlreadyPresent,
    /// The stanza was removed.
    Removed,
    /// The reader held no stanza; nothing written.
    Absent,
}

/// The scope-key ledger contract: a synchronous `Send + Sync` cache (ruling
/// R11). Lookups answer from memory; every mutator writes through to the
/// cold store in the same call and appends one audit entry (ruling R3). The
/// file store below implements it; the async ledger methods on `MemoryStore`
/// for both backends arrive in E2 (Codex SAL slice), so the envelope code
/// never depends on where records live.
pub trait ScopeKeyStore: Send + Sync {
    /// First write in an end-to-end namespace: mint, escrow and record the
    /// epoch-1 key sealed to `readers`, or return the existing current record.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::EscrowUnavailable`] with no recovery key,
    /// [`ScopeKeyStoreError::NoRecipients`], or an I/O / corruption refusal.
    fn mint(&self, namespace: &str, readers: &[ReaderKek]) -> Result<MintOutcome>;

    /// Every generation of `namespace`, ascending, dense from epoch 1.
    ///
    /// # Errors
    /// A corrupt record or audit log (never flattened to empty).
    fn history(&self, namespace: &str) -> Result<Vec<ScopeKeyRecord>>;

    /// The record of one epoch.
    ///
    /// # Errors
    /// A corrupt record or audit log.
    fn load_epoch(&self, namespace: &str, epoch: u32) -> Result<Option<ScopeKeyRecord>>;

    /// The current (highest-epoch) record.
    ///
    /// # Errors
    /// As [`Self::history`].
    fn load_current(&self, namespace: &str) -> Result<Option<ScopeKeyRecord>> {
        Ok(self.history(namespace)?.pop())
    }

    /// The record of the key an envelope names.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::KeyIdMismatch`] when the epoch is held under
    /// another key id, or a corrupt record.
    fn load_by_key_id(&self, namespace: &str, key: &ScopeKeyRef) -> Result<Option<ScopeKeyRecord>> {
        let Some(record) = self.load_epoch(namespace, key.epoch)? else {
            return Ok(None);
        };
        if record.key_ref()? == *key {
            Ok(Some(record))
        } else {
            Err(refuse(ScopeKeyStoreError::KeyIdMismatch {
                namespace: namespace.to_string(),
                epoch: key.epoch,
            }))
        }
    }

    /// [`Self::load_by_key_id`] that must answer from a ledger at least as
    /// fresh as `required` (the head a peer advertised on sync or
    /// `/keys/scope`). A cache older than that fails closed.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::SealedForeign`] while the cache head is older
    /// than `required`; otherwise as [`Self::load_by_key_id`].
    fn load_by_key_id_fresh(
        &self,
        namespace: &str,
        key: &ScopeKeyRef,
        required: LedgerHead,
    ) -> Result<Option<ScopeKeyRecord>> {
        let cached = self.ledger_head(namespace)?;
        if cached < required {
            return Err(refuse(ScopeKeyStoreError::SealedForeign {
                namespace: namespace.to_string(),
                cached_head: cached.0,
                required_head: required.0,
            }));
        }
        self.load_by_key_id(namespace, key)
    }

    /// Whether `namespace` is end-to-end: its ledger holds at least one epoch
    /// (ruling R1). A namespace whose ledger cannot be read answers `true`
    /// (fail closed: no plaintext or per-node path opens for it). E2 enforces
    /// that no non-`0x05` representation is sent or accepted for it.
    fn namespace_is_e2e(&self, namespace: &str) -> bool;

    /// The ledger head (audit entry count) this store holds for `namespace`;
    /// zero when it has no ledger.
    ///
    /// # Errors
    /// A corrupt record or audit log.
    fn ledger_head(&self, namespace: &str) -> Result<LedgerHead>;

    /// The audit log of `namespace`, oldest first.
    ///
    /// # Errors
    /// A corrupt record or audit log.
    fn audit_log(&self, namespace: &str) -> Result<Vec<AuditEntry>>;

    /// Reload the whole cache from the cold store.
    ///
    /// # Errors
    /// The scope-key directory cannot be listed or locked.
    fn refresh_from_ledger(&self) -> Result<()>;

    /// Seal `key` (already unwrapped by a current holder, or recovered from
    /// escrow) to `reader` and add the stanza to its record.
    ///
    /// # Errors
    /// The record is unknown, `key` fails the record's key check, or I/O.
    fn add_recipient(&self, key: &ScopeKey, reader: &ReaderKek) -> Result<RecipientChange>;

    /// Remove the stanza of the KEK with `kek_fingerprint`. This stops the
    /// reader pulling this epoch again; it does not take back a key already
    /// pulled, which needs [`Self::supersede`] plus rotation of old rows.
    ///
    /// # Errors
    /// [`ScopeKeyStoreError::LastRecipient`], an unknown record, or I/O.
    fn remove_recipient(
        &self,
        namespace: &str,
        epoch: u32,
        kek_fingerprint: &str,
    ) -> Result<RecipientChange>;

    /// Mint the next epoch sealed to `readers` and close the current record's
    /// window. Old records stay so rows sealed under them still open.
    ///
    /// # Errors
    /// No current record, [`ScopeKeyStoreError::EscrowUnavailable`],
    /// [`ScopeKeyStoreError::RecoveryKeyChanged`],
    /// [`ScopeKeyStoreError::NoRecipients`], or I/O.
    fn supersede(&self, namespace: &str, readers: &[ReaderKek]) -> Result<ScopeKeyRecord>;
}

/// One cache slot: a namespace's verified ledger, or the refusal its cold
/// store produced (kept so every lookup of that namespace fails closed).
type Slot = std::result::Result<NamespaceLedger, ScopeKeyStoreError>;

/// The file-backed [`ScopeKeyStore`] under a key directory.
#[derive(Debug)]
pub struct FileScopeKeyStore {
    key_dir: PathBuf,
    /// Agent id recorded as the actor of this process's mutations.
    actor: String,
    /// Namespace slug to slot.
    cache: RwLock<HashMap<String, Slot>>,
    /// Slugs whose marker reload has already failed once (#8315): the first
    /// failure warns, later ones for the same slug log at debug. Bounded by
    /// [`MARKER_WARNED_CAP`].
    marker_warned: Mutex<HashSet<String>>,
    /// Set once the saturation of `marker_warned` has been logged, so the
    /// notice is emitted once per store.
    marker_warned_full_logged: AtomicBool,
}

/// Most distinct slugs `marker_warned` remembers (#8315, code F3): a store
/// that keeps missing broken key dirs for ever-new namespaces must not grow
/// the set without bound. Past the cap a new slug is logged at debug only.
const MARKER_WARNED_CAP: usize = 1024;

/// How `note_marker_failure` classifies one marker reload failure.
#[derive(Debug, PartialEq, Eq)]
enum MarkerFailureLog {
    /// First failure of this slug: warn.
    First,
    /// Already seen: debug.
    Repeat,
    /// Set full and the slug is new: debug, and the saturation is reportable.
    Saturated,
}

/// Record `slug` in `warned`, never growing it past `cap` entries.
fn note_marker_failure(warned: &mut HashSet<String>, slug: &str, cap: usize) -> MarkerFailureLog {
    if warned.contains(slug) {
        MarkerFailureLog::Repeat
    } else if warned.len() >= cap {
        MarkerFailureLog::Saturated
    } else {
        warned.insert(slug.to_string());
        MarkerFailureLog::First
    }
}

/// Holds a `flock` until dropped (closing the descriptor releases it).
struct StoreLock {
    _file: std::fs::File,
}

/// The record epochs and the audit-log presence of one slug on disk.
#[derive(Default)]
struct SlugFiles {
    epochs: Vec<u32>,
    audit: bool,
}

/// Detail prefix of a scope-key file that cannot be opened or read
/// (R15: one constant, not a repeated literal).
const UNREADABLE_DETAIL: &str = "unreadable";

/// The [`ScopeKeyStoreError::RecordCorrupt`] detail of an I/O read failure.
fn unreadable_detail(error: &std::io::Error) -> String {
    format!("{UNREADABLE_DETAIL}: {error}")
}

fn poisoned() -> anyhow::Error {
    anyhow!("{ISSUE_TAG}: the scope-key cache lock is poisoned; refusing to answer from it")
}

impl FileScopeKeyStore {
    /// Open the store rooted at `key_dir` (the agent key directory) for the
    /// process agent `actor`, loading every namespace's ledger into memory.
    /// A namespace whose files are corrupt is kept as a refusal, so its
    /// lookups fail closed while the others work.
    ///
    /// # Errors
    /// The scope-key directory cannot be listed, locked or is insecure.
    pub fn open(key_dir: PathBuf, actor: &str) -> Result<Self> {
        let store = Self {
            key_dir,
            actor: actor.to_string(),
            cache: RwLock::new(HashMap::new()),
            marker_warned: Mutex::new(HashSet::new()),
            marker_warned_full_logged: AtomicBool::new(false),
        };
        store.refresh_from_ledger()?;
        Ok(store)
    }

    /// `<key_dir>/scope-keys`.
    #[must_use]
    pub fn scope_dir(&self) -> PathBuf {
        self.key_dir.join(SCOPE_KEY_SUBDIR)
    }

    /// The path-safe slug of `namespace`.
    #[must_use]
    pub fn slug(namespace: &str) -> String {
        let digest = Sha256::digest(namespace.as_bytes());
        hex::encode(&digest[..SLUG_BYTES])
    }

    /// The record file of `(namespace, epoch)`.
    #[must_use]
    pub fn record_path(&self, namespace: &str, epoch: u32) -> PathBuf {
        self.slug_record_path(&Self::slug(namespace), epoch)
    }

    fn slug_record_path(&self, slug: &str, epoch: u32) -> PathBuf {
        self.scope_dir()
            .join(format!("{slug}{RECORD_INFIX}{epoch}{RECORD_SUFFIX}"))
    }

    /// The audit log of `namespace`.
    #[must_use]
    pub fn audit_path(&self, namespace: &str) -> PathBuf {
        self.slug_audit_path(&Self::slug(namespace))
    }

    fn slug_audit_path(&self, slug: &str) -> PathBuf {
        self.scope_dir().join(format!("{slug}{AUDIT_SUFFIX}"))
    }

    fn open_lock_file(&self) -> Result<std::fs::File> {
        let path = self.scope_dir().join(SCOPE_KEY_LOCK_FILE);
        crate::identity::keypair::ensure_parent(&path)?;
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, &path)?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(MODE_PRIVATE);
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .with_context(|| format!("opening scope-key lock {}", path.display()))
    }

    /// The exclusive lock every mutation holds.
    fn lock(&self) -> Result<StoreLock> {
        let file = self.open_lock_file()?;
        file.lock()
            .context("locking the scope-key lock exclusively")?;
        Ok(StoreLock { _file: file })
    }

    /// The shared lock a load holds (no writer can be mid-append).
    fn lock_shared(&self) -> Result<StoreLock> {
        let file = self.open_lock_file()?;
        file.lock_shared()
            .context("locking the scope-key lock shared")?;
        Ok(StoreLock { _file: file })
    }

    fn corrupt(path: &Path, detail: impl Into<String>) -> ScopeKeyStoreError {
        ScopeKeyStoreError::RecordCorrupt {
            path: path.display().to_string(),
            detail: detail.into(),
        }
    }

    /// Read a private file: chain check first, then open without following a
    /// link, then `fstat` the open descriptor (regular file, owner-only mode)
    /// and read from that same descriptor, so the bytes read are the bytes
    /// checked.
    fn read_private(
        &self,
        path: &Path,
    ) -> std::result::Result<Option<Vec<u8>>, ScopeKeyStoreError> {
        use std::io::Read as _;
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, path)
            .map_err(|e| Self::corrupt(path, format!("insecure key directory chain: {e:#}")))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::corrupt(path, unreadable_detail(&e))),
        };
        let meta = file
            .metadata()
            .map_err(|e| Self::corrupt(path, format!("unreadable metadata: {e}")))?;
        if !meta.is_file() {
            return Err(Self::corrupt(path, "not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(Self::corrupt(
                    path,
                    format!(
                        "mode {:o} grants group/other access (expected 600)",
                        mode & 0o777
                    ),
                ));
            }
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| Self::corrupt(path, unreadable_detail(&e)))?;
        Ok(Some(bytes))
    }

    fn read_record(
        &self,
        slug: &str,
        epoch: u32,
    ) -> std::result::Result<Option<ScopeKeyRecord>, ScopeKeyStoreError> {
        let path = self.slug_record_path(slug, epoch);
        let Some(bytes) = self.read_private(&path)? else {
            return Ok(None);
        };
        let record: ScopeKeyRecord = serde_json::from_slice(&bytes)
            .map_err(|e| Self::corrupt(&path, format!("malformed: {e}")))?;
        record.validate(&path, slug, epoch)?;
        Ok(Some(record))
    }

    fn write_record(&self, record: &ScopeKeyRecord) -> Result<()> {
        let path = self.record_path(&record.namespace, record.epoch);
        crate::identity::keypair::ensure_parent(&path)?;
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, &path)?;
        let bytes = serde_json::to_vec_pretty(record).context("serialising a scope-key record")?;
        crate::identity::keypair::write_with_mode(&path, &bytes, MODE_PRIVATE)
            .with_context(|| format!("writing scope-key record {}", path.display()))
    }

    /// Append one line to the audit log: owner-only, never through a link,
    /// `O_APPEND`, flushed to disk before the call returns.
    fn append_audit_line(&self, namespace: &str, line: &str) -> Result<()> {
        use std::io::Write as _;
        let path = self.audit_path(namespace);
        crate::identity::keypair::ensure_parent(&path)?;
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, &path)?;
        let mut options = std::fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(MODE_PRIVATE);
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("opening scope-key audit log {}", path.display()))?;
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("appending to scope-key audit log {}", path.display()))
    }

    /// Every slug with files on disk (`only` narrows it to one), with its
    /// record epochs ascending.
    fn scan(&self, only: Option<&str>) -> Result<BTreeMap<String, SlugFiles>> {
        let dir = self.scope_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => {
                return Err(refuse(Self::corrupt(
                    &dir,
                    format!("unreadable directory: {e}"),
                )));
            }
        };
        let mut slugs: BTreeMap<String, SlugFiles> = BTreeMap::new();
        for entry in entries {
            let entry =
                entry.map_err(|e| refuse(Self::corrupt(&dir, format!("directory entry: {e}"))))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(slug) = name.strip_suffix(AUDIT_SUFFIX) {
                if only.is_none_or(|o| o == slug) {
                    slugs.entry(slug.to_string()).or_default().audit = true;
                }
                continue;
            }
            let Some((slug, rest)) = name
                .strip_suffix(RECORD_SUFFIX)
                .and_then(|r| r.split_once(RECORD_INFIX))
            else {
                continue;
            };
            if only.is_some_and(|o| o != slug) {
                continue;
            }
            let epoch: u32 = rest.parse().map_err(|_| {
                refuse(Self::corrupt(
                    &entry.path(),
                    "epoch in file name is not a number",
                ))
            })?;
            slugs
                .entry(slug.to_string())
                .or_default()
                .epochs
                .push(epoch);
        }
        for files in slugs.values_mut() {
            files.epochs.sort_unstable();
        }
        Ok(slugs)
    }

    /// Load and verify one slug's ledger from its files.
    fn load_slug(&self, slug: &str, files: &SlugFiles) -> Slot {
        let mut records = Vec::with_capacity(files.epochs.len());
        for (index, epoch) in files.epochs.iter().enumerate() {
            let expected = u32::try_from(index + 1).ok();
            if expected != Some(*epoch) {
                return Err(Self::corrupt(
                    &self.slug_record_path(slug, *epoch),
                    format!(
                        "epochs are not dense from 1 (found {epoch} at position {})",
                        index + 1
                    ),
                ));
            }
            let Some(record) = self.read_record(slug, *epoch)? else {
                return Err(Self::corrupt(
                    &self.slug_record_path(slug, *epoch),
                    "record vanished while loading",
                ));
            };
            if records
                .first()
                .is_some_and(|first: &ScopeKeyRecord| first.namespace != record.namespace)
            {
                return Err(Self::corrupt(
                    &self.slug_record_path(slug, *epoch),
                    "records of one slug name different namespaces",
                ));
            }
            records.push(record);
        }
        let audit_path = self.slug_audit_path(slug);
        let log = match self.read_private(&audit_path)? {
            Some(bytes) => String::from_utf8(bytes)
                .map_err(|_| Self::corrupt(&audit_path, "audit log is not UTF-8"))?,
            None => String::new(),
        };
        if records.is_empty() != log.is_empty() {
            return Err(Self::corrupt(
                &audit_path,
                "records and audit log must exist together",
            ));
        }
        NamespaceLedger::replay(records, &log)
    }

    /// R17 (code review r2 C2): the namespace marker on a cache miss. Takes
    /// the shared lock (lock order: flock first, cache second), re-reads the
    /// slug's records and audit log, caches the result and answers from it,
    /// so a store opened before another writer minted epoch 1 never reports
    /// the namespace as plaintext. A ledger that fails verification answers
    /// end-to-end (fail closed). The read path creates only the lock file
    /// (`open_lock_file` opens it with `create(true)`), never a record or an
    /// audit line.
    ///
    /// Only a key directory that does not exist answers "not end-to-end". Any
    /// other error reading it (EACCES, EIO, ELOOP) is returned, so the
    /// caller's fail-closed answer applies (code r3 F2, ERRORS-06).
    /// `symlink_metadata` reports a link in the key dir's place itself rather
    /// than following it, so a dangling link is not "absent": taking the lock
    /// below then fails closed on it. A link whose target is a directory the
    /// owner controls (it passes the ownership and mode checks) is followed
    /// like that directory, and an empty target answers "not end-to-end".
    /// Taking the lock runs `ensure_parent`, which recreates a key dir that
    /// was removed between this probe and the lock (mode 0700); the scan of
    /// that fresh, empty dir then answers "not end-to-end", the same answer
    /// a key dir that is absent at the probe gives.
    fn reload_marker(&self, slug: &str) -> Result<bool> {
        let scope_dir = self.scope_dir();
        match std::fs::symlink_metadata(&scope_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("reading scope-key directory {}", scope_dir.display())
                });
            }
        }
        let _lock = self.lock_shared()?;
        let scanned = self.scan(Some(slug))?;
        let Some(files) = scanned.get(slug) else {
            return Ok(false);
        };
        let slot = self.load_slug(slug, files);
        let e2e = slot
            .as_ref()
            .map_or(true, |ledger| !ledger.records.is_empty());
        self.cache
            .write()
            .map_err(|_| poisoned())?
            .insert(slug.to_string(), slot);
        Ok(e2e)
    }

    /// #8315: log a marker reload failure without the paths its error chain
    /// carries. Warns on the first failure of `slug`, logs at debug on every
    /// later one, so a store that keeps missing a broken key dir does not
    /// warn on every query. The warned set is per store (the `config.rs`
    /// one-shot idiom is a process-global `Once`) because the cache the miss
    /// falls through is per store too, and a second store's first miss is
    /// new information. The namespace label is a `config`-class value (the
    /// `SealedForeign` refusal and the subscription spans already carry it);
    /// a poisoned warned-set lock answers "first", so a poisoned lock warns
    /// rather than going quiet. The set holds at most [`MARKER_WARNED_CAP`]
    /// slugs; past it new slugs log at debug (code F3).
    fn log_marker_reload_failure(&self, namespace: &str, slug: &str, error: &anyhow::Error) {
        let kind = error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .map_or_else(|| "other".to_string(), |io| format!("{:?}", io.kind()));
        let outcome = self
            .marker_warned
            .lock()
            .map(|mut warned| note_marker_failure(&mut warned, slug, MARKER_WARNED_CAP))
            .unwrap_or(MarkerFailureLog::First);
        match outcome {
            MarkerFailureLog::First => tracing::warn!(
                namespace,
                kind,
                "scope-key namespace marker reload failed; answering end-to-end"
            ),
            MarkerFailureLog::Repeat => tracing::debug!(
                namespace,
                kind,
                "scope-key namespace marker reload failed again; answering end-to-end"
            ),
            MarkerFailureLog::Saturated => {
                if !self.marker_warned_full_logged.swap(true, Ordering::Relaxed) {
                    tracing::debug!(
                        cap = MARKER_WARNED_CAP,
                        "scope-key marker warned-set is full; later new namespaces log at debug only"
                    );
                }
                tracing::debug!(
                    namespace,
                    kind,
                    "scope-key namespace marker reload failed; answering end-to-end"
                );
            }
        }
    }

    /// The verified ledger of `namespace` straight from disk (the caller
    /// holds the exclusive lock).
    fn load_namespace_locked(&self, namespace: &str) -> Result<NamespaceLedger> {
        let slug = Self::slug(namespace);
        let scanned = self.scan(Some(&slug))?;
        let ledger = match scanned.get(&slug) {
            Some(files) => self.load_slug(&slug, files).map_err(refuse)?,
            None => NamespaceLedger::default(),
        };
        if ledger.namespace().is_some_and(|ns| ns != namespace) {
            return Err(refuse(Self::corrupt(
                &self.record_path(namespace, 1),
                "slug collision: the record names another namespace",
            )));
        }
        Ok(ledger)
    }

    /// Answer from the cached ledger of `namespace` (`None`: no ledger).
    fn with_ledger<T>(
        &self,
        namespace: &str,
        read: impl FnOnce(Option<&NamespaceLedger>) -> Result<T>,
    ) -> Result<T> {
        let cache = self.cache.read().map_err(|_| poisoned())?;
        match cache.get(&Self::slug(namespace)) {
            None => read(None),
            Some(Err(refusal)) => Err(refuse(refusal.clone())),
            Some(Ok(ledger)) if ledger.namespace().is_some_and(|ns| ns != namespace) => {
                Err(refuse(Self::corrupt(
                    &self.record_path(namespace, 1),
                    "slug collision: the record names another namespace",
                )))
            }
            Some(Ok(ledger)) => read(Some(ledger)),
        }
    }

    /// Write-through: append the audit entry for `change` to `ledger`
    /// (verified against the head), write `records`, append the line, then
    /// install the ledger in the cache. The caller holds the exclusive lock,
    /// so the order is always `flock` then the cache lock.
    fn commit(
        &self,
        namespace: &str,
        mut ledger: NamespaceLedger,
        change: &Change<'_>,
        records: &[&ScopeKeyRecord],
    ) -> Result<()> {
        let entry = ledger.entry_for(change);
        let line = ledger.append(entry).map_err(refuse)?;
        for record in records {
            self.write_record(record)?;
            ledger.put_record((*record).clone());
        }
        self.append_audit_line(namespace, &line)?;
        let mut cache = self.cache.write().map_err(|_| poisoned())?;
        cache.insert(Self::slug(namespace), Ok(ledger));
        Ok(())
    }

    fn recovery_pubkey(&self, namespace: &str) -> Result<PublicKey> {
        escrow::load_recovery_pubkey(&self.key_dir)?.ok_or_else(|| {
            refuse(ScopeKeyStoreError::EscrowUnavailable {
                namespace: namespace.to_string(),
            })
        })
    }

    fn require_readers(namespace: &str, readers: &[ReaderKek]) -> Result<()> {
        if readers.is_empty() {
            Err(refuse(ScopeKeyStoreError::NoRecipients {
                namespace: namespace.to_string(),
            }))
        } else {
            Ok(())
        }
    }

    fn require_record(
        ledger: &NamespaceLedger,
        namespace: &str,
        epoch: u32,
    ) -> Result<ScopeKeyRecord> {
        let index = usize::try_from(epoch.saturating_sub(1)).unwrap_or(usize::MAX);
        match ledger.records.get(index) {
            Some(record) if epoch > 0 => Ok(record.clone()),
            _ => Err(refuse(ScopeKeyStoreError::UnknownKey {
                namespace: namespace.to_string(),
                key: format!("epoch{epoch}"),
            })),
        }
    }
}

#[cfg(test)]
impl FileScopeKeyStore {
    /// TEST only: record `record` as an epoch-1 mint (record file plus its
    /// audit entry) without the escrow enrolment `mint` requires, so a test
    /// can seed the shared default key directory without enrolling a
    /// recovery key there.
    fn seed_minted_for_test(&self, record: &ScopeKeyRecord) -> Result<()> {
        let _lock = self.lock()?;
        let ledger = self.load_namespace_locked(&record.namespace)?;
        let change = Change {
            action: AuditAction::Mint,
            actor: &self.actor,
            record,
            subject: None,
            at: record.created_at.clone(),
        };
        self.commit(&record.namespace, ledger, &change, &[record])
    }
}

impl ScopeKeyStore for FileScopeKeyStore {
    fn mint(&self, namespace: &str, readers: &[ReaderKek]) -> Result<MintOutcome> {
        Self::require_readers(namespace, readers)?;
        let _lock = self.lock()?;
        let ledger = self.load_namespace_locked(namespace)?;
        if let Some(current) = ledger.records.last() {
            return Ok(MintOutcome::Existing(current.clone()));
        }
        let recovery = self.recovery_pubkey(namespace)?;
        let key_ref = ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: 1,
        };
        let key = ScopeKey::generate(namespace, key_ref);
        let record = build_record(&key, readers, &recovery, now_rfc3339())?;
        let change = Change {
            action: AuditAction::Mint,
            actor: &self.actor,
            record: &record,
            subject: None,
            at: record.created_at.clone(),
        };
        self.commit(namespace, ledger, &change, &[&record])?;
        Ok(MintOutcome::Minted(record))
    }

    fn history(&self, namespace: &str) -> Result<Vec<ScopeKeyRecord>> {
        self.with_ledger(namespace, |ledger| {
            Ok(ledger.map(|l| l.records.clone()).unwrap_or_default())
        })
    }

    fn load_epoch(&self, namespace: &str, epoch: u32) -> Result<Option<ScopeKeyRecord>> {
        self.with_ledger(namespace, |ledger| {
            let index = usize::try_from(epoch.saturating_sub(1)).unwrap_or(usize::MAX);
            Ok(ledger
                .filter(|_| epoch > 0)
                .and_then(|l| l.records.get(index).cloned()))
        })
    }

    fn namespace_is_e2e(&self, namespace: &str) -> bool {
        let slug = Self::slug(namespace);
        {
            let Ok(cache) = self.cache.read() else {
                return true;
            };
            match cache.get(&slug) {
                Some(Err(_)) => return true,
                Some(Ok(ledger)) if !ledger.records.is_empty() => return true,
                _ => {}
            }
        }
        // R17: a miss re-reads the cold store; a read error is end-to-end.
        // R4-I3 / #8315: the fail-closed answer is logged with the namespace
        // label and the root cause's kind only: never the key-directory or an
        // entry path (which carries the namespace hash), never key material
        // or ledger contents (ERRORS-18). The first miss of a slug warns;
        // later misses of the same slug log at debug.
        self.reload_marker(&slug)
            .inspect_err(|e| self.log_marker_reload_failure(namespace, &slug, e))
            .unwrap_or(true)
    }

    fn ledger_head(&self, namespace: &str) -> Result<LedgerHead> {
        self.with_ledger(namespace, |ledger| {
            Ok(ledger.map(NamespaceLedger::head).unwrap_or_default())
        })
    }

    fn audit_log(&self, namespace: &str) -> Result<Vec<AuditEntry>> {
        self.with_ledger(namespace, |ledger| {
            Ok(ledger.map(|l| l.audit.clone()).unwrap_or_default())
        })
    }

    /// Keeps `exists()` rather than the marker's `symlink_metadata` probe
    /// (R4-I2) because the later open fails closed: an unreadable key dir
    /// errors at the lock or at the scan's `read_dir`, and a slug left out
    /// of the refreshed cache is re-probed by `reload_marker` on its next
    /// `namespace_is_e2e` miss.
    fn refresh_from_ledger(&self) -> Result<()> {
        let mut fresh = HashMap::new();
        {
            let _lock = if self.scope_dir().exists() {
                Some(self.lock_shared()?)
            } else {
                None
            };
            for (slug, files) in self.scan(None)? {
                let slot = self.load_slug(&slug, &files);
                fresh.insert(slug, slot);
            }
            let mut cache = self.cache.write().map_err(|_| poisoned())?;
            *cache = fresh;
        }
        Ok(())
    }

    fn add_recipient(&self, key: &ScopeKey, reader: &ReaderKek) -> Result<RecipientChange> {
        let _lock = self.lock()?;
        let namespace = key.namespace();
        let ledger = self.load_namespace_locked(namespace)?;
        let mut record = Self::require_record(&ledger, namespace, key.key_ref().epoch)?;
        record.verify_key_check(key)?;
        let fingerprint = reader.fingerprint();
        if record.is_reader(&fingerprint) {
            return Ok(RecipientChange::AlreadyPresent);
        }
        record.recipients.push(RecipientStanza {
            agent_id: reader.agent_id.clone(),
            kek_fingerprint: fingerprint.clone(),
            wrapped: wrap_scope_key(key, &reader.public)?,
        });
        let change = Change {
            action: AuditAction::AddRecipient,
            actor: &self.actor,
            record: &record,
            subject: Some(fingerprint),
            at: now_rfc3339(),
        };
        self.commit(namespace, ledger, &change, &[&record])?;
        Ok(RecipientChange::Added)
    }

    fn remove_recipient(
        &self,
        namespace: &str,
        epoch: u32,
        kek_fingerprint: &str,
    ) -> Result<RecipientChange> {
        let _lock = self.lock()?;
        let ledger = self.load_namespace_locked(namespace)?;
        let mut record = Self::require_record(&ledger, namespace, epoch)?;
        if !record.is_reader(kek_fingerprint) {
            return Ok(RecipientChange::Absent);
        }
        if record.recipients.len() == 1 {
            return Err(refuse(ScopeKeyStoreError::LastRecipient {
                namespace: namespace.to_string(),
                epoch,
            }));
        }
        record
            .recipients
            .retain(|s| s.kek_fingerprint != kek_fingerprint);
        let change = Change {
            action: AuditAction::RemoveRecipient,
            actor: &self.actor,
            record: &record,
            subject: Some(kek_fingerprint.to_string()),
            at: now_rfc3339(),
        };
        self.commit(namespace, ledger, &change, &[&record])?;
        Ok(RecipientChange::Removed)
    }

    fn supersede(&self, namespace: &str, readers: &[ReaderKek]) -> Result<ScopeKeyRecord> {
        Self::require_readers(namespace, readers)?;
        let _lock = self.lock()?;
        let ledger = self.load_namespace_locked(namespace)?;
        let Some(mut current) = ledger.records.last().cloned() else {
            return Err(refuse(ScopeKeyStoreError::UnknownKey {
                namespace: namespace.to_string(),
                key: "current".to_string(),
            }));
        };
        let recovery = self.recovery_pubkey(namespace)?;
        let recovery_fingerprint = fingerprint_public_bytes(recovery.as_bytes());
        if recovery_fingerprint != current.escrow.recovery_fingerprint {
            return Err(refuse(ScopeKeyStoreError::RecoveryKeyChanged {
                namespace: namespace.to_string(),
                previous: current.escrow.recovery_fingerprint.clone(),
                current: recovery_fingerprint,
            }));
        }
        let epoch = ledger.current_epoch().checked_add(1).ok_or_else(|| {
            refuse(ScopeKeyStoreError::EpochExhausted {
                namespace: namespace.to_string(),
            })
        })?;
        let boundary = now_rfc3339();
        let key = ScopeKey::generate(
            namespace,
            ScopeKeyRef {
                key_id: ScopeKeyId::random(),
                epoch,
            },
        );
        let next = build_record(&key, readers, &recovery, boundary.clone())?;
        current.superseded_at = Some(boundary.clone());
        let change = Change {
            action: AuditAction::Supersede,
            actor: &self.actor,
            record: &next,
            subject: None,
            at: boundary,
        };
        // New generation first: a crash before the audit line lands leaves a
        // record the log does not account for, which the next load refuses
        // (fail closed), never a namespace with no current key.
        self.commit(namespace, ledger, &change, &[&next, &current])?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
