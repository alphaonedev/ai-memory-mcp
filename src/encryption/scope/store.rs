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
//! mode `0o600`, written stage-then-rename. `slug` is the hex of the first 16
//! bytes of SHA-256(namespace): path-safe for any namespace text, and the
//! namespace itself is stored in the record and verified on every load.
//! Mutations take an exclusive `flock` on `scope-keys/.scope-keys.lock`, which
//! serialises threads (each opens its own descriptor) and processes. The DB
//! ledger on both backends implements the same trait (Codex SAL lane).

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
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// Sub-directory of the key directory holding scope-key records.
pub const SCOPE_KEY_SUBDIR: &str = "scope-keys";
/// Lock file serialising record mutations.
pub const SCOPE_KEY_LOCK_FILE: &str = ".scope-keys.lock";
/// Infix between the namespace slug and the epoch in a record file name.
const RECORD_INFIX: &str = ".scope.";
/// Suffix of a record file name.
const RECORD_SUFFIX: &str = ".json";
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
        let Some(mut secret_bytes) = parsed else {
            return Err(self.mismatch());
        };
        let key = ScopeKey::from_parts(&self.namespace, key_ref, secret_bytes);
        secret_bytes.zeroize();
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

    /// Structural checks every load applies.
    fn validate(&self, namespace: &str, epoch: u32) -> std::result::Result<(), String> {
        if self.format != SCOPE_KEY_RECORD_FORMAT {
            return Err(format!("unsupported record format {}", self.format));
        }
        if self.namespace != namespace {
            return Err("record namespace does not match its file name".to_string());
        }
        if self.epoch != epoch || epoch == 0 {
            return Err(format!(
                "record epoch {} does not match its file name",
                self.epoch
            ));
        }
        ScopeKeyId::from_hex(&self.key_id).map_err(|e| e.to_string())?;
        if hex::decode(&self.key_check).map(|v| v.len()) != Ok(KEY_CHECK_LEN) {
            return Err("key_check is not a 16-byte hex value".to_string());
        }
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|e| format!("created_at: {e}"))?;
        if let Some(end) = &self.superseded_at {
            chrono::DateTime::parse_from_rfc3339(end).map_err(|e| format!("superseded_at: {e}"))?;
        }
        if self.recipients.is_empty() {
            return Err("record has no recipient stanza".to_string());
        }
        Ok(())
    }
}

/// Parse an id-bound stanza plaintext; `None` on any mismatch.
fn parse_stanza_plaintext(
    plaintext: &[u8],
    key_ref: ScopeKeyRef,
    namespace: &str,
) -> Option<[u8; SCOPE_KEY_LEN]> {
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
    let mut secret = [0u8; SCOPE_KEY_LEN];
    secret.copy_from_slice(&plaintext[expected_head.len()..]);
    Some(secret)
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

/// The scope-key ledger contract. The file store below implements it; the
/// SAL DB ledger on both backends implements it next (Codex lane), so the
/// envelope code never depends on where records live.
pub trait ScopeKeyStore {
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
    /// A corrupt record or a gap in the epochs (never flattened to empty).
    fn history(&self, namespace: &str) -> Result<Vec<ScopeKeyRecord>>;

    /// The record of one epoch.
    ///
    /// # Errors
    /// A corrupt record.
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
    /// [`ScopeKeyStoreError::NoRecipients`], or I/O.
    fn supersede(&self, namespace: &str, readers: &[ReaderKek]) -> Result<ScopeKeyRecord>;
}

/// The file-backed [`ScopeKeyStore`] under a key directory.
#[derive(Debug, Clone)]
pub struct FileScopeKeyStore {
    key_dir: PathBuf,
}

/// Holds the exclusive lock until dropped (closing the descriptor releases
/// the `flock`).
struct StoreLock {
    _file: std::fs::File,
}

impl FileScopeKeyStore {
    /// A store rooted at `key_dir` (the agent key directory).
    #[must_use]
    pub fn new(key_dir: PathBuf) -> Self {
        Self { key_dir }
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
        self.scope_dir().join(format!(
            "{}{RECORD_INFIX}{epoch}{RECORD_SUFFIX}",
            Self::slug(namespace)
        ))
    }

    fn lock(&self) -> Result<StoreLock> {
        let path = self.scope_dir().join(SCOPE_KEY_LOCK_FILE);
        crate::identity::keypair::ensure_parent(&path)?;
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, &path)?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(MODE_PRIVATE);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("opening scope-key lock {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking scope-key lock {}", path.display()))?;
        Ok(StoreLock { _file: file })
    }

    fn corrupt(path: &Path, detail: impl Into<String>) -> anyhow::Error {
        refuse(ScopeKeyStoreError::RecordCorrupt {
            path: path.display().to_string(),
            detail: detail.into(),
        })
    }

    fn read_record(&self, namespace: &str, epoch: u32) -> Result<Option<ScopeKeyRecord>> {
        let path = self.record_path(namespace, epoch);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::corrupt(&path, format!("unreadable: {e}"))),
        };
        crate::identity::keypair::enforce_key_path_chain_secure(&self.key_dir, &path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .map_err(|e| Self::corrupt(&path, format!("unreadable metadata: {e}")))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(Self::corrupt(
                    &path,
                    format!(
                        "mode {:o} grants group/other access (expected 600)",
                        mode & 0o777
                    ),
                ));
            }
        }
        let record: ScopeKeyRecord = serde_json::from_slice(&bytes)
            .map_err(|e| Self::corrupt(&path, format!("malformed: {e}")))?;
        record
            .validate(namespace, epoch)
            .map_err(|detail| Self::corrupt(&path, detail))?;
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

    /// The epochs present on disk for `namespace`, ascending.
    fn epochs_on_disk(&self, namespace: &str) -> Result<Vec<u32>> {
        let dir = self.scope_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Self::corrupt(&dir, format!("unreadable directory: {e}"))),
        };
        let prefix = format!("{}{RECORD_INFIX}", Self::slug(namespace));
        let mut epochs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Self::corrupt(&dir, format!("directory entry: {e}")))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name
                .strip_prefix(&prefix)
                .and_then(|r| r.strip_suffix(RECORD_SUFFIX))
            else {
                continue;
            };
            let epoch: u32 = rest
                .parse()
                .map_err(|_| Self::corrupt(&entry.path(), "epoch in file name is not a number"))?;
            epochs.push(epoch);
        }
        epochs.sort_unstable();
        Ok(epochs)
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

    fn require_record(&self, namespace: &str, epoch: u32) -> Result<ScopeKeyRecord> {
        self.read_record(namespace, epoch)?.ok_or_else(|| {
            refuse(ScopeKeyStoreError::UnknownKey {
                namespace: namespace.to_string(),
                key: format!("epoch{epoch}"),
            })
        })
    }
}

impl ScopeKeyStore for FileScopeKeyStore {
    fn mint(&self, namespace: &str, readers: &[ReaderKek]) -> Result<MintOutcome> {
        Self::require_readers(namespace, readers)?;
        let _lock = self.lock()?;
        if let Some(current) = self.history(namespace)?.pop() {
            return Ok(MintOutcome::Existing(current));
        }
        let recovery = self.recovery_pubkey(namespace)?;
        let key_ref = ScopeKeyRef {
            key_id: ScopeKeyId::random(),
            epoch: 1,
        };
        let key = ScopeKey::generate(namespace, key_ref);
        let record = build_record(&key, readers, &recovery, now_rfc3339())?;
        self.write_record(&record)?;
        Ok(MintOutcome::Minted(record))
    }

    fn history(&self, namespace: &str) -> Result<Vec<ScopeKeyRecord>> {
        let epochs = self.epochs_on_disk(namespace)?;
        let mut records = Vec::with_capacity(epochs.len());
        for (index, epoch) in epochs.iter().enumerate() {
            let expected = u32::try_from(index + 1).ok();
            if expected != Some(*epoch) {
                return Err(Self::corrupt(
                    &self.record_path(namespace, *epoch),
                    format!(
                        "epochs are not dense from 1 (found {epoch} at position {})",
                        index + 1
                    ),
                ));
            }
            records.push(self.require_record(namespace, *epoch)?);
        }
        Ok(records)
    }

    fn load_epoch(&self, namespace: &str, epoch: u32) -> Result<Option<ScopeKeyRecord>> {
        self.read_record(namespace, epoch)
    }

    fn add_recipient(&self, key: &ScopeKey, reader: &ReaderKek) -> Result<RecipientChange> {
        let _lock = self.lock()?;
        let key_ref = key.key_ref();
        let mut record = self.require_record(key.namespace(), key_ref.epoch)?;
        record.verify_key_check(key)?;
        let fingerprint = reader.fingerprint();
        if record.is_reader(&fingerprint) {
            return Ok(RecipientChange::AlreadyPresent);
        }
        record.recipients.push(RecipientStanza {
            agent_id: reader.agent_id.clone(),
            kek_fingerprint: fingerprint,
            wrapped: wrap_scope_key(key, &reader.public)?,
        });
        self.write_record(&record)?;
        Ok(RecipientChange::Added)
    }

    fn remove_recipient(
        &self,
        namespace: &str,
        epoch: u32,
        kek_fingerprint: &str,
    ) -> Result<RecipientChange> {
        let _lock = self.lock()?;
        let mut record = self.require_record(namespace, epoch)?;
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
        self.write_record(&record)?;
        Ok(RecipientChange::Removed)
    }

    fn supersede(&self, namespace: &str, readers: &[ReaderKek]) -> Result<ScopeKeyRecord> {
        Self::require_readers(namespace, readers)?;
        let _lock = self.lock()?;
        let Some(mut current) = self.history(namespace)?.pop() else {
            return Err(refuse(ScopeKeyStoreError::UnknownKey {
                namespace: namespace.to_string(),
                key: "current".to_string(),
            }));
        };
        let recovery = self.recovery_pubkey(namespace)?;
        let epoch = current.epoch.checked_add(1).ok_or_else(|| {
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
        // New generation first: a crash between the two writes leaves the old
        // window open-ended, never a namespace with no current key.
        self.write_record(&next)?;
        current.superseded_at = Some(boundary);
        self.write_record(&current)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
