// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 (E1) — the `0x05` **scope envelope**: end-to-end federation content
//! encryption under a per-namespace scope key.
//!
//! Design: `docs/design/E2E_FEDERATION_ENCRYPTION.md` (3-agent vote
//! `6def5ab6`, decisions D1 and D2). The per-node at-rest schemes (`0x02`,
//! `0x03`) seal content to ONE node's X25519 key, so federation has to decrypt
//! and re-seal at the peer. A `0x05` row is sealed under a key shared by the
//! namespace's reader set instead, so the same bytes can travel peer to peer
//! and only a reader can open them.
//!
//! ## Wire shape (fixed-size header, then the inner ciphertext)
//!
//! ```text
//! version      1 byte   = 0x05
//! key_id      16 bytes  random id minted with the scope key
//! epoch        4 bytes  u32 big-endian, 1-based scope-key generation
//! wrap_salt   16 bytes  random per record; HKDF salt of the DEK-wrap key
//! wrap_nonce  12 bytes  ChaCha20-Poly1305 nonce of the DEK wrap
//! wrapped_dek 48 bytes  per-record DEK (32) + tag (16) under the wrap key
//! inner_nonce 12 bytes  ChaCha20-Poly1305 nonce of the content
//! inner_ct    >= 16     content ciphertext + tag under the DEK
//! ```
//!
//! The namespace is NOT in the header: the row's own `namespace` column is
//! the binding input, so a row moved to another namespace cannot open.
//!
//! ## Keys and binding
//!
//! * The DEK-wrap key is `HKDF-SHA256(salt = wrap_salt, ikm = scope key,
//!   info = DEK_WRAP_INFO || key_id || epoch)`: unique per record, so the
//!   random wrap nonces never share a key across records.
//! * Both AEAD operations authenticate the same binding string
//!   `version || key_id || epoch || len32(memory_id) || memory_id ||
//!   len32(namespace) || namespace || row_version`, prefixed by a one-byte
//!   role (DEK wrap or content). `row_version` is the row's optimistic
//!   concurrency counter (`Memory::version`, i64 big-endian). Swapping
//!   ciphertext between rows, renaming the namespace, editing the key id /
//!   epoch, or presenting an older envelope of the same row under a newer row
//!   version fails authentication.
//! * Every version-bumping write of a `0x05` row therefore re-seals it (the
//!   E2 writer path). The binding stops an old envelope being replayed under
//!   the current version; refusing a whole row rolled back to an older
//!   version needs the receiver's monotonic version compare (E2).
//! * The symmetric key gives confidentiality and row binding, not writer
//!   authenticity: any reader of the namespace can produce a valid envelope.
//!   Writer authenticity is record signing (E2), design section 2.
//!
//! ## Crypto-erase
//!
//! The DEK exists only inside `wrapped_dek`. Rewriting the column to the
//! `0x04` marker ([`super::crypto_erase_marker`]) destroys it, so holding the
//! scope key no longer recovers that record. Copies held elsewhere (peer
//! replicas, backups) are erased only where the erase is applied; the
//! federation path propagates it (E2 lane).

pub mod store;

use super::{AEAD_KEY_LEN, Keypair, NONCE_LEN, RECORD_DEK_LEN, TAG_LEN};
use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Leading byte of a scope envelope.
pub const SCOPE_ENVELOPE_VERSION: u8 = 0x05;
/// Length of a scope key id.
pub const SCOPE_KEY_ID_LEN: usize = 16;
/// Length of a scope key (a ChaCha20-Poly1305-sized secret).
pub const SCOPE_KEY_LEN: usize = AEAD_KEY_LEN;
/// Length of the big-endian epoch field.
const EPOCH_LEN: usize = 4;
/// Length of the per-record HKDF salt.
const WRAP_SALT_LEN: usize = 16;
/// Length of the wrapped DEK (DEK plus AEAD tag).
const WRAPPED_DEK_LEN: usize = RECORD_DEK_LEN + TAG_LEN;

const OFF_KEY_ID: usize = 1;
const OFF_EPOCH: usize = OFF_KEY_ID + SCOPE_KEY_ID_LEN;
const OFF_SALT: usize = OFF_EPOCH + EPOCH_LEN;
const OFF_WRAP_NONCE: usize = OFF_SALT + WRAP_SALT_LEN;
const OFF_WRAPPED: usize = OFF_WRAP_NONCE + NONCE_LEN;
const OFF_INNER_NONCE: usize = OFF_WRAPPED + WRAPPED_DEK_LEN;

/// Length of the fixed header (everything before the inner ciphertext).
pub const SCOPE_HEADER_LEN: usize = OFF_INNER_NONCE + NONCE_LEN;
/// Shortest well-formed scope envelope (header plus an empty content's tag).
pub const SCOPE_ENVELOPE_MIN_LEN: usize = SCOPE_HEADER_LEN + TAG_LEN;

/// HKDF `info` label of the per-record DEK-wrap key (domain separation from
/// the `0x02` content key and the scope-key check value).
const DEK_WRAP_INFO: &[u8] = b"ai-memory/v1.0.0/e2e-scope/dek-wrap-key/v5";
/// AAD role byte of the DEK wrap.
const AAD_ROLE_DEK_WRAP: u8 = 0x01;
/// AAD role byte of the content AEAD.
const AAD_ROLE_CONTENT: u8 = 0x02;

/// Issue tag carried by the typed errors of this module.
pub const ISSUE_TAG: &str = "#8278";

/// A scope key's random 128-bit id. Random rather than derived from the
/// namespace so two nodes that mint concurrently for one namespace produce
/// distinguishable keys (the divergence is detectable, never silent).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ScopeKeyId(pub [u8; SCOPE_KEY_ID_LEN]);

impl ScopeKeyId {
    /// A fresh random id.
    #[must_use]
    pub fn random() -> Self {
        Self(random_array())
    }

    /// Lower-case hex rendering (32 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse the hex rendering.
    ///
    /// # Errors
    /// The text is not exactly 32 hex characters.
    pub fn from_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text).map_err(|e| anyhow!("scope key id is not hex: {e}"))?;
        let id: [u8; SCOPE_KEY_ID_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow!(
                "scope key id has {} bytes, expected {SCOPE_KEY_ID_LEN}",
                v.len()
            )
        })?;
        Ok(Self(id))
    }
}

impl std::fmt::Display for ScopeKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The key a `0x05` envelope names: id plus epoch.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ScopeKeyRef {
    /// The scope key id.
    pub key_id: ScopeKeyId,
    /// The 1-based scope-key generation of the namespace.
    pub epoch: u32,
}

impl std::fmt::Display for ScopeKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@epoch{}", self.key_id, self.epoch)
    }
}

/// An unwrapped scope key. The secret is zeroized on drop; the type is not
/// `Clone` so a copy is never made by accident, and `Debug` redacts it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ScopeKey {
    #[zeroize(skip)]
    namespace: String,
    #[zeroize(skip)]
    key_ref: ScopeKeyRef,
    secret: [u8; SCOPE_KEY_LEN],
}

impl ScopeKey {
    /// Mint a fresh random scope key for `namespace` at `key_ref`.
    pub(crate) fn generate(namespace: &str, key_ref: ScopeKeyRef) -> Self {
        Self {
            namespace: namespace.to_string(),
            key_ref,
            secret: random_array(),
        }
    }

    /// Rebuild a key from unwrapped material. The caller zeroizes its own
    /// copy of `secret` (arrays are `Copy`).
    pub(crate) fn from_parts(
        namespace: &str,
        key_ref: ScopeKeyRef,
        secret: [u8; SCOPE_KEY_LEN],
    ) -> Self {
        Self {
            namespace: namespace.to_string(),
            key_ref,
            secret,
        }
    }

    /// The namespace this key seals.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The id and epoch of this key.
    #[must_use]
    pub fn key_ref(&self) -> ScopeKeyRef {
        self.key_ref
    }

    /// The secret bytes, for wrapping and sealing inside this module tree.
    pub(crate) fn secret_bytes(&self) -> &[u8; SCOPE_KEY_LEN] {
        &self.secret
    }
}

impl std::fmt::Debug for ScopeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeKey")
            .field("namespace", &self.namespace)
            .field("key_ref", &self.key_ref)
            .field("secret", &crate::REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// The row identity a `0x05` envelope is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordBinding<'a> {
    /// The memory row id.
    pub memory_id: &'a str,
    /// The memory row namespace.
    pub namespace: &'a str,
    /// The row version the envelope was sealed at (`Memory::version`, the
    /// optimistic-concurrency counter every mutation bumps).
    pub row_version: i64,
}

impl<'a> RecordBinding<'a> {
    /// The binding of row `memory_id` in `namespace` at `row_version`.
    #[must_use]
    pub fn new(memory_id: &'a str, namespace: &'a str, row_version: i64) -> Self {
        Self {
            memory_id,
            namespace,
            row_version,
        }
    }
}

/// Typed failures of the `0x05` envelope. Every one is a refusal: nothing
/// opens, nothing is substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeEnvelopeError {
    /// The buffer is shorter than the fixed header plus one tag.
    Truncated {
        /// Bytes present.
        len: usize,
        /// Bytes required.
        need: usize,
    },
    /// The leading byte is not [`SCOPE_ENVELOPE_VERSION`].
    WrongVersion {
        /// The byte found.
        got: u8,
    },
    /// A `0x05` row reached a reader that did not supply the row identity
    /// (memory id and namespace) the envelope is bound to.
    BindingRequired,
    /// A memory id or namespace too long to length-prefix.
    BindingTooLong,
    /// The envelope names a different key than the one supplied.
    KeyMismatch {
        /// Key named by the envelope header.
        envelope: ScopeKeyRef,
        /// Key supplied by the caller.
        key: ScopeKeyRef,
    },
    /// The row namespace is not the namespace of the supplied key.
    NamespaceMismatch {
        /// Namespace of the row.
        row: String,
        /// Namespace of the key.
        key: String,
    },
    /// AEAD authentication failed (tampered bytes, wrong binding, wrong key).
    Authentication,
    /// The unwrapped DEK has the wrong length.
    DekLength,
    /// The plaintext is not UTF-8.
    NotUtf8,
}

impl ScopeEnvelopeError {
    /// Stable class name for logs and metrics.
    pub const CLASS: &'static str = "scope_envelope_refused";
}

impl std::fmt::Display for ScopeEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { len, need } => write!(
                f,
                "{ISSUE_TAG}: scope envelope too short: {len} bytes, need at least {need}"
            ),
            Self::WrongVersion { got } => write!(
                f,
                "{ISSUE_TAG}: not a scope envelope: version 0x{got:02x}, expected \
                 0x{SCOPE_ENVELOPE_VERSION:02x}"
            ),
            Self::BindingRequired => write!(
                f,
                "{ISSUE_TAG}: scope envelope (0x05) is bound to its memory id and namespace; this \
                 read path did not supply them, so the row stays sealed"
            ),
            Self::BindingTooLong => write!(
                f,
                "{ISSUE_TAG}: memory id or namespace too long to bind into a scope envelope"
            ),
            Self::KeyMismatch { envelope, key } => write!(
                f,
                "{ISSUE_TAG}: scope envelope names key {envelope}, the supplied key is {key}"
            ),
            Self::NamespaceMismatch { row, key } => write!(
                f,
                "{ISSUE_TAG}: row namespace {row:?} is not the scope key namespace {key:?}"
            ),
            Self::Authentication => write!(
                f,
                "{ISSUE_TAG}: scope envelope failed authentication (tampered, moved to another \
                 row or namespace, or the wrong key)"
            ),
            Self::DekLength => write!(f, "{ISSUE_TAG}: unwrapped record key has the wrong length"),
            Self::NotUtf8 => write!(f, "{ISSUE_TAG}: scope envelope plaintext is not UTF-8"),
        }
    }
}

impl std::error::Error for ScopeEnvelopeError {}

/// Downcast an error chain to [`ScopeEnvelopeError`].
#[must_use]
pub fn scope_envelope_error(err: &anyhow::Error) -> Option<&ScopeEnvelopeError> {
    err.downcast_ref::<ScopeEnvelopeError>()
}

fn refuse(err: ScopeEnvelopeError) -> anyhow::Error {
    anyhow::Error::new(err)
}

/// `N` bytes from the OS CSPRNG, built element by element from 64-bit draws
/// so no constant-initialised buffer ever reaches a key, nonce or salt.
fn random_array<const N: usize>() -> [u8; N] {
    let mut draws = std::iter::repeat_with(|| OsRng.next_u64().to_le_bytes()).flatten();
    std::array::from_fn(|_| draws.next().unwrap_or_default())
}

/// The per-record random inputs of one seal. Zeroized on drop: the DEK is
/// secret and the rest is no longer needed once the envelope is written.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SealMaterial {
    salt: [u8; WRAP_SALT_LEN],
    wrap_nonce: [u8; NONCE_LEN],
    inner_nonce: [u8; NONCE_LEN],
    dek: [u8; RECORD_DEK_LEN],
}

impl SealMaterial {
    fn random() -> Self {
        Self {
            salt: random_array(),
            wrap_nonce: random_array(),
            inner_nonce: random_array(),
            dek: random_array(),
        }
    }
}

/// Read the key reference out of a `0x05` header (version and length are
/// checked; nothing is authenticated yet).
///
/// # Errors
/// [`ScopeEnvelopeError::WrongVersion`] or [`ScopeEnvelopeError::Truncated`].
pub fn parse_scope_header(envelope: &[u8]) -> Result<ScopeKeyRef> {
    match envelope.first() {
        Some(&SCOPE_ENVELOPE_VERSION) => {}
        Some(&got) => return Err(refuse(ScopeEnvelopeError::WrongVersion { got })),
        None => {
            return Err(refuse(ScopeEnvelopeError::Truncated {
                len: 0,
                need: SCOPE_ENVELOPE_MIN_LEN,
            }));
        }
    }
    if envelope.len() < SCOPE_ENVELOPE_MIN_LEN {
        return Err(refuse(ScopeEnvelopeError::Truncated {
            len: envelope.len(),
            need: SCOPE_ENVELOPE_MIN_LEN,
        }));
    }
    let truncated = |_| {
        refuse(ScopeEnvelopeError::Truncated {
            len: envelope.len(),
            need: SCOPE_ENVELOPE_MIN_LEN,
        })
    };
    let id: [u8; SCOPE_KEY_ID_LEN] = envelope[OFF_KEY_ID..OFF_EPOCH]
        .try_into()
        .map_err(truncated)?;
    let epoch: [u8; EPOCH_LEN] = envelope[OFF_EPOCH..OFF_SALT]
        .try_into()
        .map_err(truncated)?;
    Ok(ScopeKeyRef {
        key_id: ScopeKeyId(id),
        epoch: u32::from_be_bytes(epoch),
    })
}

fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len = u32::try_from(field.len()).map_err(|_| refuse(ScopeEnvelopeError::BindingTooLong))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Length of the big-endian row-version field of the binding.
const ROW_VERSION_LEN: usize = 8;

/// The AAD of one AEAD operation: role byte, then the binding string.
fn binding_aad(role: u8, key_ref: ScopeKeyRef, binding: RecordBinding<'_>) -> Result<Vec<u8>> {
    let mut aad = Vec::with_capacity(
        2 + SCOPE_KEY_ID_LEN
            + EPOCH_LEN
            + 8
            + binding.memory_id.len()
            + binding.namespace.len()
            + ROW_VERSION_LEN,
    );
    aad.push(role);
    aad.push(SCOPE_ENVELOPE_VERSION);
    aad.extend_from_slice(&key_ref.key_id.0);
    aad.extend_from_slice(&key_ref.epoch.to_be_bytes());
    push_len_prefixed(&mut aad, binding.memory_id.as_bytes())?;
    push_len_prefixed(&mut aad, binding.namespace.as_bytes())?;
    aad.extend_from_slice(&binding.row_version.to_be_bytes());
    Ok(aad)
}

/// The per-record DEK-wrap key, expanded straight into the cipher key type.
/// The caller zeroizes the result.
fn derive_wrap_key(secret: &[u8; SCOPE_KEY_LEN], salt: &[u8], key_ref: ScopeKeyRef) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut info = Vec::with_capacity(DEK_WRAP_INFO.len() + SCOPE_KEY_ID_LEN + EPOCH_LEN);
    info.extend_from_slice(DEK_WRAP_INFO);
    info.extend_from_slice(&key_ref.key_id.0);
    info.extend_from_slice(&key_ref.epoch.to_be_bytes());
    let mut okm = Key::default();
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|e| anyhow!("HKDF expand of the scope DEK-wrap key failed: {e}"))?;
    Ok(okm)
}

/// Seal `content` for the row `binding` under `key`.
///
/// # Errors
/// [`ScopeEnvelopeError::NamespaceMismatch`] when the row is not in the key's
/// namespace, [`ScopeEnvelopeError::BindingTooLong`], or an AEAD failure.
pub fn seal_scoped(content: &str, key: &ScopeKey, binding: RecordBinding<'_>) -> Result<Vec<u8>> {
    seal_with_material(content, key, binding, &SealMaterial::random())
}

/// The deterministic core of [`seal_scoped`]: every random input comes from
/// `material`, so the known-answer test can pin the exact bytes.
fn seal_with_material(
    content: &str,
    key: &ScopeKey,
    binding: RecordBinding<'_>,
    material: &SealMaterial,
) -> Result<Vec<u8>> {
    if binding.namespace != key.namespace() {
        return Err(refuse(ScopeEnvelopeError::NamespaceMismatch {
            row: binding.namespace.to_string(),
            key: key.namespace().to_string(),
        }));
    }
    let key_ref = key.key_ref();
    let wrap_aad = binding_aad(AAD_ROLE_DEK_WRAP, key_ref, binding)?;
    let content_aad = binding_aad(AAD_ROLE_CONTENT, key_ref, binding)?;

    let mut wrap_key = derive_wrap_key(key.secret_bytes(), &material.salt, key_ref)?;
    let wrap_cipher = ChaCha20Poly1305::new(&wrap_key);
    wrap_key.as_mut_slice().zeroize();
    let wrapped = wrap_cipher.encrypt(
        Nonce::from_slice(&material.wrap_nonce),
        Payload {
            msg: &material.dek,
            aad: &wrap_aad,
        },
    );
    let content_cipher = ChaCha20Poly1305::new(Key::from_slice(&material.dek));
    let wrapped = wrapped.map_err(|e| anyhow!("scope DEK wrap failed: {e}"))?;
    if wrapped.len() != WRAPPED_DEK_LEN {
        return Err(refuse(ScopeEnvelopeError::DekLength));
    }
    let inner_ct = content_cipher
        .encrypt(
            Nonce::from_slice(&material.inner_nonce),
            Payload {
                msg: content.as_bytes(),
                aad: &content_aad,
            },
        )
        .map_err(|e| anyhow!("scope content encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(SCOPE_HEADER_LEN + inner_ct.len());
    out.push(SCOPE_ENVELOPE_VERSION);
    out.extend_from_slice(&key_ref.key_id.0);
    out.extend_from_slice(&key_ref.epoch.to_be_bytes());
    out.extend_from_slice(&material.salt);
    out.extend_from_slice(&material.wrap_nonce);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&material.inner_nonce);
    out.extend_from_slice(&inner_ct);
    Ok(out)
}

/// Open a `0x05` envelope for the row `binding` with `key`.
///
/// # Errors
/// Any [`ScopeEnvelopeError`]: the header names another key, the row is not
/// in the key's namespace, or authentication fails.
pub fn open_scoped(envelope: &[u8], key: &ScopeKey, binding: RecordBinding<'_>) -> Result<String> {
    let named = parse_scope_header(envelope)?;
    if named != key.key_ref() {
        return Err(refuse(ScopeEnvelopeError::KeyMismatch {
            envelope: named,
            key: key.key_ref(),
        }));
    }
    if binding.namespace != key.namespace() {
        return Err(refuse(ScopeEnvelopeError::NamespaceMismatch {
            row: binding.namespace.to_string(),
            key: key.namespace().to_string(),
        }));
    }
    open_with_secret(envelope, key.secret_bytes(), binding)
}

/// The cryptographic core of [`open_scoped`]: no key-identity pre-checks, so
/// the tests can prove the AEAD binding alone refuses a moved row.
fn open_with_secret(
    envelope: &[u8],
    secret: &[u8; SCOPE_KEY_LEN],
    binding: RecordBinding<'_>,
) -> Result<String> {
    let key_ref = parse_scope_header(envelope)?;
    let wrap_aad = binding_aad(AAD_ROLE_DEK_WRAP, key_ref, binding)?;
    let content_aad = binding_aad(AAD_ROLE_CONTENT, key_ref, binding)?;
    let salt = &envelope[OFF_SALT..OFF_WRAP_NONCE];
    let wrap_nonce = &envelope[OFF_WRAP_NONCE..OFF_WRAPPED];
    let wrapped = &envelope[OFF_WRAPPED..OFF_INNER_NONCE];
    let inner_nonce = &envelope[OFF_INNER_NONCE..SCOPE_HEADER_LEN];
    let inner_ct = &envelope[SCOPE_HEADER_LEN..];

    let mut wrap_key = derive_wrap_key(secret, salt, key_ref)?;
    let wrap_cipher = ChaCha20Poly1305::new(&wrap_key);
    wrap_key.as_mut_slice().zeroize();
    let mut dek = wrap_cipher
        .decrypt(
            Nonce::from_slice(wrap_nonce),
            Payload {
                msg: wrapped,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| refuse(ScopeEnvelopeError::Authentication))?;
    if dek.len() != RECORD_DEK_LEN {
        dek.zeroize();
        return Err(refuse(ScopeEnvelopeError::DekLength));
    }
    let content_cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    dek.zeroize();
    let plaintext = content_cipher
        .decrypt(
            Nonce::from_slice(inner_nonce),
            Payload {
                msg: inner_ct,
                aad: &content_aad,
            },
        )
        .map_err(|_| refuse(ScopeEnvelopeError::Authentication))?;
    String::from_utf8(plaintext).map_err(|e| {
        // The bytes decrypted fine: they are plaintext and must not linger.
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        refuse(ScopeEnvelopeError::NotUtf8)
    })
}

/// Open a `0x05` envelope as `reader`: look the named key up in `store`,
/// unwrap the reader's stanza with its KEK, then open.
///
/// # Errors
/// The key is unknown to the store (typed
/// [`store::ScopeKeyStoreError::UnknownKey`]), `reader` holds no stanza for
/// it, the stanza does not unwrap, or [`open_scoped`] refuses.
pub fn open_content_scoped_in(
    envelope: &[u8],
    reader: &Keypair,
    store: &dyn store::ScopeKeyStore,
    binding: RecordBinding<'_>,
) -> Result<String> {
    let named = parse_scope_header(envelope)?;
    let record = store
        .load_by_key_id(binding.namespace, &named)?
        .ok_or_else(|| store::unknown_scope_key(binding.namespace, named))?;
    let key = record.unwrap_for(reader)?;
    open_scoped(envelope, &key, binding)
}

/// [`open_content_scoped_in`] for `agent_id`'s on-disk KEK and the file store
/// under the resolved key directory. A read never mints anything.
///
/// # Errors
/// The agent's key is absent (typed [`super::KeyAbsent`]) or
/// [`open_content_scoped_in`] refuses.
pub fn open_content_scoped(
    envelope: &[u8],
    agent_id: &str,
    binding: RecordBinding<'_>,
) -> Result<String> {
    let reader = super::load_keypair(agent_id)?.ok_or_else(|| super::key_absent_error(agent_id))?;
    let store = store::FileScopeKeyStore::open(super::keypair_persist_dir()?, agent_id)?;
    open_content_scoped_in(envelope, &reader, &store, binding)
}

#[cfg(test)]
mod tests;
