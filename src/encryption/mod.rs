// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 (issue #228) — E2E memory content encryption at rest.
//!
//! This module is the substrate primitive for end-to-end encryption of
//! memory `content` columns at rest. It pairs a per-agent X25519 ECDH
//! keypair with ChaCha20-Poly1305 AEAD encryption so a single recipient
//! (an agent identified by `agent_id`) can decrypt content encrypted to
//! its public key.
//!
//! ## Wire shape
//!
//! Each encrypted payload is serialised as a self-describing [`Envelope`]
//! and persisted into the new `memories.encrypted_envelope` BLOB column
//! (schema v44). The envelope layout is the byte concatenation of:
//!
//! ```text
//! version (1 byte = 0x02)
//! ephemeral_pub (32 bytes — X25519 sender ephemeral pubkey)
//! nonce (12 bytes — ChaCha20-Poly1305 nonce, random)
//! ciphertext_with_tag (variable — AEAD ciphertext + 16-byte tag)
//! ```
//!
//! The recipient's static X25519 secret key (per-agent, generated and
//! cached via [`get_or_create_keypair`]) plus the envelope's ephemeral
//! pubkey produce the shared secret. That secret is **not** used directly
//! as the symmetric key — H3 runs it through HKDF-SHA256 (domain-separated
//! by [`HKDF_INFO`]) to derive the ChaCha20-Poly1305 key, and binds the
//! envelope version + ephemeral pubkey into the AEAD associated data (AAD)
//! so the header cannot be swapped without failing authentication. Derived
//! key material is zeroized immediately after the cipher is constructed.
//!
//! ## Key lifecycle
//!
//! Each per-agent X25519 keypair is **persisted to disk** under the
//! resolved key directory ([`crate::identity::keypair::default_key_dir`],
//! honoring `AI_MEMORY_KEY_DIR`) as `<agent_id>.x25519.pub` (mode 0644)
//! and `<agent_id>.x25519.priv` (mode 0600), mirroring the Ed25519
//! signing keystore. [`get_or_create_keypair`] is therefore
//! cache → load-from-disk → generate-and-save: the in-memory cache is a
//! hot path, NOT the source of truth. This is load-bearing for at-rest
//! encryption — without on-disk persistence a daemon restart would clear
//! the cache and mint a fresh key, leaving every previously-encrypted
//! `encrypted_envelope` permanently undecryptable (silent data loss).
//! On Unix the `.priv` is refused at load time if its mode grants any
//! group/other access (`mode & 0o077 != 0`), matching the keystore's
//! S4-LOW1 guard.
//!
//! ## Activation
//!
//! Callers gate at-rest encryption behind either:
//!
//! * The `[encryption].at_rest = true` config field (operator opt-in
//!   via `config.toml`), OR
//! * The `AI_MEMORY_ENCRYPT_AT_REST=1` environment variable (CLI /
//!   container-runtime opt-in).
//!
//! Both surfaces feed the same [`encryption_enabled`] gate, which the
//! storage write path consults before invoking [`encrypt`] / [`decrypt`].

use anyhow::{Context, Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

/// Envelope wire-version. Bumped when the byte layout OR the
/// cryptographic scheme (KDF / AAD construction) changes; readers refuse
/// unknown versions with a typed error so a bump doesn't silently
/// mis-parse or mis-decrypt legacy rows. `0x02` introduced the H3
/// HKDF-SHA256 key derivation + AAD header binding (the `0x01` MVP used
/// the raw X25519 output directly with empty AAD).
pub const ENVELOPE_VERSION: u8 = 0x02;

/// X25519 pubkey length in bytes.
pub const PUBKEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 AEAD tag length in bytes (appended to ciphertext
/// by `Aead::encrypt`).
pub const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 key length in bytes, and therefore the HKDF output
/// length the [`derive_aead_key`] expand step produces.
pub const AEAD_KEY_LEN: usize = 32;

/// HKDF `info` (domain-separation label) for deriving the AEAD key from
/// the X25519 shared secret. Encodes the crate, scheme version, and use
/// so the same shared secret would derive a different key under any other
/// label — preventing cross-protocol key reuse. Tied to the `0x02`
/// envelope scheme; a future scheme bump rotates this label too.
const HKDF_INFO: &[u8] = b"ai-memory/v0.7.0/e2e-content/chacha20poly1305-key/v2";

/// Per-agent X25519 keypair. The static-secret variant supports cloning
/// so the per-process cache can hand out copies without re-deriving
/// from the random generator.
#[derive(Clone)]
pub struct Keypair {
    pub agent_id: String,
    pub public: PublicKey,
    pub secret: StaticSecret,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret material.
        f.debug_struct("Keypair")
            .field("agent_id", &self.agent_id)
            .field("public", &"<x25519 pubkey>")
            .field("secret", &crate::REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// Decrypt-able envelope produced by [`encrypt`]. Carries the sender's
/// ephemeral X25519 pubkey + the AEAD nonce + the ciphertext-with-tag.
/// [`Envelope::to_bytes`] / [`Envelope::from_bytes`] handle the
/// substrate-stable wire shape; storage callers persist the bytes
/// verbatim into the `encrypted_envelope` column.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub ephemeral_pub: [u8; PUBKEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Serialise the envelope to its on-disk byte layout. See module
    /// docs for the layout. Length = 1 + 32 + 12 + ciphertext.len().
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + PUBKEY_LEN + NONCE_LEN + self.ciphertext.len());
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.ephemeral_pub);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse the envelope back out of its on-disk byte layout. Refuses
    /// unknown versions and truncated buffers with a typed error so a
    /// corrupted row surfaces cleanly instead of decrypting garbage.
    ///
    /// # Errors
    /// * Returns `Err` when the buffer is too short to contain the
    ///   fixed header (version + ephemeral_pub + nonce) plus at least
    ///   one byte of ciphertext-with-tag.
    /// * Returns `Err` when the leading version byte is not
    ///   [`ENVELOPE_VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let header_len = 1 + PUBKEY_LEN + NONCE_LEN;
        if bytes.len() < header_len + TAG_LEN {
            return Err(anyhow!(
                "envelope buffer too short: got {} bytes, need at least {}",
                bytes.len(),
                header_len + TAG_LEN
            ));
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(anyhow!(
                "unknown envelope version: got 0x{:02x}, expected 0x{:02x}",
                bytes[0],
                ENVELOPE_VERSION
            ));
        }
        let mut ephemeral_pub = [0u8; PUBKEY_LEN];
        ephemeral_pub.copy_from_slice(&bytes[1..1 + PUBKEY_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + PUBKEY_LEN..header_len]);
        let ciphertext = bytes[header_len..].to_vec();
        Ok(Envelope {
            ephemeral_pub,
            nonce,
            ciphertext,
        })
    }
}

/// Process-wide cache of per-agent X25519 keypairs. The cache is
/// populated lazily on first [`get_or_create_keypair`] call for each
/// `agent_id` and persists for the lifetime of the process. A future
/// issue will swap this for an on-disk store; the in-memory shape lets
/// the encryption substrate land without forcing a key-rotation tool
/// design decision in the same patch.
///
/// v0.7.x (issue #1174 follow-up #1196) — the cache lives on
/// [`crate::runtime_context::RuntimeContext::keypair_cache`]. The
/// returned `&'static` reference is stable because
/// `RuntimeContext::global()` itself is a `OnceLock`-backed
/// process-wide singleton; the `Arc<Mutex<HashMap<...>>>` inside it
/// is allocated once and outlives every caller.
fn keypair_cache() -> &'static Mutex<HashMap<String, Keypair>> {
    &crate::runtime_context::RuntimeContext::global().keypair_cache
}

/// On-disk filename suffix for the X25519 PUBLIC key (mode 0644).
/// Distinct from the Ed25519 keystore's `.pub` so the two key systems
/// never collide for the same `agent_id`.
const X25519_PUB_SUFFIX: &str = ".x25519.pub";
/// On-disk filename suffix for the X25519 SECRET key (mode 0600).
const X25519_PRIV_SUFFIX: &str = ".x25519.priv";
/// X25519 secret/public key length in bytes (both are 32).
const X25519_KEY_LEN: usize = 32;

/// Resolve the directory used to persist per-agent X25519 keypairs.
/// Production resolves the platform key directory (honoring
/// `AI_MEMORY_KEY_DIR`); test builds use a process-wide ephemeral
/// tempdir so the unit suite never reads or writes the real key store.
#[cfg(not(test))]
fn keypair_persist_dir() -> Result<PathBuf> {
    crate::identity::keypair::default_key_dir()
}

#[cfg(test)]
fn keypair_persist_dir() -> Result<PathBuf> {
    use std::sync::OnceLock;
    static TEST_KEY_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    Ok(TEST_KEY_DIR
        .get_or_init(|| tempfile::tempdir().expect("create ephemeral x25519 test key dir"))
        .path()
        .to_path_buf())
}

/// `(pub_path, priv_path)` for `agent_id` under `dir`.
fn x25519_key_paths(agent_id: &str, dir: &Path) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{agent_id}{X25519_PUB_SUFFIX}")),
        dir.join(format!("{agent_id}{X25519_PRIV_SUFFIX}")),
    )
}

/// Persist `kp` to `dir`: the public key at mode 0644 and the secret at
/// mode 0600 (Unix), reusing the Ed25519 keystore's mode-aware writer.
fn save_keypair_to_disk(kp: &Keypair, dir: &Path) -> Result<()> {
    let (pub_path, priv_path) = x25519_key_paths(&kp.agent_id, dir);
    crate::identity::keypair::ensure_parent(&pub_path)?;
    crate::identity::keypair::ensure_parent(&priv_path)?;
    crate::identity::keypair::write_with_mode(&pub_path, kp.public.as_bytes(), 0o644)
        .with_context(|| format!("writing x25519 public key {}", pub_path.display()))?;
    let mut secret_bytes = kp.secret.to_bytes();
    let write_res = crate::identity::keypair::write_with_mode(&priv_path, &secret_bytes, 0o600)
        .with_context(|| format!("writing x25519 private key {}", priv_path.display()));
    secret_bytes.zeroize();
    write_res
}

/// Load `agent_id`'s X25519 keypair from `dir`. Returns `Ok(None)` when
/// no `.x25519.priv` exists yet (first run for this agent). On Unix a
/// `.priv` whose mode grants group/other access is refused (mirrors the
/// Ed25519 keystore's S4-LOW1 load-time guard) rather than silently used.
fn load_keypair_from_disk(agent_id: &str, dir: &Path) -> Result<Option<Keypair>> {
    let (_pub_path, priv_path) = x25519_key_paths(agent_id, dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(&priv_path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(anyhow!(
                        "x25519 private key {} has insecure mode {mode:o}; refusing to load. \
                         Restore with: chmod 0600 {}",
                        priv_path.display(),
                        priv_path.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow!(e))
                    .with_context(|| format!("stat x25519 private key {}", priv_path.display()));
            }
        }
    }

    let mut priv_bytes = match fs::read(&priv_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow!(e))
                .with_context(|| format!("reading x25519 private key {}", priv_path.display()));
        }
    };
    if priv_bytes.len() != X25519_KEY_LEN {
        let actual = priv_bytes.len();
        priv_bytes.zeroize();
        return Err(anyhow!(
            "x25519 private key {} has {actual} bytes, expected {X25519_KEY_LEN}",
            priv_path.display()
        ));
    }
    let mut arr = [0u8; X25519_KEY_LEN];
    arr.copy_from_slice(&priv_bytes);
    priv_bytes.zeroize();
    let secret = StaticSecret::from(arr);
    arr.zeroize();
    // Derive the public key from the secret so a tampered/stale `.pub`
    // file can never desynchronize the pair.
    let public = PublicKey::from(&secret);
    Ok(Some(Keypair {
        agent_id: agent_id.to_string(),
        public,
        secret,
    }))
}

/// Look up the per-agent X25519 [`Keypair`], resolving it from (in order)
/// the in-memory cache, the on-disk keystore, or a freshly-generated and
/// persisted pair. See the module-level "Key lifecycle" note: disk
/// persistence is load-bearing so encrypted rows survive a restart.
///
/// # Errors
/// * The keypair cache mutex is poisoned (process-fatal).
/// * The key directory cannot be resolved, or a disk read/write fails
///   (fail-closed: the caller must NOT fall back to an unpersisted key).
pub fn get_or_create_keypair(agent_id: &str) -> Result<Keypair> {
    let dir =
        keypair_persist_dir().context("resolving the key directory for x25519 keypair storage")?;
    get_or_create_keypair_in(agent_id, &dir)
}

/// Directory-explicit core of [`get_or_create_keypair`]. Holds the cache
/// lock across the load/generate/save so two threads racing on the same
/// fresh `agent_id` cannot persist divergent keys.
pub(crate) fn get_or_create_keypair_in(agent_id: &str, dir: &Path) -> Result<Keypair> {
    let cache = keypair_cache();
    let mut guard = cache
        .lock()
        .map_err(|e| anyhow!("encryption keypair cache mutex poisoned: {e}"))?;
    if let Some(kp) = guard.get(agent_id) {
        return Ok(kp.clone());
    }
    // Cache miss — prefer a persisted keypair so ciphertext written before
    // a restart stays decryptable. Only mint + persist when none exists.
    if let Some(kp) = load_keypair_from_disk(agent_id, dir)? {
        guard.insert(agent_id.to_string(), kp.clone());
        return Ok(kp);
    }
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let kp = Keypair {
        agent_id: agent_id.to_string(),
        public,
        secret,
    };
    save_keypair_to_disk(&kp, dir)?;
    guard.insert(agent_id.to_string(), kp.clone());
    Ok(kp)
}

/// H3 — derive the ChaCha20-Poly1305 key from the raw X25519 shared
/// secret via HKDF-SHA256.
///
/// Raw ECDH output is a curve point's `u`-coordinate, not a uniformly
/// distributed symmetric key. HKDF (extract-then-expand) conditions it
/// into a clean [`AEAD_KEY_LEN`]-byte key and, via the [`HKDF_INFO`]
/// domain-separation label, isolates this key space from any other use
/// of the same shared secret. Salt is `None` (the empty/all-zero salt) —
/// standard for ECDH-derived keys where there is no pre-shared random
/// salt; binding context lives in `info` (here) and the AEAD AAD.
///
/// The returned array must be zeroized by the caller once the cipher has
/// been constructed.
fn derive_aead_key(shared: &SharedSecret) -> [u8; AEAD_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; AEAD_KEY_LEN];
    // `expand` only errors when the requested length exceeds 255*HashLen
    // (255*32 = 8160 bytes); AEAD_KEY_LEN is far below that bound, so this
    // is infallible by construction.
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF expand of AEAD_KEY_LEN bytes is within the 255*HashLen limit");
    okm
}

/// H3 — associated data bound into every AEAD operation: the envelope
/// version followed by the sender's ephemeral pubkey. Authenticating
/// these header fields means an attacker cannot downgrade the version or
/// substitute a different ephemeral key without failing the AEAD tag
/// check. Both [`encrypt`] and [`decrypt`] construct the AAD identically
/// from the same fields, so a well-formed envelope always verifies.
fn envelope_aad(ephemeral_pub: &[u8; PUBKEY_LEN]) -> [u8; 1 + PUBKEY_LEN] {
    let mut aad = [0u8; 1 + PUBKEY_LEN];
    aad[0] = ENVELOPE_VERSION;
    aad[1..].copy_from_slice(ephemeral_pub);
    aad
}

/// Encrypt `content` to the given recipient X25519 public key, returning
/// a self-describing [`Envelope`].
///
/// The sender generates an ephemeral X25519 secret on every call; the
/// matching ephemeral public key is included in the envelope so the
/// recipient can derive the same shared secret. H3: the shared secret is
/// run through HKDF-SHA256 ([`derive_aead_key`]) to produce the AEAD key
/// — never used raw — and the envelope version + ephemeral pubkey are
/// bound into the AEAD associated data ([`envelope_aad`]). The derived
/// key is zeroized immediately after the cipher is built.
///
/// # Errors
/// * Returns `Err` when the underlying AEAD encrypt call fails (should
///   not happen in practice for in-memory inputs of any size; rusqlite
///   already bounds content length).
pub fn encrypt(content: &str, recipient_pk: &PublicKey) -> Result<Envelope> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_pk);

    let mut okm = derive_aead_key(&shared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&okm));
    okm.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ephemeral_pub = ephemeral_public.to_bytes();
    let aad = envelope_aad(&ephemeral_pub);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: content.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("ChaCha20-Poly1305 encrypt failed: {e}"))?;

    Ok(Envelope {
        ephemeral_pub,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an [`Envelope`] using the recipient's static X25519 secret
/// key (`my_sk`). Returns the original UTF-8 plaintext.
///
/// Mirrors [`encrypt`]: derives the AEAD key from the shared secret via
/// HKDF-SHA256 and reconstructs the same version+ephemeral-pubkey AAD, so
/// any header tampering surfaces as an authentication failure.
///
/// # Errors
/// * Returns `Err` when the AEAD verification fails (tampered
///   ciphertext, swapped header, wrong recipient key, truncated nonce,
///   etc.).
/// * Returns `Err` when the decrypted bytes are not valid UTF-8 — the
///   write path always feeds `&str`, so a UTF-8 failure on read is a
///   corruption signal.
pub fn decrypt(envelope: &Envelope, my_sk: &StaticSecret) -> Result<String> {
    let ephemeral_public = PublicKey::from(envelope.ephemeral_pub);
    let shared = my_sk.diffie_hellman(&ephemeral_public);

    let mut okm = derive_aead_key(&shared);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&okm));
    okm.zeroize();

    let nonce = Nonce::from_slice(&envelope.nonce);
    let aad = envelope_aad(&envelope.ephemeral_pub);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decrypt failed (authentication): {e}"))?;

    String::from_utf8(plaintext).context("decrypted plaintext is not valid UTF-8")
}

/// Consult the [encryption].at_rest config flag OR the
/// `AI_MEMORY_ENCRYPT_AT_REST=1` env var. Truthy env values:
/// `1` / `true` / `yes` / `on` (case-insensitive). Used by the storage
/// write path to gate the encrypt-on-insert / decrypt-on-read branches.
///
/// The config flag is consulted first when present, then the env var.
/// Either truthy source enables encryption. This mirrors the precedence
/// shape of the existing `AI_MEMORY_PERMISSIONS_MODE` config knob.
#[must_use]
pub fn encryption_enabled(config_flag: Option<bool>) -> bool {
    if let Some(true) = config_flag {
        return true;
    }
    matches!(
        std::env::var("AI_MEMORY_ENCRYPT_AT_REST")
            .ok()
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// #228 Commit B — seal a memory's plaintext content for at-rest storage.
///
/// Returns `Some((envelope_bytes, placeholder))` when at-rest encryption
/// is enabled AND `content` is non-empty; `None` otherwise (the caller
/// stores `content` verbatim and leaves `encrypted_envelope` NULL — the
/// byte-identical default path). Content-only: title / tags / metadata
/// stay plaintext and are NOT routed through here.
///
/// The returned `placeholder` is the empty string — the `content` column
/// holds it while the ciphertext lives in `encrypted_envelope`. Reads
/// recover the plaintext via [`open_content`], gated on envelope
/// presence (never on [`encryption_enabled`]) so rows written while
/// encryption was on remain readable after the flag is toggled off.
///
/// Fail-closed: keypair-resolution errors propagate, and an enabled gate
/// over a memory with no `agent_id` to key encryption to is refused
/// rather than silently storing plaintext.
///
/// # Errors
/// * Returns `Err` when encryption is enabled, `content` is non-empty,
///   but `agent_id` is empty — there is no recipient key to seal to.
/// * Returns `Err` when the per-agent keypair cannot be
///   resolved/persisted, or when the AEAD encrypt call fails.
pub(crate) fn seal_content(content: &str, agent_id: &str) -> Result<Option<(Vec<u8>, String)>> {
    if !encryption_enabled(None) || content.is_empty() {
        return Ok(None);
    }
    if agent_id.is_empty() {
        return Err(anyhow!(
            "at-rest encryption enabled but memory has no agent_id to key encryption to (fail-closed)"
        ));
    }
    let kp = get_or_create_keypair(agent_id)?;
    let env = encrypt(content, &kp.public)?;
    Ok(Some((env.to_bytes(), String::new())))
}

/// #228 Commit B — decrypt an at-rest envelope back to plaintext content.
///
/// Gated by the CALLER on envelope PRESENCE (a non-NULL
/// `encrypted_envelope` BLOB / BYTEA), NOT on [`encryption_enabled`], so
/// rows written while encryption was on stay readable after the flag is
/// toggled off. The plaintext `content` column then carries the empty
/// placeholder; the recovered value here is the source of truth.
///
/// # Errors
/// * Returns `Err` when the envelope bytes don't parse (truncated /
///   unknown version), or when AEAD authentication / decryption fails
///   (tampered ciphertext, wrong recipient key, missing keypair). The
///   caller maps this to a fail-closed read error — never substitutes
///   the placeholder for the plaintext.
pub(crate) fn open_content(envelope_bytes: &[u8], agent_id: &str) -> Result<String> {
    let env = Envelope::from_bytes(envelope_bytes)?;
    let kp = get_or_create_keypair(agent_id)?;
    decrypt(&env, &kp.secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clear the process-wide keypair cache to model a daemon restart:
    /// the in-memory cache is gone and only the on-disk keys remain.
    fn clear_keypair_cache() {
        keypair_cache().lock().expect("cache lock").clear();
    }

    #[test]
    fn decrypt_survives_keypair_cache_clear_via_disk_persistence() {
        // #228 Part 1 — the per-agent X25519 keypair persists to disk, so
        // clearing the cache (a modeled restart) still decrypts rows
        // encrypted before the restart. Without persistence the cleared
        // cache would mint a fresh key and every prior ciphertext would be
        // permanently undecryptable.
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = "persist-restart-agent";
        let kp1 = get_or_create_keypair_in(agent, dir.path()).expect("generate + persist");
        let env = encrypt("survives a restart", &kp1.public).expect("encrypt");

        clear_keypair_cache(); // modeled restart — cache gone

        let kp2 = get_or_create_keypair_in(agent, dir.path()).expect("load from disk");
        assert_eq!(
            kp1.secret.to_bytes(),
            kp2.secret.to_bytes(),
            "#228: the keypair MUST round-trip from disk after a cache clear"
        );
        let recovered = decrypt(&env, &kp2.secret).expect("decrypt after restart");
        assert_eq!(recovered, "survives a restart");
    }

    #[cfg(unix)]
    #[test]
    fn keypair_disk_load_refuses_world_readable_private_key() {
        // #228 Part 1 — load-time mode-bit enforcement (Unix): a loosened
        // `.x25519.priv` is refused, not silently used (mirrors the
        // Ed25519 keystore's S4-LOW1 guard).
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = "lax-mode-agent";
        let _kp = get_or_create_keypair_in(agent, dir.path()).expect("persist");
        clear_keypair_cache();
        let priv_path = dir.path().join(format!("{agent}{X25519_PRIV_SUFFIX}"));
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen priv mode");
        let err = get_or_create_keypair_in(agent, dir.path())
            .expect_err("a world-readable .priv must be refused");
        assert!(
            format!("{err}").contains("insecure mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn keypair_round_trip_returns_same_secret() {
        // Cache-hit path: second call returns the same secret material.
        let agent = "test-agent-roundtrip";
        let a = get_or_create_keypair(agent).expect("first generate");
        let b = get_or_create_keypair(agent).expect("second fetch");
        assert_eq!(a.public.as_bytes(), b.public.as_bytes());
        assert_eq!(a.secret.to_bytes(), b.secret.to_bytes());
    }

    #[test]
    fn keypair_distinct_for_distinct_agents() {
        let a = get_or_create_keypair("agent-a").expect("a");
        let b = get_or_create_keypair("agent-b").expect("b");
        assert_ne!(a.public.as_bytes(), b.public.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_round_trip_recovers_plaintext() {
        let kp = get_or_create_keypair("roundtrip-agent").expect("keypair");
        let plaintext = "hello world — encryption substrate MVP";
        let env = encrypt(plaintext, &kp.public).expect("encrypt");
        let recovered = decrypt(&env, &kp.secret).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn envelope_wire_format_round_trips() {
        let kp = get_or_create_keypair("envelope-bytes").expect("kp");
        let env = encrypt("payload bytes", &kp.public).expect("encrypt");
        let bytes = env.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).expect("parse");
        assert_eq!(env.ephemeral_pub, parsed.ephemeral_pub);
        assert_eq!(env.nonce, parsed.nonce);
        assert_eq!(env.ciphertext, parsed.ciphertext);
        // And the round-tripped envelope decrypts.
        let recovered = decrypt(&parsed, &kp.secret).expect("decrypt parsed");
        assert_eq!(recovered, "payload bytes");
    }

    #[test]
    fn envelope_parse_rejects_short_buffer() {
        assert!(Envelope::from_bytes(&[]).is_err());
        assert!(Envelope::from_bytes(&[0x01; 10]).is_err());
    }

    #[test]
    fn envelope_parse_rejects_unknown_version() {
        let mut bad = vec![0xFF];
        bad.extend_from_slice(&[0u8; PUBKEY_LEN + NONCE_LEN + TAG_LEN + 1]);
        assert!(Envelope::from_bytes(&bad).is_err());
    }

    #[test]
    fn decrypt_with_wrong_secret_fails() {
        let kp_alice = get_or_create_keypair("alice-wrong-key").expect("alice");
        let kp_eve = get_or_create_keypair("eve-wrong-key").expect("eve");
        let env = encrypt("secret-for-alice", &kp_alice.public).expect("encrypt");
        // Eve cannot decrypt Alice's payload — AEAD authentication fails.
        assert!(decrypt(&env, &kp_eve.secret).is_err());
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let kp = get_or_create_keypair("tamper-detect").expect("kp");
        let mut env = encrypt("dont change this", &kp.public).expect("encrypt");
        // Flip a bit in the ciphertext — AEAD authentication catches it.
        env.ciphertext[0] ^= 0x01;
        assert!(decrypt(&env, &kp.secret).is_err());
    }

    // --- v0.7.0 H3 — HKDF key derivation + AAD header binding ---

    #[test]
    fn hkdf_derived_key_is_deterministic_and_differs_from_raw_shared_secret() {
        // Same shared secret -> same derived key (decrypt must reproduce
        // the encrypt-side key), but the derived key must NOT equal the
        // raw X25519 output — proving HKDF actually conditions the secret
        // rather than passing it through.
        let alice = get_or_create_keypair("h3-hkdf-alice").expect("alice");
        let bob = get_or_create_keypair("h3-hkdf-bob").expect("bob");
        let shared_a = alice.secret.diffie_hellman(&bob.public);
        let shared_b = bob.secret.diffie_hellman(&alice.public);
        // ECDH symmetry precondition.
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());

        let key1 = derive_aead_key(&shared_a);
        let key2 = derive_aead_key(&shared_b);
        assert_eq!(key1, key2, "HKDF derivation must be deterministic");
        assert_eq!(key1.len(), AEAD_KEY_LEN);
        assert_ne!(
            &key1,
            shared_a.as_bytes(),
            "derived key must not be the raw shared secret (HKDF must transform it)"
        );
    }

    #[test]
    fn envelope_aad_binds_version_and_ephemeral_pub() {
        let pubkey = [7u8; PUBKEY_LEN];
        let aad = envelope_aad(&pubkey);
        assert_eq!(aad.len(), 1 + PUBKEY_LEN);
        assert_eq!(aad[0], ENVELOPE_VERSION, "AAD[0] must pin the version");
        assert_eq!(&aad[1..], &pubkey, "AAD tail must be the ephemeral pubkey");
    }

    #[test]
    fn decrypt_fails_when_ephemeral_pub_swapped() {
        // Swapping the envelope's ephemeral pubkey for another valid one
        // must fail: it both changes the ECDH shared secret AND breaks the
        // AAD binding. No silent plaintext recovery.
        let kp = get_or_create_keypair("h3-aad-swap").expect("kp");
        let mut env = encrypt("aad-bound payload", &kp.public).expect("encrypt");
        let other = get_or_create_keypair("h3-aad-swap-other").expect("other");
        env.ephemeral_pub = other.public.to_bytes();
        assert!(
            decrypt(&env, &kp.secret).is_err(),
            "a swapped ephemeral pubkey must fail AEAD authentication"
        );
    }

    #[test]
    fn envelope_version_is_the_hkdf_aad_scheme() {
        // Pin the scheme marker so an accidental revert to the raw-DH MVP
        // (0x01) is caught: the on-the-wire version byte must be 0x02.
        let kp = get_or_create_keypair("h3-version-pin").expect("kp");
        let env = encrypt("scheme marker", &kp.public).expect("encrypt");
        assert_eq!(ENVELOPE_VERSION, 0x02);
        assert_eq!(env.to_bytes()[0], 0x02, "wire version byte must be 0x02");
    }

    #[test]
    fn encryption_enabled_config_flag_wins() {
        // Save + clear the env var so other tests aren't perturbed.
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: tests run with serial scope around env-var mutation in
        // the keypair-cache module; this single-threaded read/restore is
        // safe for the assertions below.
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
        assert!(encryption_enabled(Some(true)));
        assert!(!encryption_enabled(Some(false)));
        assert!(!encryption_enabled(None));
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
        assert!(encryption_enabled(None));
        assert!(encryption_enabled(Some(true)));
        // Restore.
        if let Some(v) = prev {
            unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v) };
        } else {
            unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
        }
    }

    // --- #228 Commit B — seal_content / open_content helpers ---

    #[test]
    fn seal_content_returns_none_when_encryption_disabled() {
        // #228 Commit B — the default (encryption-off) path: seal_content
        // is a no-op so the caller stores content verbatim with a NULL
        // envelope (byte-identical to pre-wiring behaviour). This test is
        // hermetic — it never sets the env var, relying on the default
        // disabled gate. (The env-mutating `encryption_enabled_*` test
        // restores the var, but to avoid cross-test ordering coupling we
        // assert disabled-by-default explicitly when the var is unset.)
        if encryption_enabled(None) {
            // Another test left the var set in this process; skip rather
            // than assert a false negative. The env-guarded integration
            // suite (tests/encryption_at_rest.rs) covers the enabled path.
            return;
        }
        let sealed = seal_content("plaintext content", "agent-seal-off").expect("seal");
        assert!(
            sealed.is_none(),
            "encryption disabled => seal_content must return None (verbatim store)"
        );
    }

    #[test]
    fn open_content_round_trips_via_process_test_key() {
        // #228 Commit B — open_content recovers the plaintext from an
        // envelope sealed to the agent's per-process test keypair.
        // open_content resolves the agent key through
        // `get_or_create_keypair`, which in cfg(test) reads the
        // process-wide ephemeral test key dir. To stay hermetic we:
        //   1. populate the cache for the agent (first call mints+caches),
        //   2. build the envelope with THAT keypair's public key,
        //   3. assert open_content(bytes, agent) recovers the plaintext.
        let agent = "open-content-roundtrip-agent";
        let kp = get_or_create_keypair(agent).expect("seed keypair");
        let plaintext = "round-trip via open_content — #228 Commit B";
        let env = encrypt(plaintext, &kp.public).expect("encrypt");
        let bytes = env.to_bytes();
        let recovered = open_content(&bytes, agent).expect("open_content");
        assert_eq!(recovered, plaintext);
    }
}
