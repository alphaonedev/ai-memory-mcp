// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3717 — recovery ESCROW of the per-agent at-rest key.
//!
//! A lost `<agent>.x25519.priv` used to mean lost `content` (the #3718
//! refusals name "the #3717 escrow" as the remedy; this is it). The private
//! half of every at-rest KEK is now wrapped ONCE, at mint, under a
//! DEPLOYMENT RECOVERY X25519 public key into `<agent>.x25519.escrow`:
//!
//! | File                            | Mode    | Bytes                                          |
//! |---------------------------------|---------|------------------------------------------------|
//! | `<key_dir>/recovery.x25519.pub` | `0o644` | 32 raw bytes — the recovery PUBLIC key         |
//! | `<agent>.x25519.escrow`         | `0o600` | an `0x02` [`Envelope`] over `<agent_id>\0<sk>` |
//!
//! The recovery PRIVATE half is never written under the key directory: it
//! is minted straight into the operator's off-node `0o600` file
//! (`keys init --recovery-key-out <path>`) and read back only by
//! `keys recover --recovery-key <path>` (a file channel, never argv — the
//! `AI_MEMORY_CAPABILITY_FILE` / `AI_MEMORY_STORE_URL_FILE` precedent).
//!
//! The escrow plaintext is `agent_id || 0x00 || secret` so an escrow file
//! cannot be replayed under another agent's name: the AEAD binds the id and
//! [`recover_private_from_escrow`] refuses a mismatch. Recovery restores the
//! private half FIRST (the #3146 ordering), re-derives the public half, and
//! refuses when a present `.x25519.pub` disagrees with the unwrapped secret
//! — an escrow of another generation must never overwrite a live key.
//!
//! Sealed rows are untouched by all of this: the envelope scheme, the
//! per-record DEK wrap and crypto-erase are unchanged (5-agent vote
//! `4d3ea1c5`, decision `2ee4b428`: D1 = B).

use super::{Envelope, Keypair, TRACING_TARGET, X25519_KEY_LEN, decrypt_bytes, encrypt_bytes};
use anyhow::{Context as _, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// The reserved label of the deployment recovery key (the stem of
/// [`RECOVERY_PUB_FILE`]); `keys prune` protects it like the `daemon` /
/// `owner` / witness labels.
pub const RECOVERY_LABEL: &str = "recovery";
/// The deployment recovery PUBLIC key, enrolled under the key directory
/// (`<RECOVERY_LABEL>.x25519.pub`; pinned to the label by a test).
pub const RECOVERY_PUB_FILE: &str = "recovery.x25519.pub";
/// Filename suffix of the per-agent escrow (mode `0o600`).
pub const X25519_ESCROW_SUFFIX: &str = ".x25519.escrow";
/// The command that enrolls a recovery key (named in every remedy).
pub const REMEDY_ENROLL_RECOVERY_KEY: &str =
    "ai-memory keys init --recovery-key-out <off-node-file>";
/// The command that restores a lost at-rest key from its escrow.
pub const REMEDY_RECOVER: &str = "ai-memory keys recover --recovery-key <off-node-file>";
/// Separator between the agent id and the secret inside the escrow plaintext.
const ESCROW_SEPARATOR: u8 = 0;
/// Mode of the recovery private file the operator keeps off-node.
const MODE_PRIVATE: u32 = 0o600;

/// `<dir>/recovery.x25519.pub`.
#[must_use]
pub fn recovery_pub_path(dir: &Path) -> PathBuf {
    dir.join(RECOVERY_PUB_FILE)
}

/// `<dir>/<agent_id>.x25519.escrow`.
#[must_use]
pub fn escrow_path(agent_id: &str, dir: &Path) -> PathBuf {
    dir.join(format!("{agent_id}{X25519_ESCROW_SUFFIX}"))
}

/// Whether `agent_id`'s escrow file exists under `dir`.
#[must_use]
pub fn escrow_present(agent_id: &str, dir: &Path) -> bool {
    escrow_path(agent_id, dir).is_file()
}

fn read_32(path: &Path, what: &str) -> Result<Option<[u8; X25519_KEY_LEN]>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow!(e)).with_context(|| format!("reading {what} {}", path.display()));
        }
    };
    if bytes.len() != X25519_KEY_LEN {
        bail!(
            "{what} {} has {} bytes, expected {X25519_KEY_LEN}",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; X25519_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(Some(arr))
}

/// The enrolled recovery public key under `dir`, `Ok(None)` when none is
/// enrolled.
///
/// # Errors
/// The file exists but is not 32 bytes, or cannot be read.
pub fn load_recovery_pubkey(dir: &Path) -> Result<Option<PublicKey>> {
    Ok(read_32(&recovery_pub_path(dir), "recovery public key")?.map(PublicKey::from))
}

/// What [`enroll_recovery_pubkey`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// Written this call.
    Enrolled,
    /// The same key was already enrolled; nothing written.
    AlreadyEnrolled,
}

/// Enroll `public` as the deployment recovery key under `dir`. Idempotent
/// for the same key; a DIFFERENT enrolled key is never overwritten (every
/// existing escrow was wrapped under it).
///
/// # Errors
/// A different recovery key is already enrolled, or the write fails.
pub fn enroll_recovery_pubkey(dir: &Path, public: &PublicKey) -> Result<EnrollOutcome> {
    let path = recovery_pub_path(dir);
    if let Some(existing) = load_recovery_pubkey(dir)? {
        if existing.as_bytes() == public.as_bytes() {
            return Ok(EnrollOutcome::AlreadyEnrolled);
        }
        bail!(
            "a different recovery key is already enrolled at {} — every existing escrow was \
             wrapped under it; rotating the recovery key is a separate, explicit operation \
             (#3717), nothing was written",
            path.display()
        );
    }
    crate::identity::keypair::ensure_parent(&path)?;
    crate::identity::keypair::enforce_key_path_chain_secure(dir, &path)?;
    crate::identity::keypair::write_with_mode(&path, public.as_bytes(), 0o644)
        .with_context(|| format!("writing recovery public key {}", path.display()))?;
    Ok(EnrollOutcome::Enrolled)
}

/// Mint a fresh deployment recovery keypair: the PRIVATE half goes to
/// `private_out` (created exclusively, mode `0o600` — the operator moves it
/// off-node), the PUBLIC half is enrolled under `dir`. Refuses when a
/// recovery key is already enrolled or `private_out` exists, so a re-run
/// can never orphan existing escrows or clobber an operator's file.
///
/// # Errors
/// A recovery key is already enrolled, `private_out` exists, or a write
/// fails (the public half is enrolled only after the private file landed).
pub fn mint_recovery_keypair(dir: &Path, private_out: &Path) -> Result<PublicKey> {
    if load_recovery_pubkey(dir)?.is_some() {
        bail!(
            "a recovery key is already enrolled at {} — nothing was minted (pass the existing \
             private file to `keys recover`, or rotate explicitly)",
            recovery_pub_path(dir).display()
        );
    }
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(MODE_PRIVATE);
    }
    let mut f = opts.open(private_out).with_context(|| {
        format!(
            "creating the recovery private file {} (refusing to overwrite an existing file)",
            private_out.display()
        )
    })?;
    let mut bytes = secret.to_bytes();
    let write = {
        use std::io::Write as _;
        f.write_all(&bytes).and_then(|()| f.sync_all())
    };
    bytes.zeroize();
    write.with_context(|| format!("writing {}", private_out.display()))?;
    drop(f);
    enroll_recovery_pubkey(dir, &public)?;
    Ok(public)
}

/// Read the recovery PRIVATE key from the operator's file: exactly 32
/// bytes, and on unix owner-only (`mode & 0o077 == 0`), opened once and
/// `fstat`ed on that handle (the #1790 single-open discipline).
///
/// # Errors
/// The file is missing, the wrong length, or readable by group/others.
pub fn load_recovery_secret(path: &Path) -> Result<StaticSecret> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening the recovery private file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = f
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "recovery private file {} has insecure mode {mode:o}; refusing to read it. \
                 Fix: chmod 0600 {}",
                path.display(),
                path.display()
            );
        }
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .with_context(|| format!("reading the recovery private file {}", path.display()))?;
    if bytes.len() != X25519_KEY_LEN {
        let n = bytes.len();
        bytes.zeroize();
        bail!(
            "recovery private file {} has {n} bytes, expected {X25519_KEY_LEN}",
            path.display()
        );
    }
    let mut arr = [0u8; X25519_KEY_LEN];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();
    let secret = StaticSecret::from(arr);
    arr.zeroize();
    Ok(secret)
}

/// Wrap `kp`'s private half under `recovery_pub` into
/// `<agent>.x25519.escrow` (mode `0o600`, staged + renamed like every key
/// file). Overwrites an existing escrow for the SAME key only (the caller
/// has the live secret in hand, so the new escrow is as good as the old).
///
/// # Errors
/// The AEAD wrap or the write fails.
pub(crate) fn write_escrow(kp: &Keypair, dir: &Path, recovery_pub: &PublicKey) -> Result<PathBuf> {
    let path = escrow_path(&kp.agent_id, dir);
    let mut plaintext = Vec::with_capacity(kp.agent_id.len() + 1 + X25519_KEY_LEN);
    plaintext.extend_from_slice(kp.agent_id.as_bytes());
    plaintext.push(ESCROW_SEPARATOR);
    let mut secret = kp.secret.to_bytes();
    plaintext.extend_from_slice(&secret);
    secret.zeroize();
    let sealed = encrypt_bytes(&plaintext, recovery_pub);
    plaintext.zeroize();
    let envelope = sealed.context("wrapping the at-rest key for escrow")?;
    crate::identity::keypair::ensure_parent(&path)?;
    crate::identity::keypair::enforce_key_path_chain_secure(dir, &path)?;
    crate::identity::keypair::write_with_mode(&path, &envelope.to_bytes(), MODE_PRIVATE)
        .with_context(|| format!("writing at-rest key escrow {}", path.display()))?;
    Ok(path)
}

/// What [`ensure_escrow`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowOutcome {
    /// The escrow was already on disk; nothing written.
    Present,
    /// Written this call from the live private key.
    Written,
    /// No recovery key is enrolled, so no escrow can be written.
    NoRecoveryKey,
}

/// Write the escrow for an agent whose live `.x25519.priv` exists but
/// whose escrow does not (the interrupted-mint window, or a key minted
/// before the recovery key was enrolled). Never mints a key.
///
/// # Errors
/// The live key cannot be loaded, or the wrap/write fails.
pub fn ensure_escrow(agent_id: &str, dir: &Path) -> Result<EscrowOutcome> {
    if escrow_present(agent_id, dir) {
        return Ok(EscrowOutcome::Present);
    }
    let Some(recovery) = load_recovery_pubkey(dir)? else {
        return Ok(EscrowOutcome::NoRecoveryKey);
    };
    let kp = super::load_keypair_in(agent_id, dir)?
        .ok_or_else(|| anyhow!("no live at-rest key for {agent_id:?} to escrow"))?;
    write_escrow(&kp, dir, &recovery)?;
    Ok(EscrowOutcome::Written)
}

/// Re-derive `<agent>.x25519.pub` from a present `.x25519.priv` when the
/// public file is absent (the interrupted-mint window). Returns whether it
/// was written. Never touches a present public file and never mints.
///
/// # Errors
/// The live key cannot be loaded, or the write fails.
pub fn repair_public_half(agent_id: &str, dir: &Path) -> Result<bool> {
    let (pub_path, _) = super::x25519_key_paths(agent_id, dir);
    if pub_path.exists() {
        return Ok(false);
    }
    let kp = super::load_keypair_in(agent_id, dir)?.ok_or_else(|| {
        anyhow!("no live at-rest key for {agent_id:?} to derive a public half from")
    })?;
    crate::identity::keypair::write_with_mode(&pub_path, kp.public.as_bytes(), 0o644)
        .with_context(|| format!("re-deriving x25519 public key {}", pub_path.display()))?;
    Ok(true)
}

/// The result of a successful [`recover_private_from_escrow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// The agent whose key was restored.
    pub agent_id: String,
    /// The restored private file.
    pub priv_path: PathBuf,
    /// The public file (rewritten only when it was absent).
    pub pub_path: PathBuf,
    /// Whether the public half had to be re-derived (it was absent).
    pub pub_rewritten: bool,
}

/// Restore `<agent>.x25519.priv` from its escrow using the operator's
/// recovery private key. Refuses when a live private key is already
/// present (nothing to recover), when the escrow names a different agent,
/// or when a present `.x25519.pub` disagrees with the unwrapped secret.
/// Private half first, then the public half, then the in-memory cache is
/// evicted so the next read uses the restored file.
///
/// # Errors
/// Any refusal above, a missing / corrupt escrow, a wrong recovery key
/// (AEAD failure), or a write failure.
pub fn recover_private_from_escrow(
    agent_id: &str,
    dir: &Path,
    recovery_secret: &StaticSecret,
) -> Result<Recovered> {
    let (pub_path, priv_path) = super::x25519_key_paths(agent_id, dir);
    if priv_path.exists() {
        bail!(
            "a live at-rest key already exists at {} — nothing to recover (run `keys status`)",
            priv_path.display()
        );
    }
    let escrow = escrow_path(agent_id, dir);
    let bytes = std::fs::read(&escrow)
        .with_context(|| format!("reading at-rest key escrow {}", escrow.display()))?;
    let envelope = Envelope::from_bytes(&bytes)
        .with_context(|| format!("parsing at-rest key escrow {}", escrow.display()))?;
    let mut plaintext = decrypt_bytes(&envelope, recovery_secret).with_context(|| {
        format!(
            "unwrapping {} — the recovery private key does not match the enrolled recovery \
             public key, or the escrow is corrupt",
            escrow.display()
        )
    })?;
    let Some(sep) = plaintext.iter().position(|b| *b == ESCROW_SEPARATOR) else {
        plaintext.zeroize();
        bail!("escrow {} is malformed (no agent id)", escrow.display());
    };
    if &plaintext[..sep] != agent_id.as_bytes() || plaintext.len() != sep + 1 + X25519_KEY_LEN {
        let named = String::from_utf8_lossy(&plaintext[..sep]).into_owned();
        plaintext.zeroize();
        bail!(
            "escrow {} was wrapped for agent {named:?}, not {agent_id:?} — refusing to restore \
             it under this name",
            escrow.display()
        );
    }
    let mut arr = [0u8; X25519_KEY_LEN];
    arr.copy_from_slice(&plaintext[sep + 1..]);
    plaintext.zeroize();
    let secret = StaticSecret::from(arr);
    arr.zeroize();
    let public = PublicKey::from(&secret);
    let pub_rewritten = match read_32(&pub_path, "x25519 public key")? {
        Some(on_disk) if on_disk != *public.as_bytes() => bail!(
            "escrow {} unwraps to a key whose public half differs from the present {} — the \
             escrow is of another key generation; refusing to overwrite the live public key",
            escrow.display(),
            pub_path.display()
        ),
        Some(_) => false,
        None => true,
    };
    let kp = Keypair {
        agent_id: agent_id.to_string(),
        public,
        secret,
    };
    crate::identity::keypair::enforce_key_path_chain_secure(dir, &priv_path)?;
    let mut secret_bytes = kp.secret.to_bytes();
    let write = crate::identity::keypair::write_with_mode(&priv_path, &secret_bytes, MODE_PRIVATE)
        .with_context(|| format!("restoring x25519 private key {}", priv_path.display()));
    secret_bytes.zeroize();
    write?;
    if pub_rewritten {
        crate::identity::keypair::write_with_mode(&pub_path, kp.public.as_bytes(), 0o644)
            .with_context(|| format!("re-deriving x25519 public key {}", pub_path.display()))?;
    }
    super::evict_cached_keypair(agent_id);
    tracing::warn!(
        target: TRACING_TARGET,
        agent_id = %agent_id,
        priv_path = %priv_path.display(),
        "#3717: at-rest key RESTORED from its recovery escrow; sealed rows open again"
    );
    Ok(Recovered {
        agent_id: agent_id.to_string(),
        priv_path,
        pub_path,
        pub_rewritten,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{evict_cached_keypair, get_or_create_keypair_in, load_keypair_in};

    fn sandbox() -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("tempdir under TMPDIR");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        t
    }

    fn priv_of(agent: &str, dir: &Path) -> PathBuf {
        super::super::x25519_key_paths(agent, dir).1
    }

    #[test]
    fn mint_with_enrolled_recovery_key_writes_escrow_and_recovery_round_trips_3717() {
        let dir = sandbox();
        let out = dir.path().join("recovery.key");
        mint_recovery_keypair(dir.path(), &out).expect("mint recovery key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let agent = "ai:escrow-3717";
        let kp = get_or_create_keypair_in(agent, dir.path()).expect("mint");
        assert!(escrow_present(agent, dir.path()), "escrow written at mint");
        let secret_before = kp.secret.to_bytes();

        std::fs::remove_file(priv_of(agent, dir.path())).unwrap();
        evict_cached_keypair(agent);
        assert!(load_keypair_in(agent, dir.path()).unwrap().is_none());

        let recovery = load_recovery_secret(&out).expect("read recovery key");
        let r = recover_private_from_escrow(agent, dir.path(), &recovery).expect("recover");
        assert!(!r.pub_rewritten, "the public half was present");
        let back = load_keypair_in(agent, dir.path())
            .unwrap()
            .expect("restored");
        assert_eq!(
            back.secret.to_bytes(),
            secret_before,
            "byte-identical secret"
        );
    }

    #[test]
    fn recovery_with_the_wrong_key_fails_and_writes_nothing_3717() {
        let dir = sandbox();
        mint_recovery_keypair(dir.path(), &dir.path().join("recovery.key")).unwrap();
        let agent = "ai:escrow-wrong-3717";
        get_or_create_keypair_in(agent, dir.path()).unwrap();
        std::fs::remove_file(priv_of(agent, dir.path())).unwrap();
        evict_cached_keypair(agent);
        let wrong = StaticSecret::random_from_rng(rand_core::OsRng);
        let err = recover_private_from_escrow(agent, dir.path(), &wrong).unwrap_err();
        assert!(format!("{err:#}").contains("does not match"), "{err:#}");
        assert!(!priv_of(agent, dir.path()).exists(), "nothing restored");
    }

    #[test]
    fn escrow_is_bound_to_its_agent_id_3717() {
        let dir = sandbox();
        let out = dir.path().join("recovery.key");
        mint_recovery_keypair(dir.path(), &out).unwrap();
        let a = "ai:escrow-a-3717";
        let b = "ai:escrow-b-3717";
        get_or_create_keypair_in(a, dir.path()).unwrap();
        // Replay a's escrow under b's name.
        std::fs::copy(escrow_path(a, dir.path()), escrow_path(b, dir.path())).unwrap();
        let recovery = load_recovery_secret(&out).unwrap();
        let err = recover_private_from_escrow(b, dir.path(), &recovery).unwrap_err();
        assert!(
            format!("{err:#}").contains("was wrapped for agent"),
            "{err:#}"
        );
        assert!(!priv_of(b, dir.path()).exists());
    }

    #[test]
    fn recovery_refuses_a_live_key_and_a_foreign_generation_3717() {
        let dir = sandbox();
        let out = dir.path().join("recovery.key");
        mint_recovery_keypair(dir.path(), &out).unwrap();
        let agent = "ai:escrow-gen-3717";
        get_or_create_keypair_in(agent, dir.path()).unwrap();
        let recovery = load_recovery_secret(&out).unwrap();
        let err = recover_private_from_escrow(agent, dir.path(), &recovery).unwrap_err();
        assert!(format!("{err:#}").contains("nothing to recover"), "{err:#}");
        // Lose the private half and plant a different public half: refused.
        std::fs::remove_file(priv_of(agent, dir.path())).unwrap();
        evict_cached_keypair(agent);
        let (pub_path, _) = super::super::x25519_key_paths(agent, dir.path());
        std::fs::write(&pub_path, [7u8; 32]).unwrap();
        let err = recover_private_from_escrow(agent, dir.path(), &recovery).unwrap_err();
        assert!(
            format!("{err:#}").contains("another key generation"),
            "{err:#}"
        );
        assert!(!priv_of(agent, dir.path()).exists());
    }

    #[test]
    fn mint_without_recovery_key_writes_no_escrow_and_ensure_escrow_backfills_3717() {
        let dir = sandbox();
        let agent = "ai:escrow-late-3717";
        get_or_create_keypair_in(agent, dir.path()).unwrap();
        assert!(!escrow_present(agent, dir.path()));
        assert_eq!(
            ensure_escrow(agent, dir.path()).unwrap(),
            EscrowOutcome::NoRecoveryKey
        );
        let out = dir.path().join("recovery.key");
        mint_recovery_keypair(dir.path(), &out).unwrap();
        assert_eq!(
            ensure_escrow(agent, dir.path()).unwrap(),
            EscrowOutcome::Written
        );
        assert_eq!(
            ensure_escrow(agent, dir.path()).unwrap(),
            EscrowOutcome::Present
        );
        // A second recovery mint is refused: the enrolled key owns the escrows.
        let err = mint_recovery_keypair(dir.path(), &dir.path().join("other.key")).unwrap_err();
        assert!(format!("{err:#}").contains("already enrolled"), "{err:#}");
    }

    #[test]
    fn recovery_pub_file_is_the_reserved_label_3717() {
        assert_eq!(
            RECOVERY_PUB_FILE,
            format!("{RECOVERY_LABEL}{}", super::super::X25519_PUB_SUFFIX)
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_private_file_must_be_owner_only_3717() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = sandbox();
        let out = dir.path().join("recovery.key");
        mint_recovery_keypair(dir.path(), &out).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_recovery_secret(&out)
            .err()
            .expect("insecure mode refused");
        assert!(format!("{err:#}").contains("insecure mode"), "{err:#}");
    }
}
