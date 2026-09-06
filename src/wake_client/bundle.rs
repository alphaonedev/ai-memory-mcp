// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3470 — loading the scoped `a2a-hub/join/v1` delegation bundle a
//! wake listener joins the hub with.
//!
//! # One identity root, and this is not it
//!
//! The ONLY credential this module reads is the bundle
//! [`crate::cli::identity_delegate`] writes: `<key_dir>/<agent>.a2a-hub.json`,
//! mode 0600, holding a DELEGATED private seed and the short-lived certificate
//! that binds it to the agent's enrolled key. It never reads an agent's
//! enrolled `.priv`, never generates enrolled material, and never writes a key
//! of its own. A compromised listener is worth "someone may be woken as me
//! until this expires" — never "someone may write my history".
//!
//! # Fail closed, with no flag to open it
//!
//! Every check below is a REFUSAL, not a warning, and there is deliberately no
//! `--insecure` / `--skip-verify` counterpart anywhere on the surface:
//!
//! * the bundle file must be a regular file (never a symlink) owned by the
//!   caller, mode 0600 — the same standard the writer enforced, proven
//!   through the ONE `O_NOFOLLOW` descriptor the bytes are then read from, so
//!   the file that was checked is the file that was parsed (#3522);
//! * the bundle `version` must be exactly [`DELEGATION_BUNDLE_VERSION`];
//! * the certificate must carry scope [`A2A_HUB_SCOPE`], the bundle's own
//!   principal, and the hub id we are about to dial;
//! * the delegate seed must be the key the certificate authorises
//!   (`delegate_key_id`), so a bundle whose seed was swapped is refused HERE
//!   rather than becoming an opaque `401` at the socket;
//! * the certificate must verify under the agent's ENROLLED public key from
//!   the same key directory, so a tampered or foreign certificate never
//!   reaches the wire;
//! * the window must be inside [`MAX_DELEGATION_TTL_SECS`] and must contain
//!   `now`.
//!
//! Refusing an EXPIRED bundle locally matters for manageability: the hub would
//! refuse it anyway, and a listener that discovers this only after a jittered
//! reconnect ladder looks like a network problem instead of "run `ai-memory
//! identity delegate` again".

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::cli::identity_delegate::{
    DELEGATION_BUNDLE_VERSION, DelegationBundle, default_bundle_path,
};
use crate::identity::hub_delegation::{
    A2A_HUB_SCOPE, DELEGATE_KEY_ID_BYTES, DelegationWire, check_ttl, check_validity,
    verify_hub_delegation,
};
use crate::identity::keypair;
use crate::wake_hub::frame::DEBUG_FIELD_DELEGATION_BYTES;
use crate::wake_hub::limits::{PUBKEY_BYTES, SIGNATURE_BYTES};

/// The only mode a bundle holding a private seed may carry.
pub const BUNDLE_MODE: u32 = 0o600;

/// A loaded, fully verified hub-join credential.
///
/// Holds the DELEGATED signing key in memory for the life of the listener and
/// nothing else: no enrolled key, no store handle, no message body.
pub struct HubJoinBundle {
    agent_id: String,
    hub_id: String,
    delegate: SigningKey,
    delegation: Bytes,
    not_after: String,
}

impl std::fmt::Debug for HubJoinBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sizes and public facts only. A Debug line is a log line.
        f.debug_struct("HubJoinBundle")
            .field("agent_id", &self.agent_id)
            .field("hub_id", &self.hub_id)
            .field("delegate", &"<delegated session key>")
            .field(DEBUG_FIELD_DELEGATION_BYTES, &self.delegation.len())
            .field("not_after", &self.not_after)
            .finish()
    }
}

/// The public half of one signed handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedHello {
    /// The DELEGATED Ed25519 public key this session authenticates with.
    pub pubkey: [u8; PUBKEY_BYTES],
    /// Signature over the hub-issued hello transcript.
    pub signature: [u8; SIGNATURE_BYTES],
    /// The scoped delegation binding `pubkey` to the enrolled principal.
    pub delegation: Bytes,
}

impl std::fmt::Debug for SignedHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedHello")
            .field("pubkey_bytes", &self.pubkey.len())
            .field("signature_bytes", &self.signature.len())
            .field(DEBUG_FIELD_DELEGATION_BYTES, &self.delegation.len())
            .finish()
    }
}

impl HubJoinBundle {
    /// Resolve the bundle path the way the writer does, so an operator who
    /// took the default on `identity delegate` needs no flag here.
    #[must_use]
    pub fn default_path(key_dir: &Path, agent_id: &str) -> PathBuf {
        default_bundle_path(key_dir, agent_id)
    }

    /// Load and fully verify a bundle.
    ///
    /// `hub_id` is the hub this listener is about to dial: a certificate
    /// minted for a different hub is refused here rather than presented and
    /// rejected there.
    ///
    /// # Errors
    ///
    /// Every check in the module docs, each as its own actionable refusal.
    pub fn load(path: &Path, hub_id: &str, key_dir: &Path, now_rfc3339: &str) -> Result<Self> {
        let mut file = open_owner_only(path)?;
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut raw)
            .with_context(|| format!("cannot read the delegation bundle {}", path.display()))?;
        let bundle: DelegationBundle = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "{} is not a v{DELEGATION_BUNDLE_VERSION} a2a-hub delegation bundle. Mint one \
                 with `ai-memory identity delegate --scope a2a-hub`.",
                path.display()
            )
        })?;
        Self::from_bundle(&bundle, path, hub_id, key_dir, now_rfc3339)
    }

    /// The verification core, over an already-parsed bundle.
    ///
    /// Split out so the refusal table is unit-testable without staging a file
    /// for every case.
    ///
    /// # Errors
    ///
    /// As [`Self::load`], minus the file-system checks.
    pub fn from_bundle(
        bundle: &DelegationBundle,
        source: &Path,
        hub_id: &str,
        key_dir: &Path,
        now_rfc3339: &str,
    ) -> Result<Self> {
        if bundle.version != DELEGATION_BUNDLE_VERSION {
            bail!(
                "{} is a v{} delegation bundle; this build reads v{DELEGATION_BUNDLE_VERSION}. \
                 A credential format this build does not understand is refused, never guessed at.",
                source.display(),
                bundle.version
            );
        }
        if bundle.agent_id.is_empty() {
            bail!(
                "{} names no agent, so there is no identity to join as",
                source.display()
            );
        }
        if bundle.hub_id != hub_id {
            bail!(
                "{} was minted for hub {:?} but this listener dials {hub_id:?}. A delegation is \
                 bound to ONE hub on purpose; mint one for {hub_id:?} rather than presenting \
                 this.",
                source.display(),
                bundle.hub_id
            );
        }

        let certificate = URL_SAFE_NO_PAD
            .decode(&bundle.delegation_b64)
            .with_context(|| format!("{}: delegation_b64 is not base64url", source.display()))?;
        let wire = DelegationWire::decode(&certificate).map_err(|e| {
            anyhow::anyhow!(
                "{}: the delegation certificate does not decode ({e})",
                source.display()
            )
        })?;
        if wire.scope != A2A_HUB_SCOPE {
            bail!(
                "{}: the certificate carries scope {:?}, not {A2A_HUB_SCOPE:?}. The scope element \
                 exists to be CHECKED, not merely recorded.",
                source.display(),
                wire.scope
            );
        }
        if wire.principal != bundle.agent_id {
            bail!(
                "{}: the certificate speaks for {:?} but the bundle claims {:?}",
                source.display(),
                wire.principal,
                bundle.agent_id
            );
        }
        if wire.hub_id != hub_id {
            bail!(
                "{}: the certificate is bound to hub {:?}, not {hub_id:?}",
                source.display(),
                wire.hub_id
            );
        }

        let seed = URL_SAFE_NO_PAD
            .decode(&bundle.delegate_private_b64)
            .with_context(|| {
                format!(
                    "{}: delegate_private_b64 is not base64url",
                    source.display()
                )
            })?;
        let seed: [u8; DELEGATE_KEY_ID_BYTES] = seed.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "{}: the delegated seed is {} bytes, not {DELEGATE_KEY_ID_BYTES}",
                source.display(),
                seed.len()
            )
        })?;
        let delegate = SigningKey::from_bytes(&seed);
        if delegate.verifying_key().to_bytes() != wire.delegate_key_id {
            bail!(
                "{}: the bundle's private key is NOT the key its certificate authorises. A \
                 mismatched pair is a tampered bundle, not a usable credential.",
                source.display()
            );
        }

        // The certificate must verify under the agent's ENROLLED public key
        // from this key directory. Absent public material is a refusal, not a
        // downgrade: the hub verifies this signature and a listener that could
        // not check it locally would present material it never validated.
        let enrolled = keypair::load_public(&bundle.agent_id, key_dir).with_context(|| {
            format!(
                "no enrolled `{}.pub` in {} to verify {} against. The bundle must be verified \
                 under the key that minted it; there is no flag that skips this.",
                bundle.agent_id,
                key_dir.display(),
                source.display()
            )
        })?;
        verify_hub_delegation(&enrolled, &wire.as_delegation(), &wire.signature).map_err(|e| {
            anyhow::anyhow!(
                "{}: the certificate does not verify under the enrolled key for {} ({e}). \
                 Re-mint it with `ai-memory identity delegate --scope a2a-hub`.",
                source.display(),
                bundle.agent_id
            )
        })?;

        check_ttl(&wire.as_delegation()).map_err(|e| {
            anyhow::anyhow!(
                "{}: the certificate window is not inside the protocol bound ({e})",
                source.display()
            )
        })?;
        check_validity(&wire.as_delegation(), now_rfc3339).map_err(|e| {
            anyhow::anyhow!(
                "{}: the certificate is outside its validity window at {now_rfc3339} ({e}). \
                 Mint a fresh one with `ai-memory identity delegate --scope a2a-hub`.",
                source.display()
            )
        })?;

        Ok(Self {
            agent_id: bundle.agent_id.clone(),
            hub_id: bundle.hub_id.clone(),
            delegate,
            delegation: Bytes::from(certificate),
            not_after: wire.not_after.clone(),
        })
    }

    /// The enrolled agent this credential speaks for.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// The one hub this credential is valid at.
    #[must_use]
    pub fn hub_id(&self) -> &str {
        &self.hub_id
    }

    /// RFC3339 end of the certificate window.
    #[must_use]
    pub fn not_after(&self) -> &str {
        &self.not_after
    }

    /// `true` when the certificate is still inside its window at `now`.
    ///
    /// The reconnect ladder consults this so an expired credential ends the
    /// listener with a legible message instead of retrying a refusal forever.
    #[must_use]
    pub fn is_valid_at(&self, now_rfc3339: &str) -> bool {
        DelegationWire::decode(&self.delegation)
            .is_ok_and(|wire| check_validity(&wire.as_delegation(), now_rfc3339).is_ok())
    }

    /// Sign one hub-issued hello transcript with the DELEGATED key.
    #[must_use]
    pub fn sign_hello(&self, transcript: &[u8]) -> SignedHello {
        SignedHello {
            pubkey: self.delegate.verifying_key().to_bytes(),
            signature: self.delegate.sign(transcript).to_bytes(),
            delegation: self.delegation.clone(),
        }
    }
}

/// Open a bundle no other local user could read or replace, returning the
/// descriptor every check was run against.
///
/// The permissions are proven through ONE descriptor and the bytes are then
/// read from that SAME descriptor, mirroring
/// `AllowlistCache::open_checked` on the hub side (#3504). A path-based
/// `symlink_metadata` followed by a path-based read would leave a window in
/// which the file could be swapped between the check and the read; the key
/// directory is caller-owned, so that window was only ever reachable by the
/// caller itself, but there is no reason to keep a stat-then-open pattern in a
/// credential loader when the descriptor-bound one costs nothing.
///
/// `O_NOFOLLOW` refuses a symlink AT THE OPEN, so a link in the key directory
/// pointing at a world-readable file can never have its permissions checked on
/// the target. `O_NONBLOCK` keeps a FIFO planted at this path from parking the
/// process on the open; the regular-file check below then refuses it.
fn open_owner_only(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        // ELOOP is what O_NOFOLLOW reports for a symlink on Linux and macOS.
        // Kept as its own refusal so the operator is told what is actually
        // wrong rather than being handed a bare "too many levels of symlinks".
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => bail!(
            "{} is a symlink. A credential reached through a link is a credential whose \
             permissions were checked on the wrong file.",
            path.display()
        ),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "no a2a-hub delegation bundle at {}. Mint one with `ai-memory identity \
                     delegate --scope a2a-hub`.",
                    path.display()
                )
            });
        }
    };

    // fstat on the descriptor just opened — never a second look at the path.
    let meta = file
        .metadata()
        .with_context(|| format!("cannot stat the delegation bundle {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {mode:04o}; a bundle holding a private key must be {BUNDLE_MODE:04o}. \
             Another local user can otherwise join the hub as this agent.",
            path.display()
        );
    }
    if meta.uid() != crate::wake_hub::startup::current_euid() {
        bail!(
            "{} is owned by uid {}, not by the caller (uid {})",
            path.display(),
            meta.uid(),
            crate::wake_hub::startup::current_euid()
        );
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::hub_delegation::sign_hub_delegation;
    use std::os::unix::fs::PermissionsExt as _;

    fn now() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    struct Staged {
        dir: tempfile::TempDir,
        agent_id: String,
        bundle: DelegationBundle,
        root: SigningKey,
    }

    /// Stage an enrolled key plus a freshly minted, in-window bundle — the
    /// exact artefacts `identity delegate` leaves behind.
    fn staged(hub_id: &str) -> Staged {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent_id = "ai:listener-3470".to_owned();
        let enrolled = keypair::generate(&agent_id).expect("generate");
        keypair::save(&enrolled, dir.path()).expect("save");
        let root = enrolled.private.clone().expect("private half");

        let delegate = keypair::generate(&agent_id).expect("generate delegate");
        let delegate_private = delegate.private.clone().expect("private half");
        let start = chrono::Utc::now();
        let mut wire = DelegationWire {
            principal: agent_id.clone(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate.public.to_bytes(),
            hub_id: hub_id.to_owned(),
            not_before: start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            not_after: (start + chrono::Duration::seconds(3_600))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&root, &wire.as_delegation()).expect("sign");
        let bundle = DelegationBundle {
            version: DELEGATION_BUNDLE_VERSION,
            agent_id: agent_id.clone(),
            hub_id: hub_id.to_owned(),
            delegation_b64: URL_SAFE_NO_PAD.encode(wire.encode().expect("encode")),
            delegate_private_b64: URL_SAFE_NO_PAD.encode(delegate_private.to_bytes()),
            not_before: wire.not_before.clone(),
            not_after: wire.not_after.clone(),
        };
        Staged {
            dir,
            agent_id,
            bundle,
            root,
        }
    }

    /// ALLOWED: the bundle the writer produces loads, names its agent, and
    /// signs a hello with the DELEGATED key — never the enrolled one.
    #[test]
    fn a_freshly_minted_bundle_loads_and_signs_with_the_delegated_key_3470() {
        let s = staged("hub-3470");
        let loaded = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("bundle.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect("a freshly minted bundle must load");
        assert_eq!(loaded.agent_id(), s.agent_id);
        assert_eq!(loaded.hub_id(), "hub-3470");

        let hello = loaded.sign_hello(b"transcript-3470");
        assert_ne!(
            hello.pubkey,
            s.root.verifying_key().to_bytes(),
            "a listener must never sign with the ENROLLED key"
        );
        let delegate =
            ed25519_dalek::VerifyingKey::from_bytes(&hello.pubkey).expect("delegate key");
        ed25519_dalek::Verifier::verify(
            &delegate,
            b"transcript-3470",
            &ed25519_dalek::Signature::from_bytes(&hello.signature),
        )
        .expect("the hello signature is the delegate's");
        // And the certificate presented is the one that authorises that key.
        let wire = DelegationWire::decode(&hello.delegation).expect("decode");
        assert_eq!(wire.delegate_key_id, hello.pubkey);
        assert!(loaded.is_valid_at(&now()));
    }

    /// DENIED: a bundle minted for another hub. A delegation is bound to ONE
    /// hub, and presenting it elsewhere must fail before the socket.
    #[test]
    fn a_bundle_for_another_hub_is_refused_3470() {
        let s = staged("hub-a");
        let err = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-b",
            s.dir.path(),
            &now(),
        )
        .expect_err("a certificate is bound to one hub");
        assert!(format!("{err:#}").contains("hub"), "{err:#}");
    }

    /// DENIED: the seed swapped for another key. The certificate still
    /// verifies under the enrolled root, so ONLY the delegate-key binding
    /// catches this — which is exactly why it is checked.
    #[test]
    fn a_bundle_whose_seed_is_not_the_certified_key_is_refused_3470() {
        let mut s = staged("hub-3470");
        let other = SigningKey::from_bytes(&[3u8; 32]);
        s.bundle.delegate_private_b64 = URL_SAFE_NO_PAD.encode(other.to_bytes());
        let err = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect_err("a mismatched pair is a tampered bundle");
        assert!(
            format!("{err:#}").contains("NOT the key its certificate authorises"),
            "{err:#}"
        );
    }

    /// DENIED: a certificate signed by a key that is not this agent's
    /// enrolled root. Verifying locally means a forged bundle never reaches
    /// the wire.
    #[test]
    fn a_certificate_not_signed_by_the_enrolled_root_is_refused_3470() {
        let s = staged("hub-3470");
        // Re-sign the same certificate body under a foreign root.
        let mut wire =
            DelegationWire::decode(&URL_SAFE_NO_PAD.decode(&s.bundle.delegation_b64).unwrap())
                .expect("decode");
        let forged = SigningKey::from_bytes(&[9u8; 32]);
        wire.signature = sign_hub_delegation(&forged, &wire.as_delegation()).expect("sign");
        let mut bundle = s.bundle;
        bundle.delegation_b64 = URL_SAFE_NO_PAD.encode(wire.encode().expect("encode"));

        let err = HubJoinBundle::from_bundle(
            &bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect_err("a foreign signature must not reach the wire");
        assert!(format!("{err:#}").contains("does not verify"), "{err:#}");
    }

    /// DENIED: an expired certificate, refused locally with the remediation
    /// rather than as an opaque 401 after a reconnect ladder.
    #[test]
    fn an_expired_bundle_is_refused_with_the_remediation_3470() {
        let s = staged("hub-3470");
        let future = (chrono::Utc::now() + chrono::Duration::seconds(7_200))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let err = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &future,
        )
        .expect_err("an out-of-window certificate is not a credential");
        assert!(format!("{err:#}").contains("identity delegate"), "{err:#}");
    }

    /// DENIED: a bundle without the enrolled public half to check it against.
    /// There is no downgrade path here — absent verification material is a
    /// refusal.
    #[test]
    fn a_bundle_with_no_enrolled_public_key_to_check_is_refused_3470() {
        let s = staged("hub-3470");
        std::fs::remove_file(s.dir.path().join(format!("{}.pub", s.agent_id)))
            .expect("drop the public half");
        let err = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect_err("no verification material, no join");
        assert!(
            format!("{err:#}").contains("no flag that skips this"),
            "{err:#}"
        );
    }

    /// DENIED: a group- or world-readable bundle, and a symlinked one. Both
    /// are ways another local user ends up able to join as this agent.
    #[test]
    fn a_readable_or_symlinked_bundle_is_refused_3470() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("b.json");
        std::fs::write(&path, b"{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        open_owner_only(&path).expect("0600 is the standard");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = open_owner_only(&path).expect_err("world-readable is refused");
        assert!(format!("{err:#}").contains("0644"), "{err:#}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        let err = open_owner_only(&link).expect_err("a symlinked credential is refused");
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    }

    /// The bytes a load parses come from the descriptor the permissions were
    /// proven on, not from a second look at the path. Replacing the file
    /// AFTER the check therefore cannot change what is read — the check and
    /// the read describe one inode.
    #[test]
    fn the_bundle_is_read_from_the_descriptor_that_was_checked_3522() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("b.json");
        std::fs::write(&path, b"{\"checked\":true}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let mut file = open_owner_only(&path).expect("an owner-only regular file opens");

        // Swap the path out from under the caller after the checks ran. A
        // path-based read would pick the replacement up; a descriptor-bound
        // one cannot.
        let swapped = dir.path().join("swapped.json");
        std::fs::write(&swapped, b"{\"swapped\":true}").expect("write");
        std::fs::set_permissions(&swapped, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::rename(&swapped, &path).expect("rename over the checked path");

        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut raw).expect("read");
        assert_eq!(
            raw.as_slice(),
            b"{\"checked\":true}".as_slice(),
            "the checked inode is the one that was read"
        );
    }

    /// DENIED: a FIFO at the bundle path. O_NONBLOCK keeps the open from
    /// parking the process, and the regular-file check then refuses it.
    #[test]
    fn a_fifo_at_the_bundle_path_is_refused_without_blocking_3522() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("b.json");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("cstring");
        // SAFETY: mkfifo takes a NUL-terminated path and a mode; the CString
        // above owns the buffer for the duration of the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());

        let err = open_owner_only(&path).expect_err("a FIFO is not a credential");
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
    }

    /// DENIED: a bundle format this build does not understand.
    #[test]
    fn an_unknown_bundle_version_is_refused_rather_than_guessed_at_3470() {
        let mut s = staged("hub-3470");
        s.bundle.version = DELEGATION_BUNDLE_VERSION + 1;
        let err = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect_err("an unknown credential format is refused");
        assert!(format!("{err:#}").contains("delegation bundle"), "{err:#}");
    }

    /// A `Debug` line is a log line: it must never render key material.
    #[test]
    fn debug_never_renders_the_delegated_key_3470() {
        let s = staged("hub-3470");
        let loaded = HubJoinBundle::from_bundle(
            &s.bundle,
            Path::new("b.json"),
            "hub-3470",
            s.dir.path(),
            &now(),
        )
        .expect("load");
        let rendered = format!("{loaded:?}");
        assert!(rendered.contains("<delegated session key>"), "{rendered}");
        assert!(!rendered.contains("SigningKey {"), "{rendered}");
        let hello = format!("{:?}", loaded.sign_hello(b"t"));
        assert!(hello.contains("signature_bytes"), "{hello}");
    }
}
