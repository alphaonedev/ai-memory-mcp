// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10074 — the ONE daemon signer: every daemon Ed25519 signature is made over
//! `DaemonDomain::tag() || body`, so a signature made for one meaning (a
//! `signed_events` row, a revision leaf, a forget tombstone, a governance
//! payload, the legacy cutoff) can never verify as another.
//!
//! The process-wide key is private to this module. There is no bytes-only
//! signer: [`sign`] takes a [`DaemonDomain`], and the source ratchet
//! `tests/daemon_signer_ratchet_10074.rs` holds that no other file reaches the
//! key or signs with it.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The meaning a daemon signature is made for. One variant per meaning; the
/// tag is the first bytes of the signed preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonDomain {
    /// The identity-bound signature of one `signed_events` row
    /// (`signed_events::daemon_row_signing_input`).
    EventRow,
    /// The pre-append placeholder signature over a row's payload/cause input
    /// (`SignedEvent::with_daemon_signature`); the append path replaces it with
    /// an [`DaemonDomain::EventRow`] signature.
    EventPayload,
    /// A governance payload signature (`agent_action`, `deferred_audit`); the
    /// append path replaces it with an [`DaemonDomain::EventRow`] signature.
    Governance,
    /// A forget / evict tombstone (`storage::forget_tombstone_signable_bytes`).
    Tombstone,
    /// A memory revision leaf (`revisions::revision_leaf_signable_bytes`).
    RevisionLeaf,
    /// The one legacy cutoff row of a `signed_events` chain.
    LegacyCutoff,
}

/// decision: the tombstone and revision-leaf tags are the domain prefixes those
/// preimages already carried (`forget-tombstone-v1\0`, `memory-revision-v1\0`)
/// over minting new ones, because then every stored tombstone and leaf
/// signature stays byte-identical and verifiable (no stored bytes change).
const TAG_EVENT_ROW: &[u8] = b"ai-memory/daemon-sig/v2/event-row\0";
const TAG_EVENT_PAYLOAD: &[u8] = b"ai-memory/daemon-sig/v2/event-payload\0";
const TAG_GOVERNANCE: &[u8] = b"ai-memory/daemon-sig/v2/governance\0";
const TAG_TOMBSTONE: &[u8] = b"forget-tombstone-v1\x00";
const TAG_REVISION_LEAF: &[u8] = b"memory-revision-v1\x00";
const TAG_LEGACY_CUTOFF: &[u8] = b"ai-memory/daemon-sig/v2/legacy-cutoff\0";

impl DaemonDomain {
    /// Every domain, for the cross-domain tests.
    pub const ALL: [DaemonDomain; 6] = [
        DaemonDomain::EventRow,
        DaemonDomain::EventPayload,
        DaemonDomain::Governance,
        DaemonDomain::Tombstone,
        DaemonDomain::RevisionLeaf,
        DaemonDomain::LegacyCutoff,
    ];

    /// The domain tag prefixed to every preimage of this domain. No tag is a
    /// prefix of another, so two domains never share a preimage.
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            DaemonDomain::EventRow => TAG_EVENT_ROW,
            DaemonDomain::EventPayload => TAG_EVENT_PAYLOAD,
            DaemonDomain::Governance => TAG_GOVERNANCE,
            DaemonDomain::Tombstone => TAG_TOMBSTONE,
            DaemonDomain::RevisionLeaf => TAG_REVISION_LEAF,
            DaemonDomain::LegacyCutoff => TAG_LEGACY_CUTOFF,
        }
    }
}

static DAEMON_AUDIT_KEY: OnceLock<SigningKey> = OnceLock::new();

/// Install the process-wide daemon key. First install wins (one daemon, one
/// signing identity per process lifetime); returns `true` when this call
/// installed it.
pub(crate) fn install(key: &SigningKey) -> bool {
    DAEMON_AUDIT_KEY.set(key.clone()).is_ok()
}

/// `true` when a daemon key is installed.
#[must_use]
pub fn is_installed() -> bool {
    DAEMON_AUDIT_KEY.get().is_some()
}

/// The public half of the installed daemon key.
#[must_use]
pub fn verifying_key() -> Option<VerifyingKey> {
    DAEMON_AUDIT_KEY.get().map(SigningKey::verifying_key)
}

/// The exact bytes a daemon signature of `domain` over `body` is made over.
#[must_use]
pub fn preimage(domain: DaemonDomain, body: &[u8]) -> Vec<u8> {
    let tag = domain.tag();
    let mut out = Vec::with_capacity(tag.len() + body.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
}

/// Sign `body` under `domain` with the installed daemon key. Returns
/// `Some((signature, "daemon_signed"))`, or `None` when no key is installed.
#[must_use]
pub fn sign(domain: DaemonDomain, body: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let key = DAEMON_AUDIT_KEY.get()?;
    Some((
        sign_with(key, domain, body),
        crate::models::AttestLevel::DaemonSigned.as_str(),
    ))
}

/// The one daemon `.sign(` call: `key` over `domain.tag() || body`.
fn sign_with(key: &SigningKey, domain: DaemonDomain, body: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(&preimage(domain, body));
    sig.to_bytes().to_vec()
}

/// #10145 (3-agent vote (71472661) V2-10108-KEYLESS-MARKER) — the daemon key
/// as a value, for the one path that writes the signed genesis marker (schema
/// create or v103 bump). It holds the private half by construction: no
/// `Default`, no `Option`, and the only way in is `TryFrom<AgentKeypair>`,
/// which refuses a public-only or mismatched keypair. It is never cloned and
/// its `Debug` never prints the key.
pub struct DaemonChainSigner {
    key: SigningKey,
}

impl std::fmt::Debug for DaemonChainSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonChainSigner")
            .field("verifying_key", &self.key.verifying_key())
            .finish_non_exhaustive()
    }
}

impl TryFrom<crate::identity::keypair::AgentKeypair> for DaemonChainSigner {
    type Error = DaemonKeyMissing;

    fn try_from(kp: crate::identity::keypair::AgentKeypair) -> Result<Self, Self::Error> {
        let Some(key) = kp.private else {
            return Err(DaemonKeyMissing::new(DaemonKeyCause::PublicOnly, None));
        };
        if key.verifying_key() != kp.public {
            return Err(DaemonKeyMissing::new(DaemonKeyCause::KeyMismatch, None));
        }
        Ok(Self { key })
    }
}

impl DaemonChainSigner {
    /// #10145 K-5 — the signer for a schema create or v103 bump, from the
    /// daemon key in `key_dir`. Both halves are checked here first: a key is
    /// generated only when neither half exists, and a partial key (one half
    /// alone) is refused, never healed. Nothing in the database is touched.
    ///
    /// # Errors
    /// The typed, counted [`DaemonKeyMissing`] for every cause.
    pub fn provision(key_dir: &Path) -> Result<Self, DaemonKeyMissing> {
        use crate::identity::keypair::{
            DAEMON_KEYPAIR_LABEL, EnsureOutcome, agent_priv_path, agent_pub_path, ensure_keypair,
            load,
        };
        /// One provisioning at a time in this process, so two opens never see
        /// each other's half-written pair as a partial key. The guarded state
        /// is `()`, so a poisoned lock carries nothing torn (CONCURRENCY-18).
        static PROVISION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = PROVISION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let refuse = |cause| DaemonKeyMissing::new(cause, Some(key_dir));
        let has_pub = agent_pub_path(key_dir, DAEMON_KEYPAIR_LABEL).exists();
        let has_priv = agent_priv_path(key_dir, DAEMON_KEYPAIR_LABEL).exists();
        match (has_pub, has_priv) {
            (true, true) => {}
            (true, false) => return Err(refuse(DaemonKeyCause::PublicOnly)),
            (false, true) => return Err(refuse(DaemonKeyCause::PrivateOnly)),
            (false, false) => match ensure_keypair(DAEMON_KEYPAIR_LABEL, key_dir, false) {
                Ok(EnsureOutcome::Generated { .. } | EnsureOutcome::AlreadyExists { .. }) => {}
                Ok(EnsureOutcome::SkippedDisabled) => {
                    return Err(refuse(DaemonKeyCause::GenerationDisabled));
                }
                Ok(
                    EnsureOutcome::RepairedPublicFromPrivate { .. }
                    | EnsureOutcome::PublicOnlyDegraded { .. },
                )
                | Err(_) => return Err(refuse(DaemonKeyCause::KeyDirUnusable)),
            },
        }
        let kp = load(DAEMON_KEYPAIR_LABEL, key_dir)
            .map_err(|_| refuse(DaemonKeyCause::KeyDirUnusable))?;
        Self::try_from(kp).map_err(|e| refuse(e.cause()))
    }

    /// The daemon key already installed in this process (loaded from the key
    /// directory at boot, the key `verify_chain` checks against), else
    /// [`Self::provision`] in the resolved default key directory.
    ///
    /// # Errors
    /// [`DaemonKeyMissing`] with [`DaemonKeyCause::NoKeyDir`] when no key
    /// directory resolves, else as [`Self::provision`].
    pub fn provision_default() -> Result<Self, DaemonKeyMissing> {
        if let Some(key) = DAEMON_AUDIT_KEY.get() {
            return Ok(Self { key: key.clone() });
        }
        let dir = crate::identity::keypair::default_key_dir()
            .map_err(|_| DaemonKeyMissing::new(DaemonKeyCause::NoKeyDir, None))?;
        Self::provision(&dir)
    }

    /// #10108 K-7 (3-agent vote (71472661) V2-10108-KEYLESS-MARKER) — the
    /// typed cause a ledger-writing boot refuses with when its agent is the
    /// daemon label and the daemon key in the resolved key directory is
    /// partial (one half alone), so the serve path surfaces the same typed
    /// refusal as the open path. Reads two paths; generates and heals
    /// nothing. `None` for another agent id, or when the key is whole or
    /// wholly absent (the boot's ensure step owns those).
    #[must_use]
    pub fn partial_key_refusal(agent_id: &str) -> Option<DaemonKeyMissing> {
        use crate::identity::keypair::{
            DAEMON_KEYPAIR_LABEL, agent_priv_path, agent_pub_path, default_key_dir,
        };
        if agent_id != DAEMON_KEYPAIR_LABEL {
            return None;
        }
        let Ok(dir) = default_key_dir() else {
            return Some(DaemonKeyMissing::new(DaemonKeyCause::NoKeyDir, None));
        };
        let has_pub = agent_pub_path(&dir, DAEMON_KEYPAIR_LABEL).exists();
        let has_priv = agent_priv_path(&dir, DAEMON_KEYPAIR_LABEL).exists();
        let cause = match (has_pub, has_priv) {
            (true, false) => DaemonKeyCause::PublicOnly,
            (false, true) => DaemonKeyCause::PrivateOnly,
            (true, true) | (false, false) => return None,
        };
        Some(DaemonKeyMissing::new(cause, Some(&dir)))
    }

    /// The public half, for verifying what this signer wrote.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign `row` as a daemon row: sets `attest_level` to `daemon_signed`
    /// first (it is part of the signed input), then the signature over
    /// [`DaemonDomain::EventRow`] and
    /// [`crate::signed_events::daemon_row_signing_input`].
    pub fn sign_row(&self, row: &mut crate::signed_events::SignedEvent) {
        crate::models::AttestLevel::DaemonSigned
            .as_str()
            .clone_into(&mut row.attest_level);
        let body = crate::signed_events::daemon_row_signing_input(row);
        row.signature = Some(sign_with(&self.key, DaemonDomain::EventRow, &body));
    }

    /// `true` iff `row` is `daemon_signed` and its signature verifies under
    /// `vk` over the same input [`Self::sign_row`] signs.
    #[must_use]
    pub fn verify_row(vk: &VerifyingKey, row: &crate::signed_events::SignedEvent) -> bool {
        let Some(sig) = row.signature.as_deref() else {
            return false;
        };
        row.attest_level == crate::models::AttestLevel::DaemonSigned.as_str()
            && verify(
                vk,
                DaemonDomain::EventRow,
                &crate::signed_events::daemon_row_signing_input(row),
                sig,
            )
    }
}

/// Why no [`DaemonChainSigner`] could be built. Matched exhaustively by the
/// refusal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonKeyCause {
    /// Key generation is disabled (`[identity].disabled`) and no key exists.
    GenerationDisabled,
    /// The public half exists without its private half.
    PublicOnly,
    /// The private half exists without its public half (never healed here).
    PrivateOnly,
    /// The two halves are not one keypair.
    KeyMismatch,
    /// No key directory resolves (no home directory).
    NoKeyDir,
    /// The key directory is unwritable or insecure, or a key file is unreadable.
    KeyDirUnusable,
}

impl DaemonKeyCause {
    fn describe(self) -> &'static str {
        match self {
            Self::GenerationDisabled => "key generation is disabled and no daemon key exists",
            Self::PublicOnly => "the daemon public key exists without its private key",
            Self::PrivateOnly => "the daemon private key exists without its public key",
            Self::KeyMismatch => "the daemon public and private keys are not one keypair",
            Self::NoKeyDir => "no key directory resolves (no home directory)",
            Self::KeyDirUnusable => {
                "the key directory is unwritable or insecure, or a key file is unreadable"
            }
        }
    }
}

static DAEMON_KEY_MISSING_TOTAL: AtomicU64 = AtomicU64::new(0);

/// How many [`DaemonKeyMissing`] refusals this process has raised.
#[must_use]
pub fn daemon_key_missing_total() -> u64 {
    DAEMON_KEY_MISSING_TOTAL.load(Ordering::Relaxed)
}

/// #10145 K-3 — the typed, counted refusal of a schema create or v103 bump
/// that has no daemon private key. Nothing is written when it is raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonKeyMissing {
    cause: DaemonKeyCause,
    key_dir: Option<PathBuf>,
}

impl DaemonKeyMissing {
    /// Raise (and count) the refusal.
    #[must_use]
    pub fn new(cause: DaemonKeyCause, key_dir: Option<&Path>) -> Self {
        DAEMON_KEY_MISSING_TOTAL.fetch_add(1, Ordering::Relaxed);
        Self {
            cause,
            key_dir: key_dir.map(Path::to_path_buf),
        }
    }

    /// The cause.
    #[must_use]
    pub fn cause(&self) -> DaemonKeyCause {
        self.cause
    }
}

impl std::fmt::Display for DaemonKeyMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dir = self
            .key_dir
            .as_deref()
            .map_or_else(|| "<unresolved>".to_string(), |d| d.display().to_string());
        write!(
            f,
            "daemon key missing: {}; creating or upgrading the database needs the daemon \
             signing key (key directory {dir}, override with AI_MEMORY_KEY_DIR); provision it \
             with `ai-memory identity generate --agent-id daemon`; the database was not \
             touched and can still be copied out with `ai-memory backup`",
            self.cause.describe()
        )
    }
}

impl std::error::Error for DaemonKeyMissing {}

/// `true` iff `signature` is a strict Ed25519 signature by `vk` over
/// `domain.tag() || body`.
#[must_use]
pub fn verify(vk: &VerifyingKey, domain: DaemonDomain, body: &[u8], signature: &[u8]) -> bool {
    let Ok(arr) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    vk.verify_strict(&preimage(domain, body), &Signature::from_bytes(&arr))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{DaemonDomain, preimage};

    #[test]
    fn no_domain_tag_is_a_prefix_of_another_10074() {
        for a in DaemonDomain::ALL {
            for b in DaemonDomain::ALL {
                if a != b {
                    assert!(
                        !b.tag().starts_with(a.tag()),
                        "{a:?} tag is a prefix of {b:?} tag"
                    );
                }
            }
        }
    }

    /// #10155 (K-9) — `ALL` lists every domain exactly once. The match has no
    /// wildcard arm (per CBC-04), so a new variant does not compile until it
    /// gets its slot here, and the slot test fails until it is in `ALL`.
    #[test]
    fn all_lists_every_domain_exactly_once_10155() {
        const DOMAIN_COUNT: usize = 6;
        fn slot(d: DaemonDomain) -> usize {
            match d {
                DaemonDomain::EventRow => 0,
                DaemonDomain::EventPayload => 1,
                DaemonDomain::Governance => 2,
                DaemonDomain::Tombstone => 3,
                DaemonDomain::RevisionLeaf => 4,
                DaemonDomain::LegacyCutoff => 5,
            }
        }
        assert_eq!(DaemonDomain::ALL.len(), DOMAIN_COUNT);
        let mut seen = [false; DOMAIN_COUNT];
        for d in DaemonDomain::ALL {
            let s = slot(d);
            assert!(!seen[s], "{d:?} is listed twice in ALL");
            seen[s] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "a domain is missing from ALL: {seen:?}"
        );
    }

    #[test]
    fn preimage_is_tag_then_body_10074() {
        let p = preimage(DaemonDomain::EventRow, b"xyz");
        assert_eq!(p, b"ai-memory/daemon-sig/v2/event-row\0xyz");
    }

    mod chain_signer_10145 {
        use super::super::{DaemonChainSigner, DaemonKeyCause, DaemonKeyMissing};
        use crate::identity::keypair::AgentKeypair;
        use crate::signed_events::SignedEvent;
        use ed25519_dalek::SigningKey;

        const SEED: [u8; 32] = [7u8; 32];
        const OTHER_SEED: [u8; 32] = [9u8; 32];

        fn pair(seed: [u8; 32]) -> AgentKeypair {
            let key = SigningKey::from_bytes(&seed);
            AgentKeypair {
                agent_id: crate::identity::keypair::DAEMON_KEYPAIR_LABEL.to_string(),
                public: key.verifying_key(),
                private: Some(key),
            }
        }

        fn row() -> SignedEvent {
            SignedEvent {
                id: "row-10145".to_string(),
                agent_id: "ai-memory:migration-v103".to_string(),
                event_type: "signed_events.agent_cutover".to_string(),
                payload_hash: vec![3u8; 33],
                signature: None,
                attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
                timestamp: "2026-11-26T00:00:00+00:00".to_string(),
                prev_hash: vec![0u8; 32],
                sequence: 1,
                cause_hash: None,
            }
        }

        #[test]
        fn a_public_only_keypair_builds_no_chain_signer_10145() {
            let mut kp = pair(SEED);
            kp.private = None;
            let err = DaemonChainSigner::try_from(kp).expect_err("public-only must refuse");
            assert_eq!(err.cause(), DaemonKeyCause::PublicOnly);
        }

        #[test]
        fn a_mismatched_keypair_builds_no_chain_signer_10145() {
            let mut kp = pair(SEED);
            kp.public = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
            let err = DaemonChainSigner::try_from(kp).expect_err("mismatch must refuse");
            assert_eq!(err.cause(), DaemonKeyCause::KeyMismatch);
        }

        #[test]
        fn a_signed_row_verifies_and_every_flipped_byte_fails_10145() {
            let signer = DaemonChainSigner::try_from(pair(SEED)).expect("full keypair");
            let vk = signer.verifying_key();
            let mut signed = row();
            signer.sign_row(&mut signed);
            assert_eq!(
                signed.attest_level,
                crate::models::AttestLevel::DaemonSigned.as_str()
            );
            assert_eq!(signed.signature.as_ref().map(Vec::len), Some(64));
            assert!(DaemonChainSigner::verify_row(&vk, &signed));
            let other = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
            assert!(!DaemonChainSigner::verify_row(&other, &signed));
            for i in 0..signed.payload_hash.len() {
                let mut m = signed.clone();
                m.payload_hash[i] ^= 1;
                assert!(!DaemonChainSigner::verify_row(&vk, &m), "payload byte {i}");
            }
            for i in 0..64 {
                let mut m = signed.clone();
                if let Some(s) = m.signature.as_mut() {
                    s[i] ^= 1;
                }
                assert!(
                    !DaemonChainSigner::verify_row(&vk, &m),
                    "signature byte {i}"
                );
            }
            let mut m = signed.clone();
            m.sequence = 2;
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "sequence");
            let mut m = signed.clone();
            m.attest_level = crate::models::AttestLevel::Unsigned.as_str().to_string();
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "attest level");
            let mut m = signed;
            m.signature = None;
            assert!(!DaemonChainSigner::verify_row(&vk, &m), "no signature");
        }

        #[test]
        fn the_refusal_is_counted_and_names_the_provisioning_command_10145() {
            let before = super::super::daemon_key_missing_total();
            let err = DaemonKeyMissing::new(DaemonKeyCause::GenerationDisabled, None);
            assert!(super::super::daemon_key_missing_total() > before);
            let text = err.to_string();
            assert!(
                text.contains("ai-memory identity generate --agent-id daemon"),
                "{text}"
            );
            assert!(text.contains("AI_MEMORY_KEY_DIR"), "{text}");
            assert!(text.contains("ai-memory backup"), "{text}");
            assert!(text.contains("key generation is disabled"), "{text}");
        }
    }
}
