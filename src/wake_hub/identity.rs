// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` identity boundary (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467); the real
//! verifier is issue
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! Two gates, both trait boundaries so the hub core can be tested end-to-end
//! over a real socket without any of the delegation machinery existing yet:
//!
//! 1. [`PeerAuthorizer`] — kernel-attested peer credentials. The default
//!    [`SameUidAuthorizer`] admits only peers whose uid equals this process's
//!    effective uid, which is what makes the 0600 socket a real boundary rather
//!    than a hint.
//! 2. [`HelloVerifier`] — the cryptographic half. The default shipped by this
//!    issue is [`DenyAllVerifier`]: until #3468 lands the scoped
//!    `a2a-hub/join/v1` delegation, EVERY hello is refused. That is deliberate.
//!    A hub that admitted unauthenticated peers "until identity lands" would be
//!    exactly the fail-open default the North Star forbids; refusing loudly
//!    costs a wake hint, and the `<=60 s` backstop poll still delivers.
//!
//! # Why a transcript, not a bare nonce
//!
//! The vote's item 7 requires the signature to cover a domain-separated
//! transcript binding the hub, the challenge, the claimed agent and the
//! asserted topics — so a signature harvested by one hub cannot be replayed at
//! another, against another agent id, or with a different topic set spliced in.
//! [`hello_transcript`] is that pre-image, and every field is length-prefixed
//! so no two distinct inputs can produce the same bytes.
//!
//! # Refusals never become an oracle
//!
//! [`DenyReason`] carries a precise reason for the LOG. Everything that reaches
//! the wire collapses to a single `401 unauthorized`
//! ([`DenyReason::wire_reason`]), so a peer cannot distinguish "unknown agent"
//! from "bad signature" from "expired delegation" by probing.

use std::fmt;

use sha2::{Digest, Sha256};

use super::frame::ErrorCode;
use super::limits::{HELLO_NONCE_BYTES, MAX_ID_BYTES, PUBKEY_BYTES};

/// Domain separator for the hello transcript. Distinct from every ai-memory
/// signing domain: a wake-hub signature must never cross-verify as write
/// authority in the durable identity root.
pub const HELLO_TRANSCRIPT_DOMAIN: &[u8] = b"a2a/v1/hello";

/// The single string every identity refusal is reported to the peer as.
pub const WIRE_UNAUTHORIZED_REASON: &str = "unauthorized";

// ---------------------------------------------------------------------------
// Peer credentials
// ---------------------------------------------------------------------------

/// Kernel-attested peer credentials read off the connected socket
/// (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` + `getpeereid` on macOS — tokio
/// abstracts both behind `UnixStream::peer_cred`).
///
/// `pid` is `Option` because tokio reports it that way; the hub ASSERTS at
/// start-up that this platform supplies it (see
/// [`super::startup::assert_peer_credentials_available`]) so a runtime `None`
/// is a bug, not a platform difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCred {
    /// Peer's effective uid.
    pub uid: u32,
    /// Peer's effective gid.
    pub gid: u32,
    /// Peer's pid, when the platform supplies it.
    pub pid: Option<i32>,
}

// ---------------------------------------------------------------------------
// Deny reasons
// ---------------------------------------------------------------------------

/// Why a peer or a hello was refused. Logged in full; never sent in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Peer uid is not the uid the hub runs as.
    PeerUidMismatch {
        /// uid the hub requires.
        expected: u32,
        /// uid the kernel reported.
        got: u32,
    },
    /// The platform did not supply a peer pid on an established connection.
    PeerPidUnavailable,
    /// No identity verifier is wired yet (the shipped default until #3468).
    IdentityNotConfigured,
    /// The agent id is not in the derived allowlist cache.
    UnknownAgent,
    /// The transcript signature did not verify against the presented key.
    BadSignature,
    /// The presented key is not the key bound to that agent id.
    KeyMismatch,
    /// The scoped delegation has expired or was revoked.
    DelegationInvalid,
    /// The claimed agent id was over [`MAX_ID_BYTES`] or empty.
    MalformedAgentId,
    /// The asserted topic set was rejected for this agent.
    TopicsRefused,
}

impl DenyReason {
    /// The code sent to the peer. Always `401` for identity refusals so the
    /// wire carries no discrimination signal.
    #[must_use]
    pub const fn wire_code(&self) -> ErrorCode {
        ErrorCode::Unauthorized
    }

    /// The reason string sent to the peer. Deliberately constant.
    #[must_use]
    pub const fn wire_reason(&self) -> &'static str {
        WIRE_UNAUTHORIZED_REASON
    }

    /// Stable label for logs and metrics.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PeerUidMismatch { .. } => "peer_uid_mismatch",
            Self::PeerPidUnavailable => "peer_pid_unavailable",
            Self::IdentityNotConfigured => "identity_not_configured",
            Self::UnknownAgent => "unknown_agent",
            Self::BadSignature => "bad_signature",
            Self::KeyMismatch => "key_mismatch",
            Self::DelegationInvalid => "delegation_invalid",
            Self::MalformedAgentId => "malformed_agent_id",
            Self::TopicsRefused => "topics_refused",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUidMismatch { expected, got } => {
                write!(f, "peer uid {got} is not the hub uid {expected}")
            }
            Self::PeerPidUnavailable => f.write_str("platform supplied no peer pid"),
            Self::IdentityNotConfigured => f.write_str(
                "no wake-hub identity verifier is configured — the scoped \
                 a2a-hub/join/v1 delegation lands in #3468; every hello is refused \
                 until then",
            ),
            Self::UnknownAgent => f.write_str("agent id is not in the allowlist cache"),
            Self::BadSignature => f.write_str("hello transcript signature did not verify"),
            Self::KeyMismatch => f.write_str("presented key is not bound to that agent id"),
            Self::DelegationInvalid => f.write_str("scoped delegation expired or revoked"),
            Self::MalformedAgentId => f.write_str("claimed agent id was empty or over-long"),
            Self::TopicsRefused => {
                f.write_str("asserted topics are outside the agent's read scope")
            }
        }
    }
}

impl std::error::Error for DenyReason {}

// ---------------------------------------------------------------------------
// Peer authorization
// ---------------------------------------------------------------------------

/// Gate on kernel-attested peer credentials, evaluated BEFORE a single byte is
/// read from the connection.
pub trait PeerAuthorizer: Send + Sync + 'static {
    /// Admit or refuse a connected peer.
    ///
    /// # Errors
    ///
    /// A [`DenyReason`] when the peer must be refused. The connection is then
    /// closed without being read from.
    fn authorize(&self, cred: PeerCred) -> Result<(), DenyReason>;
}

/// Production peer gate: the peer must run as the same uid as the hub.
///
/// The socket's 0600 mode and its 0700 parent directory already enforce this at
/// the filesystem layer; checking the kernel-attested credential too means a
/// mis-set mode (or a directory an operator loosened) degrades to a refusal
/// rather than to admission.
#[derive(Debug, Clone, Copy)]
pub struct SameUidAuthorizer {
    expected_uid: u32,
}

impl SameUidAuthorizer {
    /// Require the hub process's own effective uid.
    #[must_use]
    pub fn for_current_process() -> Self {
        // SAFETY: `geteuid` reads a process property, takes no pointer, and
        // cannot fail. Same call shape as `src/identity/keypair.rs`.
        let uid = unsafe { libc::geteuid() };
        Self { expected_uid: uid }
    }

    /// Require an explicit uid. Used by the DENIED regression tests to
    /// exercise the wrong-peer-uid path over a real socket without needing a
    /// second user account.
    #[must_use]
    pub const fn with_uid(expected_uid: u32) -> Self {
        Self { expected_uid }
    }

    /// The uid this authorizer admits.
    #[must_use]
    pub const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }
}

impl PeerAuthorizer for SameUidAuthorizer {
    fn authorize(&self, cred: PeerCred) -> Result<(), DenyReason> {
        if cred.pid.is_none() {
            return Err(DenyReason::PeerPidUnavailable);
        }
        if cred.uid != self.expected_uid {
            return Err(DenyReason::PeerUidMismatch {
                expected: self.expected_uid,
                got: cred.uid,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hello verification
// ---------------------------------------------------------------------------

/// Everything the verifier is given about one handshake attempt.
#[derive(Debug, Clone, Copy)]
pub struct HelloRequest<'a> {
    /// This hub's identifier, as bound into the transcript.
    pub hub_id: &'a str,
    /// The hub-issued challenge nonce for THIS connection.
    pub nonce: &'a [u8; HELLO_NONCE_BYTES],
    /// The agent id carried in the frame header's `from`.
    pub claimed_agent_id: &'a str,
    /// Ed25519 public key the client presented.
    pub pubkey: &'a [u8; PUBKEY_BYTES],
    /// Signature the client presented over [`hello_transcript`], made with the
    /// DELEGATED key in `pubkey`.
    pub signature: &'a [u8],
    /// The scoped `a2a-hub/join/v1` delegation the client presented (#3468),
    /// as carried on the wire. Empty means none was presented — which every
    /// production verifier refuses, but as a logged `401` rather than a
    /// framing error.
    pub delegation: &'a [u8],
    /// Topics the client asserted, in wire order.
    pub topics: &'a [String],
    /// Kernel-attested peer credentials for this connection.
    pub peer: PeerCred,
}

impl HelloRequest<'_> {
    /// The exact bytes the signature must cover.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        hello_transcript(
            self.hub_id,
            self.nonce,
            self.claimed_agent_id,
            &topics_hash(self.topics),
        )
    }
}

/// Which membership frame is being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MembershipAction {
    /// `join` — admission of a new member. Admission is an operator decision
    /// recorded on the ai-memory audit spine, which is why the shipped default
    /// refuses it.
    Join,
    /// `depart` — the member ends its own membership.
    Depart,
}

impl MembershipAction {
    /// Domain separator for this action's transcript. Distinct from
    /// [`HELLO_TRANSCRIPT_DOMAIN`] so a hello signature can never be replayed
    /// as a depart (which would let a passive observer of one handshake destroy
    /// another agent's membership).
    #[must_use]
    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::Join => b"a2a/v1/join",
            Self::Depart => b"a2a/v1/depart",
        }
    }
}

/// A nonce-bound membership request.
#[derive(Debug, Clone, Copy)]
pub struct MembershipRequest<'a> {
    /// Which action.
    pub action: MembershipAction,
    /// This hub's identifier.
    pub hub_id: &'a str,
    /// The hub-issued challenge nonce for THIS connection.
    pub nonce: &'a [u8; HELLO_NONCE_BYTES],
    /// The authenticated agent id the session is bound to.
    pub agent_id: &'a str,
    /// The key the session authenticated with. Carried so a verifier can
    /// actually CHECK the membership signature: without it the request could
    /// only ever be rubber-stamped, which is why the trait default refuses.
    pub pubkey: &'a [u8; PUBKEY_BYTES],
    /// Signature over [`membership_transcript`].
    pub signature: &'a [u8],
    /// Kernel-attested peer credentials.
    pub peer: PeerCred,
}

impl MembershipRequest<'_> {
    /// The exact bytes the signature must cover.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        membership_transcript(self.action, self.hub_id, self.nonce, self.agent_id)
    }
}

/// The identity a verified hello establishes for the rest of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgent {
    /// The authenticated agent id. Every later frame's `from` must equal this,
    /// and the hub stamps THIS value on egress regardless of what the client
    /// wrote.
    pub agent_id: String,
    /// The key the session is bound to.
    pub pubkey: [u8; PUBKEY_BYTES],
}

/// Cryptographic half of the handshake.
pub trait HelloVerifier: Send + Sync + 'static {
    /// Verify a handshake and return the identity to bind to the session.
    ///
    /// # Errors
    ///
    /// A [`DenyReason`]. Implementations MUST fail closed: any doubt is a
    /// refusal, never an admission.
    fn verify(&self, req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason>;

    /// Verify a nonce-bound `join` / `depart`.
    ///
    /// The default REFUSES. Membership admission and revocation are audit-spine
    /// events in the durable identity root, so a hub that has no verifier wired
    /// must not be able to grant or destroy membership.
    ///
    /// # Errors
    ///
    /// A [`DenyReason`]. Implementations MUST fail closed.
    fn verify_membership(&self, _req: &MembershipRequest<'_>) -> Result<(), DenyReason> {
        Err(DenyReason::IdentityNotConfigured)
    }
}

/// The verifier the `ai-memory wake-hub` subcommand ships with until #3468.
///
/// Refuses every hello. The hub still binds its socket, still asserts its
/// start-up invariants and still serves metrics, so an operator can verify the
/// posture — but no session is ever established. This is the fail-closed
/// default; there is deliberately NO CLI flag that swaps it out, because a flag
/// that disables identity verification is a flag that will eventually be set in
/// production.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllVerifier;

impl HelloVerifier for DenyAllVerifier {
    fn verify(&self, _req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason> {
        Err(DenyReason::IdentityNotConfigured)
    }
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

/// Build the domain-separated, length-prefixed hello transcript:
/// `"a2a/v1/hello" ‖ len(hub_id) ‖ hub_id ‖ nonce ‖ len(agent_id) ‖ agent_id ‖
/// topics_hash`.
///
/// Length prefixes are what make the encoding injective: without them
/// `hub_id = "ab"`, `agent_id = "c"` and `hub_id = "a"`, `agent_id = "bc"`
/// would hash the same bytes, and a signature harvested for one pair would
/// verify for the other.
#[must_use]
pub fn hello_transcript(
    hub_id: &str,
    nonce: &[u8; HELLO_NONCE_BYTES],
    agent_id: &str,
    topics_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HELLO_TRANSCRIPT_DOMAIN.len() + 2 + hub_id.len() + agent_id.len() + HELLO_NONCE_BYTES + 32,
    );
    out.extend_from_slice(HELLO_TRANSCRIPT_DOMAIN);
    push_len_prefixed(&mut out, hub_id.as_bytes());
    out.extend_from_slice(nonce);
    push_len_prefixed(&mut out, agent_id.as_bytes());
    out.extend_from_slice(topics_hash);
    out
}

/// Build a membership transcript:
/// `domain ‖ len(hub_id) ‖ hub_id ‖ nonce ‖ len(agent_id) ‖ agent_id`.
///
/// Same length-prefixed, domain-separated shape as [`hello_transcript`], so a
/// signature is bound to one hub, one connection's nonce, one agent and one
/// action.
#[must_use]
pub fn membership_transcript(
    action: MembershipAction,
    hub_id: &str,
    nonce: &[u8; HELLO_NONCE_BYTES],
    agent_id: &str,
) -> Vec<u8> {
    let domain = action.domain();
    let mut out =
        Vec::with_capacity(domain.len() + 2 + hub_id.len() + agent_id.len() + HELLO_NONCE_BYTES);
    out.extend_from_slice(domain);
    push_len_prefixed(&mut out, hub_id.as_bytes());
    out.extend_from_slice(nonce);
    push_len_prefixed(&mut out, agent_id.as_bytes());
    out
}

/// SHA-256 over the canonical topic list: each topic length-prefixed, in the
/// order the client asserted them.
#[must_use]
pub fn topics_hash(topics: &[String]) -> [u8; 32] {
    let mut h = Sha256::new();
    for t in topics {
        let len = u8::try_from(t.len()).unwrap_or(u8::MAX);
        h.update([len]);
        h.update(t.as_bytes());
    }
    h.finalize().into()
}

/// Length-prefix a field that is bounded by [`MAX_ID_BYTES`]. An over-long
/// field is truncated to a `u8` length only after the caller has already
/// refused it, so this saturation is unreachable in practice; it exists so the
/// helper cannot panic (`ERRORS-08`).
fn push_len_prefixed(out: &mut Vec<u8>, raw: &[u8]) {
    debug_assert!(
        raw.len() <= MAX_ID_BYTES,
        "callers bound ids before signing"
    );
    out.push(u8::try_from(raw.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(raw);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; HELLO_NONCE_BYTES] = [7u8; HELLO_NONCE_BYTES];

    #[test]
    fn same_uid_authorizer_admits_its_own_uid_and_refuses_others() {
        let a = SameUidAuthorizer::with_uid(1_000);
        let ok = PeerCred {
            uid: 1_000,
            gid: 1_000,
            pid: Some(42),
        };
        assert!(a.authorize(ok).is_ok());
        let bad = PeerCred { uid: 1_001, ..ok };
        assert_eq!(
            a.authorize(bad),
            Err(DenyReason::PeerUidMismatch {
                expected: 1_000,
                got: 1_001
            })
        );
    }

    #[test]
    fn same_uid_authorizer_refuses_a_peer_with_no_pid() {
        let a = SameUidAuthorizer::with_uid(1_000);
        let no_pid = PeerCred {
            uid: 1_000,
            gid: 1_000,
            pid: None,
        };
        assert_eq!(a.authorize(no_pid), Err(DenyReason::PeerPidUnavailable));
    }

    #[test]
    fn the_shipped_verifier_refuses_every_hello() {
        let topics = vec!["#hive".to_string()];
        let req = HelloRequest {
            hub_id: "hub",
            nonce: &NONCE,
            claimed_agent_id: "agent-a",
            pubkey: &[0u8; PUBKEY_BYTES],
            signature: &[0u8; 64],
            delegation: &[],
            topics: &topics,
            peer: PeerCred {
                uid: 1_000,
                gid: 1_000,
                pid: Some(1),
            },
        };
        assert_eq!(
            DenyAllVerifier.verify(&req),
            Err(DenyReason::IdentityNotConfigured)
        );
    }

    #[test]
    fn every_deny_reason_collapses_to_one_wire_answer() {
        for r in [
            DenyReason::PeerUidMismatch {
                expected: 1,
                got: 2,
            },
            DenyReason::PeerPidUnavailable,
            DenyReason::IdentityNotConfigured,
            DenyReason::UnknownAgent,
            DenyReason::BadSignature,
            DenyReason::KeyMismatch,
            DenyReason::DelegationInvalid,
            DenyReason::MalformedAgentId,
            DenyReason::TopicsRefused,
        ] {
            assert_eq!(r.wire_code(), ErrorCode::Unauthorized);
            assert_eq!(r.wire_reason(), WIRE_UNAUTHORIZED_REASON);
            assert!(!r.label().is_empty());
        }
    }

    #[test]
    fn transcript_is_domain_separated() {
        let t = hello_transcript("hub", &NONCE, "agent-a", &[0u8; 32]);
        assert!(t.starts_with(HELLO_TRANSCRIPT_DOMAIN));
    }

    #[test]
    fn transcript_length_prefixes_prevent_field_splicing() {
        let h = [0u8; 32];
        let a = hello_transcript("ab", &NONCE, "c", &h);
        let b = hello_transcript("a", &NONCE, "bc", &h);
        assert_ne!(
            a, b,
            "un-prefixed concatenation would make these identical and let a \
             signature be replayed across a different (hub, agent) pair"
        );
    }

    #[test]
    fn transcript_binds_the_nonce_the_hub_issued() {
        let other = [8u8; HELLO_NONCE_BYTES];
        assert_ne!(
            hello_transcript("hub", &NONCE, "a", &[0u8; 32]),
            hello_transcript("hub", &other, "a", &[0u8; 32])
        );
    }

    #[test]
    fn membership_transcripts_are_domain_separated_from_hello_and_each_other() {
        let h = hello_transcript("hub", &NONCE, "a", &topics_hash(&[]));
        let j = membership_transcript(MembershipAction::Join, "hub", &NONCE, "a");
        let d = membership_transcript(MembershipAction::Depart, "hub", &NONCE, "a");
        assert_ne!(h, j);
        assert_ne!(h, d);
        assert_ne!(
            j, d,
            "a join signature must never verify as a depart, or observing one \
             handshake would let an attacker end another agent's membership"
        );
    }

    #[test]
    fn the_shipped_verifier_refuses_membership_changes() {
        let req = MembershipRequest {
            action: MembershipAction::Depart,
            hub_id: "hub",
            nonce: &NONCE,
            agent_id: "agent-a",
            pubkey: &[0u8; PUBKEY_BYTES],
            signature: &[0u8; 64],
            peer: PeerCred {
                uid: 1_000,
                gid: 1_000,
                pid: Some(1),
            },
        };
        assert_eq!(
            DenyAllVerifier.verify_membership(&req),
            Err(DenyReason::IdentityNotConfigured)
        );
    }

    #[test]
    fn topics_hash_is_order_sensitive_and_splice_resistant() {
        let a = topics_hash(&["#hive".into(), "#swarm".into()]);
        let b = topics_hash(&["#swarm".into(), "#hive".into()]);
        assert_ne!(a, b);
        let c = topics_hash(&["#hi".into(), "ve#swarm".into()]);
        assert_ne!(a, c, "length prefixes must prevent topic splicing");
    }
}
