// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3464 — proof of possession for agent public-key binding.
//!
//! Before this module, `PUT /api/v1/agents/{id}/pubkey` (and the CLI/storage
//! twins) took a **self-asserted** base64 key and wrote it onto the agent's
//! `_agents` registration row. The key was validated as a curve point,
//! admin-gated and audited — but nothing proved the caller controlled the
//! matching PRIVATE key. So anyone holding the admin role could bind a key
//! they owned to somebody else's agent id and then mint `agent_attested`
//! writes as that agent: the strongest provenance claim the substrate makes,
//! forgeable from a role claim alone.
//!
//! The fix is a challenge-response, and — more importantly — a TYPE that
//! makes the unproven bind unrepresentable. [`PossessionProof`] has no public
//! constructor: the only ways to obtain one are
//! [`PossessionProof::verify_challenge_response`] (a signature by the
//! candidate key over a storage-consumed, single-use, domain-separated
//! transcript; accepted only for first bootstrap or same-key reassertion) and
//! the crate-internal lineage constructors: predecessor-signed succession may
//! advance only an OPEN head, while independently verified M-of-N guardian
//! recovery may also advance a CLOSED/revoked head.
//! `storage::bind_agent_pubkey` consumes the [`PossessionProof`] and atomically
//! checks its private target/key claims against current storage state, so a
//! witness cannot be reused or retargeted and candidate possession cannot
//! replace an anchored identity. That is the control: a structural prevention,
//! not an enumerated set of guarded entry points.
//!
//! # Transcript
//!
//! The bytes the candidate key signs are domain-separated and
//! LENGTH-PREFIXED, so no field boundary can be shifted to make one
//! transcript read as another (`agent_id="a"`, `pubkey="bc"` and
//! `agent_id="ab"`, `pubkey="c"` produce different bytes):
//!
//! ```text
//! "ai-memory/bind-pubkey/v1"
//!   || u32be(len(agent_id))   || agent_id
//!   || u32be(len(pubkey_b64)) || pubkey_b64
//!   || u32be(len(nonce_b64))  || nonce_b64
//!   || u32be(len(expires_at)) || expires_at
//! ```
//!
//! Binding `agent_id` AND `pubkey_b64` into the signed bytes means a proof
//! captured for one (agent, key) pair cannot be replayed onto another, and
//! binding `expires_at` means the freshness bound the server issued is itself
//! covered by the signature.
//!
//! # Freshness and single use
//!
//! The nonce is minted by the daemon and stored DURABLY in
//! `agent_pubkey_challenges` (see `storage::issue_pubkey_bind_challenge`);
//! consuming it is one atomic conditional `UPDATE` whose `consumed_at IS NULL`
//! predicate IS the admit-once decision, so a challenge can authorize at most
//! one proof-verification attempt even under concurrent submission. A bad
//! answer burns the nonce and authorizes no bind.
//!
//! Durable rather than in-process, deliberately: the certified Postgres tier
//! supports SEVERAL DAEMONS ON ONE SHARED STORE, so issuing the challenge on
//! one replica and answering it on another is a SUPPORTED deployment shape,
//! not an edge case. An in-process cache would fail those binds closed with an
//! opaque 403 and no in-product remedy, would void every outstanding enrolment
//! on a rolling deploy, and could not serve the CLI, which holds no daemon at
//! all.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;

/// Domain tag for the bind-challenge transcript. Distinct from every other
/// signing domain in the substrate, so a signature minted for a write, a
/// link, a lineage record or a sub-key cert can never be replayed as a
/// possession proof (and vice versa).
pub const BIND_CHALLENGE_V1_DOMAIN: &str = "ai-memory/bind-pubkey/v1";

/// Lifetime of an issued bind challenge, in seconds. Short enough that a
/// leaked-but-unanswered nonce ages out quickly, long enough for an operator
/// to move the transcript to an offline signer.
pub const BIND_CHALLENGE_TTL_SECS: i64 = 300;

/// Byte length of the random nonce a challenge carries (256 bits).
pub const BIND_CHALLENGE_NONCE_LEN: usize = 32;

/// A server-issued, single-use bind challenge.
///
/// Deliberately the exact set of SIGNED-TRANSCRIPT inputs and nothing more.
/// The durable row's `challenge_id` is storage identity — it is not signed and
/// verification never reads it — so it stays inside the storage layer rather
/// than becoming a field every client would have to invent when it rebuilds a
/// challenge from the wire.
///
/// Every field is part of the signed transcript, so the candidate key
/// commits to the exact agent, the exact key, and the exact expiry the
/// daemon issued — not merely to an opaque nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindChallenge {
    /// URL-safe-no-pad base64 of [`BIND_CHALLENGE_NONCE_LEN`] random bytes.
    pub nonce_b64: String,
    /// The agent whose key is being bound.
    pub agent_id: String,
    /// The CANDIDATE key, exactly as it will be bound.
    pub pubkey_b64: String,
    /// RFC3339 expiry. At or after this instant the challenge is refused.
    pub expires_at: String,
}

/// Storage-issued receipt proving a durable challenge won the atomic
/// single-use consume.
///
/// Its field is private and it is deliberately neither [`Clone`] nor
/// constructible by callers. The only constructors live in the SQLite and
/// PostgreSQL consume funnels, so a caller-built [`BindChallenge`] can be
/// signed but can never mint a [`PossessionProof`]. Consuming this value in
/// [`PossessionProof::verify_challenge_response`] and then consuming that
/// witness in the bind funnel makes admit-once structural across the public
/// Rust API too, not just an HTTP/CLI convention.
#[derive(Debug)]
pub struct ConsumedBindChallenge(BindChallenge);

impl ConsumedBindChallenge {
    /// Minted only after the backend's conditional consume wins.
    #[must_use]
    pub(crate) fn from_storage(challenge: BindChallenge) -> Self {
        Self(challenge)
    }

    /// Crate-internal inspection for exact stored-expiry matching on the CLI.
    #[must_use]
    pub(crate) fn challenge(&self) -> &BindChallenge {
        &self.0
    }
}

/// Why a presented bind proof was refused.
///
/// The variants exist for logs and audit envelopes; every one of them is a
/// hard refusal on every surface (the [`crate::identity::subkey_cert`]
/// precedent — the wire response must not leak WHICH check failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindProofError {
    /// The candidate `pubkey_b64` is not a valid 32-byte Ed25519 point.
    MalformedPubkey,
    /// The proof is not a well-formed 64-byte Ed25519 signature.
    MalformedSignature,
    /// The challenge was issued for a different agent or a different
    /// candidate key than the bind being attempted.
    ChallengeMismatch,
    /// The challenge's `expires_at` is not RFC3339, or has passed.
    Expired,
    /// The signature did not verify under the candidate key.
    ProofInvalid,
    /// The witness does not authorize this exact binding, or the binding
    /// would replace/reopen an already-anchored identity without its current
    /// lineage authority.
    BindingNotAuthorized,
}

impl std::fmt::Display for BindProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MalformedPubkey => "candidate pubkey is not a valid ed25519 key",
            Self::MalformedSignature => "bind proof is not a well-formed ed25519 signature",
            Self::ChallengeMismatch => "bind challenge does not match the requested agent and key",
            Self::Expired => "bind challenge has expired",
            Self::ProofInvalid => "bind proof did not verify under the candidate key",
            Self::BindingNotAuthorized => {
                "bind is not authorized by the target agent's current trust lineage"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for BindProofError {}

/// Which authority admitted a key binding.
///
/// Recorded on the append-only key-history row so an auditor can tell a
/// possession-proved enrollment from a lineage rotation without re-deriving
/// it from surrounding tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindAuthority {
    /// The candidate key signed a server-issued challenge. External surfaces
    /// may use it only for an unanchored bootstrap or same-key reassertion;
    /// it never authorizes a distinct replacement.
    PossessionProof,
    /// A verified [`crate::identity::lineage`] succession record: the agent's
    /// CURRENT key-holder signed the rotation to this successor. Possession
    /// of the successor key is not demonstrated, but the party that controls
    /// the identity today authorised the change — the same authority model a
    /// CA uses, and strictly stronger than the pre-#3464 posture (a bare
    /// admin role claim).
    LineageSuccession,
    /// A fully verified M-of-N guardian recovery. Unlike an ordinary
    /// predecessor signature, this independent authority may advance an
    /// identity whose latest key-history window was explicitly closed.
    GuardianRecovery,
}

impl BindAuthority {
    /// Stable wire/row token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PossessionProof => "possession_proof",
            Self::LineageSuccession => "lineage_succession",
            Self::GuardianRecovery => "guardian_recovery",
        }
    }
}

/// Unforgeable witness that a key binding is authorised.
///
/// Constructible ONLY by [`Self::verify_challenge_response`] (external
/// bootstrap/same-key surfaces), [`Self::from_verified_lineage_succession`]
/// (crate-internal predecessor rotation), or
/// [`Self::from_verified_guardian_recovery`] (crate-internal M-of-N recovery).
/// Private tuple claims make retargeting a valid witness unrepresentable rather
/// than merely discouraged (rust-1.98 ERRORS-09).
#[derive(Debug)]
pub struct PossessionProof {
    authority: BindAuthority,
    /// Exact target tuple this witness authorizes. Keeping these claims on
    /// the unforgeable value prevents a valid proof from being passed to the
    /// storage funnel with different bind arguments.
    agent_id: String,
    pubkey_b64: String,
    /// Current/history key that authorized a verified lineage transition.
    /// External candidate-possession proofs never carry one and therefore
    /// cannot authorize replacement of an anchored identity.
    predecessor_pubkey_b64: Option<String>,
    /// The consumed challenge nonce, for the audit row. `None` for the
    /// lineage authority, which carries its own signed record.
    nonce_b64: Option<String>,
}

impl PossessionProof {
    /// The authority that admitted this binding.
    #[must_use]
    pub const fn authority(&self) -> BindAuthority {
        self.authority
    }

    /// The consumed challenge nonce, when the authority is a possession
    /// proof.
    #[must_use]
    pub fn nonce_b64(&self) -> Option<&str> {
        self.nonce_b64.as_deref()
    }

    /// Verify `signature_b64` as a signature by the challenge's candidate key
    /// over [`bind_challenge_transcript`], and mint the witness.
    ///
    /// `consumed` is an opaque receipt constructible only by a durable
    /// backend's atomic consume funnel. Taking it by value means this verifier
    /// cannot be reached with a caller-built challenge or invoked twice for
    /// the same receipt.
    ///
    /// `agent_id` / `pubkey_b64` are the values the BIND will use. They are
    /// re-checked against the challenge here so a challenge minted for one
    /// pair can never admit a bind of another — the confused-deputy step that
    /// would otherwise reopen the whole defect.
    ///
    /// Freshness is evaluated against this process's current UTC clock. The
    /// clock is intentionally not an API argument: a caller that already won
    /// the atomic storage consume must not be able to delay verification and
    /// then supply an earlier instant to revive the expired receipt.
    ///
    /// # Errors
    ///
    /// [`BindProofError`] — mismatch, expiry, malformed material, or a
    /// signature that does not verify. Fail-closed in every case.
    pub fn verify_challenge_response(
        consumed: ConsumedBindChallenge,
        agent_id: &str,
        pubkey_b64: &str,
        signature_b64: &str,
    ) -> Result<Self, BindProofError> {
        Self::verify_challenge_response_at(
            consumed,
            agent_id,
            pubkey_b64,
            signature_b64,
            chrono::Utc::now().fixed_offset(),
        )
    }

    /// Private clock-injected core. Production callers cannot choose the
    /// freshness clock; keeping injection private permits exact-boundary unit
    /// tests without reopening the direct Rust API bypass.
    fn verify_challenge_response_at(
        consumed: ConsumedBindChallenge,
        agent_id: &str,
        pubkey_b64: &str,
        signature_b64: &str,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<Self, BindProofError> {
        let challenge = &consumed.0;
        let canonical_pubkey = crate::identity::keypair::canonical_public_base64(pubkey_b64)
            .map_err(|_| BindProofError::MalformedPubkey)?;
        if challenge.agent_id != agent_id || challenge.pubkey_b64 != canonical_pubkey {
            return Err(BindProofError::ChallengeMismatch);
        }
        let expires = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
            .map_err(|_| BindProofError::Expired)?;
        if now >= expires {
            return Err(BindProofError::Expired);
        }
        // Bound the window from ABOVE as well. A first-party backend always
        // issues within the TTL; retaining the check fails closed if durable
        // state is corrupted or a future adapter returns an invalid receipt.
        if expires - now > chrono::Duration::seconds(BIND_CHALLENGE_TTL_SECS) {
            return Err(BindProofError::Expired);
        }
        let key = crate::identity::keypair::decode_public_base64(&canonical_pubkey)
            .map_err(|_| BindProofError::MalformedPubkey)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(signature_b64.trim()))
            .map_err(|_| BindProofError::MalformedSignature)?;
        let sig_arr: [u8; ed25519_dalek::SIGNATURE_LENGTH] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| BindProofError::MalformedSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        let transcript = bind_challenge_transcript(
            agent_id,
            &canonical_pubkey,
            &challenge.nonce_b64,
            &challenge.expires_at,
        );
        key.verify_strict(&transcript, &sig)
            .map_err(|_| BindProofError::ProofInvalid)?;
        Ok(Self {
            authority: BindAuthority::PossessionProof,
            agent_id: agent_id.to_string(),
            pubkey_b64: canonical_pubkey,
            predecessor_pubkey_b64: None,
            nonce_b64: Some(consumed.0.nonce_b64),
        })
    }

    /// Mint the witness for a lineage rotation whose succession signature the
    /// caller has ALREADY verified under the predecessor key
    /// (`storage::append_lineage_record`).
    ///
    /// `pub(crate)` on purpose: no external surface may reach this authority,
    /// so the only externally-driven way to bind a key stays the
    /// challenge-response.
    pub(crate) fn from_verified_lineage_succession(
        agent_id: &str,
        predecessor_pubkey_b64: &str,
        successor_pubkey_b64: &str,
    ) -> Result<Self, BindProofError> {
        Ok(Self {
            authority: BindAuthority::LineageSuccession,
            agent_id: agent_id.to_string(),
            pubkey_b64: crate::identity::keypair::canonical_public_base64(successor_pubkey_b64)
                .map_err(|_| BindProofError::MalformedPubkey)?,
            predecessor_pubkey_b64: Some(
                crate::identity::keypair::canonical_public_base64(predecessor_pubkey_b64)
                    .map_err(|_| BindProofError::MalformedPubkey)?,
            ),
            nonce_b64: None,
        })
    }

    /// Mint the witness for a recovery record whose M-of-N guardian quorum
    /// the caller has already verified.
    ///
    /// This is deliberately distinct from predecessor-signed succession:
    /// only guardian recovery may advance from a closed/revoked history head.
    pub(crate) fn from_verified_guardian_recovery(
        agent_id: &str,
        predecessor_pubkey_b64: &str,
        successor_pubkey_b64: &str,
    ) -> Result<Self, BindProofError> {
        Ok(Self {
            authority: BindAuthority::GuardianRecovery,
            agent_id: agent_id.to_string(),
            pubkey_b64: crate::identity::keypair::canonical_public_base64(successor_pubkey_b64)
                .map_err(|_| BindProofError::MalformedPubkey)?,
            predecessor_pubkey_b64: Some(
                crate::identity::keypair::canonical_public_base64(predecessor_pubkey_b64)
                    .map_err(|_| BindProofError::MalformedPubkey)?,
            ),
            nonce_b64: None,
        })
    }

    /// Re-check this witness against the exact storage state that will be
    /// mutated.
    ///
    /// `latest_history` is `(key, is_open)`. Candidate possession permits
    /// only a first, unanchored bootstrap or an idempotent reassertion of the
    /// same still-live key. Every distinct replacement requires the
    /// crate-private lineage authority, whose predecessor must match the
    /// latest durable anchor. A closed history is deliberately not reopenable
    /// by candidate possession: recovery goes through the signed lineage /
    /// guardian-quorum path.
    pub(crate) fn authorize_storage_state(
        &self,
        agent_id: &str,
        pubkey_b64: &str,
        flat_pubkey_b64: Option<&str>,
        latest_history: Option<(&str, bool)>,
    ) -> Result<(), BindProofError> {
        let canonical_pubkey = crate::identity::keypair::canonical_public_base64(pubkey_b64)
            .map_err(|_| BindProofError::BindingNotAuthorized)?;
        if self.agent_id != agent_id || self.pubkey_b64 != canonical_pubkey {
            return Err(BindProofError::BindingNotAuthorized);
        }
        for stored in flat_pubkey_b64
            .into_iter()
            .chain(latest_history.map(|(key, _)| key))
        {
            let canonical = crate::identity::keypair::canonical_public_base64(stored)
                .map_err(|_| BindProofError::BindingNotAuthorized)?;
            if canonical != stored {
                return Err(BindProofError::BindingNotAuthorized);
            }
        }

        match self.authority {
            BindAuthority::PossessionProof => match latest_history {
                None if flat_pubkey_b64.is_none() || flat_pubkey_b64 == Some(pubkey_b64) => Ok(()),
                Some((latest, true))
                    if latest == pubkey_b64 && flat_pubkey_b64 == Some(pubkey_b64) =>
                {
                    Ok(())
                }
                None | Some(_) => Err(BindProofError::BindingNotAuthorized),
            },
            BindAuthority::LineageSuccession => {
                let predecessor = self
                    .predecessor_pubkey_b64
                    .as_deref()
                    .ok_or(BindProofError::BindingNotAuthorized)?;
                match latest_history {
                    Some((latest, true)) if latest == predecessor => Ok(()),
                    None if flat_pubkey_b64 == Some(predecessor) => Ok(()),
                    // A verified self-signed genesis is the only lineage bind
                    // that may create the first anchor from empty state.
                    None if flat_pubkey_b64.is_none() && predecessor == pubkey_b64 => Ok(()),
                    None | Some(_) => Err(BindProofError::BindingNotAuthorized),
                }
            }
            BindAuthority::GuardianRecovery => {
                let predecessor = self
                    .predecessor_pubkey_b64
                    .as_deref()
                    .ok_or(BindProofError::BindingNotAuthorized)?;
                match latest_history {
                    Some((latest, _)) if latest == predecessor => Ok(()),
                    None if flat_pubkey_b64 == Some(predecessor) => Ok(()),
                    None | Some(_) => Err(BindProofError::BindingNotAuthorized),
                }
            }
        }
    }
}

/// Build the exact bytes a candidate key must sign to prove possession.
///
/// Domain-separated and length-prefixed — see the module docs for the layout
/// and why both properties are load-bearing.
#[must_use]
pub fn bind_challenge_transcript(
    agent_id: &str,
    pubkey_b64: &str,
    nonce_b64: &str,
    expires_at: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        BIND_CHALLENGE_V1_DOMAIN.len()
            + 16
            + agent_id.len()
            + pubkey_b64.len()
            + nonce_b64.len()
            + expires_at.len(),
    );
    out.extend_from_slice(BIND_CHALLENGE_V1_DOMAIN.as_bytes());
    for field in [agent_id, pubkey_b64, nonce_b64, expires_at] {
        // PERF-07 — the length rides as a fixed-width big-endian u32; a field
        // longer than u32::MAX cannot occur (every input is a validated id,
        // base64 key, nonce or RFC3339 stamp) but saturate rather than wrap so
        // there is no silent truncation path even in principle.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Sign a bind challenge with the candidate key's private half, returning the
/// URL-safe-no-pad base64 proof.
///
/// The operator-side half of the handshake: used by the CLI when the operator
/// supplies the key file, and by the SDK/test helpers.
#[must_use]
pub fn sign_bind_challenge(
    signing_key: &ed25519_dalek::SigningKey,
    challenge: &BindChallenge,
) -> String {
    use ed25519_dalek::Signer as _;
    let transcript = bind_challenge_transcript(
        &challenge.agent_id,
        &challenge.pubkey_b64,
        &challenge.nonce_b64,
        &challenge.expires_at,
    );
    URL_SAFE_NO_PAD.encode(signing_key.sign(&transcript).to_bytes())
}

/// Mint a fresh challenge row id.
#[must_use]
pub fn new_challenge_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Mint a fresh random nonce for a bind challenge.
#[must_use]
pub fn new_challenge_nonce() -> String {
    use rand_core::RngCore as _;
    let mut buf = [0u8; BIND_CHALLENGE_NONCE_LEN];
    // The platform CSPRNG, the same source `keypair::generate` draws from.
    rand_core::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn challenge_for(agent: &str, pubkey_b64: &str, expires_at: &str) -> BindChallenge {
        BindChallenge {
            nonce_b64: new_challenge_nonce(),
            agent_id: agent.to_string(),
            pubkey_b64: pubkey_b64.to_string(),
            expires_at: expires_at.to_string(),
        }
    }

    fn consumed(challenge: BindChallenge) -> ConsumedBindChallenge {
        ConsumedBindChallenge::from_storage(challenge)
    }

    fn future() -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(BIND_CHALLENGE_TTL_SECS)).to_rfc3339()
    }

    #[test]
    fn honest_holder_proves_possession() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let padded =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        let ch = challenge_for("ai:alice", &pk, &future());
        let proof = sign_bind_challenge(&sk, &ch);
        let nonce = ch.nonce_b64.clone();
        let witness =
            PossessionProof::verify_challenge_response(consumed(ch), "ai:alice", &padded, &proof)
                .expect("the key holder must be able to prove possession");
        assert_eq!(witness.authority(), BindAuthority::PossessionProof);
        assert_eq!(witness.nonce_b64(), Some(nonce.as_str()));
    }

    #[test]
    fn a_key_you_do_not_hold_cannot_be_bound() {
        // The #3464 defect in miniature: the attacker holds `attacker_sk` and
        // wants `victim_pk` bound (or vice versa). Neither direction works.
        let victim = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[2u8; 32]);
        let victim_pk = URL_SAFE_NO_PAD.encode(victim.verifying_key().to_bytes());
        let ch = challenge_for("ai:victim", &victim_pk, &future());
        let forged = sign_bind_challenge(&attacker, &ch);
        assert_eq!(
            PossessionProof::verify_challenge_response(
                consumed(ch),
                "ai:victim",
                &victim_pk,
                &forged,
            )
            .expect_err("a proof signed by the WRONG key must never be admitted"),
            BindProofError::ProofInvalid
        );
    }

    #[test]
    fn closed_head_requires_guardian_recovery_authority() {
        let predecessor = SigningKey::from_bytes(&[10u8; 32]);
        let successor = SigningKey::from_bytes(&[11u8; 32]);
        let predecessor = URL_SAFE_NO_PAD.encode(predecessor.verifying_key().to_bytes());
        let successor = URL_SAFE_NO_PAD.encode(successor.verifying_key().to_bytes());
        let succession =
            PossessionProof::from_verified_lineage_succession("ai:alice", &predecessor, &successor)
                .expect("valid canonical lineage keys");
        assert_eq!(
            succession.authorize_storage_state(
                "ai:alice",
                &successor,
                None,
                Some((&predecessor, false)),
            ),
            Err(BindProofError::BindingNotAuthorized),
            "a stale predecessor signature must not reopen a revoked head"
        );

        let recovery =
            PossessionProof::from_verified_guardian_recovery("ai:alice", &predecessor, &successor)
                .expect("valid canonical recovery keys");
        recovery
            .authorize_storage_state("ai:alice", &successor, None, Some((&predecessor, false)))
            .expect("independently verified guardian recovery may advance the closed head");
        assert_eq!(recovery.authority(), BindAuthority::GuardianRecovery);
    }

    #[test]
    fn a_proof_for_one_agent_does_not_bind_another() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let ch = challenge_for("ai:alice", &pk, &future());
        let proof = sign_bind_challenge(&sk, &ch);
        // Same (valid) proof, aimed at a different agent id.
        assert_eq!(
            PossessionProof::verify_challenge_response(consumed(ch), "ai:bob", &pk, &proof)
                .expect_err("a challenge minted for one agent must not admit another"),
            BindProofError::ChallengeMismatch
        );
    }

    #[test]
    fn a_far_future_expiry_is_refused() {
        // The offline lane lets the signer choose `expires_at`; an unbounded
        // one would be a permanent bind capability.
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let far = (chrono::Utc::now() + chrono::Duration::days(3650)).to_rfc3339();
        let ch = challenge_for("ai:alice", &pk, &far);
        let proof = sign_bind_challenge(&sk, &ch);
        assert_eq!(
            PossessionProof::verify_challenge_response(consumed(ch), "ai:alice", &pk, &proof,)
                .expect_err("an unbounded expiry would be a permanent bind capability"),
            BindProofError::Expired
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let ch = challenge_for("ai:alice", &pk, &past);
        let proof = sign_bind_challenge(&sk, &ch);
        assert_eq!(
            PossessionProof::verify_challenge_response(consumed(ch), "ai:alice", &pk, &proof,)
                .expect_err("an expired challenge must be refused"),
            BindProofError::Expired
        );
    }

    #[test]
    fn exact_expiry_and_delayed_verification_are_refused() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let expires =
            chrono::DateTime::parse_from_rfc3339("2026-09-04T10:00:00Z").expect("fixed expiry");

        for now in [expires, expires + chrono::Duration::seconds(300)] {
            let ch = challenge_for("ai:alice", &pk, "2026-09-04T10:00:00Z");
            let proof = sign_bind_challenge(&sk, &ch);
            assert_eq!(
                PossessionProof::verify_challenge_response_at(
                    consumed(ch),
                    "ai:alice",
                    &pk,
                    &proof,
                    now,
                )
                .expect_err("a consumed receipt is dead at and after its expiry"),
                BindProofError::Expired
            );
        }
    }

    #[test]
    fn challenge_max_ttl_uses_an_exact_duration() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-04T10:00:00Z").expect("fixed now");
        for (delta, accepted) in [
            (chrono::Duration::seconds(BIND_CHALLENGE_TTL_SECS), true),
            (
                chrono::Duration::seconds(BIND_CHALLENGE_TTL_SECS)
                    + chrono::Duration::microseconds(1),
                false,
            ),
        ] {
            let expires = now + delta;
            let ch = challenge_for("ai:alice", &pk, &expires.to_rfc3339());
            let proof = sign_bind_challenge(&sk, &ch);
            let result = PossessionProof::verify_challenge_response_at(
                consumed(ch),
                "ai:alice",
                &pk,
                &proof,
                now,
            );
            assert_eq!(result.is_ok(), accepted);
        }
    }

    #[test]
    fn transcript_is_unambiguous_across_field_boundaries() {
        // Without length prefixes these two would encode identically.
        let a = bind_challenge_transcript("a", "bc", "n", "t");
        let b = bind_challenge_transcript("ab", "c", "n", "t");
        assert_ne!(a, b);
    }

    #[test]
    fn transcript_is_domain_separated() {
        let t = bind_challenge_transcript("ai:alice", "pk", "n", "t");
        assert!(t.starts_with(BIND_CHALLENGE_V1_DOMAIN.as_bytes()));
    }

    #[test]
    fn sdk_bind_vector_matches_rust_bytes_and_signature_3464() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../sdk/fixtures/bind_pubkey_possession_vector.json"
        ))
        .expect("parse fixed cross-language bind vector");
        let field = |name: &str| {
            vector[name]
                .as_str()
                .unwrap_or_else(|| panic!("vector field {name}"))
        };
        let seed: [u8; 32] = hex::decode(field("seed_hex"))
            .expect("seed hex")
            .try_into()
            .expect("32-byte seed");
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        assert_eq!(pubkey_b64, field("pubkey_b64"));
        let challenge = challenge_for(field("agent_id"), &pubkey_b64, field("expires_at"));
        let challenge = BindChallenge {
            nonce_b64: field("nonce").to_string(),
            ..challenge
        };
        let transcript = bind_challenge_transcript(
            &challenge.agent_id,
            &challenge.pubkey_b64,
            &challenge.nonce_b64,
            &challenge.expires_at,
        );
        assert_eq!(hex::encode(transcript), field("transcript_hex"));
        assert_eq!(
            sign_bind_challenge(&signing_key, &challenge),
            field("proof_b64url")
        );
    }

    #[test]
    fn malformed_signature_is_refused_not_panicked() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let ch = challenge_for("ai:alice", &pk, &future());
        assert_eq!(
            PossessionProof::verify_challenge_response(
                consumed(ch.clone()),
                "ai:alice",
                &pk,
                "!!!",
            )
            .expect_err("non-base64 must be refused, never panic"),
            BindProofError::MalformedSignature
        );
        assert_eq!(
            PossessionProof::verify_challenge_response(
                consumed(ch),
                "ai:alice",
                &pk,
                &URL_SAFE_NO_PAD.encode([0u8; 10]),
            )
            .expect_err("a wrong-length signature must be refused, never panic"),
            BindProofError::MalformedSignature
        );
    }

    #[test]
    fn nonce_is_fresh_per_issue() {
        assert_ne!(new_challenge_nonce(), new_challenge_nonce());
    }
}
