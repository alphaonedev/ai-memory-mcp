// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The scoped `a2a-hub/join/v1` delegation verifier (issue
//! [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! This is what replaces [`super::identity::DenyAllVerifier`] in production.
//!
//! # What the hub holds, and what it does not
//!
//! The hub holds ONLY public material: a derived allowlist cache mapping an
//! agent id to its current proven ENROLLED public key and delegated-key
//! revocations. It never holds a private key or opens the database. The
//! `identity hub-cache` exporter derives that snapshot from v97 on either
//! backend and audits publication intent. Expired snapshots fail closed.
//!
//! # The chain, in order
//!
//! 1. `claimed_agent_id` bounds — **before any lookup**. `Frame::decode`
//!    deliberately admits an empty `from` on a `hello` (the hub's own challenge
//!    frame carries an empty `to`), so an empty or over-long id must die here or
//!    it reaches a map lookup as an attacker-chosen key.
//! 2. Decode the presented delegation, bounded at every element.
//! 3. The delegation must name THIS agent, THIS hub, and THIS hello key —
//!    binding `from` to the key that authenticated, per the vote's item 7.
//! 4. Resolve the enrolled root key for the agent.
//! 5. Refuse an UNPROVEN root: a `legacy_unproven` binding predates #3464's
//!    proof of possession, and letting one mint a hub delegation would reopen
//!    that defect exactly one hop out.
//! 6. Verify the delegation under the enrolled root (`verify_strict`).
//! 7. Check the window: bounded lifetime, then `now` inside it.
//! 8. Verify the hello transcript under the DELEGATED key (`verify_strict`).
//!
//! Every failure returns a distinct [`DenyReason`] for the LOG; the wire sees
//! one `401 unauthorized` regardless (`DenyReason::wire_reason`), so a peer
//! cannot learn which step failed by probing.

use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::identity::hub_delegation::{
    DelegationWire, check_ttl, check_validity, verify_hub_delegation,
};

use super::identity::{
    DenyReason, HelloRequest, HelloVerifier, MembershipRequest, VerifiedAgent,
    membership_transcript,
};
use super::limits::MAX_ID_BYTES;

/// How an agent's enrolled key came to be bound.
///
/// Mirrors #3464's `bind_authority` vocabulary. `LegacyUnproven` has no Rust
/// enum variant on that side — it exists only as a SQL literal for bindings
/// made before proof of possession was required — so it is represented here
/// explicitly rather than being silently folded into "some other string".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootBindAuthority {
    /// Bound by answering a possession challenge (#3464).
    PossessionProof,
    /// Bound by a verified lineage succession (#3464).
    LineageSuccession,
    /// Bound by verified guardian recovery (#3464).
    GuardianRecovery,
    /// Bound before #3464 required proof. MUST NOT mint a delegation.
    LegacyUnproven,
    /// An authority string this build does not recognise. Treated as unproven:
    /// an unknown provenance is not a proven one.
    Unrecognised,
}

impl RootBindAuthority {
    /// Parse #3464's `bind_authority` column value.
    #[must_use]
    pub fn from_column(value: &str) -> Self {
        use crate::identity::pubkey_bind::BindAuthority;
        if value == BindAuthority::PossessionProof.as_str() {
            Self::PossessionProof
        } else if value == BindAuthority::LineageSuccession.as_str() {
            Self::LineageSuccession
        } else if value == BindAuthority::GuardianRecovery.as_str() {
            Self::GuardianRecovery
        } else if value == "legacy_unproven" {
            Self::LegacyUnproven
        } else {
            Self::Unrecognised
        }
    }

    /// May a root bound this way mint a hub delegation?
    ///
    /// Fail-closed: only recognized PROVEN authorities may. Anything else — a
    /// legacy binding, or a string a future schema introduces that this build
    /// has never heard of — is refused.
    #[must_use]
    pub const fn may_delegate(self) -> bool {
        matches!(
            self,
            Self::PossessionProof | Self::LineageSuccession | Self::GuardianRecovery
        )
    }
}

/// An agent's enrolled root key, with the provenance of its binding.
#[derive(Debug, Clone)]
pub struct EnrolledRoot {
    /// The enrolled public key.
    pub pubkey: VerifyingKey,
    /// How that binding was authorised.
    pub authority: RootBindAuthority,
}

/// Resolves the enrolled root key for an agent id.
///
/// A trait so the hub's derived cache and (once #3464 lands) a store-backed
/// resolver are the same seam, and so a test can supply a fixture without a
/// database.
pub trait RootKeyResolver: Send + Sync + 'static {
    /// Resolve `agent_id`'s enrolled root key.
    ///
    /// # Errors
    ///
    /// [`DenyReason::UnknownAgent`] when the agent is not in the allowlist.
    /// Implementations MUST NOT return a key on a lookup fault — a fault is a
    /// refusal, never a default.
    fn resolve(&self, agent_id: &str) -> Result<EnrolledRoot, DenyReason>;

    /// Resolve root and revocation from one snapshot.
    ///
    /// # Errors
    /// Refuses any root or revocation lookup failure.
    fn resolve_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<EnrolledRoot, DenyReason> {
        let root = self.resolve(agent_id)?;
        self.check_delegate(agent_id, key, issued)?;
        Ok(root)
    }

    /// Check the delegated key against the current public revocation snapshot.
    ///
    /// # Errors
    /// Refuses a revoked key or a failed lookup.
    fn check_delegate(
        &self,
        _agent_id: &str,
        _key: &[u8; 32],
        _issued: &str,
    ) -> Result<(), DenyReason> {
        Ok(())
    }
}

/// The hub's derived allowlist cache: agent id -> enrolled root key.
///
/// A CACHE, not a registry. ai-memory remains the source of truth; this is
/// refreshed out of band and holds only public material.
#[derive(Debug, Default)]
pub struct AllowlistCache {
    roots: HashMap<String, EnrolledRoot>,
    entries: HashMap<String, AllowlistEntry>,
}

impl AllowlistCache {
    /// An empty cache. Admits nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) an agent's enrolled root.
    pub fn insert(&mut self, agent_id: &str, root: EnrolledRoot) -> &mut Self {
        self.roots.insert(agent_id.to_owned(), root);
        self
    }

    /// Number of agents in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Is the cache empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

impl RootKeyResolver for AllowlistCache {
    fn resolve(&self, agent_id: &str) -> Result<EnrolledRoot, DenyReason> {
        self.roots
            .get(agent_id)
            .cloned()
            .ok_or(DenyReason::UnknownAgent)
    }

    fn check_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<(), DenyReason> {
        use base64::Engine as _;
        let Some(entry) = self.entries.get(agent_id) else {
            return Ok(());
        };
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let bound = chrono::DateTime::parse_from_rfc3339(&entry.bound_at)
            .map_err(|_| DenyReason::DelegationInvalid)?;
        let issued = chrono::DateTime::parse_from_rfc3339(issued)
            .map_err(|_| DenyReason::DelegationInvalid)?;
        if issued < bound || entry.revoked_keys.contains(&key) {
            return Err(DenyReason::DelegationInvalid);
        }
        Ok(())
    }
}

/// Store-free resolver that reloads the derived snapshot on each identity check.
/// A removed, unreadable, stale or invalid file immediately fails closed.
#[derive(Debug)]
pub struct ReloadingAllowlist {
    path: std::path::PathBuf,
}

impl ReloadingAllowlist {
    /// Validate the initial snapshot before arming the runtime verifier.
    ///
    /// # Errors
    /// Refuses an unreadable or invalid snapshot.
    pub fn new(path: std::path::PathBuf) -> anyhow::Result<Self> {
        AllowlistCache::load_from_file(&path)?;
        Ok(Self { path })
    }
}

impl RootKeyResolver for ReloadingAllowlist {
    fn resolve(&self, agent_id: &str) -> Result<EnrolledRoot, DenyReason> {
        AllowlistCache::load_from_file(&self.path)
            .map_err(|_| DenyReason::DelegationInvalid)?
            .resolve(agent_id)
    }

    fn resolve_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<EnrolledRoot, DenyReason> {
        AllowlistCache::load_from_file(&self.path)
            .map_err(|_| DenyReason::DelegationInvalid)?
            .resolve_delegate(agent_id, key, issued)
    }

    fn check_delegate(
        &self,
        agent_id: &str,
        key: &[u8; 32],
        issued: &str,
    ) -> Result<(), DenyReason> {
        AllowlistCache::load_from_file(&self.path)
            .map_err(|_| DenyReason::DelegationInvalid)?
            .check_delegate(agent_id, key, issued)
    }
}

/// Verifies a scoped `a2a-hub/join/v1` delegation and the hello signature made
/// under the key it delegates to.
#[derive(Debug)]
pub struct ScopedDelegationVerifier<R: RootKeyResolver> {
    resolver: R,
    /// Injected so the validity check is deterministic in tests; production
    /// passes `None` and reads the wall clock.
    fixed_now: Option<String>,
}

impl<R: RootKeyResolver> ScopedDelegationVerifier<R> {
    /// Build a verifier over a root-key resolver.
    #[must_use]
    pub const fn new(resolver: R) -> Self {
        Self {
            resolver,
            fixed_now: None,
        }
    }

    /// Pin the clock. Test-only in practice; the validity window is the one
    /// part of this chain that is not otherwise deterministic.
    #[must_use]
    pub fn with_fixed_now(mut self, now_rfc3339: impl Into<String>) -> Self {
        self.fixed_now = Some(now_rfc3339.into());
        self
    }

    fn now(&self) -> String {
        self.fixed_now.clone().unwrap_or_else(|| {
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
    }

    /// Bounds on the claimed id, BEFORE any lookup or crypto.
    fn check_claimed_agent_id(claimed: &str) -> Result<(), DenyReason> {
        if claimed.is_empty() || claimed.len() > MAX_ID_BYTES {
            return Err(DenyReason::MalformedAgentId);
        }
        Ok(())
    }
}

impl<R: RootKeyResolver> HelloVerifier for ScopedDelegationVerifier<R> {
    fn verify(&self, req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason> {
        // (1) bounds first — never let an attacker-chosen id reach a lookup.
        Self::check_claimed_agent_id(req.claimed_agent_id)?;

        // (2) decode, bounded at every element.
        let wire =
            DelegationWire::decode(req.delegation).map_err(|_| DenyReason::DelegationInvalid)?;
        let delegation = wire.as_delegation();

        // (3) this agent, this hub, this hello key.
        if delegation.principal != req.claimed_agent_id
            || delegation.hub_id != req.hub_id
            || wire.delegate_key_id != *req.pubkey
        {
            return Err(DenyReason::DelegationInvalid);
        }

        // (4) the enrolled root.
        let root = self.resolver.resolve_delegate(
            req.claimed_agent_id,
            req.pubkey,
            delegation.not_before,
        )?;
        self.verify_topics(req.claimed_agent_id, req.topics)?;

        // (5) an UNPROVEN root may not delegate.
        if !root.authority.may_delegate() {
            return Err(DenyReason::DelegationInvalid);
        }

        // (6) the delegation itself.
        verify_hub_delegation(&root.pubkey, &delegation, &wire.signature)
            .map_err(|_| DenyReason::DelegationInvalid)?;

        // (7) the window: bounded, then current.
        check_ttl(&delegation).map_err(|_| DenyReason::DelegationInvalid)?;
        check_validity(&delegation, &self.now()).map_err(|_| DenyReason::DelegationInvalid)?;

        // (8) the hello transcript, under the DELEGATED key.
        let delegate =
            VerifyingKey::from_bytes(req.pubkey).map_err(|_| DenyReason::BadSignature)?;
        let sig_bytes: [u8; 64] = req
            .signature
            .try_into()
            .map_err(|_| DenyReason::BadSignature)?;
        delegate
            .verify_strict(&req.transcript(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| DenyReason::BadSignature)?;

        Ok(VerifiedAgent {
            agent_id: req.claimed_agent_id.to_owned(),
            pubkey: *req.pubkey,
        })
    }

    fn verify_topics(&self, agent_id: &str, topics: &[String]) -> Result<(), DenyReason> {
        // A namespace may contain private rows belonging to multiple agents.
        // Only the principal's own inbox has an unconditional read-scope proof;
        // never infer whole-namespace access from one readable row.
        let own_inbox = format!("#_inbox/{agent_id}");
        if topics.iter().any(|topic| topic != &own_inbox) {
            return Err(DenyReason::TopicsRefused);
        }
        Ok(())
    }

    fn verify_membership(&self, req: &MembershipRequest<'_>) -> Result<(), DenyReason> {
        Self::check_claimed_agent_id(req.agent_id)?;
        let key = VerifyingKey::from_bytes(req.pubkey).map_err(|_| DenyReason::BadSignature)?;
        let sig_bytes: [u8; 64] = req
            .signature
            .try_into()
            .map_err(|_| DenyReason::BadSignature)?;
        let transcript = membership_transcript(req.action, req.hub_id, req.nonce, req.agent_id);
        key.verify_strict(&transcript, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| DenyReason::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::hub_delegation::{A2A_HUB_SCOPE, sign_hub_delegation};
    use crate::wake_hub::identity::{PeerCred, hello_transcript, topics_hash};
    use crate::wake_hub::limits::{HELLO_NONCE_BYTES, PUBKEY_BYTES};
    use ed25519_dalek::{Signer, SigningKey};

    const HUB: &str = "ai-memory-wake-hub";
    const AGENT: &str = "agent-a";
    const NONCE: [u8; HELLO_NONCE_BYTES] = [5u8; HELLO_NONCE_BYTES];
    const NB: &str = "2026-09-03T11:00:00Z";
    const NA: &str = "2026-09-03T13:00:00Z";
    const NOW: &str = "2026-09-03T12:00:00Z";

    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn delegate_key() -> SigningKey {
        SigningKey::from_bytes(&[12u8; 32])
    }

    fn resolver(authority: RootBindAuthority) -> AllowlistCache {
        let mut cache = AllowlistCache::new();
        cache.insert(
            AGENT,
            EnrolledRoot {
                pubkey: root_key().verifying_key(),
                authority,
            },
        );
        cache
    }

    /// A delegation minted by `root_key` for `delegate_key`, wire-encoded.
    fn delegation_bytes(principal: &str, hub_id: &str, not_after: &str) -> Vec<u8> {
        let mut wire = DelegationWire {
            principal: principal.to_owned(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate_key().verifying_key().to_bytes(),
            hub_id: hub_id.to_owned(),
            not_before: NB.to_owned(),
            not_after: not_after.to_owned(),
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&root_key(), &wire.as_delegation()).expect("mint");
        wire.encode().expect("encode")
    }

    fn hello_signature(topics: &[String]) -> [u8; 64] {
        let transcript = hello_transcript(HUB, &NONCE, AGENT, &topics_hash(topics));
        delegate_key().sign(&transcript).to_bytes()
    }

    struct Fixture {
        delegation: Vec<u8>,
        pubkey: [u8; PUBKEY_BYTES],
        signature: [u8; 64],
        topics: Vec<String>,
    }

    fn fixture() -> Fixture {
        let topics = vec![format!("#_inbox/{AGENT}")];
        Fixture {
            delegation: delegation_bytes(AGENT, HUB, NA),
            pubkey: delegate_key().verifying_key().to_bytes(),
            signature: hello_signature(&topics),
            topics,
        }
    }

    fn request<'a>(fixture: &'a Fixture, claimed: &'a str) -> HelloRequest<'a> {
        HelloRequest {
            hub_id: HUB,
            nonce: &NONCE,
            claimed_agent_id: claimed,
            pubkey: &fixture.pubkey,
            signature: &fixture.signature,
            delegation: &fixture.delegation,
            topics: &fixture.topics,
            peer: PeerCred {
                uid: 1_000,
                gid: 1_000,
                pid: Some(42),
            },
        }
    }

    fn verifier(authority: RootBindAuthority) -> ScopedDelegationVerifier<AllowlistCache> {
        ScopedDelegationVerifier::new(resolver(authority)).with_fixed_now(NOW)
    }

    // --- ALLOWED ---------------------------------------------------------

    #[test]
    fn allowed_a_proven_root_delegation_admits_the_hello() {
        let fixture = fixture();
        let verified = verifier(RootBindAuthority::PossessionProof)
            .verify(&request(&fixture, AGENT))
            .expect("a well-formed delegation must be admitted");
        assert_eq!(verified.agent_id, AGENT);
        assert_eq!(
            verified.pubkey, fixture.pubkey,
            "the session binds to the DELEGATED key, not the enrolled root"
        );
    }

    #[test]
    fn allowed_a_lineage_succession_root_may_also_delegate() {
        let fixture = fixture();
        assert!(
            verifier(RootBindAuthority::LineageSuccession)
                .verify(&request(&fixture, AGENT))
                .is_ok()
        );
    }

    // --- DENIED: the claimed id, before any lookup -----------------------

    #[test]
    fn denied_an_empty_claimed_agent_id_is_refused_before_any_lookup() {
        // `Frame::decode` deliberately admits an empty `from` on a hello, so
        // this is the gate that stops it reaching a map lookup as an
        // attacker-chosen key.
        let fixture = fixture();
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, "")),
            Err(DenyReason::MalformedAgentId)
        );
    }

    #[test]
    fn denied_an_over_long_claimed_agent_id_is_refused_before_any_lookup() {
        let fixture = fixture();
        let too_long = "a".repeat(MAX_ID_BYTES + 1);
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, &too_long)),
            Err(DenyReason::MalformedAgentId)
        );
        // Exactly at the ceiling is a normal unknown agent, not malformed —
        // proving the bound is `> MAX_ID_BYTES`, not `>=`.
        let at_ceiling = "a".repeat(MAX_ID_BYTES);
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, &at_ceiling)),
            Err(DenyReason::DelegationInvalid),
            "a 128-byte id is well-formed; it fails later, on the delegation"
        );
    }

    // --- DENIED: an unproven root ----------------------------------------

    #[test]
    fn denied_an_unproven_root_may_not_mint_a_hub_delegation() {
        // A `legacy_unproven` binding predates #3464's proof of possession.
        // Letting one delegate would reopen that defect exactly one hop out.
        let fixture = fixture();
        assert_eq!(
            verifier(RootBindAuthority::LegacyUnproven).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_an_unrecognised_bind_authority_is_treated_as_unproven() {
        let fixture = fixture();
        assert_eq!(
            verifier(RootBindAuthority::Unrecognised).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid),
            "an authority string this build has never heard of is not a proven one"
        );
        assert!(!RootBindAuthority::from_column("something_new").may_delegate());
        assert!(RootBindAuthority::from_column("possession_proof").may_delegate());
        assert!(RootBindAuthority::from_column("lineage_succession").may_delegate());
        assert!(!RootBindAuthority::from_column("legacy_unproven").may_delegate());
    }

    // --- DENIED: the delegation binding ----------------------------------

    #[test]
    fn denied_a_delegation_naming_another_agent_is_refused() {
        let mut fixture = fixture();
        fixture.delegation = delegation_bytes("agent-b", HUB, NA);
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_a_delegation_minted_for_another_hub_is_refused() {
        // Not portable across hubs: a delegation harvested at one hub must not
        // admit its holder at another.
        let mut fixture = fixture();
        fixture.delegation = delegation_bytes(AGENT, "some-other-hub", NA);
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_a_delegation_for_a_different_key_cannot_be_replayed() {
        // The delegation names ONE hello key. Presenting it alongside a key it
        // does not name is the "from bound to the hello key" gate.
        let mut fixture = fixture();
        let other = SigningKey::from_bytes(&[99u8; 32]);
        fixture.pubkey = other.verifying_key().to_bytes();
        let transcript = hello_transcript(HUB, &NONCE, AGENT, &topics_hash(&fixture.topics));
        fixture.signature = other.sign(&transcript).to_bytes();
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_an_absent_delegation_is_refused() {
        let mut fixture = fixture();
        fixture.delegation = Vec::new();
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_an_unknown_agent_is_refused() {
        let fixture = fixture();
        let empty = ScopedDelegationVerifier::new(AllowlistCache::new()).with_fixed_now(NOW);
        assert_eq!(
            empty.verify(&request(&fixture, AGENT)),
            Err(DenyReason::UnknownAgent)
        );
    }

    // --- DENIED: window and signature ------------------------------------

    #[test]
    fn denied_an_expired_delegation_is_refused() {
        let fixture = fixture();
        let expired = ScopedDelegationVerifier::new(resolver(RootBindAuthority::PossessionProof))
            .with_fixed_now("2026-09-03T13:00:01Z");
        assert_eq!(
            expired.verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid),
            "expiry IS the revocation mechanism, so an expired delegation must not admit"
        );
    }

    #[test]
    fn denied_an_over_long_window_is_refused_even_though_it_verifies() {
        // Signature-valid but un-revocable: the TTL bound must still refuse it.
        let mut fixture = fixture();
        fixture.delegation = delegation_bytes(AGENT, HUB, "2026-09-10T11:00:00Z");
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::DelegationInvalid)
        );
    }

    #[test]
    fn denied_a_hello_signature_by_the_wrong_key_is_refused() {
        let mut fixture = fixture();
        fixture.signature = SigningKey::from_bytes(&[77u8; 32])
            .sign(b"not the transcript")
            .to_bytes();
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::BadSignature)
        );
    }

    #[test]
    fn denied_a_hello_signed_over_a_different_topic_set_is_refused() {
        // The transcript commits to the topics, so a signature harvested for
        // one topic set cannot be presented with another.
        let mut fixture = fixture();
        // Empty subscriptions are permitted: this must fail on transcript
        // binding, rather than being intercepted by the read-scope gate.
        fixture.topics.clear();
        assert_eq!(
            verifier(RootBindAuthority::PossessionProof).verify(&request(&fixture, AGENT)),
            Err(DenyReason::BadSignature)
        );
    }

    #[test]
    fn every_refusal_looks_identical_on_the_wire() {
        // Distinct reasons exist for the LOG. A peer must not be able to tell
        // "unknown agent" from "bad signature" from "unproven root".
        for reason in [
            DenyReason::MalformedAgentId,
            DenyReason::UnknownAgent,
            DenyReason::DelegationInvalid,
            DenyReason::BadSignature,
        ] {
            assert_eq!(reason.wire_reason(), "unauthorized");
        }
    }

    // --- membership ------------------------------------------------------

    #[test]
    fn membership_is_verified_under_the_session_key() {
        use crate::wake_hub::identity::MembershipAction;
        let pubkey = delegate_key().verifying_key().to_bytes();
        let transcript = membership_transcript(MembershipAction::Depart, HUB, &NONCE, AGENT);
        let good = delegate_key().sign(&transcript).to_bytes();
        let verifier = verifier(RootBindAuthority::PossessionProof);
        // A named fn, not a closure: the closure form makes rustc infer one
        // lifetime for the borrowed signature and the returned request.
        fn req<'a>(pubkey: &'a [u8; PUBKEY_BYTES], sig: &'a [u8]) -> MembershipRequest<'a> {
            MembershipRequest {
                action: MembershipAction::Depart,
                hub_id: HUB,
                nonce: &NONCE,
                agent_id: AGENT,
                pubkey,
                signature: sig,
                peer: PeerCred {
                    uid: 1_000,
                    gid: 1_000,
                    pid: Some(42),
                },
            }
        }
        assert!(verifier.verify_membership(&req(&pubkey, &good)).is_ok());
        assert_eq!(
            verifier.verify_membership(&req(&pubkey, &[0u8; 64])),
            Err(DenyReason::BadSignature)
        );
        // A JOIN signature must not pass as a DEPART — the domains differ.
        let join = delegate_key()
            .sign(&membership_transcript(
                MembershipAction::Join,
                HUB,
                &NONCE,
                AGENT,
            ))
            .to_bytes();
        assert_eq!(
            verifier.verify_membership(&req(&pubkey, &join)),
            Err(DenyReason::BadSignature)
        );
    }
}

// ---------------------------------------------------------------------------
// Derived allowlist cache, on disk
// ---------------------------------------------------------------------------

/// One agent's row in the derived allowlist file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    /// The enrolled agent id.
    pub agent_id: String,
    /// Its enrolled public key, URL-safe base64 (no padding).
    pub pubkey_b64: String,
    /// #3464's `bind_authority` for that binding. An entry that omits it is
    /// treated as `legacy_unproven` — an unstated provenance is not a proven
    /// one, so it cannot delegate.
    #[serde(default = "legacy_unproven")]
    pub bind_authority: String,
    /// Start of the current open v97 key version.
    pub bound_at: String,
    /// Revoked delegated key ids, derived from durable revocation records.
    #[serde(default)]
    pub revoked_keys: Vec<String>,
}

fn legacy_unproven() -> String {
    "legacy_unproven".to_string()
}

/// The derived allowlist file the hub loads.
///
/// A CACHE of public material, refreshed out of band from ai-memory. It is not
/// a second registry: nothing here grants anything the durable identity root
/// did not already grant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistFile {
    /// Format version. An unknown version is refused, never best-effort read.
    pub version: u32,
    /// When the cache was derived, RFC3339. Required for live admission.
    #[serde(default)]
    pub refreshed_at: Option<String>,
    /// The enrolled agents.
    pub agents: Vec<AllowlistEntry>,
}

/// Format version this build reads.
pub const ALLOWLIST_FILE_VERSION: u32 = 2;

impl AllowlistCache {
    /// Load a derived allowlist from disk.
    ///
    /// # Errors
    ///
    /// Refuses a file that is group- or other-readable (it names every agent
    /// permitted to join, so it is not public), an unknown format version, a
    /// malformed entry, or a duplicate agent id — a duplicate would make which
    /// key wins depend on map iteration order, and "which key is trusted" must
    /// never be order-dependent.
    ///
    /// # Panics
    ///
    /// Never.
    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let file = Self::read_file(path)?;
        Self::from_file(file)
    }

    /// Read a cache through one permission-checked descriptor, including expired
    /// snapshots so the exporter can audit removals when refreshing them.
    ///
    /// # Errors
    /// Refuses unsafe files, malformed JSON and unsupported versions.
    pub fn read_file(path: &std::path::Path) -> anyhow::Result<AllowlistFile> {
        use anyhow::{Context, bail};
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("wake-hub: cannot open allowlist {}", path.display()))?;
        let meta = file.metadata()?;
        let mode = meta.permissions().mode() & 0o7777;
        // SAFETY: geteuid has no arguments or memory effects and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if !meta.is_file() || meta.uid() != uid || mode != 0o600 {
            bail!(
                "wake-hub: allowlist {} must be an owner-only (0600) regular file owned by this uid",
                path.display()
            );
        }
        const MAX_ALLOWLIST_BYTES: u64 = 1_048_576;
        let mut raw = String::new();
        file.take(MAX_ALLOWLIST_BYTES + 1)
            .read_to_string(&mut raw)?;
        if u64::try_from(raw.len())? > MAX_ALLOWLIST_BYTES {
            bail!("wake-hub: allowlist exceeds the byte limit");
        }
        let file: AllowlistFile = serde_json::from_str(&raw)
            .with_context(|| format!("wake-hub: allowlist {} is malformed", path.display()))?;
        if file.version != ALLOWLIST_FILE_VERSION {
            bail!(
                "wake-hub: allowlist {} is format version {}, this build reads {}",
                path.display(),
                file.version,
                ALLOWLIST_FILE_VERSION
            );
        }
        Ok(file)
    }

    fn from_file(file: AllowlistFile) -> anyhow::Result<Self> {
        use anyhow::{Context as _, bail};
        let refreshed = chrono::DateTime::parse_from_rfc3339(
            file.refreshed_at
                .as_deref()
                .context("missing cache refresh time")?,
        )?;
        let age = chrono::Utc::now().signed_duration_since(refreshed);
        if age < chrono::Duration::zero()
            || age >= chrono::Duration::seconds(crate::identity::hub_cache::MAX_CACHE_AGE_SECS)
        {
            bail!("wake-hub: identity cache is expired or future-dated");
        }
        let mut cache = Self::new();
        for entry in file.agents {
            if entry.agent_id.is_empty() || entry.agent_id.len() > MAX_ID_BYTES {
                bail!("wake-hub: malformed allowlist agent id");
            }
            if cache.roots.contains_key(&entry.agent_id) {
                bail!(
                    "wake-hub: allowlist {} lists agent {} twice; which key is trusted must \
                     never depend on iteration order",
                    "snapshot",
                    entry.agent_id
                );
            }
            let pubkey = crate::identity::keypair::decode_public_base64(&entry.pubkey_b64)
                .with_context(|| {
                    format!(
                        "wake-hub: allowlist {} has an unreadable key for agent {}",
                        "snapshot", entry.agent_id
                    )
                })?;
            if chrono::DateTime::parse_from_rfc3339(&entry.bound_at)? > refreshed {
                bail!("wake-hub: root was bound after the cache snapshot");
            }
            cache.entries.insert(entry.agent_id.clone(), entry.clone());
            cache.insert(
                &entry.agent_id,
                EnrolledRoot {
                    pubkey,
                    authority: RootBindAuthority::from_column(&entry.bind_authority),
                },
            );
        }
        Ok(cache)
    }
}
