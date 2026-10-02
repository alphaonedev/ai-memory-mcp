// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4478 — the #4356 ancestor-owner bind gate on the FEDERATED
//! `namespace_meta[]` apply (`/sync/push`, both receive loops).
//!
//! Before #4478 both loops applied an inbound binding with no ancestor check:
//! sqlite called `db::set_namespace_standard` raw and postgres went through
//! the admin apply context, whose bypass skips the gate. The only gate was the
//! #2479 / #2536 peer-scope check, which asks whether the PEER may touch the
//! row's namespace, never whether a governed ancestor ABOVE it is owned
//! locally. A peer scoped to `P/x/**` could therefore open the first standard
//! at `P/x` under a locally governed `P` and opt that subtree out of `P`'s
//! write / promote / delete / approval gates for every LOCAL caller. The
//! origin node's own check does not cover this: it judged the ORIGIN's chain
//! and owners, not the receiver's.
//!
//! ## Who the federated caller is (decided here, documented in the changelog)
//!
//! The gate needs one principal to compare with the governing ancestor's
//! owner. A federated apply has no tenant caller, and the local admin apply
//! context must not stand in for one (that is the bypass being closed). The
//! principal is the agent the pushing peer is AUTHENTICATED to act for, under
//! the lane's existing authorship contract (#238 sender attestation, #1464
//! per-agent allowlist):
//!
//! 1. the bound standard memory's stored owner (`metadata.agent_id`), when the
//!    peer is authorized to act as that agent: it is the #238-attested sender,
//!    or it is listed in the peer's `allowed_sender_agent_ids`, or no
//!    allowlist is configured at all (the zero-config faith posture, exactly
//!    as #1464 attributes row ownership there);
//! 2. otherwise the #238-attested sender itself (the peer id when the body is
//!    the legacy unauthored shape).
//!
//! It CANNOT be established — and is `None`, which can never match an owner —
//! when the `X-Peer-Id` header is absent or the operator set the
//! `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` bypass (the sender is then a bare body
//! claim). A `None` actor fails closed exactly where the gate matters: a first
//! bind under an OWNED governing ancestor is refused; an ungoverned target and
//! an unowned ancestor (the documented unowned-PASS) are unaffected.
//!
//! ## What is gated
//!
//! Every binding state, through the shared
//! [`crate::ns_standard_ancestor::set_admission`] verdict for the federated
//! actor (#4495, GOD ruling): a FIRST bind (or the repair of a severed one)
//! needs the governing ancestor's owner (#4356), and a REBIND of a resolved
//! standard needs its current owner (#3758 parity). After the write, a
//! re-parent must not have DETACHED the target from a governing ancestor the
//! actor does not own ([`federated_reparent_admission`]). All of it runs after
//! the #2479 / #2536 peer-scope check, inside the bind's write transaction.
//!
//! The actor is only as strong as the `X-Peer-Id` authentication: in the
//! zero-config legacy posture (no attestation allowlist, the push-scope
//! requirement off) an unsigned `X-Peer-Id` naming an owner is that owner, as
//! for every other lane in that posture (existing trust model, documented in
//! `docs/governance.md`).

use crate::federation::peer_attestation::PeerAttestationConfig;
use crate::ns_standard_ancestor::{GoverningAncestor, SetRefusal, needs_ancestor, set_admission};
use crate::visibility::NamespaceStandardBinding;

/// The fixed, value-free WARN line for a refused entry (per-entry skip; the
/// batch survives). No namespace, owner, peer or policy is interpolated.
pub const ANCESTOR_GATE_SKIP_LOG: &str = "sync_push: refusing a federated namespace_meta \
     entry: the #4356 ancestor-owner bind gate refused a first bind under a locally governed \
     ancestor (the pushing peer does not act for its owner, the ancestor is severed or corrupt, \
     or the chain could not be read); skipping this entry, batch survives (#4478)";

/// The principal the pushing peer is authenticated to act for on this entry
/// (see the module docs). `None` when it cannot be established.
#[must_use]
pub fn federated_bind_actor(
    peer_header: Option<&str>,
    sender_agent_id: &str,
    bound_owner: Option<&str>,
    cfg: &PeerAttestationConfig,
    trust_body_bypass: bool,
) -> Option<String> {
    if trust_body_bypass {
        return None;
    }
    let peer = peer_header.map(str::trim).filter(|p| !p.is_empty())?;
    let sender = Some(sender_agent_id.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(peer);
    // The lane's #1464 authorship contract, verbatim: the attested sender
    // acts as itself; under an allowlist the peer acts for exactly the agents
    // it is allowlisted for; in the zero-config posture (no allowlist) claims
    // are taken on faith, as the receive loop already does for row ownership.
    let acts_for = |agent: &str| {
        agent == sender
            || !cfg.has_allowlist()
            || cfg
                .scope_for(peer)
                .is_some_and(|s| s.allowed_sender_agent_ids.iter().any(|a| a == agent))
    };
    match bound_owner.map(str::trim).filter(|o| !o.is_empty()) {
        Some(owner) if acts_for(owner) => Some(owner.to_string()),
        _ => Some(sender.to_string()),
    }
}

/// #4478 / #4495 — the shared #3758 + #4356 verdict for one inbound entry, in
/// EVERY binding state: a first bind (or severed repair) needs the governing
/// ancestor's owner, a rebind of a resolved standard needs its current owner
/// (#3758 parity). An actor that cannot be established is refused wherever an
/// owner is consulted, and admitted only where none is (an ungoverned first
/// bind, an unowned standard or ancestor).
///
/// # Errors
///
/// [`SetRefusal`] — the caller skips the entry (fail closed).
pub fn federated_bind_admission(
    actor: Option<&str>,
    namespace: &str,
    binding: &NamespaceStandardBinding,
    ancestor: &GoverningAncestor,
) -> Result<(), SetRefusal> {
    let Some(actor) = actor else {
        if let NamespaceStandardBinding::Resolved(Some(owner)) = binding
            && crate::ns_standard_ancestor::normalise_owner(Some(owner.clone())).is_some()
        {
            return Err(SetRefusal::NotOwner);
        }
        if needs_ancestor(binding) {
            return match ancestor {
                GoverningAncestor::Standard { owner: Some(_) } => Err(SetRefusal::NotOwner),
                GoverningAncestor::Severed => Err(SetRefusal::AncestorUnresolvable),
                GoverningAncestor::None | GoverningAncestor::Standard { owner: None } => Ok(()),
            };
        }
        return Ok(());
    };
    set_admission(actor, false, namespace, binding, ancestor)
}

/// #4495 — a federated bind must not DETACH its target from a governing
/// ancestor the actor does not own: the nearest governing ancestor after the
/// write (`after`, read in the same transaction) must be the one before
/// (`before`), unless there was none (or it was unowned) or the actor owns it.
/// (#2542 per-hop entitlement plus #3758 owner parity already make such a
/// detach unreachable in practice; this is the fail-closed post-condition.)
///
/// # Errors
///
/// [`SetRefusal`] — the write is rolled back and the entry skipped.
pub fn federated_reparent_admission(
    actor: Option<&str>,
    before: &GoverningAncestor,
    after: &GoverningAncestor,
) -> Result<(), SetRefusal> {
    match before {
        GoverningAncestor::None | GoverningAncestor::Standard { owner: None } => Ok(()),
        _ if after == before => Ok(()),
        GoverningAncestor::Standard { owner: Some(o) } if actor == Some(o.as_str()) => Ok(()),
        GoverningAncestor::Standard { .. } => Err(SetRefusal::NotOwner),
        GoverningAncestor::Severed => Err(SetRefusal::AncestorUnresolvable),
    }
}

/// A federated entry refused by the gate (carried through the write
/// transaction as an error so the transaction rolls back). Fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederatedBindRefused(pub SetRefusal);

impl std::fmt::Display for FederatedBindRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(ANCESTOR_GATE_SKIP_LOG)
    }
}

impl std::error::Error for FederatedBindRefused {}

/// The sqlite half, run by the receive loop INSIDE the write transaction that
/// performs the bind: the standard must exist first (a missing standard is
/// the same not-found skip the postgres adapter reports, never a governance
/// refusal), then the binding and the governing ancestor are read and
/// decided, the row is written, and the governing ancestor is re-read to
/// refuse a detaching re-parent. Every refusal or read fault in the gate is a
/// [`FederatedBindRefused`] error (the transaction rolls back).
///
/// # Errors
///
/// [`FederatedBindRefused`], or the storage error of the write itself.
pub fn federated_bind_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    standard_id: &str,
    parent: Option<&str>,
    actor_for: impl FnOnce(Option<&str>) -> Option<String>,
) -> anyhow::Result<()> {
    let refused = |r: SetRefusal| anyhow::Error::new(FederatedBindRefused(r));
    let Some(mem) =
        crate::storage::get(conn, standard_id).map_err(|_| refused(SetRefusal::Unverifiable))?
    else {
        // Not found: let the write report it exactly as it always has.
        return crate::storage::set_namespace_standard(conn, namespace, standard_id, parent);
    };
    let binding = crate::storage::namespace_standard_binding(conn, namespace)
        .map_err(|_| refused(SetRefusal::Unverifiable))?;
    let before = crate::storage::ns_standard_ancestor::governing_ancestor_binding(conn, namespace)
        .map_err(|_| refused(SetRefusal::Unverifiable))?;
    let owner = mem
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str);
    let actor = actor_for(owner);
    federated_bind_admission(actor.as_deref(), namespace, &binding, &before).map_err(refused)?;
    crate::storage::set_namespace_standard(conn, namespace, standard_id, parent)?;
    let after = crate::storage::ns_standard_ancestor::governing_ancestor_binding(conn, namespace)
        .map_err(|_| refused(SetRefusal::Unverifiable))?;
    federated_reparent_admission(actor.as_deref(), &before, &after).map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::federation::peer_attestation::PeerScope;

    fn cfg(allowed: &[&str]) -> PeerAttestationConfig {
        let mut peers = std::collections::HashMap::new();
        if !allowed.is_empty() {
            peers.insert(
                "ai:peer".to_string(),
                PeerScope {
                    allowed_sender_agent_ids: allowed.iter().map(|a| (*a).to_string()).collect(),
                    allowed_namespaces: Vec::new(),
                },
            );
        }
        PeerAttestationConfig::from_peers(peers)
    }

    #[test]
    fn actor_is_the_bound_owner_only_when_the_peer_acts_for_it_4478() {
        let c = cfg(&["ai:peer", "ai:owner"]);
        assert_eq!(
            federated_bind_actor(Some("ai:peer"), "ai:peer", Some("ai:owner"), &c, false),
            Some("ai:owner".into())
        );
        // an owner the peer is NOT authorized for falls back to the sender
        assert_eq!(
            federated_bind_actor(Some("ai:peer"), "ai:peer", Some("ai:victim"), &c, false),
            Some("ai:peer".into())
        );
        // the attested sender itself
        assert_eq!(
            federated_bind_actor(
                Some("ai:peer"),
                "ai:owner",
                Some("ai:owner"),
                &cfg(&[]),
                false
            ),
            Some("ai:owner".into())
        );
        // legacy unauthored body: the peer id
        assert_eq!(
            federated_bind_actor(Some("ai:peer"), "", None, &c, false),
            Some("ai:peer".into())
        );
    }

    /// N4: a sender that IS the ancestor owner acts as itself even when the
    /// bound standard belongs to someone it cannot act for.
    #[test]
    fn attested_sender_acts_as_itself_for_a_foreign_standard_4478() {
        assert_eq!(
            federated_bind_actor(
                Some("ai:peer"),
                "ai:owner",
                Some("ai:victim"),
                &cfg(&[]),
                false
            ),
            Some("ai:owner".into())
        );
    }

    #[test]
    fn a_reparent_may_not_detach_from_an_ancestor_the_actor_does_not_own_4495() {
        let owned = GoverningAncestor::Standard {
            owner: Some("ai:owner".into()),
        };
        let none = GoverningAncestor::None;
        assert_eq!(
            federated_reparent_admission(Some("ai:peer"), &owned, &none),
            Err(SetRefusal::NotOwner)
        );
        assert!(federated_reparent_admission(Some("ai:owner"), &owned, &none).is_ok());
        assert!(federated_reparent_admission(Some("ai:peer"), &owned, &owned).is_ok());
        assert!(federated_reparent_admission(Some("ai:peer"), &none, &owned).is_ok());
        assert_eq!(
            federated_reparent_admission(None, &GoverningAncestor::Severed, &none),
            Err(SetRefusal::AncestorUnresolvable)
        );
    }

    /// Zero-config (no allowlist): the bound owner is taken on faith, as #1464
    /// attributes row ownership in that posture (the lane itself is refused
    /// there unless the push-scope requirement is explicitly opted out).
    #[test]
    fn zero_config_takes_the_bound_owner_on_faith_4495() {
        let zero = PeerAttestationConfig::default();
        assert!(!zero.has_allowlist());
        assert_eq!(
            federated_bind_actor(Some("ai:peer"), "ai:peer", Some("ai:victim"), &zero, false),
            Some("ai:victim".into())
        );
    }

    #[test]
    fn actor_cannot_be_established_without_attestation_4478() {
        let c = cfg(&[]);
        assert_eq!(
            federated_bind_actor(None, "ai:owner", Some("ai:owner"), &c, false),
            None
        );
        assert_eq!(
            federated_bind_actor(Some("ai:owner"), "ai:owner", Some("ai:owner"), &c, true),
            None
        );
    }

    #[test]
    fn admission_gates_every_binding_state_and_fails_closed_without_an_actor_4478_4495() {
        let owned = GoverningAncestor::Standard {
            owner: Some("ai:owner".into()),
        };
        let nm = NamespaceStandardBinding::NoMetaRow;
        assert_eq!(
            federated_bind_admission(Some("ai:peer"), "p/x", &nm, &owned),
            Err(SetRefusal::NotOwner)
        );
        assert_eq!(
            federated_bind_admission(None, "p/x", &nm, &owned),
            Err(SetRefusal::NotOwner)
        );
        assert!(federated_bind_admission(Some("ai:owner"), "p/x", &nm, &owned).is_ok());
        assert_eq!(
            federated_bind_admission(Some("ai:owner"), "p/x", &nm, &GoverningAncestor::Severed),
            Err(SetRefusal::AncestorUnresolvable)
        );
        assert!(federated_bind_admission(None, "p/x", &nm, &GoverningAncestor::None).is_ok());
        assert!(
            federated_bind_admission(
                None,
                "p/x",
                &nm,
                &GoverningAncestor::Standard { owner: None }
            )
            .is_ok()
        );
        // #4495: a rebind needs the CURRENT owner (#3758 parity)
        let rebind = NamespaceStandardBinding::Resolved(Some("ai:victim".into()));
        assert_eq!(
            federated_bind_admission(Some("ai:peer"), "p/x", &rebind, &owned),
            Err(SetRefusal::NotOwner)
        );
        assert!(federated_bind_admission(Some("ai:victim"), "p/x", &rebind, &owned).is_ok());
        assert_eq!(
            federated_bind_admission(None, "p/x", &rebind, &owned),
            Err(SetRefusal::NotOwner)
        );
        let unowned = NamespaceStandardBinding::Resolved(None);
        assert!(federated_bind_admission(None, "p/x", &unowned, &GoverningAncestor::None).is_ok());
        // a severed target's repair is gated like a first bind
        let severed = NamespaceStandardBinding::Unresolvable;
        assert_eq!(
            federated_bind_admission(Some("ai:peer"), "p/x", &severed, &owned),
            Err(SetRefusal::NotOwner)
        );
    }
}
