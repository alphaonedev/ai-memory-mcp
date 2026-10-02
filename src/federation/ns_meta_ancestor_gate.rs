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
//!    or it is listed in the peer's `allowed_sender_agent_ids`;
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
//! Exactly the #4356 act: a FIRST bind (no binding of the target's own) or the
//! repair of a severed one, through the shared
//! [`crate::ns_standard_ancestor::set_admission`] verdict. A REBIND of an
//! existing standard stays governed by the #2479 peer-scope gate alone,
//! unchanged by this issue (the receive loops never ran #3758, and changing
//! that is a separate decision).

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
    let acts_for = |agent: &str| {
        agent == sender
            || cfg
                .scope_for(peer)
                .is_some_and(|s| s.allowed_sender_agent_ids.iter().any(|a| a == agent))
    };
    match bound_owner.map(str::trim).filter(|o| !o.is_empty()) {
        Some(owner) if acts_for(owner) => Some(owner.to_string()),
        _ => Some(sender.to_string()),
    }
}

/// The #4356 verdict for one inbound entry: a first bind / severed repair
/// needs the governing ancestor's owner; anything else is left to #2479.
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
    if !needs_ancestor(binding) {
        return Ok(());
    }
    set_admission(
        actor.unwrap_or(crate::identity::sentinels::ANONYMOUS_INVALID),
        false,
        namespace,
        binding,
        ancestor,
    )
}

/// The sqlite half: read the target's binding, the governing ancestor and the
/// bound memory's owner on `conn` (the receive loop runs this INSIDE the
/// write transaction that performs the bind), then decide. Every read fault
/// is [`SetRefusal::Unverifiable`] (fail closed).
///
/// # Errors
///
/// [`SetRefusal`].
pub fn federated_bind_admission_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    standard_id: &str,
    actor_for: impl FnOnce(Option<&str>) -> Option<String>,
) -> Result<(), SetRefusal> {
    let binding = crate::storage::namespace_standard_binding(conn, namespace)
        .map_err(|_| SetRefusal::Unverifiable)?;
    if !needs_ancestor(&binding) {
        return Ok(());
    }
    let ancestor =
        crate::storage::ns_standard_ancestor::governing_ancestor_binding(conn, namespace)
            .map_err(|_| SetRefusal::Unverifiable)?;
    let owner = crate::storage::get(conn, standard_id)
        .map_err(|_| SetRefusal::Unverifiable)?
        .and_then(|m| {
            m.metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let actor = actor_for(owner.as_deref());
    federated_bind_admission(actor.as_deref(), namespace, &binding, &ancestor)
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
    fn admission_gates_first_binds_only_and_fails_closed_without_an_actor_4478() {
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
        // a rebind is left to #2479 (unchanged lane semantics)
        let rebind = NamespaceStandardBinding::Resolved(Some("ai:victim".into()));
        assert!(federated_bind_admission(Some("ai:peer"), "p/x", &rebind, &owned).is_ok());
        // a severed target's repair is gated like a first bind
        let severed = NamespaceStandardBinding::Unresolvable;
        assert_eq!(
            federated_bind_admission(Some("ai:peer"), "p/x", &severed, &owned),
            Err(SetRefusal::NotOwner)
        );
    }
}
