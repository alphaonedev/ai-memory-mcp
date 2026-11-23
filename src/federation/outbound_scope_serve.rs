// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9996 / #10037 — the outbound namespace scope on the pull path.
//!
//! `GET /sync/since` hands rows to a peer exactly as the push lanes do, so
//! it is bound by the same per-peer [`PeerOutboundScope`]
//! ([`super::outbound_scope`]). This module is the one admission funnel of
//! that path:
//!
//! 1. [`AuthenticatedPullPeer`] is the peer whose scope applies. It is built
//!    only from the peer id bound to the presented mTLS certificate
//!    ([`AuthenticatedPullPeer::tls_bound`]) or from an `X-Peer-Id` whose
//!    signature verified ([`AuthenticatedPullPeer::signature_verified`],
//!    which takes a [`SignatureProof`] only the signature check mints). A
//!    caller-supplied header alone never selects a scope.
//! 2. [`resolve_pull_scope`] maps that peer to its configured entry through
//!    the entry's `peer_ids`. An unauthenticated request, an id no entry
//!    names, an unset config and a malformed one all resolve to
//!    [`PeerOutboundScope::Deny`] (fail closed).
//! 3. [`admit_rows`] is the only constructor of [`AdmittedRows`], the only
//!    row set the handler serialises into the page. A row is admitted only
//!    when the outbound scope AND the inbound attestation allowlist both
//!    admit its namespace; the `AI_MEMORY_FED_SYNC_TRUST_PEER` bypass can
//!    widen the attestation test, never the outbound scope. Every row left
//!    out is counted per `(peer, namespace)` under the configured peer's
//!    stable id, the same label the push lanes use (#10039).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

use super::outbound_scope::{
    FILTERED_UNRESOLVED_LABEL, FilteredTally, OUTBOUND_SCOPE_ENV, OUTBOUND_SCOPE_TRACE_TARGET,
    OutboundRefusal, OutboundScopeConfigError, PeerOutboundScope, note_refusal, parse_entries,
    record_filtered,
};
use crate::models::Memory;

/// `scope_status` of a `/sync/since` page refused by the outbound scope.
pub const SCOPE_STATUS_OUTBOUND_DENY: &str = "outbound_scope_deny";
/// Lane name of the pull path in outbound scope traces.
pub const LANE_SYNC_SINCE: &str = "sync_since";
/// Peer label of a pull whose authenticated peer no entry names, or that
/// carries no authenticated peer at all.
pub const PULL_UNRESOLVED_PEER_LABEL: &str = FILTERED_UNRESOLVED_LABEL;

/// Proof that the `X-Peer-Id` signature of this request verified against
/// the key enrolled for that peer id. Minted only by the `/sync/since`
/// signature check (a source ratchet pins the one call site).
#[derive(Debug)]
pub struct SignatureProof {
    _private: (),
}

impl SignatureProof {
    /// Mint the proof. Called only once the signature has verified.
    #[must_use]
    pub(crate) fn mint_after_signature_check() -> Self {
        Self { _private: () }
    }
}

/// The authenticated peer of one pull request (CBC-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPullPeer(String);

impl AuthenticatedPullPeer {
    /// The peer id bound to the presented mTLS client certificate. A cert
    /// with no operator binding proves no peer id.
    #[must_use]
    pub fn tls_bound(cert: &crate::tls::ClientCertPeerId) -> Option<Self> {
        cert.0
            .as_deref()
            .filter(|id| !id.is_empty())
            .map(|id| Self(id.to_string()))
    }

    /// The `X-Peer-Id` whose signature verified.
    #[must_use]
    pub fn signature_verified(peer_id: &str, proof: SignatureProof) -> Option<Self> {
        let SignatureProof { _private: () } = proof;
        (!peer_id.is_empty()).then(|| Self(peer_id.to_string()))
    }

    /// The authenticated peer id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The outbound scope that applies to one pull, with its counter label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeScope {
    label: String,
    scope: PeerOutboundScope,
}

impl ServeScope {
    fn unresolved() -> Self {
        Self {
            label: PULL_UNRESOLVED_PEER_LABEL.to_string(),
            scope: PeerOutboundScope::Deny,
        }
    }

    /// The counter label: the configured peer's stable id, else
    /// [`PULL_UNRESOLVED_PEER_LABEL`].
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The resolved scope.
    #[must_use]
    pub fn scope(&self) -> &PeerOutboundScope {
        &self.scope
    }

    /// True when this pull is served nothing.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self.scope, PeerOutboundScope::Deny)
    }
}

/// Authenticated peer id to `(stable peer id, scope)`.
type PullIndex = HashMap<String, (String, PeerOutboundScope)>;

/// The last env value parsed and its index, so a request costs one string
/// compare while the value is unchanged.
static PULL_INDEX_CACHE: Mutex<Option<(String, Arc<Result<PullIndex, OutboundScopeConfigError>>)>> =
    Mutex::new(None);

fn build_index(raw: &str) -> Result<PullIndex, OutboundScopeConfigError> {
    let mut index = PullIndex::new();
    for (stable_id, entry) in parse_entries(raw)? {
        for peer_id in entry.peer_ids {
            index.insert(peer_id, (stable_id.clone(), entry.scope.clone()));
        }
    }
    Ok(index)
}

fn cached_index(raw: &str) -> Arc<Result<PullIndex, OutboundScopeConfigError>> {
    let mut cache = PULL_INDEX_CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some((cached_raw, index)) = cache.as_ref()
        && cached_raw == raw
    {
        return Arc::clone(index);
    }
    let index = Arc::new(build_index(raw));
    *cache = Some((raw.to_string(), Arc::clone(&index)));
    index
}

/// The outbound scope of `peer` from [`OUTBOUND_SCOPE_ENV`], read on every
/// request. Unset, not UTF-8, malformed, no authenticated peer and an id no
/// entry names all resolve to [`PeerOutboundScope::Deny`].
#[must_use]
pub fn resolve_pull_scope(peer: Option<&AuthenticatedPullPeer>) -> ServeScope {
    resolve_in(peer, std::env::var(OUTBOUND_SCOPE_ENV))
}

/// [`resolve_pull_scope`] over a given env read (the unit-test seam).
fn resolve_in(
    peer: Option<&AuthenticatedPullPeer>,
    env: Result<String, std::env::VarError>,
) -> ServeScope {
    let Some(peer) = peer else {
        return ServeScope::unresolved();
    };
    let raw = match env {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return ServeScope::unresolved(),
        Err(std::env::VarError::NotUnicode(_)) => {
            warn_config(&OutboundScopeConfigError::NotUnicode);
            return ServeScope::unresolved();
        }
    };
    match cached_index(&raw).as_ref() {
        Ok(index) => {
            index
                .get(peer.as_str())
                .map_or_else(ServeScope::unresolved, |(label, scope)| ServeScope {
                    label: label.clone(),
                    scope: scope.clone(),
                })
        }
        Err(e) => {
            warn_config(e);
            ServeScope::unresolved()
        }
    }
}

fn warn_config(e: &OutboundScopeConfigError) {
    tracing::warn!(
        target: OUTBOUND_SCOPE_TRACE_TARGET,
        "federation: /sync/since serves nothing: {e}"
    );
}

/// Trace and count one pull refused by the outbound scope.
pub fn note_pull_refused(scope: &ServeScope) {
    note_refusal(
        &scope.label,
        LANE_SYNC_SINCE,
        &OutboundRefusal::NoOutboundScope,
    );
}

/// The rows of one pull page that passed [`admit_rows`]. It serialises as
/// the row array, so the page carries no row this funnel did not admit.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct AdmittedRows(Vec<Memory>);

impl AdmittedRows {
    /// Rows admitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no row was admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Drop the admitted rows `keep` refuses (the visibility filter). It can
    /// only shrink the set.
    pub fn retain(&mut self, keep: impl FnMut(&Memory) -> bool) {
        self.0.retain(keep);
    }

    /// The first admitted row.
    #[must_use]
    pub fn first(&self) -> Option<&Memory> {
        self.0.first()
    }

    /// The last admitted row.
    #[must_use]
    pub fn last(&self) -> Option<&Memory> {
        self.0.last()
    }
}

/// Admit the rows `scope` and `inbound_allowed` both admit by namespace,
/// counting each row left out under the scope's label.
#[must_use]
pub fn admit_rows(
    rows: Vec<Memory>,
    scope: &ServeScope,
    inbound_allowed: impl Fn(&str) -> bool,
) -> AdmittedRows {
    let mut tally = FilteredTally::default();
    let kept: Vec<Memory> = rows
        .into_iter()
        .filter(|m| {
            let ok = scope.scope.allows(&m.namespace) && inbound_allowed(&m.namespace);
            if !ok {
                tally.add(&m.namespace);
            }
            ok
        })
        .collect();
    record_filtered(&scope.label, &tally);
    AdmittedRows(kept)
}

#[cfg(test)]
#[path = "outbound_scope_serve_tests.rs"]
mod tests;
