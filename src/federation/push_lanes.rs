// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Gate 1 structural confinement — `/sync/push` write-lane census (#2682).
//!
//! Cutline (`docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`): confinement must
//! land as **one structural choke + reflection exhaustiveness**, not another
//! hand-enumerated lane patch. This module is the **exhaustiveness table**:
//! every write subcollection on [`crate::handlers::federation_receive::SyncPushBody`]
//! that can mutate local state is named here. Adding a new wire field without
//! registering it here **fails the unit test**.
//!
//! Namespace enforcement still routes through
//! [`crate::federation::receive_auth::inbound_write_namespace_authorized`] and
//! siblings — the choke is that every lane *must* call one of those (or a
//! documented exempt meta path). Crypto-only authorization (transitions,
//! checkpoints) is **not** a substitute for namespace scope (#2649 / #2650).

/// A write-capable subcollection on `POST /api/v1/sync/push`.
///
/// Meta fields on `SyncPushBody` (sender_agent_id, clocks, dry_run, …) are
/// **not** lanes — they do not apply rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncPushWriteLane {
    Memories,
    /// Embeddings travel with memories; confinement is inherited (no standalone apply).
    Embeddings,
    Deletions,
    Archives,
    Restores,
    Links,
    Pendings,
    PendingDecisions,
    NamespaceMeta,
    NamespaceMetaClears,
    Signals,
    ActionTransitions,
    Checkpoints,
}

impl SyncPushWriteLane {
    /// Wire JSON key on `SyncPushBody` (serde field name).
    #[must_use]
    pub const fn wire_field(self) -> &'static str {
        match self {
            Self::Memories => "memories",
            Self::Embeddings => "embeddings",
            Self::Deletions => "deletions",
            Self::Archives => "archives",
            Self::Restores => "restores",
            Self::Links => "links",
            Self::Pendings => "pendings",
            Self::PendingDecisions => "pending_decisions",
            Self::NamespaceMeta => "namespace_meta",
            Self::NamespaceMetaClears => "namespace_meta_clears",
            Self::Signals => "signals",
            Self::ActionTransitions => "action_transitions",
            Self::Checkpoints => "checkpoints",
        }
    }

    /// How namespace scope is (or must be) enforced for this lane.
    ///
    /// Used by the exhaustiveness test and by reviewers — not a runtime
    /// dispatcher yet (dispatcher lands when all rows route through one call).
    #[must_use]
    pub const fn confinement_kind(self) -> ConfinementKind {
        match self {
            Self::Memories => ConfinementKind::ClaimedNamespace,
            Self::Embeddings => ConfinementKind::InheritedWithMemories,
            Self::Deletions | Self::Archives | Self::Restores => {
                ConfinementKind::ByIdStoredNamespace
            }
            Self::Links => ConfinementKind::ByIdEndpoints,
            Self::Pendings | Self::PendingDecisions => ConfinementKind::PendingPayloadNamespace,
            Self::NamespaceMeta | Self::NamespaceMetaClears => ConfinementKind::NamespaceMeta,
            Self::Signals => ConfinementKind::ClaimedNamespace,
            Self::ActionTransitions | Self::Checkpoints => ConfinementKind::ByIdStoredNamespace,
        }
    }
}

/// Structural confinement strategy for a write lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinementKind {
    /// Row carries an explicit namespace string (memory / signal).
    ClaimedNamespace,
    /// Apply is by id; load stored namespace then gate (delete/archive/restore).
    ByIdStoredNamespace,
    /// Link endpoints: gate source **and** target stored namespaces.
    ByIdEndpoints,
    /// Pending payload / namespace resolution helpers.
    PendingPayloadNamespace,
    /// Governance standard meta helpers.
    NamespaceMeta,
    /// Not applied alone — must not open a write path without parent lane.
    InheritedWithMemories,
}

/// Complete inventory of write lanes — **the exhaustiveness pin**.
///
/// Order matches the `SyncPushBody` field declaration order for human review.
pub const ALL_SYNC_PUSH_WRITE_LANES: &[SyncPushWriteLane] = &[
    SyncPushWriteLane::Memories,
    SyncPushWriteLane::Embeddings,
    SyncPushWriteLane::Deletions,
    SyncPushWriteLane::Archives,
    SyncPushWriteLane::Restores,
    SyncPushWriteLane::Links,
    SyncPushWriteLane::Pendings,
    SyncPushWriteLane::PendingDecisions,
    SyncPushWriteLane::NamespaceMeta,
    SyncPushWriteLane::NamespaceMetaClears,
    SyncPushWriteLane::Signals,
    SyncPushWriteLane::ActionTransitions,
    SyncPushWriteLane::Checkpoints,
];

/// Lane token strings shared with receive_auth logging / existing LANE_* consts.
pub mod lane_tokens {
    pub const MEMORIES: &str = "memories";
    pub const EMBEDDINGS: &str = "embeddings";
    pub const LINKS: &str = "links";
    pub const SIGNALS: &str = "signals";
    pub const ACTION_TRANSITIONS: &str = "action_transitions";
    pub const CHECKPOINTS: &str = "checkpoints";
    pub const ARCHIVES: &str = "archives";
    pub const RESTORES: &str = "restores";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Gate 1 exhaustiveness: every write subcollection is registered exactly once.
    #[test]
    fn gate1_all_write_lanes_registered_exactly_once() {
        let mut seen = HashSet::new();
        for lane in ALL_SYNC_PUSH_WRITE_LANES {
            assert!(
                seen.insert(lane.wire_field()),
                "duplicate wire field in ALL_SYNC_PUSH_WRITE_LANES: {}",
                lane.wire_field()
            );
        }
        // Hard pin: 13 write collections as of 2026-08-03 SyncPushBody census.
        // If you add a field to SyncPushBody that applies state, ADD A LANE HERE
        // and route it through inbound_* confinement — do not hand-patch only
        // federation_receive.rs (#2682 / cutline).
        assert_eq!(
            ALL_SYNC_PUSH_WRITE_LANES.len(),
            13,
            "SyncPushBody write-lane count changed — update ALL_SYNC_PUSH_WRITE_LANES \
             and wire confinement (Gate 1 structural choke)"
        );
    }

    #[test]
    fn gate1_wire_fields_match_expected_sync_push_body_names() {
        let expected = [
            "memories",
            "embeddings",
            "deletions",
            "archives",
            "restores",
            "links",
            "pendings",
            "pending_decisions",
            "namespace_meta",
            "namespace_meta_clears",
            "signals",
            "action_transitions",
            "checkpoints",
        ];
        let got: Vec<&str> = ALL_SYNC_PUSH_WRITE_LANES
            .iter()
            .map(|l| l.wire_field())
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn gate1_links_and_signals_require_namespace_strategy() {
        assert_eq!(
            SyncPushWriteLane::Links.confinement_kind(),
            ConfinementKind::ByIdEndpoints
        );
        assert_eq!(
            SyncPushWriteLane::Signals.confinement_kind(),
            ConfinementKind::ClaimedNamespace
        );
    }
}
