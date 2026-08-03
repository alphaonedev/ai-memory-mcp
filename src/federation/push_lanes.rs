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
//! Wire field strings live once in [`crate::federation::receive_auth`] `LANE_*`
//! consts (pm-v3.1 no-hardcoded-literal). This module only references those names.

use crate::federation::receive_auth::{
    LANE_ACTION_TRANSITIONS, LANE_ARCHIVES, LANE_CHECKPOINTS, LANE_DELETIONS, LANE_EMBEDDINGS,
    LANE_LINKS, LANE_MEMORIES, LANE_NAMESPACE_META, LANE_NAMESPACE_META_CLEARS,
    LANE_PENDING_DECISIONS, LANE_PENDINGS, LANE_RESTORES, LANE_SIGNALS,
};

/// A write-capable subcollection on `POST /api/v1/sync/push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncPushWriteLane {
    Memories,
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
            Self::Memories => LANE_MEMORIES,
            Self::Embeddings => LANE_EMBEDDINGS,
            Self::Deletions => LANE_DELETIONS,
            Self::Archives => LANE_ARCHIVES,
            Self::Restores => LANE_RESTORES,
            Self::Links => LANE_LINKS,
            Self::Pendings => LANE_PENDINGS,
            Self::PendingDecisions => LANE_PENDING_DECISIONS,
            Self::NamespaceMeta => LANE_NAMESPACE_META,
            Self::NamespaceMetaClears => LANE_NAMESPACE_META_CLEARS,
            Self::Signals => LANE_SIGNALS,
            Self::ActionTransitions => LANE_ACTION_TRANSITIONS,
            Self::Checkpoints => LANE_CHECKPOINTS,
        }
    }

    /// How namespace scope is (or must be) enforced for this lane.
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
            // #2649: stored action namespace (already loaded for signable).
            Self::ActionTransitions => ConfinementKind::ByIdStoredNamespace,
            // #2650: wire `cp.namespace` is the freeze-anchor write subject.
            Self::Checkpoints => ConfinementKind::ClaimedNamespace,
        }
    }
}

/// Structural confinement strategy for a write lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinementKind {
    ClaimedNamespace,
    ByIdStoredNamespace,
    ByIdEndpoints,
    PendingPayloadNamespace,
    NamespaceMeta,
    InheritedWithMemories,
}

/// Complete inventory of write lanes — **the exhaustiveness pin**.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        assert_eq!(
            ALL_SYNC_PUSH_WRITE_LANES.len(),
            13,
            "SyncPushBody write-lane count changed — update ALL_SYNC_PUSH_WRITE_LANES \
             and wire confinement (Gate 1 structural choke)"
        );
    }

    #[test]
    fn gate1_wire_fields_match_expected_sync_push_body_names() {
        // Expected order is SyncPushBody field order; values come only from LANE_* consts.
        let expected: &[&str] = &[
            LANE_MEMORIES,
            LANE_EMBEDDINGS,
            LANE_DELETIONS,
            LANE_ARCHIVES,
            LANE_RESTORES,
            LANE_LINKS,
            LANE_PENDINGS,
            LANE_PENDING_DECISIONS,
            LANE_NAMESPACE_META,
            LANE_NAMESPACE_META_CLEARS,
            LANE_SIGNALS,
            LANE_ACTION_TRANSITIONS,
            LANE_CHECKPOINTS,
        ];
        let got: Vec<&str> = ALL_SYNC_PUSH_WRITE_LANES
            .iter()
            .map(|l| l.wire_field())
            .collect();
        assert_eq!(got.as_slice(), expected);
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

    /// #2649 / #2650 — crypto lanes must declare a namespace strategy (not "exempt").
    #[test]
    fn gate1_crypto_lanes_require_namespace_strategy() {
        assert_eq!(
            SyncPushWriteLane::ActionTransitions.confinement_kind(),
            ConfinementKind::ByIdStoredNamespace
        );
        assert_eq!(
            SyncPushWriteLane::Checkpoints.confinement_kind(),
            ConfinementKind::ClaimedNamespace
        );
        assert_eq!(
            SyncPushWriteLane::ActionTransitions.wire_field(),
            LANE_ACTION_TRANSITIONS
        );
        assert_eq!(
            SyncPushWriteLane::Checkpoints.wire_field(),
            LANE_CHECKPOINTS
        );
    }
}
