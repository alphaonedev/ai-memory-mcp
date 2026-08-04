// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Gate 1 structural confinement — `/sync/push` write-lane census (#2682).
//!
//! Cutline (`docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`): confinement must
//! land as **one structural choke + reflection exhaustiveness**, not another
//! hand-enumerated lane patch. This module is the **exhaustiveness table**:
//! every write subcollection on [`crate::handlers::federation_receive::SyncPushBody`]
//! that can mutate local state is named here.
//!
//! #2723 (CB-3 / CB-21) — the census is **DERIVED FROM `SyncPushBody`**, not a
//! hand-written literal that can silently drift. Two mechanisms enforce it:
//!   * a **compile-time exhaustiveness pin** (`reflect_sync_push_fields` in the
//!     tests) destructures EVERY field of `SyncPushBody` with **no `..`
//!     wildcard**, so adding a new wire field fails to compile until its author
//!     classifies it as a write lane or as sync metadata; and
//!   * a **reflection test** asserts [`ALL_SYNC_PUSH_WRITE_LANES`] equals the
//!     destructured write-lane serde field names IN ORDER, so a new `Vec<_>`
//!     subcollection cannot land green without a census entry.
//! EVERY `SyncPushBody` field is accounted for: the write lanes here plus the
//! non-confined [`SyncPushMetadataField`] set ([`ConfinementKind::SyncMetadata`]),
//! which explicitly includes `sender_clock` (a peer-controlled field that DOES
//! advance local `sync_state` via `VectorClock::merge`) rather than omitting it.
//!
//! Wire field strings for the write lanes live once in
//! [`crate::federation::receive_auth`] `LANE_*` consts (pm-v3.1
//! no-hardcoded-literal). This module only references those names.

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
    /// #2723 — namespace-AGNOSTIC sync/transport metadata, **not** a
    /// namespace-confined write subcollection. A field with this kind may still
    /// mutate local sync bookkeeping (e.g. `sender_clock` advances `sync_state`
    /// via [`crate::models::VectorClock::merge`]), but it carries no namespace
    /// to confine, so the Gate-1 confinement funnels do not — and must not —
    /// gate it. Present so the census accounts for EVERY `SyncPushBody` field,
    /// not only the write lanes. Carried by [`SyncPushMetadataField`], never by
    /// a [`SyncPushWriteLane`].
    SyncMetadata,
}

/// Every `SyncPushBody` field that is **not** a namespace-confined write lane
/// (#2723). Companion to [`SyncPushWriteLane`] so the Gate-1 census accounts for
/// EVERY wire field, not just the write subcollections — a field is either a
/// confined write lane or documented sync/transport metadata here. Each maps to
/// [`ConfinementKind::SyncMetadata`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncPushMetadataField {
    /// Peer identity; recorded in `sync_state`, attested against `x-peer-id`
    /// (#238). Carries no write namespace.
    SenderAgentId,
    /// Peer-controlled `VectorClock`. #2723: it DOES advance local `sync_state`
    /// (`VectorClock::merge` inside `sync_state_merge`), but it is
    /// namespace-AGNOSTIC causality metadata — there is no namespace to
    /// confine — so the confinement funnels neither do nor must gate it.
    /// Classified here (not silently omitted) so the census is complete.
    SenderClock,
    /// Observability-only sender wall-clock for clock-skew detection.
    SenderWallClock,
    /// FED-RQ-03 (#1947) governance-freshness gate input.
    SenderPolicySeq,
    /// FED-RQ-03 (#1947) same-seq policy-divergence diagnostic.
    SenderPolicyDigestHex,
    /// Preview control flag — classify-and-count, never writes.
    DryRun,
}

impl SyncPushMetadataField {
    /// Wire JSON key on `SyncPushBody` (serde field name).
    #[must_use]
    pub const fn wire_field(self) -> &'static str {
        match self {
            Self::SenderAgentId => "sender_agent_id",
            Self::SenderClock => "sender_clock",
            Self::SenderWallClock => "sender_wall_clock",
            Self::SenderPolicySeq => "sender_policy_seq",
            Self::SenderPolicyDigestHex => "sender_policy_digest_hex",
            Self::DryRun => "dry_run",
        }
    }

    /// Always [`ConfinementKind::SyncMetadata`]: these fields carry no namespace
    /// to confine.
    #[must_use]
    pub const fn confinement_kind(self) -> ConfinementKind {
        match self {
            Self::SenderAgentId
            | Self::SenderClock
            | Self::SenderWallClock
            | Self::SenderPolicySeq
            | Self::SenderPolicyDigestHex
            | Self::DryRun => ConfinementKind::SyncMetadata,
        }
    }
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

/// Complete inventory of the non-write-lane metadata fields (#2723). Together
/// with [`ALL_SYNC_PUSH_WRITE_LANES`] this names EVERY field on `SyncPushBody`;
/// the compile-time destructure pin in the tests enforces the completeness.
pub const ALL_SYNC_PUSH_METADATA_FIELDS: &[SyncPushMetadataField] = &[
    SyncPushMetadataField::SenderAgentId,
    SyncPushMetadataField::SenderClock,
    SyncPushMetadataField::SenderWallClock,
    SyncPushMetadataField::SenderPolicySeq,
    SyncPushMetadataField::SenderPolicyDigestHex,
    SyncPushMetadataField::DryRun,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::federation_receive::SyncPushBody;
    use std::collections::HashSet;

    /// Compile-time exhaustiveness pin (#2723). Destructures EVERY field of
    /// [`SyncPushBody`] with **no `..` wildcard**, so adding a new wire field
    /// fails to compile HERE until its author classifies it as either a
    /// registered write lane (add a [`SyncPushWriteLane`] variant + an
    /// [`ALL_SYNC_PUSH_WRITE_LANES`] entry) or documented sync metadata (add a
    /// [`SyncPushMetadataField`] variant + an [`ALL_SYNC_PUSH_METADATA_FIELDS`]
    /// entry). Returns `(write_lane_fields, metadata_fields)` as their serde
    /// names via `stringify!` (no string literals) so the reflection test below
    /// can prove the census references the REAL, current struct fields — not a
    /// stale hand-written copy that the old same-file expected-list could not.
    fn reflect_sync_push_fields(body: &SyncPushBody) -> (Vec<&'static str>, Vec<&'static str>) {
        // NO `..`: a new SyncPushBody field breaks this destructure. Fields are
        // bound to `_` (nothing moved, no unused-variable warnings) — the
        // `stringify!` names below are the compile-checked field idents.
        let SyncPushBody {
            // ---- registered write lanes (namespace-confined subcollections) ----
            memories: _,
            embeddings: _,
            deletions: _,
            archives: _,
            restores: _,
            links: _,
            pendings: _,
            pending_decisions: _,
            namespace_meta: _,
            namespace_meta_clears: _,
            signals: _,
            action_transitions: _,
            checkpoints: _,
            // ---- ConfinementKind::SyncMetadata: namespace-AGNOSTIC transport
            //      metadata, NOT namespace-confined write subcollections ----
            sender_agent_id: _,
            sender_clock: _,
            sender_wall_clock: _,
            sender_policy_seq: _,
            sender_policy_digest_hex: _,
            dry_run: _,
        } = body;
        let lanes = vec![
            stringify!(memories),
            stringify!(embeddings),
            stringify!(deletions),
            stringify!(archives),
            stringify!(restores),
            stringify!(links),
            stringify!(pendings),
            stringify!(pending_decisions),
            stringify!(namespace_meta),
            stringify!(namespace_meta_clears),
            stringify!(signals),
            stringify!(action_transitions),
            stringify!(checkpoints),
        ];
        let metadata = vec![
            stringify!(sender_agent_id),
            stringify!(sender_clock),
            stringify!(sender_wall_clock),
            stringify!(sender_policy_seq),
            stringify!(sender_policy_digest_hex),
            stringify!(dry_run),
        ];
        (lanes, metadata)
    }

    fn minimal_sync_push_body() -> SyncPushBody {
        // Only `sender_agent_id` + `memories` lack a serde default; everything
        // else is `#[serde(default)]`, so this exercises the real deserialize
        // path (the wire shape the funnels decode).
        serde_json::from_value(serde_json::json!({
            "sender_agent_id": "",
            "memories": [],
        }))
        .expect("minimal SyncPushBody must deserialize")
    }

    /// #2723 — the census is DERIVED from `SyncPushBody`, not a hand-written
    /// literal: a new `Vec<_>` subcollection field cannot land green without a
    /// census entry. Red-before/green-after mechanism: the destructure in
    /// `reflect_sync_push_fields` fails to COMPILE on an unclassified new field;
    /// once classified as a lane it must ALSO appear here (order + count), or
    /// this assertion fails.
    #[test]
    fn gate1_census_is_derived_from_sync_push_body() {
        let body = minimal_sync_push_body();
        let (lane_fields, metadata_fields) = reflect_sync_push_fields(&body);

        let census: Vec<&str> = ALL_SYNC_PUSH_WRITE_LANES
            .iter()
            .map(|l| l.wire_field())
            .collect();
        assert_eq!(
            lane_fields, census,
            "ALL_SYNC_PUSH_WRITE_LANES must equal SyncPushBody's write-lane serde \
             fields, in order — a new Vec<_> subcollection on SyncPushBody must be \
             registered as a SyncPushWriteLane (#2723)."
        );

        let metadata_inventory: Vec<&str> = ALL_SYNC_PUSH_METADATA_FIELDS
            .iter()
            .map(|m| m.wire_field())
            .collect();
        assert_eq!(
            metadata_fields, metadata_inventory,
            "ALL_SYNC_PUSH_METADATA_FIELDS must equal SyncPushBody's non-lane serde \
             fields, in order — a new metadata field must be registered (#2723)."
        );

        // Every field is classified exactly once (lanes + metadata are disjoint
        // and together cover the whole struct — the no-`..` destructure proves
        // coverage at compile time; this proves disjointness at test time).
        let mut seen: HashSet<&str> = HashSet::new();
        for field in lane_fields.iter().chain(metadata_fields.iter()) {
            assert!(
                seen.insert(field),
                "field `{field}` classified more than once"
            );
        }
        assert_eq!(seen.len(), lane_fields.len() + metadata_fields.len());
    }

    /// #2723 — `sender_clock` (peer-controlled, mutates local `sync_state` via
    /// `VectorClock::merge`) is REGISTERED as sync metadata, not silently
    /// omitted, and every metadata field carries [`ConfinementKind::SyncMetadata`].
    #[test]
    fn gate1_metadata_fields_are_sync_metadata_and_sender_clock_registered() {
        for field in ALL_SYNC_PUSH_METADATA_FIELDS {
            assert_eq!(
                field.confinement_kind(),
                ConfinementKind::SyncMetadata,
                "metadata field {field:?} must be classified SyncMetadata"
            );
        }
        assert!(
            ALL_SYNC_PUSH_METADATA_FIELDS.contains(&SyncPushMetadataField::SenderClock),
            "sender_clock must be registered in the census, not silently omitted (#2723)"
        );
    }

    /// #2723 / CB-7 — every declared write lane must be HANDLED by the receive
    /// funnel, not orphaned in the census. Structural pin (mirrors the
    /// `include_str!` source pins used elsewhere in `tests/`): the sqlite apply
    /// funnel reads `body.<lane>` for every lane, so each lane's wire field must
    /// appear as `body.<field>` in that funnel's source. A census entry with no
    /// funnel handling would fail here. Scope is census integrity — this does
    /// NOT re-verify the confinement CB-7 already wired, only that no lane is
    /// declared without an apply/enforcement site.
    #[test]
    fn gate1_every_lane_is_handled_by_the_receive_funnel() {
        const RECEIVE_FUNNEL_SRC: &str = include_str!("../handlers/federation_receive.rs");
        for lane in ALL_SYNC_PUSH_WRITE_LANES {
            let field = lane.wire_field();
            let access = format!("body.{field}");
            assert!(
                RECEIVE_FUNNEL_SRC.contains(&access),
                "census lane `{field}` is never read as `{access}` by the sqlite \
                 receive funnel (src/handlers/federation_receive.rs) — an orphaned \
                 census entry declares a lane with no apply/enforcement site (#2723)."
            );
        }
    }

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
