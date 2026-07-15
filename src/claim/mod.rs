// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1836 (TRACT-gap G22) — a NON-AUTHORITATIVE, read-only "Claim view" of the
//! thick 28-field [`Memory`] row, and a machine-checked record of exactly where
//! it diverges from the frozen 9-field TRACT L1 Claim.
//!
//! # This is NOT the Claim algebra
//!
//! The substrate does **not** implement the TRACT L1 closed Claim algebra (see
//! `docs/spec/TRACT-L1-CLAIM-CONTRACT.md`). This module is deliberately small
//! and deliberately humble:
//!
//! - [`ClaimView`] is a **derived view** — it projects the CURRENT row through
//!   the Claim shape. TRACT's arrangement is the INVERSE (the thin Claim kernel
//!   is authoritative and the row projects *from* it); that inversion is
//!   v1.x work and is **UNBUILT**. `ClaimView` therefore encodes the
//!   status-quo direction (row → view) and MUST NOT be read as the kernel.
//! - The projection is **lossy by construction**. Several Claim fields have no
//!   faithful home on the row (`owner` is un-projectable, `id` is a UUID not a
//!   TRACT CIDv1, `sig_witnesses` do not exist, `confidence` is mutable, the
//!   `kind`/`lifecycle` vocabularies differ). Those holes are represented as
//!   `Option`/empty and enumerated in [`KNOWN_DIVERGENCES`] — the `Option`s ARE
//!   the divergence record.
//! - [`CLOSED_ALGEBRA_ENFORCED_BY_DEFAULT`] is `false`: the default write path
//!   still performs in-place UPDATE + hard DELETE (spec §4).
//!
//! Its only jobs are (1) to give the migration contract an executable, typed
//! anchor so the 28→9 mapping typechecks against the real struct, and (2) to
//! act as a drift-guard: the test suite asserts the known divergences still
//! hold, so a future change that silently "fixed" one (or broke the projection)
//! is caught.

pub mod refusal;
pub mod relation;

use crate::models::{Memory, MemoryLink};

/// The exact points where the [`Memory`] row diverges from the frozen 9-field
/// TRACT L1 Claim (spec `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §3/§4). Machine-
/// readable so the drift-guard test pins the set.
pub const KNOWN_DIVERGENCES: &[&str] = &[
    "id: UUID primary key, not a TRACT CIDv1 (cid is a different preimage)",
    "kind: MemoryKind (13-16 variants), not collapsed to the frozen 5-kind vocabulary",
    "content: UTF-8 String, no {mime, bytes}",
    "provenance: synthesized from >=4 columns; valid_time only since schema v79",
    "owner: UN-PROJECTABLE — no lineage-DAG owner ref on the row",
    "confidence: mutable f64 (decay overwrites), not the immutable value_at_assert",
    "attestation: single writer signature, no sig_witnesses[] on the row",
    "lifecycle: LifecycleState vocabulary, not asserted|superseded|forgotten",
    "links: live in a separate MemoryLink table, not on the Memory struct",
];

/// `true` only when the substrate enforces the closed-algebra invariants
/// (no in-place UPDATE, no silent DELETE) BY DEFAULT. It does not at v1.0.0 —
/// the default `human`/`agent` path UPDATEs in place and FORGET hard-DELETEs
/// (spec §4). Pinned as a const so the honesty state is machine-checked; the
/// day this flips to `true` is a deliberate edit here + in the spec ledger.
pub const CLOSED_ALGEBRA_ENFORCED_BY_DEFAULT: bool = false;

/// Synthesized provenance (Claim field 4). Assembled from several row columns;
/// `valid_time` only exists on schema-v79+ rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProvenanceView {
    /// From `metadata.agent_id` (a claimed string, not a lineage node).
    pub asserter: Option<String>,
    /// From `Memory.source`.
    pub source: String,
    /// From `Memory.source_uri`, when present.
    pub source_uri: Option<String>,
    /// Bitemporal `valid_from` (schema v79+), when present.
    pub valid_from: Option<String>,
    /// Bitemporal `valid_until` (schema v79+), when present.
    pub valid_until: Option<String>,
    /// `Memory.created_at` (transaction time).
    pub created_at: String,
}

/// One RELATE edge, projected from a caller-supplied [`MemoryLink`] row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimLinkView {
    pub predicate: String,
    pub target: String,
}

/// A read-only, NON-AUTHORITATIVE view of a [`Memory`] through the frozen
/// 9-field Claim shape. Lossy by construction — see [`KNOWN_DIVERGENCES`]. This
/// is NOT the Claim kernel and NOT evidence of algebra conformance.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimView {
    /// Field 1 — the row's UUID id. NOT the TRACT CIDv1.
    pub id_uuid: String,
    /// Field 1 (divergent) — the v74 content-address (`b3:…`) when present; a
    /// DIFFERENT preimage than TRACT's `dCBOR(content)‖dCBOR(provenance)` CIDv1.
    pub cid: Option<String>,
    /// Field 2 — the NATIVE `memory_kind` slug, not collapsed to the frozen 5.
    pub kind_native: String,
    /// Field 3 — the content bytes as UTF-8; no `mime`.
    pub content: String,
    /// Field 4 — synthesized provenance.
    pub provenance: ProvenanceView,
    /// Field 5 — TRACT `owner` (lineage-DAG ref). ALWAYS `None`: un-projectable.
    pub owner: Option<()>,
    /// Field 6 — the CURRENT (possibly decay-mutated) confidence, NOT the
    /// immutable `value_at_assert`.
    pub confidence_current: f64,
    /// Field 7 — attest level (`claimed`/`attested` analogue).
    pub attest_level: String,
    /// Field 7 — the witness signatures. ALWAYS empty: a `Memory` row carries a
    /// single writer signature, no `sig_witnesses[]`.
    pub sig_witnesses: Vec<Vec<u8>>,
    /// Field 8 — the NATIVE `lifecycle_state` slug, not the TRACT
    /// `asserted|superseded|forgotten` vocabulary.
    pub lifecycle_native: String,
    /// Field 9 — RELATE edges, from the caller-supplied link rows (links are NOT
    /// a column of `Memory`).
    pub links: Vec<ClaimLinkView>,
}

impl ClaimView {
    /// Derive a [`ClaimView`] from a row + its link rows. **Non-authoritative,
    /// read-only, lossy** — see the module docs. Total: never panics; round-
    /// trips every field the row genuinely carries and represents every
    /// divergence as an `Option`/empty per [`KNOWN_DIVERGENCES`]. The caller
    /// supplies `links` because they live in a separate table.
    #[must_use]
    pub fn of_memory(mem: &Memory, links: &[MemoryLink]) -> Self {
        let asserter = mem
            .metadata
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        Self {
            id_uuid: mem.id.clone(),
            cid: mem.cid.clone(),
            kind_native: mem.memory_kind.as_str().to_string(),
            content: mem.content.clone(),
            provenance: ProvenanceView {
                asserter,
                source: mem.source.clone(),
                source_uri: mem.source_uri.clone(),
                // valid_from/valid_until are v79 bitemporal columns not on the
                // Memory struct's public fields; left None here (a further
                // divergence surfaced by the mapping, not fabricated).
                valid_from: None,
                valid_until: None,
                created_at: mem.created_at.clone(),
            },
            // Un-projectable: TRACT owner is a lineage-DAG node ref; the row has
            // no such field. NEVER synthesized.
            owner: None,
            confidence_current: mem.confidence,
            attest_level: mem
                .metadata
                .get(crate::models::field_names::ATTEST_LEVEL)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("claimed")
                .to_string(),
            // No witness array exists on a Memory row.
            sig_witnesses: Vec::new(),
            lifecycle_native: mem.lifecycle_state.as_str().to_string(),
            links: links
                .iter()
                .map(|l| ClaimLinkView {
                    predicate: l.relation.as_str().to_string(),
                    target: l.target_id.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Memory;

    fn sample() -> Memory {
        Memory {
            id: "11111111-2222-3333-4444-555555555555".into(),
            content: "hello".into(),
            source: "unit-test".into(),
            confidence: 0.9,
            created_at: "2026-07-15T00:00:00Z".into(),
            ..Memory::default()
        }
    }

    // The anchor's job: projection TOTALITY (never panics + round-trips present
    // fields) — NOT algebra conformance.
    #[test]
    fn projection_is_total_and_round_trips_present_fields() {
        let mem = sample();
        let view = ClaimView::of_memory(&mem, &[]);
        assert_eq!(view.id_uuid, mem.id, "id round-trips (as the UUID)");
        assert_eq!(view.content, mem.content, "content round-trips");
        assert_eq!(view.confidence_current, mem.confidence);
        assert_eq!(view.provenance.source, mem.source);
        assert_eq!(view.provenance.created_at, mem.created_at);
        assert_eq!(view.kind_native, mem.memory_kind.as_str());
        assert_eq!(view.lifecycle_native, mem.lifecycle_state.as_str());
    }

    // The drift-guard: the KNOWN divergences must still hold. If a future change
    // "fixes" one silently, this fails and forces a deliberate spec + ledger
    // update (it is NOT a conformance test).
    #[test]
    fn known_divergences_still_hold() {
        let view = ClaimView::of_memory(&sample(), &[]);
        // owner is un-projectable — never synthesized.
        assert!(view.owner.is_none(), "TRACT owner has no row home");
        // No witness array on a row.
        assert!(
            view.sig_witnesses.is_empty(),
            "no sig_witnesses[] on Memory"
        );
        // id is the UUID, not a TRACT CIDv1 (`b3:`-prefixed cid is separate).
        assert!(
            !view.id_uuid.starts_with("b3:"),
            "id_uuid is the UUID PK, not the content-address"
        );
        // The closed algebra is NOT enforced by default (spec §4).
        assert!(
            !CLOSED_ALGEBRA_ENFORCED_BY_DEFAULT,
            "the default path still UPDATEs in place + hard-DELETEs"
        );
        // The divergence record is the frozen set of 9.
        assert_eq!(KNOWN_DIVERGENCES.len(), 9, "one divergence per Claim field");
    }

    #[test]
    fn links_project_from_supplied_rows_not_the_memory_struct() {
        use crate::models::{MemoryLink, MemoryLinkRelation};
        let link = MemoryLink {
            source_id: "a".into(),
            target_id: "b".into(),
            relation: MemoryLinkRelation::RelatedTo,
            created_at: "2026-07-15T00:00:00Z".into(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
        };
        let view = ClaimView::of_memory(&sample(), std::slice::from_ref(&link));
        assert_eq!(
            view.links.len(),
            1,
            "links come from the caller, not &Memory"
        );
        assert_eq!(view.links[0].target, "b");
    }
}
