// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! L2-2 cross-peer reflection bookkeeping (v0.7.0 Wave-2 fix B2 / S6-M1).
//!
//! When a reflection memory replicates from a remote peer (via
//! `federation_receive::sync_push`), the receiver needs three things to
//! hold:
//!
//! 1. The imported row preserves the source peer's `reflection_depth`
//!    on the wire — the substrate's `apply_remote_memory` already does
//!    insert-if-newer with the wire-shape Memory, so depth is carried.
//!    Provenance lives in `metadata.peer_origin` so a curator can later
//!    distinguish locally-minted reflections from imported ones.
//! 2. When a LOCAL curator subsequently writes a NEW reflection whose
//!    sources include the imported reflection, the depth cap applied
//!    is the LOCAL namespace's `max_reflection_depth` — not the source
//!    peer's. The existing `storage::reflect::reflect_with_hooks`
//!    already enforces this (resolves governance via the receiver's
//!    `resolve_governance_policy`), so the substrate primitive needs
//!    no change. What this module adds is the audit-emit + the
//!    `memory_reflection_origin` MCP introspection tool.
//! 3. Ed25519 signature verification on `reflects_on` edges already
//!    runs through the generic link-attest path in
//!    `federation_receive::sync_push`'s H3 verify branch
//!    (`identity::verify::verify` is relation-agnostic). No extra
//!    machinery here.
//!
//! Wire shape of `metadata.peer_origin`:
//!
//! ```json
//! {
//!   "peer_origin": {
//!     "peer_id": "<sender_agent_id>",
//!     "original_depth": 2,
//!     "imported_at": "2026-05-13T12:34:56Z"
//!   }
//! }
//! ```
//!
//! Idempotent: if the row already carries a `peer_origin` block (e.g.
//! the wire payload was relayed through a third peer that stamped it
//! first), we leave the existing block alone so the original-importer
//! attribution is preserved.

use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Map, Value, json};

use crate::models::Memory;

/// v0.7.0 Wave-2 fix B2 (S6-M1) — splice a `peer_origin` block into a
/// memory's `metadata` BEFORE insert via `apply_remote_memory`.
///
/// Mutates `mem.metadata` in place. The caller is the federation
/// receive path; the source peer id comes from
/// `SyncPushBody::sender_agent_id` (already validated as a syntactic
/// agent id by `validate::validate_agent_id`).
///
/// Two early-return guards keep the splice additive:
///   * Memories with `reflection_depth == 0` are not reflections; we
///     do not stamp them so the marker stays specific to reflection
///     provenance (and bookkeeping queries don't need to walk every
///     federation-imported row).
///   * Memories whose metadata already has `peer_origin` are
///     pass-through (idempotent re-stamping by a third-peer relay
///     would otherwise overwrite the original importer's attribution).
pub fn stamp_peer_origin(mem: &mut Memory, source_peer_id: &str) {
    if mem.reflection_depth <= 0 {
        return;
    }
    // Take ownership of the metadata object so we can mutate; if it's
    // not an object, we replace it with one (matches the substrate's
    // `default_metadata` posture).
    let mut map: Map<String, Value> = match std::mem::take(&mut mem.metadata) {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    if map.contains_key("peer_origin") {
        // Re-assemble + bail — already stamped.
        mem.metadata = Value::Object(map);
        return;
    }
    let block = json!({
        "peer_id": source_peer_id,
        "original_depth": mem.reflection_depth,
        "imported_at": Utc::now().to_rfc3339(),
    });
    map.insert("peer_origin".to_string(), block);
    mem.metadata = Value::Object(map);
}

/// v0.7.0 Wave-2 fix B2 (S6-M1) — return the `peer_origin` block (if
/// any) on a memory. Used by the `memory_reflection_origin` MCP tool
/// and by the cross-peer audit-emit path so the depth-cap refusal
/// includes the source-peer attribution.
///
/// Returns `None` when the memory has no `metadata.peer_origin` (the
/// memory was locally minted, or it's a non-reflection row).
#[must_use]
pub fn peer_origin_of(mem: &Memory) -> Option<&Value> {
    mem.metadata.get("peer_origin")
}

/// v0.7.0 Wave-2 fix B2 (S6-M1) — structured payload returned by the
/// MCP `memory_reflection_origin` tool. Fields mirror the wire-shape
/// block written by `stamp_peer_origin` plus the receiver-side
/// `local_depth_at_arrival` snapshot.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct ReflectionOrigin {
    /// Memory id queried.
    pub memory_id: String,
    /// `metadata.peer_origin.peer_id` — `None` when the memory is
    /// locally minted (no peer_origin block).
    pub peer_origin: Option<String>,
    /// `metadata.peer_origin.original_depth` — the depth the source
    /// peer recorded for this reflection. `None` when not stamped.
    pub original_depth: Option<i32>,
    /// Local row's `reflection_depth` at the time of the query.
    /// Always present (a memory is the row, the row has a depth).
    pub local_depth_at_arrival: i32,
    /// `metadata.agent_id` — the signing agent on the source peer when
    /// peer_origin is present, else the local writer's agent.
    pub signing_agent: Option<String>,
}

/// v0.7.0 Wave-2 fix B2 (S6-M1) — fetch the `peer_origin` block for a
/// memory id. Backs the `memory_reflection_origin` MCP tool.
///
/// # Errors
///
/// Returns the underlying `rusqlite`-wrapped storage error if the read
/// fails. Returns `Ok(None)` when no row matches the id.
pub fn lookup_reflection_origin(
    conn: &Connection,
    memory_id: &str,
) -> anyhow::Result<Option<ReflectionOrigin>> {
    let Some(mem) = crate::storage::get(conn, memory_id)? else {
        return Ok(None);
    };
    let signing_agent = mem
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let (peer_origin, original_depth) = match peer_origin_of(&mem) {
        Some(block) => (
            block
                .get("peer_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            block
                .get("original_depth")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok()),
        ),
        None => (None, None),
    };
    Ok(Some(ReflectionOrigin {
        memory_id: mem.id,
        peer_origin,
        original_depth,
        local_depth_at_arrival: mem.reflection_depth,
        signing_agent,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tier;
    use serde_json::json;

    fn reflection_fixture(depth: i32) -> Memory {
        Memory {
            id: "mem-r1".into(),
            tier: Tier::Mid,
            namespace: "ns-a".into(),
            title: "imported reflection".into(),
            content: "body".into(),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "claude".into(),
            access_count: 0,
            created_at: "2026-05-13T12:00:00Z".into(),
            updated_at: "2026-05-13T12:00:00Z".into(),
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:remote-curator"}),
            reflection_depth: depth,
        }
    }

    #[test]
    fn stamp_peer_origin_adds_block_on_reflection_memory() {
        let mut m = reflection_fixture(2);
        stamp_peer_origin(&mut m, "peer-A");
        let block = m.metadata.get("peer_origin").expect("peer_origin stamped");
        assert_eq!(block["peer_id"], "peer-A");
        assert_eq!(block["original_depth"], 2);
        assert!(block["imported_at"].as_str().is_some());
        // Original metadata fields preserved.
        assert_eq!(m.metadata["agent_id"], "ai:remote-curator");
    }

    #[test]
    fn stamp_peer_origin_is_idempotent_on_already_stamped_row() {
        let mut m = reflection_fixture(2);
        stamp_peer_origin(&mut m, "peer-A");
        let first_imported_at = m.metadata["peer_origin"]["imported_at"]
            .as_str()
            .unwrap()
            .to_string();
        // Re-stamp with a DIFFERENT peer id; original-importer wins.
        stamp_peer_origin(&mut m, "peer-B");
        assert_eq!(m.metadata["peer_origin"]["peer_id"], "peer-A");
        assert_eq!(
            m.metadata["peer_origin"]["imported_at"].as_str().unwrap(),
            first_imported_at
        );
    }

    #[test]
    fn stamp_peer_origin_skips_non_reflection_rows() {
        let mut m = reflection_fixture(0);
        stamp_peer_origin(&mut m, "peer-A");
        assert!(m.metadata.get("peer_origin").is_none());
    }

    #[test]
    fn stamp_peer_origin_creates_metadata_object_when_absent() {
        let mut m = reflection_fixture(1);
        m.metadata = serde_json::Value::Null;
        stamp_peer_origin(&mut m, "peer-A");
        assert_eq!(m.metadata["peer_origin"]["peer_id"], "peer-A");
    }

    #[test]
    fn peer_origin_of_returns_block_when_present() {
        let mut m = reflection_fixture(2);
        stamp_peer_origin(&mut m, "peer-A");
        let block = peer_origin_of(&m).expect("present");
        assert_eq!(block["peer_id"], "peer-A");
    }

    #[test]
    fn peer_origin_of_is_none_for_local_memory() {
        let m = reflection_fixture(2);
        assert!(peer_origin_of(&m).is_none());
    }
}
