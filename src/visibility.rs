// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #951 (Track A QC sweep, 2026-05-20) — single canonical
//! `is_visible_to_caller` helper, available on both `sal` and
//! non-sal builds.
//!
//! Pre-#951 the same visibility check was inlined / duplicated in
//! at least 3 sites:
//! - `src/store/mod.rs::is_visible_to_caller` (sal-gated; canonical)
//! - `src/handlers/memories_query.rs::is_visible_to_caller`
//!   (handler-local duplicate; DRIFT — missing the
//!   `metadata.target_agent_id` inbox carve-out)
//! - `src/handlers/memories.rs::get_memory` (inline gate per #927;
//!   couldn't import the canonical version because `crate::store`
//!   is `#[cfg(feature = "sal")]`-gated)
//!
//! Moving the helper here (not gated) lets the sqlite-only build,
//! the sal-only build, and the sal-postgres build all share the
//! same predicate so future scope semantics can change once and
//! land everywhere.
//!
//! Semantics (load-bearing — DO NOT drift):
//!   `is_visible_to_caller(mem, caller)` returns true iff:
//!     - `mem.metadata.scope != "private"` (rows without the field
//!       default to private per the CLAUDE.md NHI contract), OR
//!     - `mem.metadata.agent_id == caller` (owner), OR
//!     - `mem.metadata.target_agent_id == caller` (inbox carve-
//!       out: the sender stamps `target_agent_id` on a private-by-
//!       default `_inbox/<recipient>` row so the recipient can
//!       read their own inbox even though the row is scope=private
//!       under the sender's ownership).

use crate::models::Memory;

/// Returns `true` when the caller is entitled to see the memory.
///
/// Per #951 this is the **single canonical** implementation — every
/// handler, MCP tool, and SAL adapter that needs an in-process
/// visibility check should call this rather than re-implementing
/// the predicate. Drift between copies is a real defect (the
/// pre-#951 inline copy in `handlers/memories_query.rs` was missing
/// the inbox carve-out, which would have surfaced the day a private
/// inbox row hit a list+filter path).
#[must_use]
pub fn is_visible_to_caller(mem: &Memory, caller: &str) -> bool {
    let scope = mem
        .metadata
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("private");
    if scope != "private" {
        return true;
    }
    let owner = mem
        .metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if owner == caller {
        return true;
    }
    let target = mem
        .metadata
        .get("target_agent_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    target == caller
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use serde_json::json;

    fn mem_with_metadata(metadata: serde_json::Value) -> Memory {
        Memory {
            id: "test-id".to_string(),
            tier: Tier::Long,
            namespace: "test-ns".to_string(),
            title: "test".to_string(),
            content: "test".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-05-20T00:00:00Z".to_string(),
            updated_at: "2026-05-20T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        }
    }

    #[test]
    fn private_default_owner_can_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice"}));
        assert!(is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn private_default_non_owner_cannot_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice"}));
        assert!(!is_visible_to_caller(&m, "bob"));
    }

    #[test]
    fn explicit_private_owner_can_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "private"}));
        assert!(is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn explicit_private_non_owner_cannot_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "private"}));
        assert!(!is_visible_to_caller(&m, "bob"));
    }

    #[test]
    fn shared_scope_anyone_can_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "shared"}));
        assert!(is_visible_to_caller(&m, "bob"));
        assert!(is_visible_to_caller(&m, "carol"));
    }

    #[test]
    fn inbox_target_can_see_private_row() {
        // Inbox carve-out: sender stamps target_agent_id; recipient
        // reads their own inbox even though scope=private under
        // sender's ownership.
        let m = mem_with_metadata(json!({
            "agent_id": "alice",
            "scope": "private",
            "target_agent_id": "bob"
        }));
        assert!(is_visible_to_caller(&m, "bob"));
        // Non-target non-owner still blocked.
        assert!(!is_visible_to_caller(&m, "carol"));
    }

    #[test]
    fn empty_owner_blocks_named_caller() {
        // Legacy unowned (no agent_id) scope=private rows are NOT
        // visible to a named caller — the empty `owner` string
        // doesn't match "alice", so the predicate denies. (Higher-
        // level handler code interprets empty owner as
        // "unowned-legacy" and may treat that as claimable, but
        // the predicate itself is strict-equality.)
        let m = mem_with_metadata(json!({"scope": "private"}));
        assert!(!is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn empty_owner_visible_to_empty_caller_edge_case() {
        // The "" == "" equality is a degenerate edge case — handler
        // callers always synthesize a non-empty principal
        // (`anonymous:req-<uuid>` or X-Agent-Id), so this branch
        // would only fire on a misconfigured caller chain. Document
        // the behavior so a future refactor doesn't tighten it
        // without understanding the call-site contract.
        let m = mem_with_metadata(json!({"scope": "private"}));
        assert!(is_visible_to_caller(&m, ""));
    }
}
