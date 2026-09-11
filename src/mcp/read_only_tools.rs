// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B6 — the MCP tools that never write (the dispatch-layer
//! record-stop fence lets these through unconditionally). Split out of
//! `src/mcp/mod.rs` by #3549 (QUAL-10); the #3549 read-funnel structural
//! guard parses this table as the read-only inventory.

/// Wave-2 B6 — MCP tools that MUST stay live under record-stop (reads /
/// status / capabilities). Everything else is a mutating write and is
/// fenced at the dispatch layer. Fail-closed: a newly added tool that
/// is not in this set is treated as a write.
pub(crate) fn mcp_tool_is_read_only(name: &str) -> bool {
    use crate::mcp::registry::tool_names as t;
    matches!(
        name,
        t::MEMORY_RECALL
            | t::MEMORY_RECALL_OBSERVATIONS
            | t::MEMORY_SEARCH
            | t::MEMORY_LIST
            | t::MEMORY_GET
            | t::MEMORY_GET_LINKS
            | t::MEMORY_GET_TAXONOMY
            | t::MEMORY_STATS
            | t::MEMORY_CAPABILITIES
            | t::MEMORY_CHECK_DUPLICATE
            | t::MEMORY_CHECK_AGENT_ACTION
            | t::MEMORY_ENTITY_GET_BY_ALIAS
            | t::MEMORY_FIND_PATHS
            | t::MEMORY_LINEAGE
            | t::MEMORY_KG_QUERY
            | t::MEMORY_KG_TIMELINE
            | t::MEMORY_VERIFY
            | t::MEMORY_REPLAY
            | t::MEMORY_INBOX
            | t::MEMORY_PENDING_LIST
            | t::MEMORY_ACTION_GET
            | t::MEMORY_ACTION_LIST
            | t::MEMORY_ACTION_EDGES
            | t::MEMORY_ACTION_FRONTIER
            | t::MEMORY_ACTION_NEXT
            | t::MEMORY_LEASE_GET
            | t::MEMORY_ROUTINE_LIST
            | t::MEMORY_ROUTINE_STATUS
            | t::MEMORY_CHECKPOINT_QUERY
            | t::MEMORY_CHECKPOINT_VERIFY
            | t::MEMORY_SIGNAL_INBOX
            | t::MEMORY_SIGNAL_READ
            | t::MEMORY_SIGNAL_THREAD
            | t::MEMORY_SKILL_GET
            | t::MEMORY_SKILL_LIST
            | t::MEMORY_SKILL_EXPORT
            | t::MEMORY_SKILL_RESOURCE
            | t::MEMORY_SKILL_COMPOSITIONAL_CONTEXT
            | t::MEMORY_ARCHIVE_LIST
            | t::MEMORY_ARCHIVE_STATS
            | t::MEMORY_NAMESPACE_GET_STANDARD
            | t::MEMORY_QUOTA_STATUS
            | t::MEMORY_RULE_LIST
            | t::MEMORY_AGENT_LIST
            | t::MEMORY_LIST_SUBSCRIPTIONS
            | t::MEMORY_SUBSCRIPTION_DLQ_LIST
            | t::MEMORY_SMART_LOAD
            | t::MEMORY_LOAD_FAMILY
            | t::MEMORY_EXPAND_QUERY
            | t::MEMORY_REFLECTION_ORIGIN
            | t::MEMORY_EXPORT_REFLECTION
            | t::MEMORY_DEPENDENTS_OF_INVALIDATED
            | t::MEMORY_PERSONA
            | t::MEMORY_DEREF
    )
}
