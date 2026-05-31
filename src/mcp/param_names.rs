// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Canonical SSOT for MCP tool-call parameter field names.
//
// Closes Fix #5 (literal-sweep v0.7.0 deferred-item): every MCP tool
// handler that extracts a field from `serde_json::Value` arguments via
// `.get("X")` / `["X"]` references a JSON key whose canonical truth
// lived as a scattered string literal across ~100 callsites under
// `src/mcp/tools/*.rs` + `src/mcp/mod.rs`. This module centralizes
// every such name as a `pub const FOO: &str = "foo"` so:
//
//   1. typos at extraction-site are caught at compile time (a missing
//      const → "use of undeclared name" rust-error),
//   2. JSON-Schema fields and the runtime extraction agree by SSOT
//      reference rather than literal-duplication,
//   3. a mechanical parity test (`tests/mcp_param_names_invariant.rs`)
//      asserts every production extraction-site literal corresponds
//      to a const in this module — new drift fails fast.
//
// Adding a new MCP tool parameter:
//   1. Add `pub const FOO_BAR: &str = "foo_bar";` to this module
//      (canonical snake_case = JSON key shape per MCP convention).
//   2. Use `crate::mcp::param_names::FOO_BAR` at the extraction site
//      in `src/mcp/tools/<your_tool>.rs`.
//   3. The parity test auto-picks up the new const + literal pairing.
//
// The const names mirror the canonical JSON key spelling in UPPER_SNAKE
// (e.g. `AGENT_ID = "agent_id"`). Future renames touch both this module
// + the parity-test allowlist in lockstep.

// 98 canonical MCP tool-call parameter field names (v0.7.0 census).
// Source: grep of every `.get("X")` / `["X"]` literal in
// `src/mcp/mod.rs` + `src/mcp/tools/*.rs` production code.
pub const AGENT_FILTER: &str = "agent_filter";
pub const AGENT_ID: &str = "agent_id";
pub const AGENT_TYPE: &str = "agent_type";
pub const ALIAS: &str = "alias";
pub const ALIASES: &str = "aliases";
pub const ALLOWED_AGENTS: &str = "allowed_agents";
pub const ARGUMENTS: &str = "arguments";
pub const AS_AGENT: &str = "as_agent";
pub const BY_SOURCE_URI: &str = "by_source_uri";
pub const BYTE_ESTIMATE: &str = "byte_estimate";
pub const CALLER_AGENT_ID: &str = "caller_agent_id";
pub const CANONICAL_NAME: &str = "canonical_name";
pub const CAPABILITIES: &str = "capabilities";
pub const CITATIONS: &str = "citations";
pub const CONFIDENCE: &str = "confidence";
pub const CONSUMED: &str = "consumed";
pub const CONTENT: &str = "content";
pub const CONTEXT: &str = "context";
pub const DEPTH: &str = "depth";
pub const DRY_RUN: &str = "dry_run";
pub const EDIT_SOURCE: &str = "edit_source";
pub const ENTITY_ID: &str = "entity_id";
pub const EVENT_TYPES: &str = "event_types";
pub const EVENTS: &str = "events";
pub const EXPECTED_VERSION: &str = "expected_version";
pub const EXPIRES_AT: &str = "expires_at";
pub const FAMILY: &str = "family";
pub const FILTER: &str = "filter";
pub const FOLDER_PATH: &str = "folder_path";
pub const FORCE: &str = "force";
pub const FORCE_RE_ATOMISE: &str = "force_re_atomise";
pub const FORMAT: &str = "format";
pub const GOVERNANCE: &str = "governance";
pub const ID: &str = "id";
pub const ID_A: &str = "id_a";
pub const ID_B: &str = "id_b";
pub const IDS: &str = "ids";
pub const INCLUDE_ARCHIVED: &str = "include_archived";
pub const INCLUDE_INVALIDATED: &str = "include_invalidated";
pub const INHERIT: &str = "inherit";
pub const INLINE_SKILL: &str = "inline_skill";
pub const INTENT: &str = "intent";
pub const K: &str = "k";
pub const KIND: &str = "kind";
pub const KIND_INNER: &str = "kind_inner";
pub const LIMIT: &str = "limit";
pub const LINK_ID: &str = "link_id";
pub const MAX_ATOM_TOKENS: &str = "max_atom_tokens";
pub const MAX_DEPTH: &str = "max_depth";
pub const MAX_RESULTS: &str = "max_results";
pub const MEMORY_ID: &str = "memory_id";
pub const METADATA: &str = "metadata";
pub const NAME: &str = "name";
pub const NAMESPACE: &str = "namespace";
pub const NAMESPACE_FILTER: &str = "namespace_filter";
pub const OFFSET: &str = "offset";
pub const OLDER_THAN_DAYS: &str = "older_than_days";
pub const ON_CONFLICT: &str = "on_conflict";
pub const PARENT: &str = "parent";
pub const PATTERN: &str = "pattern";
pub const PAYLOAD: &str = "payload";
pub const PIPELINE_OVERRIDE: &str = "pipeline_override";
pub const PRIORITY: &str = "priority";
pub const QUERY: &str = "query";
pub const REFLECTION_ID: &str = "reflection_id";
pub const RELATION: &str = "relation";
pub const REMEMBER: &str = "remember";
pub const RESOURCE_PATH: &str = "resource_path";
pub const SCOPE: &str = "scope";
pub const SECRET: &str = "secret";
pub const SINCE: &str = "since";
pub const SKILL_DESCRIPTION: &str = "skill_description";
pub const SKILL_ID: &str = "skill_id";
pub const SKILL_NAME: &str = "skill_name";
pub const SOURCE: &str = "source";
pub const SOURCE_ID: &str = "source_id";
pub const SOURCE_IDS: &str = "source_ids";
pub const SOURCE_MEMORY_ID: &str = "source_memory_id";
pub const SOURCE_SPAN: &str = "source_span";
pub const SOURCE_URI: &str = "source_uri";
pub const STATUS: &str = "status";
pub const SUBSCRIPTION_ID: &str = "subscription_id";
pub const SUMMARY: &str = "summary";
pub const TAGS: &str = "tags";
pub const TARGET_AGENT_ID: &str = "target_agent_id";
pub const TARGET_FOLDER: &str = "target_folder";
pub const TARGET_ID: &str = "target_id";
pub const TARGET_TIER: &str = "target_tier";
pub const THRESHOLD: &str = "threshold";
pub const TIER: &str = "tier";
pub const TITLE: &str = "title";
pub const TO_NAMESPACE: &str = "to_namespace";
pub const TTL_SECONDS: &str = "ttl_seconds";
pub const UNREAD_ONLY: &str = "unread_only";
pub const UNTIL: &str = "until";
pub const URL: &str = "url";
pub const VALID_AT: &str = "valid_at";
pub const VALID_UNTIL: &str = "valid_until";

/// Every canonical MCP tool-call parameter name, surfaced as a single
/// allowlist slice for the parity test in
/// `tests/mcp_param_names_invariant.rs` to assert that every
/// production `.get("X")` / `["X"]` literal under `src/mcp/` matches.
///
/// SSOT pin: this array's length is the v0.7.0 census of unique
/// param names (98). The parity test compares the grep-extracted
/// production-literal set with `ALL_PARAM_NAMES` and fails on either
/// orphan (literal not in allowlist) OR unused-allowlist (allowlist
/// const that no production code references — surfaces dead consts
/// for cleanup).
pub const ALL_PARAM_NAMES: &[&str] = &[
    AGENT_FILTER,
    AGENT_ID,
    AGENT_TYPE,
    ALIAS,
    ALIASES,
    ALLOWED_AGENTS,
    ARGUMENTS,
    AS_AGENT,
    BY_SOURCE_URI,
    BYTE_ESTIMATE,
    CALLER_AGENT_ID,
    CANONICAL_NAME,
    CAPABILITIES,
    CITATIONS,
    CONFIDENCE,
    CONSUMED,
    CONTENT,
    CONTEXT,
    DEPTH,
    DRY_RUN,
    EDIT_SOURCE,
    ENTITY_ID,
    EVENT_TYPES,
    EVENTS,
    EXPECTED_VERSION,
    EXPIRES_AT,
    FAMILY,
    FILTER,
    FOLDER_PATH,
    FORCE,
    FORCE_RE_ATOMISE,
    FORMAT,
    GOVERNANCE,
    ID,
    ID_A,
    ID_B,
    IDS,
    INCLUDE_ARCHIVED,
    INCLUDE_INVALIDATED,
    INHERIT,
    INLINE_SKILL,
    INTENT,
    K,
    KIND,
    KIND_INNER,
    LIMIT,
    LINK_ID,
    MAX_ATOM_TOKENS,
    MAX_DEPTH,
    MAX_RESULTS,
    MEMORY_ID,
    METADATA,
    NAME,
    NAMESPACE,
    NAMESPACE_FILTER,
    OFFSET,
    OLDER_THAN_DAYS,
    ON_CONFLICT,
    PARENT,
    PATTERN,
    PAYLOAD,
    PIPELINE_OVERRIDE,
    PRIORITY,
    QUERY,
    REFLECTION_ID,
    RELATION,
    REMEMBER,
    RESOURCE_PATH,
    SCOPE,
    SECRET,
    SINCE,
    SKILL_DESCRIPTION,
    SKILL_ID,
    SKILL_NAME,
    SOURCE,
    SOURCE_ID,
    SOURCE_IDS,
    SOURCE_MEMORY_ID,
    SOURCE_SPAN,
    SOURCE_URI,
    STATUS,
    SUBSCRIPTION_ID,
    SUMMARY,
    TAGS,
    TARGET_AGENT_ID,
    TARGET_FOLDER,
    TARGET_ID,
    TARGET_TIER,
    THRESHOLD,
    TIER,
    TITLE,
    TO_NAMESPACE,
    TTL_SECONDS,
    UNREAD_ONLY,
    UNTIL,
    URL,
    VALID_AT,
    VALID_UNTIL,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_param_names_length_pins_v070_census() {
        // SSOT pin. Adjusting this number requires:
        //   1. Adding the const above
        //   2. Adding the symbol to ALL_PARAM_NAMES below
        //   3. Bumping this assertion
        //   4. Re-running tests/mcp_param_names_invariant.rs to
        //      confirm no orphan-literal drift.
        assert_eq!(
            ALL_PARAM_NAMES.len(),
            98,
            "MCP param-name SSOT census drifted from v0.7.0 baseline"
        );
    }

    #[test]
    fn all_param_names_alphabetically_sorted_and_unique() {
        for i in 1..ALL_PARAM_NAMES.len() {
            assert!(
                ALL_PARAM_NAMES[i - 1] < ALL_PARAM_NAMES[i],
                "ALL_PARAM_NAMES not alphabetically sorted: {} >= {} at index {}",
                ALL_PARAM_NAMES[i - 1],
                ALL_PARAM_NAMES[i],
                i
            );
        }
    }

    #[test]
    fn all_param_names_match_lowercase_snake_case() {
        for name in ALL_PARAM_NAMES {
            for c in name.chars() {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
                    "param name {name:?} contains non-snake-case char {c:?}; MCP \
                     JSON convention is snake_case ASCII-lowercase + digits + _"
                );
            }
            assert!(
                !name.starts_with('_') && !name.ends_with('_'),
                "param name {name:?} has leading/trailing underscore — likely typo"
            );
        }
    }
}
