// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Tool registry: tool definitions, profile filtering, capabilities family dispatch.

use serde_json::{Value, json};

// --- v0.7.x (issue #1174 PR1 — pm-v3.1 MCP tool name sweep) — tool_names module ---

/// v0.7.x (issue #1174 PR1 — pm-v3.1 MCP tool name sweep) — canonical
/// constants for every MCP tool name. Replaces ~150 inline string
/// literals across the codebase. Adding a tool name in one place
/// instead of N places makes renaming a one-line edit and prevents
/// silent drift between dispatch-arm tables and audit/governance
/// allowlists.
///
/// **Invariants pinned by the registry-level pin tests below
/// (`tool_names::pin_tests`):**
///
/// - Every const's value is byte-equal to the historical wire string
///   it replaces; the wire layer still emits `"memory_store"` as the
///   JSON-RPC method name, exact byte-for-byte.
/// - Every tool registered in [`registered_tools`] has a matching
///   `pub const` here and the const value equals the tool's
///   `McpTool::name()` return.
/// - The count of consts equals
///   [`crate::profile::Profile::full().expected_tool_count`].
///
/// **Adding a new tool**: append the const here AND the
/// `RegisteredTool::of::<…>()` line in [`registered_tools`]. The pin
/// tests will fail if either side is missed.
///
/// Naming convention: `MEMORY_<UPPER_SNAKE>` matches the wire string
/// `memory_<lower_snake>` so the call site reads naturally
/// (`tool_names::MEMORY_STORE => …` ⇒ `"memory_store" => …`).
pub mod tool_names {
    pub const MEMORY_AGENT_LIST: &str = "memory_agent_list";
    pub const MEMORY_AGENT_REGISTER: &str = "memory_agent_register";
    pub const MEMORY_ARCHIVE_LIST: &str = "memory_archive_list";
    pub const MEMORY_ARCHIVE_PURGE: &str = "memory_archive_purge";
    pub const MEMORY_ARCHIVE_RESTORE: &str = "memory_archive_restore";
    pub const MEMORY_ARCHIVE_STATS: &str = "memory_archive_stats";
    pub const MEMORY_ATOMISE: &str = "memory_atomise";
    pub const MEMORY_AUTO_TAG: &str = "memory_auto_tag";
    pub const MEMORY_CALIBRATE_CONFIDENCE: &str = "memory_calibrate_confidence";
    pub const MEMORY_CAPABILITIES: &str = "memory_capabilities";
    pub const MEMORY_CHECK_AGENT_ACTION: &str = "memory_check_agent_action";
    pub const MEMORY_CHECK_DUPLICATE: &str = "memory_check_duplicate";
    pub const MEMORY_CONSOLIDATE: &str = "memory_consolidate";
    pub const MEMORY_DELETE: &str = "memory_delete";
    pub const MEMORY_DEPENDENTS_OF_INVALIDATED: &str = "memory_dependents_of_invalidated";
    pub const MEMORY_DEREF: &str = "memory_deref";
    pub const MEMORY_DETECT_CONTRADICTION: &str = "memory_detect_contradiction";
    pub const MEMORY_ENTITY_GET_BY_ALIAS: &str = "memory_entity_get_by_alias";
    pub const MEMORY_ENTITY_REGISTER: &str = "memory_entity_register";
    pub const MEMORY_EXPAND_QUERY: &str = "memory_expand_query";
    pub const MEMORY_EXPORT_REFLECTION: &str = "memory_export_reflection";
    pub const MEMORY_FIND_PATHS: &str = "memory_find_paths";
    pub const MEMORY_FORGET: &str = "memory_forget";
    pub const MEMORY_GC: &str = "memory_gc";
    pub const MEMORY_GET: &str = "memory_get";
    pub const MEMORY_GET_LINKS: &str = "memory_get_links";
    pub const MEMORY_GET_TAXONOMY: &str = "memory_get_taxonomy";
    pub const MEMORY_INBOX: &str = "memory_inbox";
    pub const MEMORY_INGEST_MULTISTEP: &str = "memory_ingest_multistep";
    pub const MEMORY_KG_INVALIDATE: &str = "memory_kg_invalidate";
    pub const MEMORY_KG_QUERY: &str = "memory_kg_query";
    pub const MEMORY_KG_TIMELINE: &str = "memory_kg_timeline";
    pub const MEMORY_LINK: &str = "memory_link";
    pub const MEMORY_LIST: &str = "memory_list";
    pub const MEMORY_LIST_SUBSCRIPTIONS: &str = "memory_list_subscriptions";
    pub const MEMORY_LOAD_FAMILY: &str = "memory_load_family";
    pub const MEMORY_NAMESPACE_CLEAR_STANDARD: &str = "memory_namespace_clear_standard";
    pub const MEMORY_NAMESPACE_GET_STANDARD: &str = "memory_namespace_get_standard";
    pub const MEMORY_NAMESPACE_SET_STANDARD: &str = "memory_namespace_set_standard";
    pub const MEMORY_NOTIFY: &str = "memory_notify";
    pub const MEMORY_OFFLOAD: &str = "memory_offload";
    pub const MEMORY_PENDING_APPROVE: &str = "memory_pending_approve";
    pub const MEMORY_PENDING_LIST: &str = "memory_pending_list";
    pub const MEMORY_PENDING_REJECT: &str = "memory_pending_reject";
    pub const MEMORY_PERSONA: &str = "memory_persona";
    pub const MEMORY_PERSONA_GENERATE: &str = "memory_persona_generate";
    pub const MEMORY_PROMOTE: &str = "memory_promote";
    pub const MEMORY_QUOTA_STATUS: &str = "memory_quota_status";
    pub const MEMORY_RECALL: &str = "memory_recall";
    pub const MEMORY_RECALL_OBSERVATIONS: &str = "memory_recall_observations";
    pub const MEMORY_REFLECT: &str = "memory_reflect";
    pub const MEMORY_REFLECTION_ORIGIN: &str = "memory_reflection_origin";
    pub const MEMORY_REPLAY: &str = "memory_replay";
    pub const MEMORY_RULE_LIST: &str = "memory_rule_list";
    pub const MEMORY_SEARCH: &str = "memory_search";
    pub const MEMORY_SESSION_START: &str = "memory_session_start";
    pub const MEMORY_SHARE: &str = "memory_share";
    pub const MEMORY_SKILL_COMPOSITIONAL_CONTEXT: &str = "memory_skill_compositional_context";
    pub const MEMORY_SKILL_EXPORT: &str = "memory_skill_export";
    pub const MEMORY_SKILL_GET: &str = "memory_skill_get";
    pub const MEMORY_SKILL_LIST: &str = "memory_skill_list";
    pub const MEMORY_SKILL_PROMOTE_FROM_REFLECTION: &str = "memory_skill_promote_from_reflection";
    pub const MEMORY_SKILL_REGISTER: &str = "memory_skill_register";
    pub const MEMORY_SKILL_RESOURCE: &str = "memory_skill_resource";
    pub const MEMORY_SMART_LOAD: &str = "memory_smart_load";
    pub const MEMORY_STATS: &str = "memory_stats";
    pub const MEMORY_STORE: &str = "memory_store";
    pub const MEMORY_SUBSCRIBE: &str = "memory_subscribe";
    pub const MEMORY_SUBSCRIPTION_DLQ_LIST: &str = "memory_subscription_dlq_list";
    pub const MEMORY_SUBSCRIPTION_REPLAY: &str = "memory_subscription_replay";
    pub const MEMORY_UNSUBSCRIBE: &str = "memory_unsubscribe";
    pub const MEMORY_UPDATE: &str = "memory_update";
    pub const MEMORY_VERIFY: &str = "memory_verify";

    /// The full canonical set of every MCP tool name. Useful for
    /// iterating in tests + the audit-tool-call dispatcher's
    /// "known names" guard. Order is alphabetical by const name so
    /// adding a new entry has a stable diff position. The slice
    /// length is pinned to `73` by [`pin_tests::const_count_is_73`].
    ///
    /// `dead_code` is allowed because the only consumer today is the
    /// `pin_tests` module below; making it `pub` keeps the API
    /// available to external test crates (e.g. integration tests
    /// under `tests/`) that may want to iterate the canonical set
    /// without re-typing it.
    #[allow(dead_code)]
    pub const ALL: &[&str] = &[
        MEMORY_AGENT_LIST,
        MEMORY_AGENT_REGISTER,
        MEMORY_ARCHIVE_LIST,
        MEMORY_ARCHIVE_PURGE,
        MEMORY_ARCHIVE_RESTORE,
        MEMORY_ARCHIVE_STATS,
        MEMORY_ATOMISE,
        MEMORY_AUTO_TAG,
        MEMORY_CALIBRATE_CONFIDENCE,
        MEMORY_CAPABILITIES,
        MEMORY_CHECK_AGENT_ACTION,
        MEMORY_CHECK_DUPLICATE,
        MEMORY_CONSOLIDATE,
        MEMORY_DELETE,
        MEMORY_DEPENDENTS_OF_INVALIDATED,
        MEMORY_DEREF,
        MEMORY_DETECT_CONTRADICTION,
        MEMORY_ENTITY_GET_BY_ALIAS,
        MEMORY_ENTITY_REGISTER,
        MEMORY_EXPAND_QUERY,
        MEMORY_EXPORT_REFLECTION,
        MEMORY_FIND_PATHS,
        MEMORY_FORGET,
        MEMORY_GC,
        MEMORY_GET,
        MEMORY_GET_LINKS,
        MEMORY_GET_TAXONOMY,
        MEMORY_INBOX,
        MEMORY_INGEST_MULTISTEP,
        MEMORY_KG_INVALIDATE,
        MEMORY_KG_QUERY,
        MEMORY_KG_TIMELINE,
        MEMORY_LINK,
        MEMORY_LIST,
        MEMORY_LIST_SUBSCRIPTIONS,
        MEMORY_LOAD_FAMILY,
        MEMORY_NAMESPACE_CLEAR_STANDARD,
        MEMORY_NAMESPACE_GET_STANDARD,
        MEMORY_NAMESPACE_SET_STANDARD,
        MEMORY_NOTIFY,
        MEMORY_OFFLOAD,
        MEMORY_PENDING_APPROVE,
        MEMORY_PENDING_LIST,
        MEMORY_PENDING_REJECT,
        MEMORY_PERSONA,
        MEMORY_PERSONA_GENERATE,
        MEMORY_PROMOTE,
        MEMORY_QUOTA_STATUS,
        MEMORY_RECALL,
        MEMORY_RECALL_OBSERVATIONS,
        MEMORY_REFLECT,
        MEMORY_REFLECTION_ORIGIN,
        MEMORY_REPLAY,
        MEMORY_RULE_LIST,
        MEMORY_SEARCH,
        MEMORY_SESSION_START,
        MEMORY_SHARE,
        MEMORY_SKILL_COMPOSITIONAL_CONTEXT,
        MEMORY_SKILL_EXPORT,
        MEMORY_SKILL_GET,
        MEMORY_SKILL_LIST,
        MEMORY_SKILL_PROMOTE_FROM_REFLECTION,
        MEMORY_SKILL_REGISTER,
        MEMORY_SKILL_RESOURCE,
        MEMORY_SMART_LOAD,
        MEMORY_STATS,
        MEMORY_STORE,
        MEMORY_SUBSCRIBE,
        MEMORY_SUBSCRIPTION_DLQ_LIST,
        MEMORY_SUBSCRIPTION_REPLAY,
        MEMORY_UNSUBSCRIBE,
        MEMORY_UPDATE,
        MEMORY_VERIFY,
    ];

    #[cfg(test)]
    mod pin_tests {
        //! v0.7.x (issue #1174 PR1) — pin tests for every const VALUE
        //! is byte-equal to the historical wire string it replaces.
        //! If any of these fail, the refactor introduced wire drift —
        //! revert the offending const or the dispatch site, NOT this
        //! test.
        use super::*;

        #[test]
        fn const_count_is_73() {
            // The v0.7.0 surface advertises 73 MCP tools at
            // `--profile full` (72 callable + the always-on
            // `memory_capabilities` bootstrap; both are in `ALL`).
            // If you added a new tool: bump this to N+1 AND add the
            // const above AND the slice entry AND a per-name byte-
            // equal test below AND a `RegisteredTool::of::<…>()`
            // line in `registered_tools()`. The
            // `consts_match_registered_tools` test below mechanically
            // verifies the registry side.
            assert_eq!(
                ALL.len(),
                73,
                "tool_names::ALL must hold exactly the 73 v0.7.0 MCP tool names"
            );
        }

        #[test]
        fn const_set_is_deduplicated() {
            // Defence-in-depth: forbids accidental copy-paste
            // duplication when adding a new const. A duplicate entry
            // in `ALL` would silently mask the missing tool.
            use std::collections::BTreeSet;
            let unique: BTreeSet<&&str> = ALL.iter().collect();
            assert_eq!(
                unique.len(),
                ALL.len(),
                "tool_names::ALL has duplicate entries"
            );
        }

        #[test]
        fn const_values_lowercase_memory_prefix() {
            // Wire-shape invariant: every tool name starts with
            // `"memory_"` and is otherwise `[a-z_]+`. Catches the
            // failure mode where someone writes
            // `pub const MEMORY_Foo: &str = "memory_Foo";` and the
            // const compiles but the wire side rejects the casing.
            for name in ALL {
                assert!(
                    name.starts_with("memory_"),
                    "tool name {name:?} does not start with 'memory_'"
                );
                assert!(
                    name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                    "tool name {name:?} contains non-[a-z_] character"
                );
            }
        }

        /// Per-name byte-equal pin tests. Each `assert_eq!(CONST, "literal")`
        /// is the load-bearing assertion: if anyone "tidies" the const
        /// value (e.g. `"memory_Store"` for camel-case "consistency"
        /// with a renamed module), the wire layer breaks and this
        /// test surfaces the regression at `cargo test` time, not at
        /// `Claude Desktop reload` time.
        #[test]
        fn const_values_byte_equal_to_historical_wire_strings() {
            assert_eq!(MEMORY_AGENT_LIST, "memory_agent_list");
            assert_eq!(MEMORY_AGENT_REGISTER, "memory_agent_register");
            assert_eq!(MEMORY_ARCHIVE_LIST, "memory_archive_list");
            assert_eq!(MEMORY_ARCHIVE_PURGE, "memory_archive_purge");
            assert_eq!(MEMORY_ARCHIVE_RESTORE, "memory_archive_restore");
            assert_eq!(MEMORY_ARCHIVE_STATS, "memory_archive_stats");
            assert_eq!(MEMORY_ATOMISE, "memory_atomise");
            assert_eq!(MEMORY_AUTO_TAG, "memory_auto_tag");
            assert_eq!(MEMORY_CALIBRATE_CONFIDENCE, "memory_calibrate_confidence");
            assert_eq!(MEMORY_CAPABILITIES, "memory_capabilities");
            assert_eq!(MEMORY_CHECK_AGENT_ACTION, "memory_check_agent_action");
            assert_eq!(MEMORY_CHECK_DUPLICATE, "memory_check_duplicate");
            assert_eq!(MEMORY_CONSOLIDATE, "memory_consolidate");
            assert_eq!(MEMORY_DELETE, "memory_delete");
            assert_eq!(
                MEMORY_DEPENDENTS_OF_INVALIDATED,
                "memory_dependents_of_invalidated"
            );
            assert_eq!(MEMORY_DEREF, "memory_deref");
            assert_eq!(MEMORY_DETECT_CONTRADICTION, "memory_detect_contradiction");
            assert_eq!(MEMORY_ENTITY_GET_BY_ALIAS, "memory_entity_get_by_alias");
            assert_eq!(MEMORY_ENTITY_REGISTER, "memory_entity_register");
            assert_eq!(MEMORY_EXPAND_QUERY, "memory_expand_query");
            assert_eq!(MEMORY_EXPORT_REFLECTION, "memory_export_reflection");
            assert_eq!(MEMORY_FIND_PATHS, "memory_find_paths");
            assert_eq!(MEMORY_FORGET, "memory_forget");
            assert_eq!(MEMORY_GC, "memory_gc");
            assert_eq!(MEMORY_GET, "memory_get");
            assert_eq!(MEMORY_GET_LINKS, "memory_get_links");
            assert_eq!(MEMORY_GET_TAXONOMY, "memory_get_taxonomy");
            assert_eq!(MEMORY_INBOX, "memory_inbox");
            assert_eq!(MEMORY_INGEST_MULTISTEP, "memory_ingest_multistep");
            assert_eq!(MEMORY_KG_INVALIDATE, "memory_kg_invalidate");
            assert_eq!(MEMORY_KG_QUERY, "memory_kg_query");
            assert_eq!(MEMORY_KG_TIMELINE, "memory_kg_timeline");
            assert_eq!(MEMORY_LINK, "memory_link");
            assert_eq!(MEMORY_LIST, "memory_list");
            assert_eq!(MEMORY_LIST_SUBSCRIPTIONS, "memory_list_subscriptions");
            assert_eq!(MEMORY_LOAD_FAMILY, "memory_load_family");
            assert_eq!(
                MEMORY_NAMESPACE_CLEAR_STANDARD,
                "memory_namespace_clear_standard"
            );
            assert_eq!(
                MEMORY_NAMESPACE_GET_STANDARD,
                "memory_namespace_get_standard"
            );
            assert_eq!(
                MEMORY_NAMESPACE_SET_STANDARD,
                "memory_namespace_set_standard"
            );
            assert_eq!(MEMORY_NOTIFY, "memory_notify");
            assert_eq!(MEMORY_OFFLOAD, "memory_offload");
            assert_eq!(MEMORY_PENDING_APPROVE, "memory_pending_approve");
            assert_eq!(MEMORY_PENDING_LIST, "memory_pending_list");
            assert_eq!(MEMORY_PENDING_REJECT, "memory_pending_reject");
            assert_eq!(MEMORY_PERSONA, "memory_persona");
            assert_eq!(MEMORY_PERSONA_GENERATE, "memory_persona_generate");
            assert_eq!(MEMORY_PROMOTE, "memory_promote");
            assert_eq!(MEMORY_QUOTA_STATUS, "memory_quota_status");
            assert_eq!(MEMORY_RECALL, "memory_recall");
            assert_eq!(MEMORY_RECALL_OBSERVATIONS, "memory_recall_observations");
            assert_eq!(MEMORY_REFLECT, "memory_reflect");
            assert_eq!(MEMORY_REFLECTION_ORIGIN, "memory_reflection_origin");
            assert_eq!(MEMORY_REPLAY, "memory_replay");
            assert_eq!(MEMORY_RULE_LIST, "memory_rule_list");
            assert_eq!(MEMORY_SEARCH, "memory_search");
            assert_eq!(MEMORY_SESSION_START, "memory_session_start");
            assert_eq!(MEMORY_SHARE, "memory_share");
            assert_eq!(
                MEMORY_SKILL_COMPOSITIONAL_CONTEXT,
                "memory_skill_compositional_context"
            );
            assert_eq!(MEMORY_SKILL_EXPORT, "memory_skill_export");
            assert_eq!(MEMORY_SKILL_GET, "memory_skill_get");
            assert_eq!(MEMORY_SKILL_LIST, "memory_skill_list");
            assert_eq!(
                MEMORY_SKILL_PROMOTE_FROM_REFLECTION,
                "memory_skill_promote_from_reflection"
            );
            assert_eq!(MEMORY_SKILL_REGISTER, "memory_skill_register");
            assert_eq!(MEMORY_SKILL_RESOURCE, "memory_skill_resource");
            assert_eq!(MEMORY_SMART_LOAD, "memory_smart_load");
            assert_eq!(MEMORY_STATS, "memory_stats");
            assert_eq!(MEMORY_STORE, "memory_store");
            assert_eq!(MEMORY_SUBSCRIBE, "memory_subscribe");
            assert_eq!(MEMORY_SUBSCRIPTION_DLQ_LIST, "memory_subscription_dlq_list");
            assert_eq!(MEMORY_SUBSCRIPTION_REPLAY, "memory_subscription_replay");
            assert_eq!(MEMORY_UNSUBSCRIBE, "memory_unsubscribe");
            assert_eq!(MEMORY_UPDATE, "memory_update");
            assert_eq!(MEMORY_VERIFY, "memory_verify");
        }

        #[test]
        fn consts_match_registered_tools() {
            // The `tool_names::ALL` slice and the
            // `registered_tools()` iterator are two halves of the
            // same contract: they enumerate the same set of names.
            // This test enforces that every const value also appears
            // as some registered tool's `name()` return, and vice
            // versa. Drift in either direction is a refactor bug.
            use std::collections::BTreeSet;
            let from_consts: BTreeSet<&str> = ALL.iter().copied().collect();
            let from_registry: BTreeSet<&str> = crate::mcp::registry::registered_tools()
                .iter()
                .map(|r| r.name)
                .collect();
            let only_in_consts: Vec<&&str> = from_consts.difference(&from_registry).collect();
            let only_in_registry: Vec<&&str> = from_registry.difference(&from_consts).collect();
            assert!(
                only_in_consts.is_empty() && only_in_registry.is_empty(),
                "tool_names::ALL and registered_tools() drifted; \
                 only_in_consts = {only_in_consts:?}, \
                 only_in_registry = {only_in_registry:?}"
            );
        }
    }
}

// --- McpTool trait (v0.7.0 #972 D1.1, issue #982) ---

/// Per-tool descriptor surface introduced by v0.7.0 #972 split D1.1.
///
/// The pre-D1 registry was a single 1500-line `json!({...})` macro in
/// [`tool_definitions`] that hand-coded every tool's `inputSchema`
/// alongside its `name` / `description` / `docs`. That layout drifted
/// from handler reality (e.g. `memory_capabilities` schema still says
/// `accept: ["v1","v2"]` while the [`crate::mcp::tools::capabilities::CapabilitiesAccept`]
/// enum has been `V1`/`V2`/`V3` since A5) because nothing forced the
/// schema and the handler to be authored from the same source.
///
/// The D1 split moves each tool to its own module under
/// [`crate::mcp::tools`]. Each module exports a zero-sized type that
/// implements [`McpTool`]. The trait's [`McpTool::input_schema`]
/// returns a `serde_json::Value` derived from a per-tool
/// `#[derive(schemars::JsonSchema, serde::Deserialize)]` request
/// struct — so a new field on the request struct lands automatically
/// in the wire schema, and a typo in field name fails to deserialise
/// at the handler boundary.
///
/// D1.1 (this issue, #982) defines the trait + a PoC implementation
/// for `memory_capabilities`. D1.2 (#983) wires the schemars derive
/// pipeline. D1.3 (#984) migrates the 5 default `--profile core`
/// tools. D1.4 (#985) + D1.5 (#986) migrate the remaining ~65 tools
/// in parallel. D1.6 (#987) deletes the giant `tool_definitions()`
/// macro and replaces its body with iteration over
/// `registered_tools()`. D1.7 (#988) lands per-profile snapshot tests
/// + the compile-time schema↔handler parity invariant. D1.8 (#989)
/// updates the docs.
///
/// During D1.1-D1.5 both surfaces coexist: the legacy `tool_definitions`
/// macro still emits the full catalog on the wire, and per-tool
/// `McpTool` impls coexist as a parallel source-of-truth. Snapshot
/// tests verify the schemars-derived schema matches the legacy
/// hand-coded one modulo property ordering (schemars sorts).
///
/// The `dead_code` allow comes off in D1.6 (#987) when the giant
/// `tool_definitions` macro is replaced with iteration over
/// `McpTool` impls. During the D1.1-D1.5 window the trait is
/// authored ahead of its first consumer (the per-profile
/// `registered_tools()` iterator that D1.6 introduces).
#[allow(dead_code)]
pub trait McpTool {
    /// Wire-level tool name (e.g. `"memory_capabilities"`).
    fn name() -> &'static str;

    /// Short one-sentence description (≤ 50 cl100k tokens) shown on
    /// the bare `tools/list` payload.
    fn description() -> &'static str;

    /// Long-form prose + examples; reachable via
    /// `memory_capabilities { family=<f>, include_schema=true, verbose=true }`.
    /// May be empty for tools that don't ship long-form docs.
    fn docs() -> &'static str;

    /// JSON Schema for the tool's request body. Derived from the
    /// per-tool `<Tool>Request` struct via
    /// `schemars::schema_for!(<Tool>Request)` and converted to
    /// `serde_json::Value`.
    fn input_schema() -> Value;

    /// Family tag (one of `core` / `lifecycle` / `graph` /
    /// `governance` / `power` / `meta` / `archive` / `other`) used by
    /// [`Profile::loads`] for per-profile filtering on `tools/list`.
    fn family() -> &'static str;
}

// --- v0.7.0 #972 D1.6 (#987) — registered_tools() iterator ---

/// v0.7.0 #972 D1.6 (#987) — owned snapshot of one tool's catalog
/// row, derived from its per-tool [`McpTool`] impl. Together with
/// [`registered_tools`] it replaces the hand-coded `json!({...})`
/// body of [`tool_definitions`] (D1.6 collapses the macro).
///
/// The row carries the tool's `name`, `description`, `docs`, family
/// tag, and the schemars-derived `inputSchema`. [`RegisteredTool::of`]
/// constructs the row from any `T: McpTool` so the dispatch table is
/// authored in one place: `registered_tools()`.
pub struct RegisteredTool {
    pub name: &'static str,
    pub description: &'static str,
    pub docs: &'static str,
    /// Family tag retained on the struct for per-profile filtering
    /// (D1.7 (#988) will consume this in the per-profile snapshot
    /// tests). [`RegisteredTool::to_value`] does NOT emit it — the
    /// wire shape excludes the family tag to keep the post-D1.6
    /// catalog byte-identical to the pre-D1.6 shape modulo the
    /// allowed-diffs catalog. So it reads as dead code at compile
    /// time until D1.7 lands; the allow stays narrow and load-bearing.
    #[allow(dead_code)]
    pub family: &'static str,
    pub input_schema: Value,
}

impl RegisteredTool {
    /// Derive a catalog row from any type that implements [`McpTool`].
    /// All five `McpTool` methods are pure / cheap; the schemars-derived
    /// `input_schema` is recomputed each call (no caching) because the
    /// per-request budget is dominated by the JSON serialisation below,
    /// not by schemars reflection.
    #[must_use]
    pub fn of<T: McpTool>() -> Self {
        Self {
            name: T::name(),
            description: T::description(),
            docs: T::docs(),
            family: T::family(),
            input_schema: T::input_schema(),
        }
    }

    /// Render the row in the wire shape `tool_definitions` emits:
    /// `{ name, description, docs, inputSchema }`. The `family` tag is
    /// kept out of the wire form (it's a server-side filter only) so
    /// the post-D1.6 payload matches the pre-D1.6 payload byte-for-byte
    /// modulo the documented allowed-diffs (property order, schemars
    /// `default: null` on optional fields, schemars
    /// `additionalProperties: false`).
    ///
    /// Normalisation: schemars omits the `properties` map entirely
    /// when the request struct has zero fields (e.g. `StatsRequest`,
    /// `ArchiveStatsRequest`, `AgentListRequest`,
    /// `ListSubscriptionsRequest`). The pre-D1.6 hand-coded macro
    /// emitted `"properties": {}` for those tools so the wire shape
    /// stayed uniform across tools. Backfill the empty map here so
    /// the post-D1.6 wire shape preserves that uniformity.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut input_schema = self.input_schema.clone();
        if let Some(obj) = input_schema.as_object_mut()
            && !obj.contains_key("properties")
        {
            obj.insert(
                "properties".to_string(),
                Value::Object(serde_json::Map::new()),
            );
        }
        json!({
            "name": self.name,
            "description": self.description,
            "docs": self.docs,
            "inputSchema": input_schema,
        })
    }
}

/// v0.7.0 #972 D1.6 (#987) — canonical iterator over every
/// `McpTool`-impl in the codebase. Each entry pairs the tool with a
/// closure that derives its catalog row via [`RegisteredTool::of`].
///
/// **One row per tool. Adding a tool = adding ONE line here + an impl
/// in the per-tool module.** That's the post-D1.6 contract — see the
/// "New MCP tool" recipe in `CLAUDE.md`.
///
/// Order matches the pre-D1.6 `tool_definitions()` macro order so
/// callers that iterate the wire array see the same sequence they
/// saw before the migration.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn registered_tools() -> Vec<RegisteredTool> {
    // ORDER MUST MATCH THE PRE-D1.6 `tool_definitions()` macro order
    // so callers iterating the wire array see the same sequence they
    // saw before the migration. Re-ordering is allowed at the wire
    // form (the JSON output) but pinning it here keeps the snapshot
    // regression test (Phase 4) trivial — any future reorder shows up
    // as a single diff hunk in this file, not as a 73-tool reshuffle
    // in the wire snapshot.
    vec![
        RegisteredTool::of::<crate::mcp::store::StoreTool>(),
        RegisteredTool::of::<crate::mcp::recall::RecallTool>(),
        RegisteredTool::of::<crate::mcp::recall_observations::RecallObservationsTool>(),
        RegisteredTool::of::<crate::mcp::search::SearchTool>(),
        RegisteredTool::of::<crate::mcp::list::ListTool>(),
        RegisteredTool::of::<crate::mcp::load_family::LoadFamilyTool>(),
        RegisteredTool::of::<crate::mcp::load_family::SmartLoadTool>(),
        RegisteredTool::of::<crate::mcp::get_taxonomy::GetTaxonomyTool>(),
        RegisteredTool::of::<crate::mcp::check_duplicate::CheckDuplicateTool>(),
        RegisteredTool::of::<crate::mcp::entity_register::EntityRegisterTool>(),
        RegisteredTool::of::<crate::mcp::entity_get_by_alias::EntityGetByAliasTool>(),
        RegisteredTool::of::<crate::mcp::kg_timeline::KgTimelineTool>(),
        RegisteredTool::of::<crate::mcp::kg_invalidate::KgInvalidateTool>(),
        RegisteredTool::of::<crate::mcp::kg_query::KgQueryTool>(),
        RegisteredTool::of::<crate::mcp::find_paths::FindPathsTool>(),
        RegisteredTool::of::<crate::mcp::delete::DeleteTool>(),
        RegisteredTool::of::<crate::mcp::promote::PromoteTool>(),
        RegisteredTool::of::<crate::mcp::forget::ForgetTool>(),
        RegisteredTool::of::<crate::mcp::forget::StatsTool>(),
        RegisteredTool::of::<crate::mcp::update::UpdateTool>(),
        RegisteredTool::of::<crate::mcp::get::GetTool>(),
        RegisteredTool::of::<crate::mcp::link::LinkTool>(),
        RegisteredTool::of::<crate::mcp::link::GetLinksTool>(),
        RegisteredTool::of::<crate::mcp::verify::VerifyTool>(),
        RegisteredTool::of::<crate::mcp::replay::ReplayTool>(),
        RegisteredTool::of::<crate::mcp::reflect::ReflectTool>(),
        RegisteredTool::of::<crate::mcp::export_reflection::ExportReflectionTool>(),
        RegisteredTool::of::<crate::mcp::persona::PersonaTool>(),
        RegisteredTool::of::<crate::mcp::persona::PersonaGenerateTool>(),
        RegisteredTool::of::<crate::mcp::reflection_origin::ReflectionOriginTool>(),
        RegisteredTool::of::<crate::mcp::dependents_of_invalidated::DependentsOfInvalidatedTool>(),
        RegisteredTool::of::<crate::mcp::consolidate::ConsolidateTool>(),
        RegisteredTool::of::<crate::mcp::ingest_multistep::IngestMultistepTool>(),
        RegisteredTool::of::<crate::mcp::atomise::AtomiseTool>(),
        RegisteredTool::of::<crate::mcp::share::ShareTool>(),
        RegisteredTool::of::<crate::mcp::calibrate_confidence::CalibrateConfidenceTool>(),
        RegisteredTool::of::<crate::mcp::capabilities::CapabilitiesTool>(),
        RegisteredTool::of::<crate::mcp::expand_query::ExpandQueryTool>(),
        RegisteredTool::of::<crate::mcp::auto_tag::AutoTagTool>(),
        RegisteredTool::of::<crate::mcp::detect_contradiction::DetectContradictionTool>(),
        RegisteredTool::of::<crate::mcp::archive::ArchiveListTool>(),
        RegisteredTool::of::<crate::mcp::archive::ArchiveRestoreTool>(),
        RegisteredTool::of::<crate::mcp::archive::ArchivePurgeTool>(),
        RegisteredTool::of::<crate::mcp::archive::ArchiveStatsTool>(),
        RegisteredTool::of::<crate::mcp::archive::GcTool>(),
        RegisteredTool::of::<crate::mcp::session_start::SessionStartTool>(),
        RegisteredTool::of::<crate::mcp::namespace::NamespaceSetStandardTool>(),
        RegisteredTool::of::<crate::mcp::namespace::NamespaceGetStandardTool>(),
        RegisteredTool::of::<crate::mcp::namespace::NamespaceClearStandardTool>(),
        RegisteredTool::of::<crate::mcp::pending::PendingListTool>(),
        RegisteredTool::of::<crate::mcp::pending::PendingApproveTool>(),
        RegisteredTool::of::<crate::mcp::pending::PendingRejectTool>(),
        RegisteredTool::of::<crate::mcp::agent::AgentRegisterTool>(),
        RegisteredTool::of::<crate::mcp::agent::AgentListTool>(),
        RegisteredTool::of::<crate::mcp::notify::NotifyTool>(),
        RegisteredTool::of::<crate::mcp::notify::InboxTool>(),
        RegisteredTool::of::<crate::mcp::subscribe::SubscribeTool>(),
        RegisteredTool::of::<crate::mcp::subscribe::UnsubscribeTool>(),
        RegisteredTool::of::<crate::mcp::subscribe::ListSubscriptionsTool>(),
        RegisteredTool::of::<crate::mcp::subscribe::SubscriptionReplayTool>(),
        RegisteredTool::of::<crate::mcp::pending::SubscriptionDlqListTool>(),
        RegisteredTool::of::<crate::mcp::quota_status::QuotaStatusTool>(),
        RegisteredTool::of::<crate::mcp::check_agent_action::CheckAgentActionTool>(),
        RegisteredTool::of::<crate::mcp::rule_list::RuleListTool>(),
        RegisteredTool::of::<crate::mcp::skill_register::SkillRegisterTool>(),
        RegisteredTool::of::<crate::mcp::skill_list::SkillListTool>(),
        RegisteredTool::of::<crate::mcp::skill_get::SkillGetTool>(),
        RegisteredTool::of::<crate::mcp::skill_resource::SkillResourceTool>(),
        RegisteredTool::of::<crate::mcp::skill_export::SkillExportTool>(),
        RegisteredTool::of::<crate::mcp::skill_promote::SkillPromoteFromReflectionTool>(),
        RegisteredTool::of::<crate::mcp::skill_compositional_context::SkillCompositionalContextTool>(
        ),
        RegisteredTool::of::<crate::mcp::offload::OffloadTool>(),
        RegisteredTool::of::<crate::mcp::offload::DerefTool>(),
    ]
}

// --- Tool definitions ---

/// Version tag for the `tools/list` response schema. Bumped whenever
/// an existing tool's shape changes in a breaking way (renamed params,
/// tightened schemas, removed options). Adding a new tool is additive
/// and does NOT require a bump. Ultrareview #351.
///
/// v0.7 C4 — bumped to `2026-05-06` because `tools/list` now ships
/// the trimmed schema by default (optional params hidden unless the
/// caller passes `verbose=true` to `memory_capabilities`). The wire
/// shape of every existing tool's `inputSchema.properties` map is
/// strictly a subset of the prior version, which is a breaking change
/// for any client that was reading the long-tail optional params off
/// `tools/list` directly. The full schema is still reachable via
/// `memory_capabilities { family=<f>, include_schema=true, verbose=true }`.
const TOOLS_VERSION: &str = "2026-05-06";

/// v0.7 C4 — tools/list optional-param trim allow-list.
///
/// **Historical (pre-#859):** optional properties (those NOT in
/// `inputSchema.required`) were dropped from the default `tools/list`
/// payload UNLESS their name appeared here. This hid the long-tail
/// optionals (`max_depth`, `relation`, `confidence`, …) from MCP
/// clients reading the wire schema directly, breaking NHI runtime
/// discovery (issue #859).
///
/// **Current (#859 / v0.7.0 fix):** every property is preserved on
/// the wire; the allow-list is retained for narrative purposes (and
/// as a marker if a future tightening reintroduces a per-name gate)
/// but is no longer consulted by [`trim_optional_params`].
#[allow(dead_code)]
const C4_KEEP_OPTIONAL_PARAMS: &[&str] = &["namespace", "format"];

/// v0.7 C4 (rev #859) — wire-schema property pruner.
///
/// **What it does on the wire-form schema:**
/// - **Preserves** every `inputSchema.properties` entry, including
///   the long-tail optionals (`max_depth`, `relation`, `valid_at`,
///   `allowed_agents`, `limit`, `include_invalidated`, …). NHI
///   agents reading `tools/list` need to DISCOVER what knobs exist
///   to set them.
/// - **Preserves** every property's structural metadata: `type`,
///   `enum`, `minimum`, `maximum`, `default`, `items`, `minItems`,
///   `maxItems`, `oneOf`. These are load-bearing for argument
///   validation on the client side.
/// - **Preserves** the `required` array — clients still need to
///   know which params are mandatory.
/// - **Strips** per-property `description` text (the prose). The
///   long-form prose is reachable via `memory_capabilities {
///   family=<f>, include_schema=true, verbose=true }`. Callers
///   that just want to know "what params does this tool accept"
///   no longer pay for the prose on every `tools/list` request.
/// - **Strips** per-property `default` values that are non-trivial
///   strings (>32 chars). Numeric / boolean / short-string defaults
///   stay (they're tiny and load-bearing for client-side argument
///   construction).
///
/// Note: per-property `description` stripping is also performed by
/// [`strip_docs_from_tools`]; running both is idempotent. This
/// function is kept as a stable entry point so call sites that
/// historically invoked it (and the budget model in
/// [`crate::sizes`]) keep their semantics aligned with the wire.
///
/// **Why this changed (#859).** Pre-#859 the function dropped entire
/// optional property keys (everything not in `required` + the small
/// allow-list `[namespace, format]`), which produced
/// `memory_kg_query.inputSchema.properties = {source_id}` on the
/// wire — agents could not see that `max_depth`, `valid_at`,
/// `allowed_agents`, `limit`, `include_invalidated` were valid
/// params at all. The fix restores discovery by keeping every
/// property entry on the wire and trimming only the prose.
///
/// Returns the count of property entries whose `description` was
/// stripped — useful for telemetry / acceptance assertions in tests.
/// (Pre-#859 this counted dropped property entries; same shape,
/// different denominator.)
pub(crate) fn trim_optional_params(defs: &mut Value) -> usize {
    let Some(tools) = defs.get_mut("tools").and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut stripped = 0_usize;
    for tool in tools.iter_mut() {
        let Some(input_schema) = tool.get_mut("inputSchema") else {
            continue;
        };
        let Some(properties) = input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        for (_param_name, prop_value) in properties.iter_mut() {
            // Count `description` removals before the recursive
            // walker erases them, for telemetry.
            let had_desc = prop_value
                .as_object()
                .is_some_and(|o| o.contains_key("description"));
            strip_description_recursively(prop_value);
            if had_desc {
                stripped += 1;
            }
        }
    }
    stripped
}

/// v0.6.4-006 — Build the `families` overview included in the v2
/// `memory_capabilities` response. Each entry carries:
///
/// - `name` — family identifier (`core`, `graph`, …)
/// - `tool_count` — expected tool count per the family map
/// - `loaded` — whether the family is loaded under the active profile
/// - `tools` — the canonical tool-name list for that family
///
/// This is the v0.6.4 NHI runtime-discovery surface: an agent reading
/// the response sees which families are reachable AND can decide which
/// to opt into (via `memory_capabilities --include-schema family=<f>`)
/// without restarting the MCP server.
pub(crate) fn families_overview(profile: &crate::profile::Profile) -> Value {
    use crate::profile::Family;
    let defs = tool_definitions();
    let all_tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let entries: Vec<Value> = Family::all()
        .iter()
        .map(|fam| {
            let tools_in_family: Vec<&str> = all_tools
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .filter(|n| Family::for_tool(n) == Some(*fam))
                .collect();
            json!({
                "name": fam.name(),
                "tool_count": tools_in_family.len(),
                "loaded": profile.includes(*fam),
                "tools": tools_in_family,
            })
        })
        .collect();
    json!({
        "schema_version": "v0.6.4-families-1",
        "always_on": crate::profile::ALWAYS_ON_TOOLS,
        "families": entries,
    })
}

/// v0.6.4-006 — Handle `memory_capabilities` invocations that pass a
/// `family=<name>` parameter. When `include_schema=false` (default),
/// returns the canonical tool-name list. When `include_schema=true`,
/// returns the full MCP-style tool definitions for each tool — the
/// caller (an NHI agent or a host like Claude Code's deferred-tools
/// path) can register them at runtime without restarting the server.
///
/// v0.6.4-008 — when `include_schema=true` AND the daemon's
/// `[mcp.allowlist]` is configured, the requesting `agent_id` must be
/// permitted by the allowlist for the requested family. Permissive
/// (no-allowlist) default preserves Tier-1 single-process behavior —
/// operators opt into the gate by writing the table.
///
/// v0.7 C2 — `verbose` controls whether the per-tool `docs` field
/// (long-form description + examples) is preserved in the response.
/// When `verbose=false` (default), `docs` is stripped, matching the
/// always-on `tools/list` shape; when `verbose=true` AND
/// `include_schema=true`, callers receive the full documentation.
/// `verbose=true` without `include_schema=true` is a no-op (the
/// name-list response carries no `docs`).
///
/// v0.7 C4 — when `include_schema=true`, the returned tool schemas
/// are now trimmed by default (optional params hidden) to match the
/// `tools/list` shape. Pass `verbose=true` to opt into the full
/// schema — every optional param, every default, every per-property
/// description. The trim/keep allow-list lives in
/// [`C4_KEEP_OPTIONAL_PARAMS`]. C2's `docs`-field strip and C4's
/// `inputSchema.properties` trim are orthogonal and both governed by
/// the same `verbose` flag.
///
/// Errors:
/// - Unknown family → `Err` with diagnostic listing valid families.
/// - Empty family name → `Err`.
/// - Allowlist deny → `Err` with structured reason.
pub fn handle_capabilities_family(
    family_name: &str,
    include_schema: bool,
    verbose: bool,
    profile: &crate::profile::Profile,
    allowlist_cfg: Option<&crate::config::McpConfig>,
    agent_id: Option<&str>,
    audit_conn: Option<&rusqlite::Connection>,
) -> Result<Value, String> {
    use crate::profile::Family;
    if family_name.is_empty() {
        return Err("memory_capabilities: 'family' must not be empty".to_string());
    }
    let family = Family::all()
        .iter()
        .find(|f| f.name() == family_name)
        .copied()
        .ok_or_else(|| {
            let valid: Vec<&str> = Family::all().iter().map(|f| f.name()).collect();
            format!(
                "unknown family '{family_name}'. Valid families: {}.",
                valid.join(", ")
            )
        })?;

    // v0.6.4-008 — allowlist gate, only on the runtime-expansion path.
    if include_schema && let Some(mcp_cfg) = allowlist_cfg {
        use crate::config::AllowlistDecision;
        match mcp_cfg.allowlist_decision(agent_id, family.name()) {
            AllowlistDecision::Disabled | AllowlistDecision::Allow => {}
            AllowlistDecision::Deny => {
                // v0.6.4-009 — record the deny so operators can see
                // attempted-but-blocked expansion patterns.
                if let Some(conn) = audit_conn {
                    crate::db::record_capability_expansion(
                        conn,
                        agent_id,
                        family.name(),
                        false,
                        None,
                    );
                }
                return Err(format!(
                    "agent '{}' is not permitted to expand family '{}' under \
                     [mcp.allowlist]. Ask an operator to add a matching rule \
                     to config.toml or pass an allowed agent_id.",
                    agent_id.unwrap_or("<anonymous>"),
                    family.name()
                ));
            }
        }
    }

    // v0.6.4-009 — record the grant on the include_schema=true path.
    // Lightweight name-list calls are not audited (they're informational
    // only — no schema material released).
    if include_schema && let Some(conn) = audit_conn {
        crate::db::record_capability_expansion(conn, agent_id, family.name(), true, None);
    }

    let mut defs = tool_definitions();
    // v0.7 C4 — apply the optional-param trim BEFORE filtering by
    // family when the caller did not opt into verbose. Trimming is a
    // cheap pass over every tool's `inputSchema.properties` map, so
    // running it pre-filter is fine and keeps the call site simple.
    if !verbose {
        trim_optional_params(&mut defs);
    }
    let all_tools = defs
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut in_family: Vec<Value> = all_tools
        .into_iter()
        .filter(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .and_then(Family::for_tool)
                == Some(family)
        })
        .collect();

    // v0.7 C2 — strip the verbose `docs` field unless the caller
    // explicitly opted into the long-form payload via `verbose=true`.
    // This keeps the family drilldown response consistent with the
    // bare `tools/list` shape by default.
    if !verbose {
        strip_docs_from_tools(&mut in_family);
    }

    if include_schema {
        Ok(json!({
            "schema_version": "v0.6.4-family-schemas-1",
            "family": family.name(),
            "loaded_under_active_profile": profile.includes(family),
            "verbose": verbose,
            "tools": in_family,
        }))
    } else {
        let names: Vec<&str> = in_family
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        Ok(json!({
            "schema_version": "v0.6.4-family-list-1",
            "family": family.name(),
            "loaded_under_active_profile": profile.includes(family),
            "tools": names,
        }))
    }
}

/// v0.6.4-002 — Filter `tool_definitions()` down to the tools loaded
/// under `profile`. Tools whose family is not in the profile's family
/// list are dropped from `tools[]`. `memory_capabilities` and any
/// other [`crate::profile::ALWAYS_ON_TOOLS`] are kept regardless of
/// profile so the runtime-discovery dance still works on
/// `--profile core`.
///
/// v0.7 C2 — the verbose `docs` field (long-form description + examples)
/// is stripped from each entry so the always-on `tools/list` payload
/// stays inside the C5 token budget. Callers that want the full docs
/// invoke `memory_capabilities { family=<f>, verbose: true }`, which
/// uses `tool_definitions()` directly without stripping.
///
/// v0.7 C4 — on top of the C2 docs strip, optional
/// `inputSchema.properties` are also stripped from each tool by
/// default (see [`trim_optional_params`]) so the `tools/list` payload
/// fits the v0.7 token budget. Callers that need the full schema
/// (every optional, every default) should call
/// [`tool_definitions_for_profile_verbose`] or, on the wire, pass
/// `verbose=true` to `memory_capabilities`. The C2 (description/docs)
/// trim and the C4 (optional-params) trim are orthogonal — both run
/// on the default path; both are skipped on the verbose path.
pub fn tool_definitions_for_profile(profile: &crate::profile::Profile) -> Value {
    // v0.7.0 #1077 — memoize per-Profile so repeat `tools/list` calls
    // are a single `Value::clone()` of the cached payload instead of
    // re-running the schemars + trim + strip + compact pipeline. The
    // catalog is build-time-fixed (schemars-derived), so no
    // invalidation is needed across the daemon lifetime.
    static CACHE: std::sync::OnceLock<
        std::sync::RwLock<std::collections::HashMap<crate::profile::Profile, Value>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    if let Ok(read) = cache.read()
        && let Some(cached) = read.get(profile)
    {
        return cached.clone();
    }
    let defs = build_tool_definitions_for_profile(profile);
    if let Ok(mut write) = cache.write() {
        write.entry(profile.clone()).or_insert_with(|| defs.clone());
    }
    defs
}

/// v0.7.0 #1077 — cache-miss path. Pulled out of
/// [`tool_definitions_for_profile`] so the hot path is a pure
/// hashmap-read clone.
fn build_tool_definitions_for_profile(profile: &crate::profile::Profile) -> Value {
    let mut defs = tool_definitions_for_profile_verbose(profile);
    if !tools_verbose_env_enabled() {
        trim_optional_params(&mut defs);
        wire_compact_descriptions(&mut defs);
    }
    defs
}

/// #859 helper — wire-form description compaction. After
/// [`trim_optional_params`] preserves every property entry on the
/// wire (so MCP clients can DISCOVER what knobs exist), the wire
/// payload still has to fit the C5 token budget. Two strategies are
/// applied, in order:
///
/// 1. **Truncate** the top-level tool `description` to the first
///    sentence (anything before `.` / `;` / first 28 characters,
///    whichever is shorter). The verbose drilldown
///    (`memory_capabilities { verbose=true }`) still carries the
///    full short-form description; the wire form is now even
///    shorter so the budget gate at 11000 cl100k tokens (post-D1.6 schemars expansion, was 3500 in pre-D1.6 hand-coded macro) holds.
/// 2. **Strip** numeric / boolean schema defaults that match the
///    JSON-Schema validation no-op (e.g. `"default": 0` on an
///    `integer` with `minimum: 0`). Currently no-op; left as a
///    future-proofing seam so a future tightening doesn't require
///    a fresh trimmer entry point.
fn wire_compact_descriptions(defs: &mut Value) {
    let Some(tools) = defs.get_mut("tools").and_then(Value::as_array_mut) else {
        return;
    };
    for tool in tools.iter_mut() {
        let Some(obj) = tool.as_object_mut() else {
            continue;
        };
        let Some(desc) = obj.get("description").and_then(Value::as_str) else {
            continue;
        };
        let compact = compact_description(desc);
        if compact.len() != desc.len() {
            obj.insert("description".to_string(), Value::String(compact));
        }
    }
}

/// Truncate a tool's short-form description to the first sentence
/// (or the first 32 characters at a word boundary), preserving at
/// least the verb-noun gist so display surfaces have a label.
///
/// Strategy:
/// 1. If the full description is ≤ 32 chars, keep it verbatim (cheap
///    enough to ship intact).
/// 2. If there's a sentence terminator (`.` / `;`) at or before the
///    32-char mark, cut just before it — that's the cleanest break.
/// 3. Otherwise cut at the last whitespace before 32 chars so we
///    never split a word in half. If no whitespace exists in the
///    first 32 chars, fall back to a char-boundary-safe truncation.
fn compact_description(s: &str) -> String {
    const MAX: usize = 32;
    if s.len() <= MAX {
        return s.to_string();
    }
    // Sentence-terminator path — preserves natural prose boundary.
    let slice = &s[..MAX.min(s.len())];
    if let Some(idx) = slice.find(['.', ';']) {
        return s[..idx].to_string();
    }
    // Word-boundary path — never split a word.
    if let Some(idx) = slice.rfind(char::is_whitespace) {
        return s[..idx].to_string();
    }
    // No whitespace in budget — char-boundary-safe truncation.
    let mut end = MAX.min(s.len());
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    s[..end].to_string()
}

/// Round-4 — process-level escape hatch from the C4 trim used by
/// [`tool_definitions_for_profile`]. Reads `AI_MEMORY_TOOLS_VERBOSE`
/// once and accepts `1` or `true` (case-insensitive) as the truthy
/// values; anything else (including absent) is false. Cached behind a
/// `OnceLock` so the hot tools/list path doesn't re-stat the env on
/// every call.
fn tools_verbose_env_enabled() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("AI_MEMORY_TOOLS_VERBOSE")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// v0.7 C4 — full-schema (verbose) variant of
/// [`tool_definitions_for_profile`]. Returns every optional param,
/// every default, every per-property description. Used by the
/// `memory_capabilities { verbose=true }` opt-in path so power users /
/// NHI agents can still set the long-tail knobs (`confidence`,
/// `priority`, `tier`, `metadata`, `agent_id`, …) without restarting
/// the MCP server with a different profile.
///
/// v0.7 C2 — note that `docs` (long-form prose) is still stripped on
/// the verbose path; the verbose flag controls whether
/// `inputSchema.properties` is trimmed (C4), not the top-level `docs`
/// field (C2). To recover the long-form docs, call
/// [`tool_definitions`] directly.
pub fn tool_definitions_for_profile_verbose(profile: &crate::profile::Profile) -> Value {
    let mut defs = tool_definitions();
    if let Some(arr) = defs.get_mut("tools").and_then(|t| t.as_array_mut()) {
        arr.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| profile.loads(name))
        });
        strip_docs_from_tools(arr);
    }
    defs
}

/// v0.7 C2 — strip every long-form natural-language string from a
/// `tools[]` array so the bare `tools/list` payload stays inside the
/// C5 token budget (≤ 11000 cl100k tokens for the full profile (post-D1.6)).
///
/// Removed:
/// - The top-level `docs` field (the long-form prose mirror of
///   `description`).
/// - Every `description` string nested under
///   `inputSchema.properties.*` — agents that need parameter prose
///   should re-fetch with `memory_capabilities { family=<f>,
///   include_schema: true, verbose: true }`, which calls
///   [`tool_definitions`] directly without stripping.
///
/// Preserved on the bare path:
/// - The top-level short `description` (≤ 50 cl100k tokens).
/// - The full `inputSchema` shape (`type`, `enum`, `default`,
///   `minimum`, `maximum`, `required`, `items`) so callers can still
///   construct valid argument objects without a verbose drilldown.
pub(crate) fn strip_docs_from_tools(tools: &mut Vec<Value>) {
    for tool in tools.iter_mut() {
        let Some(obj) = tool.as_object_mut() else {
            continue;
        };
        obj.remove("docs");
        if let Some(input_schema) = obj.get_mut("inputSchema").and_then(Value::as_object_mut) {
            // **v0.7.0 #987/#988 update.** D1.6 schemars-derived schemas
            // emit additional metadata the legacy hand-coded macro didn't:
            // - top-level `description` on the request struct itself
            // - `$schema` reference
            // - `title` field
            // - `definitions` map for `$ref`-resolved untagged enums
            //   (e.g. `RecallKindsFilter::Many(Vec<String>) | One(String)`)
            //
            // The wire form is a discovery surface for NHI agents; the
            // verbose drilldown (`memory_capabilities { verbose=true }`)
            // is the prose surface. Strip the schemars-only metadata
            // from the wire to keep the post-D1.6 trimmed-payload
            // ceiling honest.
            input_schema.remove("description");
            input_schema.remove("$schema");
            input_schema.remove("title");
            if let Some(defs) = input_schema
                .get_mut("definitions")
                .and_then(Value::as_object_mut)
            {
                for (_name, def_value) in defs.iter_mut() {
                    strip_description_recursively(def_value);
                }
            }
            if let Some(props) = input_schema
                .get_mut("properties")
                .and_then(Value::as_object_mut)
            {
                for (_param_name, prop_value) in props.iter_mut() {
                    strip_description_recursively(prop_value);
                }
            }
        }
    }
}

/// #859 helper — walk a property value and drop every `description`
/// key encountered, including inside nested `properties` maps and
/// `oneOf` / `anyOf` / `allOf` branch arrays. Idempotent.
///
/// v0.7.0 #1058 (Agent-4 F4) — also drops every `default: null` key.
/// Every `Option<T>` field on a schemars-derived request struct emits
/// `default: null` on the wire (≈170 entries in `tools_list_full.json`,
/// cumulative ~700-1000 cl100k tokens of pure noise — the pre-D1.6
/// hand-coded `tool_definitions` macro never emitted these). Stripping
/// keeps wire payloads honest about which defaults are load-bearing
/// (numeric / boolean / short-enum defaults that callers need to
/// construct valid arguments) while dropping the schemars-only
/// `null` noise.
fn strip_description_recursively(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("description");
            // v0.7.0 #1058 — drop `default: null` (schemars-only noise).
            if let Some(Value::Null) = map.get("default") {
                map.remove("default");
            }
            // Drop long string defaults (>32 chars of prose) — short
            // numeric / boolean / enum defaults are load-bearing for
            // client-side argument construction so stay.
            if let Some(default) = map.get("default")
                && default.as_str().is_some_and(|s| s.len() > 32)
            {
                map.remove("default");
            }
            for (_, child) in map.iter_mut() {
                strip_description_recursively(child);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                strip_description_recursively(item);
            }
        }
        _ => {}
    }
}

/// v0.7 C2 — canonical tool catalog. Each tool entry carries a short
/// one-sentence `description` (≤ 50 cl100k_base tokens) and a
/// long-form `docs` field with the full prose + examples. The
/// always-on `tools/list` payload strips `docs` via
/// [`tool_definitions_for_profile`]; callers wanting the verbose form
/// invoke `memory_capabilities { family=<f>, verbose: true }` which
/// preserves `docs` so an NHI can drill in without reloading the
/// full-fat catalog into context.
pub fn tool_definitions() -> Value {
    // v0.7.0 #1077 — cache the deterministic catalog Value in a
    // `OnceLock<Value>`. `registered_tools()` is build-time static,
    // so the full catalog is invariant across the daemon lifetime.
    // Pre-#1077 every MCP `tools/list` request paid the full
    // schemars expansion across all 73 tools; post-#1077 every call
    // after boot is a single `Value::clone()` of the cached payload.
    static CACHE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let tools: Vec<Value> = registered_tools()
                .iter()
                .map(RegisteredTool::to_value)
                .collect();
            json!({
                "toolsVersion": TOOLS_VERSION,
                "tools": tools,
            })
        })
        .clone()
}

#[cfg(test)]
mod d1_6_987_tests {
    //! D1.6 (#987) — registry-level regression tests for the
    //! post-collapse [`tool_definitions`] wire shape.
    //!
    //! The snapshot at `tests/snapshots/tool_definitions_pre_d1_6.json`
    //! is the pre-D1.6 catalog (captured before the macro collapse
    //! landed). These tests pin the post-D1.6 catalog against it,
    //! tolerating only the documented allowed-diffs:
    //!
    //! - Property order (schemars sorts; legacy was insertion-ordered)
    //! - `default: null` on schemars-derived Option<T> fields vs.
    //!   typed defaults on legacy
    //! - `additionalProperties: false` added by schemars (tightening)
    //! - `minimum`/`maximum` range-constraint loss on Option<T>
    //!   fields lacking `#[schemars(range)]` attributes
    //!
    //! Disallowed (tests fail):
    //! - Tools added or removed
    //! - Property names changed or missing
    //! - Description text changed (must be byte-equal)
    //! - `required` array changed
    //! - Type widening or narrowing beyond Option<T>::None nullable
    use super::*;
    use std::collections::BTreeSet;

    fn load_snapshot() -> Value {
        let path = "tests/snapshots/tool_definitions_pre_d1_6.json";
        let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "missing pre-D1.6 snapshot at {path}: {e}; \
                 regenerate via the one-shot capture documented in #987 dispatch"
            )
        });
        serde_json::from_str(&raw).expect("snapshot must be valid JSON")
    }

    /// Pre-D1.6 vs. post-D1.6: same tool COUNT.
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_count() {
        let pre = load_snapshot();
        let post = tool_definitions();
        let pre_count = pre["tools"].as_array().map_or(0, Vec::len);
        let post_count = post["tools"].as_array().map_or(0, Vec::len);
        assert_eq!(
            pre_count, post_count,
            "post-D1.6 tool count must match pre-D1.6 snapshot ({pre_count}); \
             a tool was added or removed."
        );
    }

    /// Pre-D1.6 vs. post-D1.6: same tool NAMES (set equality).
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_names() {
        let pre = load_snapshot();
        let post = tool_definitions();
        let names = |v: &Value| -> BTreeSet<String> {
            v["tools"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.get("name").and_then(Value::as_str).map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let pre_names = names(&pre);
        let post_names = names(&post);
        let added: Vec<&String> = post_names.difference(&pre_names).collect();
        let removed: Vec<&String> = pre_names.difference(&post_names).collect();
        assert!(
            added.is_empty() && removed.is_empty(),
            "post-D1.6 tool name set drifted: added = {added:?}, removed = {removed:?}"
        );
    }

    /// Pre-D1.6 vs. post-D1.6: per-tool short DESCRIPTION strings
    /// byte-for-byte equal. The D1.2 (#983) parity contract pinned
    /// this — D1.6 must preserve it.
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_descriptions() {
        let pre = load_snapshot();
        let post = tool_definitions();
        let by_name = |v: &Value| -> std::collections::BTreeMap<String, String> {
            v["tools"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            let name = t.get("name").and_then(Value::as_str)?.to_string();
                            let desc = t.get("description").and_then(Value::as_str)?.to_string();
                            Some((name, desc))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let pre_map = by_name(&pre);
        let post_map = by_name(&post);
        for (name, want) in &pre_map {
            let got = post_map
                .get(name)
                .unwrap_or_else(|| panic!("post-D1.6 missing tool {name}"));
            assert_eq!(
                got, want,
                "post-D1.6 {name}.description drifted from snapshot\n  legacy: {want:?}\n  post-D1.6: {got:?}"
            );
        }
    }

    /// Pre-D1.6 vs. post-D1.6: per-tool long-form DOCS strings
    /// byte-for-byte equal. Same contract as descriptions.
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_docs() {
        let pre = load_snapshot();
        let post = tool_definitions();
        let by_name = |v: &Value| -> std::collections::BTreeMap<String, String> {
            v["tools"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            let name = t.get("name").and_then(Value::as_str)?.to_string();
                            let docs = t.get("docs").and_then(Value::as_str)?.to_string();
                            Some((name, docs))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let pre_map = by_name(&pre);
        let post_map = by_name(&post);
        for (name, want) in &pre_map {
            let got = post_map
                .get(name)
                .unwrap_or_else(|| panic!("post-D1.6 missing tool {name}"));
            assert_eq!(
                got, want,
                "post-D1.6 {name}.docs drifted from snapshot\n  legacy: {want:?}\n  post-D1.6: {got:?}"
            );
        }
    }

    /// Pre-D1.6 vs. post-D1.6: per-tool `inputSchema.properties`
    /// KEY SET (property names). Order is allowed to differ
    /// (schemars sorts); membership must match exactly.
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_property_keys() {
        let pre = load_snapshot();
        let post = tool_definitions();

        let props_by_name = |v: &Value| -> std::collections::BTreeMap<String, BTreeSet<String>> {
            v["tools"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            let name = t.get("name").and_then(Value::as_str)?.to_string();
                            let keys: BTreeSet<String> = t
                                .pointer("/inputSchema/properties")
                                .and_then(Value::as_object)
                                .map(|m| m.keys().cloned().collect())
                                .unwrap_or_default();
                            Some((name, keys))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let pre_props = props_by_name(&pre);
        let post_props = props_by_name(&post);
        for (name, want) in &pre_props {
            let got = post_props
                .get(name)
                .unwrap_or_else(|| panic!("post-D1.6 missing tool {name}"));
            let added: Vec<&String> = got.difference(want).collect();
            let removed: Vec<&String> = want.difference(got).collect();
            assert!(
                added.is_empty() && removed.is_empty(),
                "post-D1.6 {name}.inputSchema.properties drifted: added = {added:?}, removed = {removed:?}"
            );
        }
    }

    /// Pre-D1.6 vs. post-D1.6: per-tool `required` array. Order
    /// allowed to differ; set membership must match.
    #[test]
    fn tool_definitions_byte_shape_v0_7_0_compat_987_required() {
        let pre = load_snapshot();
        let post = tool_definitions();

        let req_by_name = |v: &Value| -> std::collections::BTreeMap<String, BTreeSet<String>> {
            v["tools"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            let name = t.get("name").and_then(Value::as_str)?.to_string();
                            let req: BTreeSet<String> = t
                                .pointer("/inputSchema/required")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            Some((name, req))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let pre_req = req_by_name(&pre);
        let post_req = req_by_name(&post);
        for (name, want) in &pre_req {
            let got = post_req
                .get(name)
                .unwrap_or_else(|| panic!("post-D1.6 missing tool {name}"));
            assert_eq!(
                got, want,
                "post-D1.6 {name}.inputSchema.required drifted; \
                 the D1.6 allowed-diffs do NOT permit required-set changes"
            );
        }
    }
}
