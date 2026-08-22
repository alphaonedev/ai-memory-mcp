// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_kg_query` handler.

use crate::mcp::registry::McpTool;
use crate::models::field_names;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_kg_query` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_kg_query`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct KgQueryRequest {
    /// Source memory ID.
    pub source_id: String,

    /// Hops, 1..=5.
    #[serde(default)]
    pub max_depth: Option<i64>,

    /// RFC3339; keep links valid at instant. Omit to skip temporal filter.
    #[serde(default)]
    pub valid_at: Option<String>,

    /// Observed-by allowlist. Empty array = zero rows.
    #[serde(default)]
    pub allowed_agents: Option<Vec<String>>,

    /// Cap across all depths [1,1000].
    #[serde(default)]
    pub limit: Option<i64>,

    /// When true, traverse historically-invalidated edges.
    #[serde(default)]
    pub include_invalidated: Option<bool>,

    #[schemars(description = "#889 traverse by source_uri.")]
    #[serde(default)]
    pub by_source_uri: Option<String>,

    /// Restrict to namespace.
    #[serde(default)]
    pub namespace: Option<String>,

    /// #3171 — #151 scope-visibility agent (honoured but undeclared until the
    /// tool-contract audit); mirrors `memory_search.as_agent`.
    #[serde(default)]
    pub as_agent: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_kg_query`.
#[allow(dead_code)]
pub struct KgQueryTool;

impl McpTool for KgQueryTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_KG_QUERY
    }
    fn description() -> &'static str {
        "Outbound KG traversal from a source memory (<=5 hops)."
    }
    fn docs() -> &'static str {
        "Pillar 2 / Stream C: BFS/CTE traversal with cycle detection. Each row carries valid_from/valid_until/observed_by + target title/namespace. Filters chain across every hop. max_depth ceiling 5."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<KgQueryRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Graph.name()
    }
}

// v0.7.0 ARCH-3 / FX-12 — promoted from `pub(super)` to `pub` so the
// `ai-memory kg query` CLI subcommand can dispatch into the same
// substrate primitive the MCP `memory_kg_query` tool consumes, without
// duplicating business logic. Wire envelope is byte-equal across MCP /
// HTTP / CLI.
pub fn handle_kg_query(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // v0.7.0 Provenance Gap 6 (#889) — reciprocal "subgraph rooted at
    // every memory sharing source_uri" entrypoint. When
    // `by_source_uri` is supplied, every memory carrying that URI is
    // returned alongside its outbound links so callers see the full
    // forest rooted at the document. The traversal is unbounded (one
    // hop, since the goal is "what else is from this document") and
    // bypasses the `source_id`-required argument check.
    let by_source_uri = params[field_names::BY_SOURCE_URI]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(uri) = by_source_uri {
        validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
        let namespace = params["namespace"].as_str();
        let limit = params["limit"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok());
        // #975 — accept an `as_agent` MCP param so callers that
        // identify themselves get the post-#942 scope=private
        // visibility gate on the reciprocal source-uri endpoint.
        // Absent param leaves `as_agent = None` which preserves the
        // pre-#975 unfiltered behaviour for substrate-internal callers.
        let as_agent = params["as_agent"].as_str();
        if let Some(a) = as_agent {
            validate::validate_namespace(a).map_err(|e| e.to_string())?;
        }
        // v0.8.0 #1720 A3 — owner-keyed scope=private gate. Resolve the
        // read-path visibility caller (the agent's `metadata.agent_id`,
        // DISTINCT from the `as_agent` namespace) and thread it to the
        // owner-keyed `visibility_clause` private arm. `None` = fail-
        // closed (no private rows reach an unidentified caller).
        let caller = crate::identity::resolve_read_visibility_caller();
        let roots =
            db::list_by_source_uri(conn, uri, namespace, limit, as_agent, caller.as_deref())
                .map_err(|e| e.to_string())?;
        let memories_json: Vec<Value> = roots
            .iter()
            .map(|m| {
                json!({
                    "target_id": m.id,
                    "title": m.title,
                    (field_names::TARGET_NAMESPACE): m.namespace,
                    "depth": 0,
                    (field_names::SOURCE_URI): m.source_uri,
                })
            })
            .collect();
        return Ok(json!({
            (field_names::BY_SOURCE_URI): uri,
            "memories": memories_json,
            "count": roots.len(),
        }));
    }

    let source_id = params["source_id"]
        .as_str()
        .ok_or(crate::errors::msg::SOURCE_ID_REQUIRED)?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;

    let max_depth = params["max_depth"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(1);

    let valid_at = params["valid_at"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(t) = valid_at {
        validate::validate_expires_at_format(t).map_err(|e| e.to_string())?;
    }

    let allowed_agents: Option<Vec<String>> = params["allowed_agents"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .map(str::to_string)
            .collect()
    });
    if let Some(agents) = allowed_agents.as_ref() {
        for a in agents {
            validate::validate_agent_id(a).map_err(|e| e.to_string())?;
        }
    }

    let limit = params["limit"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());

    // NHI-P3-T7 (v0.7.0 NHI testing): default to "current view" —
    // exclude edges whose `valid_until` lies in the past. Pass
    // `include_invalidated=true` to traverse the full historical graph.
    let include_invalidated = params[field_names::INCLUDE_INVALIDATED]
        .as_bool()
        .unwrap_or(false);

    let nodes = db::kg_query(
        conn,
        source_id,
        max_depth,
        valid_at,
        allowed_agents.as_deref(),
        limit,
        include_invalidated,
    )
    .map_err(|e| e.to_string())?;

    // #1935 (CWE-863) — visibility filter, mirroring the HTTP twin at
    // `src/handlers/kg.rs`. `db::kg_query` returns each reachable node's
    // title + namespace with NO per-caller gate; because links can be forged
    // to targets the caller cannot see (#1929), an attacker-rooted walk could
    // otherwise disclose the titles/namespaces/graph-structure of linked
    // PRIVATE memories. Keyed on the ENFORCED-read caller (env-only) so it
    // fires ONLY when `AI_MEMORY_AGENT_ID` is set (multi-tenant opt-in); the
    // single-operator trust-all default returns the full topology
    // byte-unchanged. Nodes the caller cannot see (or that can't be fetched)
    // are DROPPED — fail closed.
    let nodes: Vec<_> = if let Some(caller) = crate::identity::resolve_read_visibility_caller() {
        nodes
            .into_iter()
            .filter(|n| match db::get(conn, &n.target_id) {
                Ok(Some(mem)) => crate::visibility::is_visible_to_caller(&mem, &caller),
                _ => false,
            })
            .collect()
    } else {
        nodes
    };

    let memories_json: Vec<Value> = nodes
        .iter()
        .map(|n| {
            json!({
                "target_id": n.target_id,
                "relation": n.relation,
                (field_names::VALID_FROM): n.valid_from,
                (field_names::VALID_UNTIL): n.valid_until,
                (field_names::OBSERVED_BY): n.observed_by,
                "title": n.title,
                (field_names::TARGET_NAMESPACE): n.target_namespace,
                "depth": n.depth,
                "path": n.path,
            })
        })
        .collect();
    let paths_json: Vec<&str> = nodes.iter().map(|n| n.path.as_str()).collect();

    Ok(json!({
        "source_id": source_id,
        "max_depth": max_depth,
        "memories": memories_json,
        "paths": paths_json,
        "count": nodes.len(),
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_kg_query`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_kg_query_parity_985() {
        let derived = derived_props_for::<KgQueryRequest>();
        assert_property_set_parity("memory_kg_query", &derived);
        assert_descriptions_match("memory_kg_query", &derived);
    }

    #[test]
    fn memory_kg_query_tool_metadata_985() {
        assert_eq!(KgQueryTool::name(), "memory_kg_query");
        assert_eq!(KgQueryTool::family(), "graph");
    }
}

#[cfg(test)]
mod visibility_1935_tests {
    //! #1935 (CWE-863) — MCP `handle_kg_query` must apply the same
    //! visibility filter as its HTTP twin so a forged-link walk cannot
    //! disclose the title/namespace of a memory the caller cannot see.
    use super::*;
    use serde_json::json;

    fn open_db() -> rusqlite::Connection {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.db");
        let c = crate::db::open(&path).expect("db::open");
        std::mem::forget(dir);
        c
    }

    fn insert_mem(
        c: &rusqlite::Connection,
        title: &str,
        ns: &str,
        meta: serde_json::Value,
    ) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let m = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body {title}"),
            created_at: now.clone(),
            updated_at: now,
            metadata: meta,
            ..Default::default()
        };
        crate::db::insert(c, &m).expect("insert")
    }

    /// A KG walk rooted at the attacker's OWN memory that links to a
    /// VICTIM-owned PRIVATE memory must NOT disclose the victim node.
    /// Fail-before/pass-after: pre-fix every reachable node was returned
    /// with no per-caller gate.
    #[test]
    fn kg_walk_hides_invisible_target_1935() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let c = open_db();
        let src = insert_mem(
            &c,
            "attacker-root",
            "attacker-ns",
            json!({"agent_id": "ai:attacker"}),
        );
        let victim = insert_mem(
            &c,
            "victim-secret",
            "victim-ns",
            json!({"agent_id": "ai:victim", "scope": "private"}),
        );
        crate::db::create_link(&c, &src, &victim, "related_to").expect("link");

        // Attacker caller → the victim's private node is filtered out.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:attacker") };
        let out = handle_kg_query(&c, &json!({"source_id": src, "max_depth": 2})).expect("query");
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        let mems = out["memories"].as_array().expect("memories array");
        let leaked = mems.iter().any(|m| {
            m["title"].as_str() == Some("victim-secret")
                || m[field_names::TARGET_NAMESPACE].as_str() == Some("victim-ns")
                || m["target_id"].as_str() == Some(victim.as_str())
        });
        assert!(!leaked, "victim private node must not be disclosed: {out}");

        // Control: env UNSET (single-operator trust-all default) → the full
        // topology is still returned (behaviour byte-unchanged).
        let out2 = handle_kg_query(&c, &json!({"source_id": src, "max_depth": 2})).expect("query2");
        assert!(
            out2["count"].as_u64().unwrap_or(0) >= 1,
            "default path must return the full topology: {out2}"
        );
    }
}
