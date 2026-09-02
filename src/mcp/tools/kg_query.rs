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

// ---------------------------------------------------------------------------
// #3386 — shared visibility gate for BOTH traversal paths
// ---------------------------------------------------------------------------

/// #3386 — `true` when `mem` survives the full `memory_kg_query` read gate.
///
/// Two independent narrowing steps, applied in order; a node must pass both:
///
/// 1. **The enforced-caller gate (#1935 / #951).** `caller` is the read
///    principal resolved from `AI_MEMORY_AGENT_ID` by the SAME
///    [`crate::identity::resolve_read_visibility_caller`] every other read tool
///    uses. `None` is the single-operator trust-all posture and skips this
///    step, exactly as before #3386.
/// 2. **The #151 scope-agent gate.** `as_agent` is the caller-supplied scope
///    agent this tool has advertised since #3171 as "mirrors
///    `memory_search.as_agent`" — and, pre-#3386, did not honour at all on the
///    `source_id` path. It is evaluated through
///    [`crate::visibility::is_visible_to_scope_agent`], the in-process twin of
///    the SQL `visibility_clause` that `memory_search` and
///    `db::list_by_source_uri` bind: the team/unit/org SUBTREE arms key on
///    `as_agent`, while the owner-keyed PRIVATE arm keys on the identified
///    `caller` and FAILS CLOSED when there is none. Keying private on
///    `as_agent` instead would let a wire value unlock another principal's
///    private rows on the `by_source_uri` path, whose baseline is fail-closed.
///
/// Because each step can only REMOVE rows, a wire `as_agent` can never widen
/// past the enforced caller. That is what makes honouring a self-asserted value
/// safe on a READ filter, in contrast to the write/authz SUBJECT of
/// #3171/#3363, which must be BOUND to the caller: there a wire value chooses
/// the principal a decision is made *as*; here it can only drop rows.
///
/// With neither a caller nor an `as_agent` this is vacuously `true` — the
/// zero-config posture, byte-identical to pre-#3386.
fn node_visible(mem: &crate::models::Memory, caller: Option<&str>, as_agent: Option<&str>) -> bool {
    if let Some(c) = caller
        && !crate::visibility::is_visible_to_caller(mem, c)
    {
        return false;
    }
    if let Some(a) = as_agent
        && !crate::visibility::is_visible_to_scope_agent(mem, a, caller)
    {
        return false;
    }
    true
}

/// #3386 — the `by_source_uri` traversal path, extracted from
/// [`handle_kg_query`] so each path is readable on its own and the shared
/// ingress gate above it is impossible to miss.
///
/// `namespace` / `limit` / `as_agent` / `caller` are the handler's ONE parse of
/// those inputs, so this path and the `source_id` path can never diverge on
/// what they filter by.
///
/// # Errors
/// A `source_uri` validation failure or the stringified substrate error.
fn kg_query_by_source_uri(
    conn: &rusqlite::Connection,
    uri: &str,
    namespace: Option<&str>,
    limit: Option<usize>,
    as_agent: Option<&str>,
    caller: Option<&str>,
) -> Result<Value, String> {
    validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
    let roots = db::list_by_source_uri(conn, uri, namespace, limit, as_agent, caller)
        .map_err(|e| e.to_string())?;
    // #3386 — run the CANONICAL in-process predicate on this path too, so
    // the two traversal paths agree row-for-row. The SQL
    // `visibility_clause` above is prefix-keyed; `node_visible` carries the
    // #1921 team/unit/org subtree rule and the #2633 unrecognised-token
    // narrowing on top of it. Mirrors `handle_search`, which likewise
    // applies the SQL clause AND an in-process `filter_visible`.
    let roots: Vec<_> = roots
        .into_iter()
        .filter(|m| node_visible(m, caller, as_agent))
        .collect();
    let memories_json: Vec<Value> = roots
        .iter()
        .map(|m| {
            json!({
                "target_id": m.id,
                // #3386 — a root is a node, not an edge, so it has no
                // relation. Emitted as an explicit null (rather than an
                // absent key) so ONE client parser handles both envelopes.
                "relation": Value::Null,
                "title": m.title,
                (field_names::TARGET_NAMESPACE): m.namespace,
                "depth": 0,
                "path": m.id,
                (field_names::SOURCE_URI): m.source_uri,
            })
        })
        .collect();
    // #3386 — `paths` was present on the main envelope and absent here, so
    // a client had to branch on which request it sent. Additive: no key is
    // removed or repurposed.
    let paths_json: Vec<&str> = roots.iter().map(|m| m.id.as_str()).collect();
    Ok(json!({
        (field_names::BY_SOURCE_URI): uri,
        "memories": memories_json,
        "paths": paths_json,
        "count": roots.len(),
    }))
}

// v0.7.0 ARCH-3 / FX-12 — promoted from `pub(super)` to `pub` so the
// `ai-memory kg query` CLI subcommand can dispatch into the same
// substrate primitive the MCP `memory_kg_query` tool consumes, without
// duplicating business logic. Wire envelope is byte-equal across MCP /
// HTTP / CLI.
pub fn handle_kg_query(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3386 — `namespace`, `as_agent` and `limit` are read HERE, ONCE, ahead
    // of the `by_source_uri` branch below, so BOTH traversal paths get the
    // identical gate. Pre-#3386 all three were read only INSIDE that branch,
    // so on the main `source_id` path the two advertised filters were DEAD
    // code paths: `namespace` (a documented MCP param AND the
    // `ai-memory kg-query --namespace` CLI flag) was silently ignored, and
    // `as_agent` — documented since #3171 as "mirrors
    // `memory_search.as_agent`" — did nothing, so `as_agent:"ai:bob"` still
    // returned alice's `scope=private` node with its title and namespace in
    // full. A negative `limit`/`max_depth` was silently coerced to the server
    // default because `Value::as_u64` returns `None` for a negative, which is
    // indistinguishable from "absent" (the exact #3171 `optional_non_negative_u64`
    // defect class, on two params that audit missed).
    let namespace = params["namespace"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(ns) = namespace {
        validate::validate_namespace(ns).map_err(|e| e.to_string())?;
    }
    // #975 — the #151 scope-visibility agent. Absent leaves `as_agent = None`,
    // which preserves the pre-#975 unfiltered behaviour for substrate-internal
    // callers.
    let as_agent = params["as_agent"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(a) = as_agent {
        validate::validate_namespace(a).map_err(|e| e.to_string())?;
    }
    // v0.8.0 #1720 A3 — owner-keyed scope=private gate. Resolve the read-path
    // visibility caller (the agent's `metadata.agent_id`, DISTINCT from the
    // `as_agent` namespace) — the SAME resolver `memory_search` /
    // `memory_list` / `memory_recall` use — and thread it to the owner-keyed
    // `visibility_clause` private arm. `None` = fail-closed (no private rows
    // reach an unidentified caller).
    let caller = crate::identity::resolve_read_visibility_caller();
    // #3386 — refuse a negative / non-integer bound instead of coercing it.
    let limit = crate::mcp::param_guard::optional_non_negative_u64(params, "limit")?
        // Saturate rather than `.ok()`: a value above `usize::MAX` must reach
        // the substrate's own documented cap, not silently become "absent".
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));

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
        return kg_query_by_source_uri(conn, uri, namespace, limit, as_agent, caller.as_deref());
    }

    kg_query_from_source(conn, params, namespace, limit, as_agent, caller.as_deref())
}

/// #3386 — the main (`source_id`) traversal path, extracted from
/// [`handle_kg_query`] alongside [`kg_query_by_source_uri`] so both paths are
/// visibly fed by the SAME ingress-parsed `namespace` / `limit` / `as_agent` /
/// `caller`. Pre-#3386 this path silently ignored the first three.
///
/// # Errors
/// A `source_id` / `valid_at` / `allowed_agents` / `max_depth` validation
/// failure, or the stringified substrate traversal error.
fn kg_query_from_source(
    conn: &rusqlite::Connection,
    params: &Value,
    namespace: Option<&str>,
    limit: Option<usize>,
    as_agent: Option<&str>,
    caller: Option<&str>,
) -> Result<Value, String> {
    let source_id = params["source_id"]
        .as_str()
        .ok_or(crate::errors::msg::SOURCE_ID_REQUIRED)?;
    validate::validate_id(source_id).map_err(|e| e.to_string())?;

    // #3386 — refuse a negative / non-integer depth instead of coercing it to
    // the default of 1. Saturating on overflow lets a huge value hit
    // `db::kg_query`'s own `max_depth > KG_QUERY_MAX_SUPPORTED_DEPTH` refusal
    // rather than silently becoming a 1-hop walk.
    let max_depth = crate::mcp::param_guard::optional_non_negative_u64(params, "max_depth")?
        .map_or(1, |n| usize::try_from(n).unwrap_or(usize::MAX));

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

    // #3386 — the `namespace` restriction, previously DEAD on this path. Applied
    // to the RESULT rows rather than pruned mid-walk: pruning would change
    // reachability (a same-namespace node two hops away through a foreign one
    // would vanish), whereas the documented contract is "restrict to
    // namespace", the exact-match semantics `db::list_by_source_uri` already
    // gives the `by_source_uri` path (`m.namespace = ?`). Applied BEFORE the
    // visibility filter so the cheap string compare shrinks the set the
    // per-node `db::get` runs over.
    let nodes: Vec<_> = match namespace {
        Some(ns) => nodes
            .into_iter()
            .filter(|n| n.target_namespace == ns)
            .collect(),
        None => nodes,
    };

    // #1935 (CWE-863) — visibility filter, mirroring the HTTP twin at
    // `src/handlers/kg.rs`. `db::kg_query` returns each reachable node's
    // title + namespace with NO per-caller gate; because links can be forged
    // to targets the caller cannot see (#1929), an attacker-rooted walk could
    // otherwise disclose the titles/namespaces/graph-structure of linked
    // PRIVATE memories. Nodes the caller cannot see (or that can't be fetched)
    // are DROPPED — fail closed.
    //
    // #3386 — the gate now also runs the #151 `as_agent` step, not just the
    // enforced-read caller, which is what finally makes `as_agent` bite on this
    // path. With neither supplied, `trust_all` short-circuits and the full
    // topology is returned byte-unchanged.
    // `true` when neither narrowing step can fire — the zero-config posture.
    let trust_all = caller.is_none() && as_agent.is_none();
    let nodes: Vec<_> = if trust_all {
        nodes
    } else {
        nodes
            .into_iter()
            .filter(|n| match db::get(conn, &n.target_id) {
                Ok(Some(mem)) => node_visible(&mem, caller, as_agent),
                _ => false,
            })
            .collect()
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
