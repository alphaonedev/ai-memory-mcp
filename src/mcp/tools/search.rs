// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_search` handler.

use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::models::Tier;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_search` (core family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_search`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SearchRequest {
    pub query: String,

    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,

    /// Exact metadata.agent_id filter.
    #[serde(default)]
    pub agent_id: Option<String>,

    #[schemars(description = "#151 scope-visibility agent.")]
    #[serde(default)]
    pub as_agent: Option<String>,

    /// WT-1-E: include atomised sources.
    #[serde(default)]
    pub include_archived: Option<bool>,

    /// Response format. toon_compact saves 79%.
    #[serde(default)]
    pub format: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_search`.
#[allow(dead_code)]
pub struct SearchTool;

impl McpTool for SearchTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SEARCH
    }
    fn description() -> &'static str {
        "Search memories by exact keyword match (AND semantics)."
    }
    fn docs() -> &'static str {
        "Exact keyword AND search. Deterministic; no fuzzy/semantic. Filters: namespace, tier, agent_id, as_agent (Task 1.5 scope). WT-1-E: atomised sources hidden by default."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SearchRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Core.name()
    }
}

/// v0.7.0 #1468 — the underlying `db::search_with_source_uri` /
/// `db::list_by_source_uri` apply the #151 namespace-scope (`as_agent`)
/// visibility, but NOT the per-row `scope=private` ownership predicate, so
/// a cross-agent private row can still match a keyword query. When
/// `caller` is `Some` (MCP dispatch resolved a stable `AI_MEMORY_AGENT_ID`
/// identity via [`crate::identity::resolve_read_visibility_caller`]) we
/// additionally drop rows the caller does not own per
/// [`crate::visibility::is_visible_to_caller`]. `None` keeps the
/// single-tenant trust-all behavior.
pub(super) fn handle_search(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let query = params["query"].as_str();
    let namespace = params["namespace"].as_str();
    let tier = params["tier"].as_str().and_then(Tier::from_str);
    // Ultrareview #339: saturate instead of panic on 32-bit targets
    // where u64 may exceed usize::MAX. A malicious client passing
    // limit=2^63 would otherwise take down the daemon.
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(20)).unwrap_or(usize::MAX);

    let agent_id = params["agent_id"].as_str();
    if let Some(aid) = agent_id {
        validate::validate_agent_id(aid).map_err(|e| e.to_string())?;
    }
    let as_agent = params["as_agent"].as_str();
    if let Some(a) = as_agent {
        validate::validate_namespace(a).map_err(|e| e.to_string())?;
    }
    // v0.7.0 WT-1-E — atom-preference search semantics. See
    // `mcp::tools::recall::handle_recall` for the full contract.
    let include_archived = params["include_archived"].as_bool().unwrap_or(false);
    // v0.7.0 Provenance Gap 6 (#889) — reciprocal source filter.
    // When `source_uri` is supplied + non-empty, results are
    // narrowed to memories whose `source_uri` column exactly matches.
    // The partial `idx_memories_source_uri` index (v38) covers the
    // lookup so the reciprocal "everything from this document"
    // query is O(log N), not O(N) JSON-path scan.
    let source_uri = params[param_names::SOURCE_URI]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(uri) = source_uri {
        validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
    }

    // When `query` is empty but `source_uri` is supplied, route through
    // the index-only `list_by_source_uri` so callers can ask "give me
    // every memory from this document" without typing a query token.
    if query.unwrap_or("").trim().is_empty() {
        if let Some(uri) = source_uri {
            // #975 — propagate the caller's `as_agent` to the reciprocal
            // source-uri endpoint so the MCP source_uri-only path
            // respects the same scope=private gate as `search_with_source_uri`.
            let results =
                db::list_by_source_uri(conn, uri, namespace, Some(limit.min(200)), as_agent)
                    .map_err(|e| e.to_string())?;
            let results = filter_visible(results, caller);
            return Ok(json!({"results": results, "count": results.len()}));
        }
        return Err(crate::errors::msg::QUERY_REQUIRED.into());
    }

    let results = db::search_with_source_uri(
        conn,
        query.unwrap_or(""),
        namespace,
        tier.as_ref(),
        limit.min(200),
        None,
        None,
        None,
        None,
        agent_id,
        as_agent,
        include_archived,
        source_uri,
    )
    .map_err(|e| e.to_string())?;
    let results = filter_visible(results, caller);
    Ok(json!({"results": results, "count": results.len()}))
}

/// Drop rows the `caller` does not own (canonical #951 predicate). No-op
/// when `caller` is `None` (single-tenant trust-all read posture).
fn filter_visible(
    results: Vec<crate::models::Memory>,
    caller: Option<&str>,
) -> Vec<crate::models::Memory> {
    match caller {
        Some(c) => results
            .into_iter()
            .filter(|m| crate::visibility::is_visible_to_caller(m, c))
            .collect(),
        None => results,
    }
}

#[cfg(test)]
mod visibility_1468_tests {
    //! v0.7.0 #1468 — caller-scoped `scope=private` post-filter on the
    //! `memory_search` read path.
    use super::*;
    use crate::models::{Memory, Tier as MTier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn mem(title: &str, agent: &str, scope: Option<&str>) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        let metadata = match scope {
            Some(s) => json!({crate::META_KEY_AGENT_ID: agent, crate::META_KEY_SCOPE: s}),
            None => json!({crate::META_KEY_AGENT_ID: agent}),
        };
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: MTier::Mid,
            namespace: "ns".to_string(),
            title: title.to_string(),
            // shared keyword so the FTS query matches every row
            content: "needle in the haystack".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        }
    }

    fn seed(conn: &rusqlite::Connection) {
        use crate::models::namespace::MemoryScope;
        // private row owned by alice + collective row owned by bob
        db::insert(conn, &mem("priv", "ai:alice", None)).expect("ins");
        db::insert(
            conn,
            &mem("shared", "ai:bob", Some(MemoryScope::Collective.as_str())),
        )
        .expect("ins");
    }

    #[test]
    fn caller_none_returns_all() {
        let conn = fresh_conn();
        seed(&conn);
        let out = handle_search(&conn, &json!({"query": "needle"}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    #[test]
    fn non_owner_excludes_cross_agent_private() {
        let conn = fresh_conn();
        seed(&conn);
        let out = handle_search(&conn, &json!({"query": "needle"}), Some("ai:carol")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
        assert_eq!(out["results"][0]["title"], "shared");
    }

    #[test]
    fn owner_sees_own_private_and_shared() {
        let conn = fresh_conn();
        seed(&conn);
        let out = handle_search(&conn, &json!({"query": "needle"}), Some("ai:alice")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    /// #1468 — the empty-query + `source_uri` early-return branch
    /// (`db::list_by_source_uri`) MUST apply the same caller-scoped
    /// `scope=private` filter as the main keyword path; without it the
    /// reciprocal "everything from this document" query would leak a
    /// cross-agent private row.
    #[test]
    fn source_uri_only_branch_excludes_cross_agent_private() {
        // Build the fixture URI from the validator's accepted-scheme
        // SSOT so the test can't rot if the scheme set changes.
        let uri = format!(
            "{}atlas/doc-1",
            crate::validate::VALID_SOURCE_URI_SCHEMES[0]
        );
        let conn = fresh_conn();
        let mut priv_row = mem("priv", "ai:alice", None);
        priv_row.source_uri = Some(uri.clone());
        let mut shared_row = mem("shared", "ai:bob", Some("collective"));
        shared_row.source_uri = Some(uri.clone());
        db::insert(&conn, &priv_row).expect("ins");
        db::insert(&conn, &shared_row).expect("ins");

        // Non-owner: alice's private row is dropped, bob's shared survives.
        let out = handle_search(&conn, &json!({"source_uri": uri}), Some("ai:carol")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
        assert_eq!(out["results"][0]["title"], "shared");

        // Trust-all caller (None) keeps both.
        let all = handle_search(&conn, &json!({"source_uri": uri}), None).expect("ok");
        assert_eq!(all["count"].as_u64(), Some(2));
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_search`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_search_parity_985() {
        let derived = derived_props_for::<SearchRequest>();
        assert_property_set_parity("memory_search", &derived);
        assert_descriptions_match("memory_search", &derived);
    }

    #[test]
    fn memory_search_tool_metadata_985() {
        assert_eq!(SearchTool::name(), "memory_search");
        assert_eq!(SearchTool::family(), "core");
    }
}
