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

    /// #3171 — exact `source_uri` filter (honoured but undeclared until the
    /// tool-contract audit).
    #[serde(default)]
    pub source_uri: Option<String>,
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
    // v0.8.0 PE-2 (#1730) — read-action governance gate (zero-config
    // fast-path when no read_action rules exist).
    {
        let actor = caller
            .or_else(|| params["agent_id"].as_str())
            .unwrap_or_default();
        crate::governance::agent_action::gate_read_surface(conn, actor, "search", namespace, query)
            .map_err(|r| {
                crate::governance::deny_message(
                    "search",
                    crate::governance::DenyGate::Governance,
                    &r.reason,
                )
            })?;
    }
    // v1.0.0 #3130 — FAIL CLOSED on an unrecognised `tier` (was
    // `.and_then(Tier::from_str)`, which silently dropped the filter and
    // returned UNFILTERED results — wrong results, not fewer).
    let tier = Tier::parse_optional(params["tier"].as_str())?;
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
            let results = db::list_by_source_uri(
                conn,
                uri,
                namespace,
                Some(limit.min(200)),
                as_agent,
                caller,
            )
            .map_err(|e| e.to_string())?;
            let results = filter_visible(results, caller, namespace);
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
        caller,
    )
    .map_err(|e| e.to_string())?;
    let results = filter_visible(results, caller, namespace);
    Ok(json!({"results": results, "count": results.len()}))
}

/// Drop rows the `caller` may not read, via the canonical #951 predicate.
///
/// v1.0.0 #3348 — routes through [`crate::visibility::is_readable_on_query`]
/// rather than applying the predicate only when a `caller` happens to resolve.
/// The old shape (`None` => return everything) meant an unscoped `search` on a
/// shared store returned every other agent's `_messages/<them>` inbox mail and
/// the `_agents` registry as ordinary results. Substrate rows now require the
/// request to NAME their namespace; ordinary namespaces are unchanged.
fn filter_visible(
    results: Vec<crate::models::Memory>,
    caller: Option<&str>,
    requested_namespace: Option<&str>,
) -> Vec<crate::models::Memory> {
    results
        .into_iter()
        .filter(|m| crate::visibility::is_readable_on_query(m, caller, requested_namespace))
        .collect()
}

#[cfg(test)]
mod tier_fail_closed_3130_tests {
    //! v1.0.0 #3130 — `memory_search` REFUSES an unrecognised `tier`
    //! instead of dropping the filter and answering with unfiltered
    //! results (wrong results, not fewer).
    use super::*;
    use crate::models::Tier as MTier;
    use crate::storage as db;

    #[test]
    fn unknown_tier_is_refused_not_unfiltered_3130() {
        let conn = db::open(std::path::Path::new(":memory:")).expect("open in-memory db");
        let err = handle_search(&conn, &json!({"query": "anything", "tier": "Long"}), None)
            .expect_err("an unrecognised tier must be refused");
        assert!(err.contains("invalid tier"), "got: {err}");
        assert!(
            err.contains(MTier::VALUES_HINT),
            "must name the valid tiers: {err}"
        );
    }

    #[test]
    fn absent_tier_is_still_unconstrained_3130() {
        let conn = db::open(std::path::Path::new(":memory:")).expect("open in-memory db");
        handle_search(&conn, &json!({"query": "anything"}), None)
            .expect("an absent tier stays genuinely unconstrained");
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
            cid: None,
            valid_from: None,
            valid_until: None,
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
            lifecycle_state: crate::models::LifecycleState::Open,
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
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        seed(&conn);
        let out = handle_search(&conn, &json!({"query": "needle"}), Some("ai:carol")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
        assert_eq!(out["results"][0]["title"], "shared");
    }

    #[test]
    fn owner_sees_own_private_and_shared() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        seed(&conn);
        let out = handle_search(&conn, &json!({"query": "needle"}), Some("ai:alice")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    // ---- #3348 — substrate namespaces on the `memory_search` funnel -------
    //
    // Reported: an unscoped `search` on a shared store returned other agents'
    // `_messages/*` inbox mail and `_agents` registry rows as ordinary
    // results. Pre-#3348 `caller == None` skipped the filter entirely, so the
    // first assertion below returned 3 instead of 2.

    fn mem_in(ns: &str, agent: &str, scope: Option<&str>) -> Memory {
        let mut m = mem("row", agent, scope);
        m.namespace = ns.to_string();
        m
    }

    #[test]
    fn unscoped_search_withholds_substrate_rows_3348() {
        let conn = fresh_conn();
        seed(&conn);
        db::insert(&conn, &mem_in("_messages/ai:carol", "ai:bob", None)).expect("ins mail");
        db::insert(
            &conn,
            &mem_in(
                "_agents",
                "ai:bob",
                Some(crate::models::namespace::MemoryScope::Collective.as_str()),
            ),
        )
        .expect("ins registry");

        for caller in [None, Some("ai:alice")] {
            let out = handle_search(&conn, &json!({"query": "needle"}), caller).expect("ok");
            let namespaces: Vec<&str> = out["results"]
                .as_array()
                .expect("results array")
                .iter()
                .filter_map(|r| r["namespace"].as_str())
                .collect();
            assert!(
                !namespaces.iter().any(|n| n.starts_with("_messages/")),
                "#3348: an unscoped search must not return another agent's inbox \
                 mail (caller={caller:?}); got {namespaces:?}"
            );
            assert!(
                !namespaces.contains(&"_agents"),
                "#3348: a BROAD scope must not make the agent registry an ambient \
                 search result (caller={caller:?}); got {namespaces:?}"
            );
        }
    }

    #[test]
    fn naming_the_inbox_namespace_still_reaches_your_own_mail_3348() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mut mail = mem_in("_messages/ai:carol", "ai:bob", None);
        mail.metadata[crate::META_KEY_TARGET_AGENT_ID] = json!("ai:carol");
        db::insert(&conn, &mail).expect("ins mail");

        let out = handle_search(
            &conn,
            &json!({"query": "needle", "namespace": "_messages/ai:carol"}),
            Some("ai:carol"),
        )
        .expect("ok");
        assert_eq!(
            out["count"].as_u64(),
            Some(1),
            "#3348: naming the namespace is the opt-in — the recipient reading \
             their OWN inbox must still work"
        );

        let denied = handle_search(
            &conn,
            &json!({"query": "needle", "namespace": "_messages/ai:carol"}),
            Some("ai:dave"),
        )
        .expect("ok");
        assert_eq!(
            denied["count"].as_u64(),
            Some(0),
            "#3348: the opt-in lifts the AMBIENT exclusion only — the canonical \
             owner/inbox predicate still confines the row to its addressee"
        );
    }

    /// #1468 — the empty-query + `source_uri` early-return branch
    /// (`db::list_by_source_uri`) MUST apply the same caller-scoped
    /// `scope=private` filter as the main keyword path; without it the
    /// reciprocal "everything from this document" query would leak a
    /// cross-agent private row.
    #[test]
    fn source_uri_only_branch_excludes_cross_agent_private() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
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
