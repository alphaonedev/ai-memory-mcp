// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_list` handler.

use crate::mcp::registry::McpTool;
use crate::models::Tier;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_list` (core family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ListRequest {
    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,

    /// Exact metadata.agent_id filter.
    #[serde(default)]
    pub agent_id: Option<String>,

    /// #1834 claim-bitemporal as-of: RFC3339 point in valid-time. Returns only
    /// claims asserted to hold at this instant (valid_from/valid_until window).
    #[serde(default)]
    pub valid_at: Option<String>,

    /// Response format: `toon_compact` (DEFAULT — ~79% smaller), `toon`,
    /// or `json`. #3171 — the default was undocumented, so a caller that
    /// omitted this got TOON where it expected JSON.
    #[serde(default)]
    pub format: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_list`.
#[allow(dead_code)]
pub struct ListTool;

impl McpTool for ListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_LIST
    }
    fn description() -> &'static str {
        "List memories, optionally filtered by namespace or tier."
    }
    fn docs() -> &'static str {
        "Browse memories. Filters: namespace, tier, agent_id, valid_at. Limit caps at 200. \
         #3171: the default response format is `toon_compact`, NOT json — pass \
         format=\"json\" for a JSON envelope."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Core.name()
    }
}

/// v0.7.0 #1468 — `db::list` applies NO visibility filter (it is a pure
/// namespace/tier/agent_id query), so a cross-agent `scope=private` row
/// would otherwise leak onto the MCP wire. When `caller` is `Some` (the
/// MCP dispatch resolved a stable `AI_MEMORY_AGENT_ID` identity via
/// [`crate::identity::resolve_read_visibility_caller`]) we drop every row
/// the caller does not own per the canonical
/// [`crate::visibility::is_visible_to_caller`] predicate. `None`
/// (single-tenant / no env identity) preserves the trust-all behavior.
pub(super) fn handle_list(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    // #3040 — honor the same list/bulk page-size cap (`AI_MEMORY_MAX_PAGE_SIZE`,
    // env #52) the HTTP surface applies via `AppState.max_page_size`. The MCP
    // stdio loop carries no `AppState`, so the resolved cap is mirrored into a
    // process-global seeded at boot; consult it here so `memory_list` can never
    // return more rows than the operator's OOM guard permits. Unseeded
    // raw-library reads yield the compiled `MAX_BULK_SIZE`, so the historical
    // 200-row default is unchanged.
    handle_list_capped(conn, params, caller, crate::max_page_size())
}

/// #3040 — inner list handler with the operator's page-size cap threaded in
/// explicitly, so the cap plumbing is unit-testable without mutating the
/// process-global `MAX_PAGE_SIZE` (which concurrent list tests read).
fn handle_list_capped(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
    page_cap: usize,
) -> Result<Value, String> {
    let namespace = params["namespace"].as_str();
    // v0.8.0 PE-2 (#1730) — read-action governance gate (zero-config
    // fast-path when no read_action rules exist).
    {
        let actor = caller
            .or_else(|| params["agent_id"].as_str())
            .unwrap_or_default();
        crate::governance::agent_action::gate_read_surface(conn, actor, "list", namespace, None)
            .map_err(|r| {
                crate::governance::deny_message(
                    "list",
                    crate::governance::DenyGate::Governance,
                    &r.reason,
                )
            })?;
    }
    // v1.0.0 #3130 — FAIL CLOSED on an unrecognised `tier` (was
    // `.and_then(Tier::from_str)`, which listed EVERY tier as if the
    // caller had asked for it).
    let tier = Tier::parse_optional(params["tier"].as_str())?;
    // Ultrareview #339: saturate instead of panic (see handle_search).
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(20)).unwrap_or(usize::MAX);
    let agent_id = params["agent_id"].as_str();
    if let Some(aid) = agent_id {
        validate::validate_agent_id(aid).map_err(|e| e.to_string())?;
    }
    // v1.0.0 #1834 — claim-bitemporal AS-OF; RFC3339-validate at this entry
    // surface so a malformed value is a clear error, not a silent lexicographic
    // mis-filter.
    let valid_at = params["valid_at"].as_str();
    if let Some(v) = valid_at {
        validate::validate_valid_at(v).map_err(|e| e.to_string())?;
    }

    // #3040 — cap the page size at the SMALLER of the historical MCP 200-row
    // ceiling and the operator-resolved `max_page_size`, so MCP never exceeds
    // the OOM guard (and never loosens its own tighter default when the cap is
    // larger than 200).
    let effective_limit = limit.min(200).min(page_cap);
    let results = db::list(
        conn,
        namespace,
        tier.as_ref(),
        effective_limit,
        0,
        None,
        None,
        None,
        None,
        agent_id,
        valid_at,
    )
    .map_err(|e| e.to_string())?;
    let results = match caller {
        Some(c) => results
            .into_iter()
            .filter(|m| crate::visibility::is_visible_to_caller(m, c))
            .collect::<Vec<_>>(),
        None => results,
    };
    Ok(json!({"memories": results, "count": results.len()}))
}

#[cfg(test)]
mod tests {
    //! L0.7-3 Tier B chunk-A — coverage tests for `handle_list`.
    //!
    //! Six-category template subset relevant to a read-only list:
    //! A. happy path — empty + populated, optional filters
    //! B. validation — bad agent_id, invalid tier (silently ignored), limit overflow
    //! E. idempotency

    use super::*;
    use crate::models::{Memory, Tier as MTier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str, ns: &str, tier: MTier, agent: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("content for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": agent}),
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

    // A. happy path — empty db
    #[test]
    fn empty_db_returns_empty_list() {
        let conn = fresh_conn();
        let out = handle_list(&conn, &json!({}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(0));
        assert!(out["memories"].as_array().unwrap().is_empty());
    }

    // A. happy path — populated, default args
    #[test]
    fn returns_all_memories_with_default_limit() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "test", MTier::Mid, "ai:a")).expect("ins");
        db::insert(&conn, &make_mem("b", "test", MTier::Mid, "ai:b")).expect("ins");
        let out = handle_list(&conn, &json!({}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    // A. happy path — namespace filter
    #[test]
    fn filters_by_namespace() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns1", MTier::Mid, "ai:a")).expect("ins");
        db::insert(&conn, &make_mem("b", "ns2", MTier::Mid, "ai:b")).expect("ins");
        let out = handle_list(&conn, &json!({"namespace": "ns1"}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
    }

    // A. tier filter exercises the Tier::parse_optional branch
    #[test]
    fn filters_by_tier() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Short, "ai:a")).expect("ins");
        db::insert(&conn, &make_mem("b", "ns", MTier::Long, "ai:b")).expect("ins");
        let out = handle_list(&conn, &json!({"tier": MTier::Long.as_str()}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
    }

    // B. validation — v1.0.0 #3130: an unrecognised tier is REFUSED, not
    // silently dropped. Pre-fix this asserted `count == 2` (every row
    // listed as if the caller had asked for no tier filter at all).
    #[test]
    fn unknown_tier_is_refused_not_unfiltered_3130() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Short, "ai:a")).expect("ins");
        db::insert(&conn, &make_mem("b", "ns", MTier::Long, "ai:b")).expect("ins");
        let err = handle_list(&conn, &json!({"tier": "nonsense"}), None)
            .expect_err("an unrecognised tier must be refused");
        assert!(err.contains("invalid tier"), "got: {err}");
        assert!(
            err.contains(MTier::VALUES_HINT),
            "must name the valid tiers: {err}"
        );
    }

    // An ABSENT tier stays genuinely unconstrained — the distinction the
    // `.and_then(Tier::from_str)` shape collapsed (#3130).
    #[test]
    fn absent_tier_still_lists_every_tier_3130() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Short, "ai:a")).expect("ins");
        db::insert(&conn, &make_mem("b", "ns", MTier::Long, "ai:b")).expect("ins");
        let out = handle_list(&conn, &json!({}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    // A. agent_id filter (validated path)
    #[test]
    fn filters_by_agent_id() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Mid, "ai:alice")).expect("ins");
        db::insert(&conn, &make_mem("b", "ns", MTier::Mid, "ai:bob")).expect("ins");
        let out = handle_list(&conn, &json!({"agent_id": "ai:alice"}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
    }

    // B. validation — bad agent_id format
    #[test]
    fn invalid_agent_id_rejected() {
        let conn = fresh_conn();
        let err = handle_list(&conn, &json!({"agent_id": "has space"}), None).unwrap_err();
        assert!(!err.is_empty(), "expected validation err, got {err}");
    }

    // limit overflow (saturating u64 → usize::MAX clamps to 200 cap)
    #[test]
    fn limit_overflow_saturates_and_caps() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Mid, "ai:a")).expect("ins");
        let out = handle_list(&conn, &json!({"limit": u64::MAX}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(1));
    }

    // #3040 — the operator's `max_page_size` cap bounds the MCP list page, so
    // `memory_list` never returns more rows than the OOM guard HTTP applies.
    #[test]
    fn page_size_cap_bounds_mcp_list_3040() {
        let conn = fresh_conn();
        for i in 0..3 {
            db::insert(&conn, &make_mem(&format!("m{i}"), "ns", MTier::Mid, "ai:a")).expect("ins");
        }
        // Large caller limit + a small operator cap (2) → the page is bounded.
        let capped = handle_list_capped(&conn, &json!({"limit": 1000}), None, 2).expect("ok");
        assert_eq!(
            capped["count"].as_u64(),
            Some(2),
            "max_page_size=2 must cap the MCP list page: {capped}"
        );
        // A cap larger than the historical MCP 200-row ceiling never LOOSENS it
        // (all 3 rows are under both bounds, so all 3 return).
        let generous = handle_list_capped(&conn, &json!({"limit": 1000}), None, 5000).expect("ok");
        assert_eq!(generous["count"].as_u64(), Some(3));
    }

    // E. idempotency
    #[test]
    fn idempotent_listing() {
        let conn = fresh_conn();
        db::insert(&conn, &make_mem("a", "ns", MTier::Mid, "ai:a")).expect("ins");
        let one = handle_list(&conn, &json!({"namespace": "ns"}), None).expect("ok");
        let two = handle_list(&conn, &json!({"namespace": "ns"}), None).expect("ok");
        assert_eq!(one["count"], two["count"]);
    }

    // --- v0.7.0 #1468 — caller-scoped visibility post-filter ----------------

    /// Build a `scope=private` row owned by `agent` (the make_mem default
    /// already omits scope, which `is_visible_to_caller` reads as private).
    fn private_mem(title: &str, ns: &str, agent: &str) -> Memory {
        make_mem(title, ns, MTier::Mid, agent)
    }

    /// Build a `scope=collective` row (visible to any caller).
    fn shared_mem(title: &str, ns: &str, agent: &str) -> Memory {
        use crate::models::namespace::MemoryScope;
        let mut m = make_mem(title, ns, MTier::Mid, agent);
        m.metadata = json!({
            crate::META_KEY_AGENT_ID: agent,
            crate::META_KEY_SCOPE: MemoryScope::Collective.as_str(),
        });
        m
    }

    // #1468 — caller=None preserves trust-all (single-tenant) read.
    #[test]
    fn caller_none_lists_all_including_cross_agent_private() {
        let conn = fresh_conn();
        db::insert(&conn, &private_mem("p", "ns", "ai:alice")).expect("ins");
        db::insert(&conn, &shared_mem("s", "ns", "ai:bob")).expect("ins");
        let out = handle_list(&conn, &json!({"namespace": "ns"}), None).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }

    // #1468 — a non-owner caller never sees another agent's private row,
    // but still sees shared rows.
    #[test]
    fn caller_non_owner_excludes_cross_agent_private() {
        let conn = fresh_conn();
        db::insert(&conn, &private_mem("p", "ns", "ai:alice")).expect("ins");
        db::insert(&conn, &shared_mem("s", "ns", "ai:bob")).expect("ins");
        let out = handle_list(&conn, &json!({"namespace": "ns"}), Some("ai:carol")).expect("ok");
        assert_eq!(
            out["count"].as_u64(),
            Some(1),
            "only the shared row is visible"
        );
        assert_eq!(out["memories"][0]["title"], "s");
    }

    // #1468 — the owning caller sees its OWN private row plus shared rows.
    #[test]
    fn caller_owner_sees_own_private_and_shared() {
        let conn = fresh_conn();
        db::insert(&conn, &private_mem("p", "ns", "ai:alice")).expect("ins");
        db::insert(&conn, &shared_mem("s", "ns", "ai:bob")).expect("ins");
        let out = handle_list(&conn, &json!({"namespace": "ns"}), Some("ai:alice")).expect("ok");
        assert_eq!(out["count"].as_u64(), Some(2));
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_list`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_list_parity_985() {
        let derived = derived_props_for::<ListRequest>();
        assert_property_set_parity("memory_list", &derived);
        assert_descriptions_match("memory_list", &derived);
    }

    #[test]
    fn memory_list_tool_metadata_985() {
        assert_eq!(ListTool::name(), "memory_list");
        assert_eq!(ListTool::family(), "core");
    }
}
