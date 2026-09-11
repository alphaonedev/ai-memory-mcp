// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L2-3 (issue #668) — MCP
//! `memory_dependents_of_invalidated` handler.
//!
//! Returns the list of memories whose `reflects_on` edge points at a
//! given reflection — i.e. the dependents that were (or would be)
//! flagged by the L2-3 invalidation-propagation walker if/when that
//! reflection is superseded.
//!
//! Pure read-only — does not mutate the DB or trigger the walker. The
//! walker is invoked exclusively by `mcp::tools::link::handle_link`
//! when a Reflection→Reflection `supersedes` edge lands.

use serde_json::{Value, json};

/// MCP `memory_dependents_of_invalidated` handler.
///
/// Wire shape:
///
/// ```json
/// {
///   "memory_id": "<reflection-id>",
///   "count": 3,
///   "dependents": [
///     {"id": "...", "namespace": "team/alpha"},
///     {"id": "...", "namespace": "team/alpha"},
///     {"id": "...", "namespace": "team/beta"}
///   ]
/// }
/// ```
///
/// Errors:
/// * `memory_id is required` — caller omitted the parameter.
/// * `memory_id cannot be empty`.
/// * substrate errors are bubbled up verbatim.
pub fn handle_dependents_of_invalidated(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let memory_id = params["memory_id"]
        .as_str()
        .ok_or(crate::errors::msg::MEMORY_ID_REQUIRED)?;
    if memory_id.is_empty() {
        return Err(crate::errors::msg::MEMORY_ID_EMPTY.to_string());
    }
    let dependents =
        crate::notification::invalidation::list_dependents_of_invalidated(conn, memory_id)
            .map_err(|e| format!("dependents_of_invalidated substrate error: {e}"))?;
    // v1.0.0 #3599 — the dependent list (and the transitive suspect set
    // below) is an existence + namespace oracle over rows the caller may not
    // read. Filter every rendered row through the per-row scope predicate,
    // naming the row's OWN namespace (the #3549 read-funnel contract); `count`
    // / `transitive_count` reflect the VISIBLE set. An unfetchable row is
    // HIDDEN (fail closed, the #3232 disposition).
    //
    // The gate reads the row UNFILTERED (`get_any`, the #3270 authz-read
    // rule) and is therefore lifecycle-NEUTRAL: it decides ownership/scope
    // over the row that exists and never changes WHICH lifecycle states this
    // tool discloses. That matters here more than anywhere — the `supersedes`
    // path (#3324) auto-stamps every downstream dependent `contaminated`
    // BEFORE the curator asks this tool for the review queue, and
    // `contaminated` is outside the recall-visible set, so a gate built on
    // the filtered `get` hid exactly the rows the tool exists to list
    // (`tests/notification/invalidation_test.rs` caught it).
    let row_readable = |id: &str| -> bool {
        match crate::db::get_any(conn, id) {
            Ok(Some(mem)) => {
                crate::visibility::is_readable_on_query(&mem, caller, Some(mem.namespace.as_str()))
            }
            Ok(None) | Err(_) => false,
        }
    };
    let rendered: Vec<Value> = dependents
        .iter()
        .filter(|d| row_readable(&d.id))
        .map(|d| {
            json!({
                "id": d.id,
                "namespace": d.namespace,
            })
        })
        .collect();
    let mut out = json!({
        "memory_id": memory_id,
        "count": rendered.len(),
        "dependents": rendered,
    });

    // v1.0.0 R55 (#1959) — opt-in TRANSITIVE suspect set. The legacy
    // `dependents` list above is the DIRECT inbound `reflects_on` hop only;
    // when `transitive` is requested, additionally walk the FULL provenance
    // DAG (P = derived_from/reflects_on/derives_from) DOWNSTREAM so a suspect
    // source taints every record derived from it, transitively. Lazy /
    // computed (cycle-safe, depth-bounded) — the direct default stays
    // byte-identical.
    if params["transitive"].as_bool().unwrap_or(false) {
        let suspects =
            crate::db::transitive_suspects(conn, memory_id, crate::db::LINEAGE_MAX_DEPTH)
                .map_err(|e| format!("transitive_suspects substrate error: {e}"))?;
        let rendered_suspects: Vec<Value> = suspects
            .iter()
            .filter(|n| row_readable(&n.id))
            .map(|n| {
                json!({
                    "id": n.id,
                    "cid": n.cid,
                    "relation": n.relation,
                    "depth": n.depth,
                })
            })
            .collect();
        if let Value::Object(map) = &mut out {
            map.insert(
                "transitive_count".to_string(),
                json!(rendered_suspects.len()),
            );
            map.insert(
                "transitive_suspects".to_string(),
                Value::Array(rendered_suspects),
            );
        }
    }

    Ok(out)
}

// --- D1.5 (#986): per-tool McpTool impl for memory_dependents_of_invalidated ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for
/// `memory_dependents_of_invalidated`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct DependentsOfInvalidatedRequest {
    /// Invalidated reflection id.
    pub memory_id: String,

    /// v1.0.0 R55 (#1959) — when true, also return `transitive_suspects`:
    /// every record derived (transitively) from `memory_id` over the
    /// provenance DAG (derived_from/reflects_on/derives_from). Default false
    /// (direct reflects_on dependents only).
    #[serde(default)]
    pub transitive: bool,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for
/// `memory_dependents_of_invalidated`.
#[allow(dead_code)]
pub struct DependentsOfInvalidatedTool;

impl McpTool for DependentsOfInvalidatedTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_DEPENDENTS_OF_INVALIDATED
    }
    fn description() -> &'static str {
        "List dependents flagged by the L2-3 invalidation walker."
    }
    fn docs() -> &'static str {
        "L2-3 (#668): read-only list of memories with reflects_on->memory_id. Notification, NOT cascade — dependents are flagged for curator review. Returns {memory_id, count, dependents:[{id, namespace}]}. Unknown ids => empty."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<DependentsOfInvalidatedRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_dependents_of_invalidated`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn dependents_of_invalidated_parity_986() {
        let derived = derived_props_for::<DependentsOfInvalidatedRequest>();
        assert_property_set_parity("memory_dependents_of_invalidated", &derived);
        assert_descriptions_match("memory_dependents_of_invalidated", &derived);
    }

    #[test]
    fn dependents_of_invalidated_tool_metadata_986() {
        assert_eq!(
            DependentsOfInvalidatedTool::name(),
            "memory_dependents_of_invalidated"
        );
        assert_eq!(DependentsOfInvalidatedTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str, namespace: &str, kind: MemoryKind) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: namespace.to_string(),
            title: title.to_string(),
            content: format!("body {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:tester"}),
            reflection_depth: if matches!(kind, MemoryKind::Reflection) {
                1
            } else {
                0
            },
            memory_kind: kind,
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

    #[test]
    fn missing_memory_id_returns_error() {
        let conn = fresh_conn();
        let err = handle_dependents_of_invalidated(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("memory_id"));
    }

    #[test]
    fn empty_memory_id_returns_error() {
        let conn = fresh_conn();
        let err =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": ""}), None).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn unknown_id_returns_empty_envelope() {
        let conn = fresh_conn();
        let out = handle_dependents_of_invalidated(&conn, &json!({"memory_id": "nope-id"}), None)
            .unwrap();
        assert_eq!(out["count"].as_u64(), Some(0));
        assert_eq!(out["dependents"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn returns_only_inbound_reflects_on_edges() {
        let _lineage = crate::test_support::no_lineage_dag_guard();
        let conn = fresh_conn();
        let r1 = make_mem("R1", "ns-a", MemoryKind::Reflection);
        let m1 = make_mem("M1", "ns-a", MemoryKind::Observation);
        let m2 = make_mem("M2", "ns-b", MemoryKind::Observation);
        let m3 = make_mem("M3", "ns-a", MemoryKind::Observation);
        let r1_id = db::insert(&conn, &r1).unwrap();
        let m1_id = db::insert(&conn, &m1).unwrap();
        let m2_id = db::insert(&conn, &m2).unwrap();
        let m3_id = db::insert(&conn, &m3).unwrap();
        db::create_link(&conn, &m1_id, &r1_id, "reflects_on").unwrap();
        db::create_link(&conn, &m2_id, &r1_id, "reflects_on").unwrap();
        db::create_link(&conn, &m3_id, &r1_id, "related_to").unwrap();

        let out =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), None).unwrap();
        assert_eq!(out["count"].as_u64(), Some(2));
        let deps = out["dependents"].as_array().unwrap();
        let ids: Vec<&str> = deps.iter().filter_map(|d| d["id"].as_str()).collect();
        assert!(ids.contains(&m1_id.as_str()));
        assert!(ids.contains(&m2_id.as_str()));
        assert!(!ids.contains(&m3_id.as_str()), "related_to leaked");
    }
}

#[cfg(test)]
mod authority_gate_3599_tests {
    //! v1.0.0 #3599 — DENIED / ALLOWED matrix for the
    //! `memory_dependents_of_invalidated` read gate: another owner's private
    //! dependents are dropped (and not counted); the owner sees them.
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn mem(title: &str, kind: MemoryKind, owner: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "ns-a".to_string(),
            title: title.to_string(),
            content: format!("body {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": owner, "scope": "private"}),
            reflection_depth: i32::from(matches!(kind, MemoryKind::Reflection)),
            memory_kind: kind,
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

    /// Anchor R1 with two `reflects_on` dependents: alice's private M1 and
    /// bob's private M2. Returns `(r1_id, m1_id, m2_id)`.
    fn seed(conn: &rusqlite::Connection) -> (String, String, String) {
        let r1_id = db::insert(conn, &mem("R1", MemoryKind::Reflection, "ai:tester")).unwrap();
        let m1_id = db::insert(conn, &mem("M1", MemoryKind::Observation, "ai:alice")).unwrap();
        let m2_id = db::insert(conn, &mem("M2", MemoryKind::Observation, "ai:bob")).unwrap();
        db::create_link(conn, &m1_id, &r1_id, "reflects_on").unwrap();
        db::create_link(conn, &m2_id, &r1_id, "reflects_on").unwrap();
        (r1_id, m1_id, m2_id)
    }

    fn ids(out: &Value) -> Vec<String> {
        out["dependents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn foreign_owner_private_dependents_are_dropped_and_not_counted_3599() {
        let _lineage = crate::test_support::no_lineage_dag_guard();
        let conn = fresh_conn();
        let (r1_id, _m1_id, m2_id) = seed(&conn);
        let out =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), Some("ai:bob"))
                .unwrap();
        assert_eq!(
            out["count"].as_u64(),
            Some(1),
            "only bob's own row counts: {out}"
        );
        assert_eq!(
            ids(&out),
            vec![m2_id],
            "alice's private M1 must not be listed"
        );
    }

    #[test]
    fn owner_sees_their_dependent_and_local_operator_sees_all_3599() {
        let _lineage = crate::test_support::no_lineage_dag_guard();
        let conn = fresh_conn();
        let (r1_id, m1_id, _m2_id) = seed(&conn);
        let own =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), Some("ai:alice"))
                .unwrap();
        assert_eq!(ids(&own), vec![m1_id]);
        let all =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), None).unwrap();
        assert_eq!(
            all["count"].as_u64(),
            Some(2),
            "None caller is trust-all: {all}"
        );
    }

    /// The #3324 `supersedes` path stamps dependents `contaminated` before the
    /// curator lists them. The gate is lifecycle-NEUTRAL: a contaminated
    /// dependent stays listed for its owner and the local operator (the
    /// pre-#3599 disclosure), and is still dropped for a foreign caller.
    #[test]
    fn contaminated_dependent_stays_listed_for_owner_and_operator_3599() {
        let _lineage = crate::test_support::no_lineage_dag_guard();
        let conn = fresh_conn();
        let (r1_id, m1_id, m2_id) = seed(&conn);
        conn.execute(
            "UPDATE memories SET lifecycle_state = 'contaminated' WHERE id = ?1",
            rusqlite::params![m1_id],
        )
        .unwrap();
        assert!(
            db::get(&conn, &m1_id).unwrap().is_none(),
            "precondition: the filtered read hides a contaminated row"
        );
        let all =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), None).unwrap();
        assert_eq!(
            all["count"].as_u64(),
            Some(2),
            "operator still sees the contaminated dependent: {all}"
        );
        let own =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), Some("ai:alice"))
                .unwrap();
        assert_eq!(ids(&own), vec![m1_id], "owner keeps their contaminated row");
        let bob =
            handle_dependents_of_invalidated(&conn, &json!({"memory_id": r1_id}), Some("ai:bob"))
                .unwrap();
        assert_eq!(ids(&bob), vec![m2_id], "foreign private row still dropped");
    }
}
