// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_get` handler.

use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_get` (core family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct GetRequest {
    /// Memory ID.
    pub id: String,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_get`.
#[allow(dead_code)]
pub struct GetTool;

impl McpTool for GetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_GET
    }
    fn description() -> &'static str {
        "Get a specific memory by ID, including its links."
    }
    fn docs() -> &'static str {
        "Memory row + linked ids (in+out). Use memory_get_links for full link rows with attestation."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(GetRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "core"
    }
}

/// Existence-hiding error returned both when the id resolves to no row and
/// when the resolved row is not visible to the caller. Reusing one constant
/// for both arms keeps the wire response byte-identical so `memory_get` cannot
/// be used as a presence oracle for another tenant's `scope=private` rows
/// (#1553 — matches the HTTP GET /memories/{id} 404-mask, `memories.rs`).
pub(super) const NOT_FOUND_MSG: &str = "memory not found";

pub(super) fn handle_get(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"].as_str().ok_or("id is required")?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    match db::resolve_id(conn, id).map_err(|e| e.to_string())? {
        Some(mem) => {
            // #1553 — scope=private visibility gate, parity with the sibling
            // read tools (recall/list/search) and the HTTP GET-by-id path. A
            // resolved-but-not-visible row is masked as not-found rather than
            // 403'd so existence is not disclosed. `caller == None` is the
            // single-tenant trust-all posture and is preserved unchanged.
            if let Some(c) = caller {
                if !crate::visibility::is_visible_to_caller(&mem, c) {
                    return Err(NOT_FOUND_MSG.into());
                }
            }
            let links = db::get_links(conn, &mem.id).unwrap_or_default();
            // Flatten: merge memory fields with links at top level (#96)
            let mut val = serde_json::to_value(&mem).map_err(|e| e.to_string())?;
            if let Some(obj) = val.as_object_mut() {
                obj.insert("links".to_string(), json!(links));
            }
            Ok(val)
        }
        None => Err(NOT_FOUND_MSG.into()),
    }
}

#[cfg(test)]
mod tests {
    //! L0.7-3 Tier B chunk-A — coverage tests for `handle_get`.
    //!
    //! Six-category template (playbook §4):
    //! A. happy path (full id) + flattened `links`
    //! B. input validation errors (missing / empty / invalid id)
    //! D. state-dependent error (id not found)
    //! E. idempotency (twice = same)
    //! plus prefix-resolution branch + link flattening when links exist.

    use super::*;
    use crate::models::{Memory, Tier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "test".to_string(),
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
            metadata: json!({"agent_id": "ai:test"}),
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

    // A. happy path
    #[test]
    fn returns_memory_with_links_flattened() {
        let conn = fresh_conn();
        let mem = make_mem("hello");
        let id = db::insert(&conn, &mem).expect("insert");
        let out = handle_get(&conn, &json!({"id": id}), None).expect("ok");
        assert_eq!(out["title"].as_str(), Some("hello"));
        assert!(out["links"].is_array(), "links must be flattened in");
        assert_eq!(out["links"].as_array().unwrap().len(), 0);
    }

    // A. happy path with non-empty links
    #[test]
    fn returns_memory_with_populated_links() {
        let conn = fresh_conn();
        let a = make_mem("a");
        let b = make_mem("b");
        let a_id = db::insert(&conn, &a).expect("ins a");
        let b_id = db::insert(&conn, &b).expect("ins b");
        db::create_link(&conn, &a_id, &b_id, "related_to").expect("link");
        let out = handle_get(&conn, &json!({"id": a_id}), None).expect("ok");
        let links = out["links"].as_array().expect("links arr");
        assert_eq!(links.len(), 1);
    }

    // Prefix-resolution branch (resolve_id falls through to get_by_prefix)
    #[test]
    fn resolves_by_8char_prefix() {
        let conn = fresh_conn();
        let mut mem = make_mem("prefixed");
        mem.id = "01234567-aaaa-bbbb-cccc-ddddeeeeffff".to_string();
        let _ = db::insert(&conn, &mem).expect("insert");
        let out = handle_get(&conn, &json!({"id": "01234567"}), None).expect("prefix resolve");
        assert_eq!(out["id"].as_str(), Some(mem.id.as_str()));
    }

    // B. input validation — missing id
    #[test]
    fn missing_id_returns_error() {
        let conn = fresh_conn();
        let err = handle_get(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("id is required"), "got: {err}");
    }

    // B. input validation — invalid id format
    #[test]
    fn invalid_id_format_returns_error() {
        let conn = fresh_conn();
        // bad chars (space, control) → validate_id rejects
        let err = handle_get(&conn, &json!({"id": " "}), None).unwrap_err();
        assert!(!err.is_empty(), "validation error expected, got empty");
    }

    // D. state-dependent error — id valid but row absent
    #[test]
    fn unknown_id_returns_not_found() {
        let conn = fresh_conn();
        let err = handle_get(
            &conn,
            &json!({"id": "11111111-2222-3333-4444-555555555555"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    // E. idempotency — calling twice yields the same answer
    #[test]
    fn idempotent_repeated_calls() {
        let conn = fresh_conn();
        let mem = make_mem("idem");
        let id = db::insert(&conn, &mem).expect("insert");
        let one = handle_get(&conn, &json!({"id": &id}), None).expect("ok 1");
        let two = handle_get(&conn, &json!({"id": &id}), None).expect("ok 2");
        assert_eq!(one["id"], two["id"]);
        assert_eq!(one["title"], two["title"]);
    }

    // #1553 — scope=private visibility gate (multi-tenant caller posture).
    fn make_private_mem_owned_by(owner: &str, title: &str) -> Memory {
        let mut m = make_mem(title);
        m.metadata = json!({"agent_id": owner, "scope": "private"});
        m
    }

    #[test]
    fn caller_cannot_get_other_agents_private_row() {
        let conn = fresh_conn();
        let alice = make_private_mem_owned_by("alice", "alice-secret");
        let id = db::insert(&conn, &alice).expect("insert");
        // Bob (a different resolved caller) is masked with the not-found error.
        let err = handle_get(&conn, &json!({"id": id}), Some("bob")).unwrap_err();
        assert_eq!(err, NOT_FOUND_MSG, "must 404-mask, not 403 / not leak");
    }

    #[test]
    fn caller_cannot_get_other_agents_private_row_by_prefix() {
        let conn = fresh_conn();
        let mut alice = make_private_mem_owned_by("alice", "alice-secret");
        alice.id = "0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff".to_string();
        db::insert(&conn, &alice).expect("insert");
        let err = handle_get(&conn, &json!({"id": "0a1b2c3d"}), Some("bob")).unwrap_err();
        assert_eq!(err, NOT_FOUND_MSG, "prefix path must mask too");
    }

    #[test]
    fn owner_can_get_their_own_private_row() {
        let conn = fresh_conn();
        let alice = make_private_mem_owned_by("alice", "alice-secret");
        let id = db::insert(&conn, &alice).expect("insert");
        let out = handle_get(&conn, &json!({"id": id}), Some("alice")).expect("owner reads own");
        assert_eq!(out["title"].as_str(), Some("alice-secret"));
    }

    #[test]
    fn none_caller_is_trust_all_unchanged() {
        let conn = fresh_conn();
        let alice = make_private_mem_owned_by("alice", "alice-secret");
        let id = db::insert(&conn, &alice).expect("insert");
        // Single-tenant (env unset → None) preserves the legacy trust-all read.
        let out = handle_get(&conn, &json!({"id": id}), None).expect("trust-all read");
        assert_eq!(out["title"].as_str(), Some("alice-secret"));
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_get`.
    //! Reuses the allowed-diffs catalog documented in d1_2_983_tests.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_get_parity_985() {
        let derived = derived_props_for::<GetRequest>();
        assert_property_set_parity("memory_get", &derived);
        assert_descriptions_match("memory_get", &derived);
    }

    #[test]
    fn memory_get_tool_metadata_985() {
        assert_eq!(GetTool::name(), "memory_get");
        assert_eq!(GetTool::family(), "core");
    }
}
