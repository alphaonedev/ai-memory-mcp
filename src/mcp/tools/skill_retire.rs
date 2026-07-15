// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_retire` handler (#2024 — operator-authorized skill
//! lifecycle).
//!
//! Reversible SOFT-retire: sets (or clears) a `retired` flag in the EXISTING
//! `skills.metadata` JSON column, hiding a registered skill from
//! `memory_skill_list` discovery WITHOUT deleting the row or its audit
//! history. `retired: false` un-retires. NO schema migration — skills are
//! sqlite-only and `metadata` already exists (the #1865 `parameters_schema`
//! precedent stores into the same column).
//!
//! Hard-delete / purge is a deliberate follow-up: a destructive, irreversible
//! removal drags in a governance/auth design that does not belong in a
//! reversible-first surface, so this tool NEVER removes a row.

use rusqlite::{Connection, params};
use serde_json::{Value, json};

/// The `skills.metadata` JSON key carrying the reversible retire flag.
const RETIRED_KEY: &str = "retired";

/// MCP `memory_skill_retire` substrate handler.
///
/// Promoted to `pub` so a future CLI `ai-memory skill retire` / HTTP route can
/// dispatch into the same implementation (parity follow-up).
///
/// # Errors
/// Returns a typed error when the skill id is missing / unknown, or when the
/// metadata read / update SQL fails.
pub fn handle_skill_retire(conn: &Connection, args: &Value) -> Result<Value, String> {
    let skill_id = args["skill_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("memory_skill_retire requires 'skill_id'")?;
    // Default to retiring; `retired: false` un-retires (reversible).
    let retire = args[RETIRED_KEY].as_bool().unwrap_or(true);

    // Read the row's current namespace/name/metadata (also the existence gate).
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT namespace, name, metadata FROM skills WHERE id = ?1",
            [skill_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let Some((namespace, name, metadata_str)) = row else {
        return Err(crate::errors::msg::skill_not_found(skill_id));
    };

    // Read-modify-write the metadata JSON object: set/clear `retired`.
    let mut meta: Value = serde_json::from_str(&metadata_str).unwrap_or_else(|_| json!({}));
    if !meta.is_object() {
        meta = json!({});
    }
    if let Some(obj) = meta.as_object_mut() {
        if retire {
            obj.insert(RETIRED_KEY.to_string(), json!(true));
        } else {
            obj.remove(RETIRED_KEY);
        }
    }
    let new_metadata = meta.to_string();

    // #913-style state-change audit: capture the lifecycle intent BEFORE the
    // write so the forensic chain records it regardless of storage outcome
    // (mirrors `skill_register`).
    let caller = crate::identity::resolve_agent_id(args["agent_id"].as_str(), None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "skill_retire",
        "",
        json!({ "namespace": namespace, "name": name, RETIRED_KEY: retire }),
    );

    conn.execute(
        "UPDATE skills SET metadata = ?2 WHERE id = ?1",
        params![skill_id, new_metadata],
    )
    .map_err(|e| format!("skill_retire update: {e}"))?;

    Ok(json!({
        "id": skill_id,
        "namespace": namespace,
        "name": name,
        RETIRED_KEY: retire,
    }))
}

// --- #2024: per-tool McpTool impl for memory_skill_retire ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// #2024 — request body for `memory_skill_retire`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillRetireRequest {
    /// ID of the skill to retire (or un-retire).
    pub skill_id: String,

    /// `true` (default) retires the skill (hidden from `memory_skill_list`
    /// discovery); `false` un-retires it. Reversible either way.
    #[serde(default)]
    pub retired: Option<bool>,
}

/// #2024 — `McpTool` impl for `memory_skill_retire`.
#[allow(dead_code)]
pub struct SkillRetireTool;

impl McpTool for SkillRetireTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_RETIRE
    }
    fn description() -> &'static str {
        "Retire (hide from discovery) or un-retire a registered skill by id."
    }
    fn docs() -> &'static str {
        "#2024: reversible soft-retire via a skills.metadata `retired` flag; the skill row + its audit history are preserved. `retired:false` un-retires. Hard-delete/purge is a separate operation."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillRetireRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! Schema parity for `memory_skill_retire` (mirrors the sibling skill
    //! tools' `d1_5_986_tests`). Shared helpers live at
    //! [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_retire_parity() {
        let derived = derived_props_for::<SkillRetireRequest>();
        assert_property_set_parity("memory_skill_retire", &derived);
        assert_descriptions_match("memory_skill_retire", &derived);
    }

    #[test]
    fn skill_retire_tool_metadata() {
        assert_eq!(SkillRetireTool::name(), "memory_skill_retire");
        assert_eq!(SkillRetireTool::family(), "other");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_db() -> Connection {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        std::mem::forget(dir);
        conn
    }

    fn insert_skill(conn: &Connection, id: &str, ns: &str, name: &str) {
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, ?2, ?3, 'd', '{}', ?4, ?5, 0)",
            params![id, ns, name, body_blob, digest],
        )
        .unwrap();
    }

    fn metadata_of(conn: &Connection, id: &str) -> Value {
        let s: String = conn
            .query_row("SELECT metadata FROM skills WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn retire_sets_metadata_flag() {
        let conn = open_db();
        insert_skill(&conn, "s1", "ns", "old-compat");
        let out = handle_skill_retire(&conn, &json!({"skill_id": "s1"})).unwrap();
        assert_eq!(out["retired"], json!(true));
        assert_eq!(out["id"], json!("s1"));
        assert_eq!(metadata_of(&conn, "s1")["retired"], json!(true));
    }

    #[test]
    fn retired_skill_hidden_from_list() {
        let conn = open_db();
        insert_skill(&conn, "s1", "ns", "old-compat");
        insert_skill(&conn, "s2", "ns", "live");
        handle_skill_retire(&conn, &json!({"skill_id": "s1"})).unwrap();
        let listed = crate::mcp::skill_list::handle_skill_list(&conn, &json!({})).unwrap();
        assert_eq!(listed["count"], json!(1));
        assert_eq!(listed["skills"][0]["id"], json!("s2"));
    }

    #[test]
    fn unretire_restores_discovery() {
        let conn = open_db();
        insert_skill(&conn, "s1", "ns", "old-compat");
        handle_skill_retire(&conn, &json!({"skill_id": "s1"})).unwrap();
        // Reverse it.
        let out = handle_skill_retire(&conn, &json!({"skill_id": "s1", "retired": false})).unwrap();
        assert_eq!(out["retired"], json!(false));
        assert!(metadata_of(&conn, "s1").get("retired").is_none());
        let listed = crate::mcp::skill_list::handle_skill_list(&conn, &json!({})).unwrap();
        assert_eq!(listed["count"], json!(1));
    }

    #[test]
    fn retire_preserves_other_metadata_keys() {
        let conn = open_db();
        insert_skill(&conn, "s1", "ns", "x");
        conn.execute(
            "UPDATE skills SET metadata = '{\"author\":\"alice\"}' WHERE id = 's1'",
            [],
        )
        .unwrap();
        handle_skill_retire(&conn, &json!({"skill_id": "s1"})).unwrap();
        let m = metadata_of(&conn, "s1");
        assert_eq!(m["retired"], json!(true));
        assert_eq!(
            m["author"],
            json!("alice"),
            "retire must not clobber siblings"
        );
    }

    #[test]
    fn unknown_skill_id_errors() {
        let conn = open_db();
        let err = handle_skill_retire(&conn, &json!({"skill_id": "nope"})).unwrap_err();
        assert!(
            err.contains("nope") || err.to_lowercase().contains("skill"),
            "got: {err}"
        );
    }

    #[test]
    fn missing_skill_id_errors() {
        let conn = open_db();
        let err = handle_skill_retire(&conn, &json!({})).unwrap_err();
        assert!(err.contains("skill_id"), "got: {err}");
    }
}
