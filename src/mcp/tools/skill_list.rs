// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_list` handler (L1-5 Agent Skills substrate).
//!
//! Returns the **discovery payload** for all current (non-superseded)
//! skills in a given namespace. Each entry carries ~100 tokens of
//! metadata (name, description, id, namespace, created_at, digest_hex)
//! but does NOT return the body. #8832 / #8834: every entry is loaded
//! through the verified read path, so a skill the caller may not read, or
//! whose digest or signature does not verify, is omitted from discovery.

use crate::models::field_names;
use rusqlite::Connection;
use serde_json::{Value, json};

/// #8834 (code LOW 2 / security L2) — the most rows one `memory_skill_list`
/// call reads and verifies. The namespace and text filters run in SQL first,
/// so only the rows of this page pay the verify cost (digest, resource
/// digests, bounded body decode). A response that reached the page limit
/// carries `truncated: true`; the caller narrows with `namespace` / `filter`.
pub const SKILL_LIST_PAGE_LIMIT: usize = 1000;

/// MCP `memory_skill_list` substrate handler.
///
/// Promoted to `pub` for v0.7.0 Cluster E API-2 (issue #767) so the
/// CLI `ai-memory skill list` subcommand and the HTTP
/// `GET /api/v1/skill/list` route can dispatch into the same
/// implementation without duplicating SQL.
///
/// #8832 — `read_caller` is the resolved read principal (MCP:
/// `Authority::read_caller`; CLI: the process identity). `None` is the
/// single-operator / admin-gated posture and reads every skill.
///
/// # Errors
/// Returns the substrate's error string when SQL prepare/query fails, or
/// when the store fails while a row is verified (#8834: a store failure is a
/// refusal, never an empty or partial list).
pub fn handle_skill_list(
    conn: &Connection,
    params: &Value,
    read_caller: Option<&str>,
) -> Result<Value, String> {
    use super::skill_integrity::SkillLoadError;
    let namespace = params["namespace"].as_str().unwrap_or("%");
    let filter = params["filter"].as_str().unwrap_or("");
    // #2024 — discovery HIDES retired skills by default. `include_retired`
    // drops the retired predicate so operators can enumerate retired
    // lineages (each such entry carries `retired: true` + its stamp).
    let include_retired = params[field_names::INCLUDE_RETIRED]
        .as_bool()
        .unwrap_or(false);
    let retired_predicate = if include_retired {
        ""
    } else {
        " AND retired_at IS NULL"
    };

    // Only return current (non-superseded) skills; retired rows are
    // hidden unless `include_retired` is set (the predicate above). The
    // text filter is the case-sensitive substring match on name or
    // description (`instr`), applied here so unmatched rows are never
    // verified; one row past the page limit detects truncation.
    let fetch = SKILL_LIST_PAGE_LIMIT.saturating_add(1);
    let sql = format!(
        "SELECT id FROM skills \
         WHERE superseded_by IS NULL \
           AND (namespace = ?1 OR ?1 = '%'){retired_predicate} \
           AND (?2 = '' OR instr(name, ?2) > 0 OR instr(description, ?2) > 0) \
         ORDER BY namespace, name, created_at DESC \
         LIMIT {fetch}"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("skill_list prepare", e))?;
    let mut ids = stmt
        .query_map([namespace, filter], |row| row.get::<_, String>(0))
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("skill_list query", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("skill_list row", e))?;
    let truncated = ids.len() > SKILL_LIST_PAGE_LIMIT;
    ids.truncate(SKILL_LIST_PAGE_LIMIT);

    let mut skills: Vec<Value> = Vec::with_capacity(ids.len());
    for id in ids {
        let skill = match super::skill_integrity::load_verified_skill(conn, &id, read_caller) {
            Ok(skill) => skill,
            // #8832 — a skill the caller may not read is simply not listed.
            Err(SkillLoadError::NotFound(_)) => continue,
            // #8834 — a row that fails verification is never discoverable;
            // the operator sees why in the log, the caller sees nothing.
            Err(SkillLoadError::Integrity(e)) => {
                tracing::warn!(skill_id = %id, error = %e, "memory_skill_list omitted a skill");
                continue;
            }
            // #8834 (code MEDIUM 1) — a store failure is not a verdict on
            // one row: refuse the whole call rather than under-report.
            Err(e @ SkillLoadError::Substrate(_)) => return Err(e.into()),
        };

        let digest_hex: String = skill.digest.iter().map(|b| format!("{b:02x}")).collect();

        let mut entry = json!({
            "id": skill.id,
            "namespace": skill.namespace,
            "name": skill.name,
            (field_names::DESCRIPTION): skill.description,
            "digest": digest_hex,
            (field_names::CREATED_AT): skill.created_at,
        });

        if let Some(lic) = skill.license {
            entry["license"] = json!(lic);
        }
        if let Some(compat) = skill.compatibility {
            entry[field_names::COMPATIBILITY] = json!(compat);
        }
        if let Some(tools) = skill.allowed_tools {
            entry[field_names::ALLOWED_TOOLS] = json!(tools);
        }
        if let Some(agent) = skill.signing_agent {
            entry[field_names::SIGNING_AGENT] = json!(agent);
        }
        // #2024 — surface the retired flag on retired entries (only
        // reachable when `include_retired` was set).
        if let Some(ts) = skill.retired_at {
            entry[field_names::RETIRED] = json!(true);
            entry[field_names::RETIRED_AT] = json!(ts);
        }
        if !skill
            .metadata
            .as_object()
            .is_none_or(serde_json::Map::is_empty)
        {
            entry["metadata"] = skill.metadata;
        }

        skills.push(entry);
    }

    Ok(json!({
        "count": skills.len(),
        "skills": skills,
        (field_names::TRUNCATED): truncated,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_list ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_skill_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillListRequest {
    /// Namespace filter. Omit or '%' = all.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Text filter on name + description.
    #[serde(default)]
    pub filter: Option<String>,

    /// Include RETIRED skills in the listing (#2024). Default `false`
    /// hides retired lineages from discovery; `true` drops the retired
    /// predicate so retired entries appear (each carrying `retired`).
    #[serde(default)]
    pub include_retired: Option<bool>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_skill_list`.
#[allow(dead_code)]
pub struct SkillListTool;

impl McpTool for SkillListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_LIST
    }
    fn description() -> &'static str {
        "List current (non-superseded) skills; body not returned."
    }
    fn docs() -> &'static str {
        "L1-5: discovery (name, description, id, namespace, digest, metadata). Use memory_skill_get for body."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_skill_list`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_list_parity_986() {
        let derived = derived_props_for::<SkillListRequest>();
        assert_property_set_parity("memory_skill_list", &derived);
        assert_descriptions_match("memory_skill_list", &derived);
    }

    #[test]
    fn skill_list_tool_metadata_986() {
        assert_eq!(SkillListTool::name(), "memory_skill_list");
        assert_eq!(SkillListTool::family(), "other");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn open_db() -> rusqlite::Connection {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        std::mem::forget(dir);
        conn
    }

    fn insert_skill(
        conn: &rusqlite::Connection,
        id: &str,
        ns: &str,
        name: &str,
        description: &str,
        created_at: i64,
    ) {
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6, ?7)",
            params![id, ns, name, description, body_blob, digest, created_at],
        )
        .unwrap();
        // #8834 — the verified read path serves only rows whose digest holds.
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
    }

    #[test]
    fn empty_db_returns_empty_list() {
        let conn = open_db();
        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        assert_eq!(v["count"], json!(0));
        assert_eq!(v["skills"], json!([]));
    }

    #[test]
    fn returns_only_current_non_superseded() {
        let conn = open_db();
        insert_skill(&conn, "id-old", "ns", "name", "old", 0);
        insert_skill(&conn, "id-new", "ns", "name", "new", 1);
        conn.execute(
            "UPDATE skills SET superseded_by = 'id-new' WHERE id = 'id-old'",
            [],
        )
        .unwrap();

        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        assert_eq!(v["count"], json!(1));
        let arr = v["skills"].as_array().unwrap();
        assert_eq!(arr[0]["id"], json!("id-new"));
    }

    #[test]
    fn filters_by_namespace() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns-a", "ska", "a", 0);
        insert_skill(&conn, "b", "ns-b", "skb", "b", 1);

        let v = handle_skill_list(&conn, &json!({"namespace": "ns-a"}), None).unwrap();
        assert_eq!(v["count"], json!(1));
        assert_eq!(v["skills"][0]["namespace"], json!("ns-a"));
    }

    #[test]
    fn wildcard_namespace_returns_all() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns-a", "ska", "a", 0);
        insert_skill(&conn, "b", "ns-b", "skb", "b", 1);

        let v = handle_skill_list(&conn, &json!({"namespace": "%"}), None).unwrap();
        assert_eq!(v["count"], json!(2));
    }

    #[test]
    fn no_namespace_defaults_to_wildcard() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns-a", "ska", "a", 0);
        insert_skill(&conn, "b", "ns-b", "skb", "b", 1);

        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        assert_eq!(v["count"], json!(2));
    }

    #[test]
    fn filter_matches_name() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns", "deploy-canary", "k8s canary deploy", 0);
        insert_skill(&conn, "b", "ns", "audit-logs", "fetch audit logs", 1);

        let v = handle_skill_list(&conn, &json!({"filter": "canary"}), None).unwrap();
        assert_eq!(v["count"], json!(1));
        assert_eq!(v["skills"][0]["id"], json!("a"));
    }

    #[test]
    fn filter_matches_description() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns", "x", "kubernetes deploy notes", 0);
        insert_skill(&conn, "b", "ns", "y", "totally different", 1);

        let v = handle_skill_list(&conn, &json!({"filter": "kubernetes"}), None).unwrap();
        assert_eq!(v["count"], json!(1));
    }

    #[test]
    fn filter_no_match_returns_empty() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns", "x", "k8s", 0);

        let v = handle_skill_list(&conn, &json!({"filter": "no-such-text"}), None).unwrap();
        assert_eq!(v["count"], json!(0));
    }

    #[test]
    fn includes_optional_columns_when_present() {
        let conn = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0xab_u8; 32];
        let allowed_tools = serde_json::to_string(&vec!["tool1"]).unwrap();
        let metadata = serde_json::json!({"author": "alice"}).to_string();
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, license, compatibility, \
                                  allowed_tools, metadata, body_blob, digest, \
                                  created_at) \
             VALUES ('id1', 'ns', 'name', 'd', 'MIT', 'v1', ?1, ?2, ?3, ?4, 0)",
            params![allowed_tools, metadata, body_blob, digest],
        )
        .unwrap();
        crate::mcp::reseal_skill_digest_for_tests(&conn, "id1").expect("reseal");

        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        let entry = &v["skills"][0];
        assert_eq!(entry["license"], json!("MIT"));
        assert_eq!(entry["compatibility"], json!("v1"));
        // #8834: an unsigned row never lists a signer.
        assert!(entry.get("signing_agent").is_none(), "{entry}");
        assert_eq!(entry["allowed_tools"], json!(["tool1"]));
        assert_eq!(entry["metadata"]["author"], json!("alice"));
        // digest is hex.
        let dig = entry["digest"].as_str().unwrap();
        assert_eq!(dig.len(), 64);
    }

    #[test]
    fn omits_empty_metadata_object() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns", "x", "d", 0);
        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        let entry = &v["skills"][0];
        // metadata `{}` is omitted from the response.
        assert!(entry.get("metadata").is_none());
    }

    #[test]
    fn omits_a_row_with_malformed_allowed_tools_json_8834() {
        let conn = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, allowed_tools, metadata, \
                                  body_blob, digest, created_at) \
             VALUES ('id1', 'ns', 'x', 'd', 'not-json', '{}', ?1, ?2, 0)",
            params![body_blob, digest],
        )
        .unwrap();
        let v = handle_skill_list(&conn, &json!({}), None).unwrap();
        // #8834 — `allowed_tools` is on the digest surface: a column that
        // does not parse is a tampered row, never listed.
        assert_eq!(v["count"], json!(0));
    }

    #[test]
    fn empty_filter_string_is_no_filter() {
        let conn = open_db();
        insert_skill(&conn, "a", "ns", "x", "d", 0);
        insert_skill(&conn, "b", "ns", "y", "e", 1);
        let v = handle_skill_list(&conn, &json!({"filter": ""}), None).unwrap();
        assert_eq!(v["count"], json!(2));
    }
}
