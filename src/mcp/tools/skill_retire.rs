// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_retire` handler (#2024 — operator-authorized skill
//! retire/unretire lifecycle).
//!
//! RETIRE hides a skill lineage from discovery (`memory_skill_list`) and
//! BLOCKS re-registration onto it (`register_core` refuses inside its
//! `BEGIN IMMEDIATE` tx), while keeping the rows addressable by id
//! (activation-by-id stays allowed, consistent with the
//! superseded-stays-addressable contract — the flag is surfaced, not a
//! hard block). UNRETIRE reverses it. Both are fully reversible; the
//! hard-delete / purge half of a lifecycle is deliberately DEFERRED
//! (out of scope for #2024).
//!
//! Default target is the whole `(namespace, name)` LINEAGE — every row
//! in the version chain is stamped so `memory_skill_get` is truthful for
//! superseded versions too. An optional single-version target by
//! `skill_id` retires just that row. Re-retiring an already-retired
//! target is idempotent: it succeeds with `affected = 0`, never an
//! error.
//!
//! Authz: this is the operator-as-actor path (NO admin gate, matching
//! `handle_skill_register`); the HTTP surface (`skill_retire_route`)
//! layers `require_admin` on top. Every mutation runs inside one
//! `BEGIN IMMEDIATE` transaction; a daemon-signed `signed_events` row
//! (`skill.retired` / `skill.unretired`) is appended in the same tx, and
//! a forensic `record_decision` row is emitted before the mutation.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::identity::keypair::AgentKeypair;
use crate::models::field_names;
use crate::signed_events::{SignedEvent, append_signed_event_no_tx, event_types, payload_hash};

// ---------------------------------------------------------------------------
// Shared by-id retire surfacing helper
// ---------------------------------------------------------------------------

/// #2024 — set the `retired` flag (plus `retired_at` / `retired_by` /
/// `retire_reason` when the row is retired) on a by-id skill response, so
/// every by-id read surface (`memory_skill_get`, `_export`,
/// `_compositional_context`) can honor a retirement. Best-effort: a
/// missing row or SQL hiccup leaves `response` unchanged.
pub(crate) fn apply_retired_fields(conn: &Connection, skill_id: &str, response: &mut Value) {
    let row: Option<(Option<i64>, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT retired_at, retired_by, retire_reason FROM skills WHERE id = ?1",
            [skill_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    if let Some((retired_at, retired_by, retire_reason)) = row {
        response[field_names::RETIRED] = json!(retired_at.is_some());
        if let Some(ts) = retired_at {
            response[field_names::RETIRED_AT] = json!(ts);
            if let Some(by) = retired_by {
                response[field_names::RETIRED_BY] = json!(by);
            }
            if let Some(reason) = retire_reason {
                response[field_names::RETIRE_REASON] = json!(reason);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// MCP `memory_skill_retire` substrate handler.
///
/// `active_keypair` is accepted for surface-symmetry with the other
/// skill write handlers; the audit row is DAEMON-signed (the
/// governance-toggle lane, like `governance.rule_disabled`) via the
/// process-wide audit key, not the caller keypair.
///
/// # Errors
/// Returns a substrate error string when neither `skill_id` nor a
/// `(namespace, name)` pair is supplied, or a `skill_id` names no row.
pub fn handle_skill_retire(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let _ = active_keypair;

    let unretire = params["unretire"].as_bool().unwrap_or(false);
    let reason = params["reason"].as_str().filter(|s| !s.is_empty());
    let caller = crate::identity::resolve_agent_id(params["agent_id"].as_str(), None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());

    // Resolve the target: a single version by `skill_id`, else the whole
    // (namespace, name) lineage.
    let skill_id = params["skill_id"].as_str().filter(|s| !s.is_empty());
    let (namespace, name, single_id): (String, String, Option<String>) = if let Some(id) = skill_id
    {
        let found: Option<(String, String)> = conn
            .query_row(
                "SELECT namespace, name FROM skills WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let Some((ns, nm)) = found else {
            return Err(crate::errors::msg::skill_not_found(id));
        };
        (ns, nm, Some(id.to_string()))
    } else {
        let ns = params["namespace"].as_str().filter(|s| !s.is_empty());
        let nm = params["name"].as_str().filter(|s| !s.is_empty());
        match (ns, nm) {
            (Some(ns), Some(nm)) => (ns.to_string(), nm.to_string(), None),
            _ => {
                return Err("memory_skill_retire requires either 'skill_id' or both \
                            'namespace' and 'name'"
                    .to_string());
            }
        }
    };

    let action = if unretire { "unretire" } else { "retire" };

    // Forensic decision row BEFORE the mutation (mirrors skill_register).
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        if unretire {
            "skill_unretire"
        } else {
            "skill_retire"
        },
        "",
        json!({
            "namespace": namespace,
            "name": name,
            "skill_id": single_id,
            "reason": reason,
        }),
    );

    // All mutations inside ONE BEGIN IMMEDIATE tx (mirrors register_core):
    // the write lock serialises us against a concurrent register/retire so
    // the retire REFUSE in register_core cannot race a silent revive, and
    // the RAII drop of `tx` rolls back on any early `?` return.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| format!("skill retire BEGIN IMMEDIATE: {e}"))?;
    let txn: &Connection = &tx;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Idempotent: the predicate excludes already-in-the-target-state rows,
    // so a re-retire / re-unretire lands `affected = 0` and still succeeds.
    let affected = if unretire {
        if let Some(ref id) = single_id {
            txn.execute(
                "UPDATE skills SET retired_at = NULL, retired_by = NULL, retire_reason = NULL \
                 WHERE id = ?1 AND retired_at IS NOT NULL",
                params![id],
            )
        } else {
            txn.execute(
                "UPDATE skills SET retired_at = NULL, retired_by = NULL, retire_reason = NULL \
                 WHERE namespace = ?1 AND name = ?2 AND retired_at IS NOT NULL",
                params![namespace, name],
            )
        }
    } else if let Some(ref id) = single_id {
        txn.execute(
            "UPDATE skills SET retired_at = ?1, retired_by = ?2, retire_reason = ?3 \
             WHERE id = ?4 AND retired_at IS NULL",
            params![now_secs, caller, reason, id],
        )
    } else {
        txn.execute(
            "UPDATE skills SET retired_at = ?1, retired_by = ?2, retire_reason = ?3 \
             WHERE namespace = ?4 AND name = ?5 AND retired_at IS NULL",
            params![now_secs, caller, reason, namespace, name],
        )
    }
    .map_err(|e| format!("skill retire UPDATE: {e}"))?;

    // Daemon-signed audit event in the SAME tx (governance-toggle lane).
    let event_type = if unretire {
        event_types::SKILL_UNRETIRED
    } else {
        event_types::SKILL_RETIRED
    };
    let event_payload = json!({
        "namespace": namespace,
        "name": name,
        "skill_id": single_id,
        "action": action,
        "affected": affected,
        "retired_by": caller,
    });
    let event_bytes = serde_json::to_vec(&event_payload).unwrap_or_default();
    let event = SignedEvent::with_daemon_signature(
        payload_hash(&event_bytes),
        caller.clone(),
        event_type.to_string(),
        chrono::Utc::now().to_rfc3339(),
        None,
    );
    let _ = append_signed_event_no_tx(txn, &event);

    tx.commit()
        .map_err(|e| format!("skill retire COMMIT: {e}"))?;

    let flag = if unretire {
        field_names::UNRETIRED
    } else {
        field_names::RETIRED
    };
    let mut response = json!({
        flag: true,
        "action": action,
        "namespace": namespace,
        "name": name,
        "affected": affected,
    });
    if let Some(id) = single_id {
        response["skill_id"] = json!(id);
    }
    if !unretire {
        response[field_names::RETIRED_AT] = json!(now_secs);
        response[field_names::RETIRED_BY] = json!(caller);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Hard delete / purge (#2024 — the irreversible, deliberately-explicit op)
// ---------------------------------------------------------------------------

/// MCP `memory_skill_delete` substrate handler — hard-purge an ENTIRE
/// skill lineage.
///
/// Target is always the whole `(namespace, name)` lineage (every version),
/// so NO `superseded_by` pointer is ever left dangling — a partial
/// mid-chain delete is deliberately unsupported. A by-`skill_id` request
/// resolves the id to its `(namespace, name)` and purges the whole
/// lineage.
///
/// SAFETY GATE: purge is irreversible, so it is refused unless the lineage
/// is already RETIRED (`retired_at IS NOT NULL` on every version) OR the
/// request carries `force = true`. The default two-step retire→delete flow
/// makes accidental purge of an active skill impossible.
///
/// AUDIT-SAFE ERASURE: inside one `BEGIN IMMEDIATE` tx a daemon-signed
/// `skill.purged` `signed_events` row (carrying the purged ids + their
/// `digest` hex + namespace/name) is appended BEFORE the `DELETE` — the
/// `signed_events` table has NO FK to `skills`, so the tamper-evident
/// audit record survives the content erasure (the forget-tombstone /
/// cid-genesis-nulled-on-erase pattern). `skill_resources` rows cascade
/// via `ON DELETE CASCADE`.
///
/// `active_keypair` is accepted for surface-symmetry; the audit row is
/// daemon-signed via the process-wide audit key.
///
/// # Errors
/// Returns a substrate error string when no target is supplied, a
/// `skill_id` names no row, the lineage does not exist (`SKILL_NOT_FOUND`),
/// or the lineage is not retired and `force` was not set.
pub fn handle_skill_delete(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let _ = active_keypair;

    let force = params["force"].as_bool().unwrap_or(false);
    let caller = crate::identity::resolve_agent_id(params["agent_id"].as_str(), None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());

    // Resolve the target lineage. A by-id request purges the WHOLE lineage
    // that id belongs to (never a partial-chain delete).
    let skill_id = params["skill_id"].as_str().filter(|s| !s.is_empty());
    let (namespace, name): (String, String) = if let Some(id) = skill_id {
        let found: Option<(String, String)> = conn
            .query_row(
                "SELECT namespace, name FROM skills WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        match found {
            Some(t) => t,
            None => return Err(crate::errors::msg::skill_not_found(id)),
        }
    } else {
        let ns = params["namespace"].as_str().filter(|s| !s.is_empty());
        let nm = params["name"].as_str().filter(|s| !s.is_empty());
        match (ns, nm) {
            (Some(ns), Some(nm)) => (ns.to_string(), nm.to_string()),
            _ => {
                return Err("memory_skill_delete requires either 'skill_id' or both \
                            'namespace' and 'name'"
                    .to_string());
            }
        }
    };

    // Gather the lineage rows (id + digest + retired state) up front.
    let rows: Vec<(String, Vec<u8>, Option<i64>)> = {
        let mut stmt = conn
            .prepare("SELECT id, digest, retired_at FROM skills WHERE namespace = ?1 AND name = ?2")
            .map_err(|e| format!("skill_delete prepare: {e}"))?;
        let out = stmt
            .query_map(params![namespace, name], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|e| format!("skill_delete query: {e}"))?
            .filter_map(Result::ok)
            .collect();
        out
    };

    if rows.is_empty() {
        // Idempotent: unknown lineage → SKILL_NOT_FOUND (404 on HTTP).
        return Err(crate::errors::msg::skill_not_found(&format!(
            "{namespace}/{name}"
        )));
    }

    // SAFETY GATE — require the lineage to be already RETIRED unless forced.
    let all_retired = rows.iter().all(|(_, _, retired_at)| retired_at.is_some());
    if !force && !all_retired {
        return Err(format!(
            "skill lineage '{namespace}/{name}' is not retired; retire it first \
             (memory_skill_retire) or pass force=true to purge an active lineage"
        ));
    }

    let skill_ids: Vec<String> = rows.iter().map(|(id, _, _)| id.clone()).collect();
    let digests: Vec<String> = rows.iter().map(|(_, d, _)| hex::encode(d)).collect();

    // Forensic decision row BEFORE the mutation.
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "skill_delete",
        "",
        json!({
            "namespace": namespace,
            "name": name,
            "skill_ids": skill_ids,
            "force": force,
        }),
    );

    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| format!("skill delete BEGIN IMMEDIATE: {e}"))?;
    let txn: &Connection = &tx;

    // Emit the signed PURGE audit row BEFORE the delete (the row outlives
    // the erased content — signed_events has no FK to skills).
    let event_payload = json!({
        "namespace": namespace,
        "name": name,
        "skill_ids": skill_ids,
        "digests": digests,
        "action": "purge",
        "purged_by": caller,
    });
    let event_bytes = serde_json::to_vec(&event_payload).unwrap_or_default();
    let event = SignedEvent::with_daemon_signature(
        payload_hash(&event_bytes),
        caller.clone(),
        event_types::SKILL_PURGED.to_string(),
        chrono::Utc::now().to_rfc3339(),
        None,
    );
    let _ = append_signed_event_no_tx(txn, &event);

    // Purge the whole lineage; skill_resources cascade via ON DELETE CASCADE.
    let affected = txn
        .execute(
            "DELETE FROM skills WHERE namespace = ?1 AND name = ?2",
            params![namespace, name],
        )
        .map_err(|e| format!("skill_delete DELETE: {e}"))?;

    tx.commit()
        .map_err(|e| format!("skill delete COMMIT: {e}"))?;

    Ok(json!({
        "purged": true,
        "namespace": namespace,
        "name": name,
        "affected": affected,
        "skill_ids": skill_ids,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_retire ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// #2024 — request body for `memory_skill_retire`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillRetireRequest {
    /// Namespace of the lineage to (un)retire. Paired with `name` to
    /// target the whole (namespace, name) version chain. Omit when
    /// targeting a single version by `skill_id`.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Name of the lineage to (un)retire (paired with `namespace`).
    #[serde(default)]
    pub name: Option<String>,

    /// Target a SINGLE version by id instead of the whole lineage.
    #[serde(default)]
    pub skill_id: Option<String>,

    /// Optional free-form reason recorded on the retired rows + audit.
    #[serde(default)]
    pub reason: Option<String>,

    /// `true` = UNRETIRE (clear the retire stamp); `false` (default) =
    /// RETIRE.
    #[serde(default)]
    pub unretire: bool,

    /// Operator/agent id performing the action (operator-as-actor).
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// #2024 — `McpTool` impl for `memory_skill_retire`.
#[allow(dead_code)]
pub struct SkillRetireTool;

impl McpTool for SkillRetireTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_RETIRE
    }
    fn description() -> &'static str {
        "Retire (hide + block re-register) or unretire a skill lineage."
    }
    fn docs() -> &'static str {
        "#2024: reversible RETIRE/UNRETIRE. Default target = whole (namespace,name) lineage; \
         optional single version by skill_id. Idempotent (affected=0). Set unretire=true to reverse."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillRetireRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

/// #2024 — request body for `memory_skill_delete` (hard purge).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillDeleteRequest {
    /// Namespace of the lineage to purge (paired with `name`).
    #[serde(default)]
    pub namespace: Option<String>,

    /// Name of the lineage to purge (paired with `namespace`).
    #[serde(default)]
    pub name: Option<String>,

    /// A skill id whose WHOLE lineage is purged (resolved to its
    /// (namespace, name); never a partial-chain delete).
    #[serde(default)]
    pub skill_id: Option<String>,

    /// `true` bypasses the retire-first safety gate and purges an active
    /// (un-retired) lineage. Default `false` requires the lineage to be
    /// retired first.
    #[serde(default)]
    pub force: bool,

    /// Operator/agent id performing the action (operator-as-actor).
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// #2024 — `McpTool` impl for `memory_skill_delete`.
#[allow(dead_code)]
pub struct SkillDeleteTool;

impl McpTool for SkillDeleteTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_DELETE
    }
    fn description() -> &'static str {
        "Hard-purge an entire skill lineage (irreversible; retire-first gated)."
    }
    fn docs() -> &'static str {
        "#2024: IRREVERSIBLE purge of the whole (namespace,name) lineage (all versions + resources). \
         Refused unless the lineage is already retired OR force=true. Emits a signed skill.purged audit row \
         that survives the erasure. #3171: this MCP entry has NO ADMIN GATE — unlike the HTTP \
         twin (which requires the admin role), any MCP caller may purge any lineage, and \
         force=true also skips the retire-first requirement. Restrict access to the MCP \
         surface itself, or split profiles, if that is not acceptable."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillDeleteRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! #2024 — schema parity for `memory_skill_retire` + `memory_skill_delete`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_retire_parity_986() {
        let derived = derived_props_for::<SkillRetireRequest>();
        assert_property_set_parity("memory_skill_retire", &derived);
        assert_descriptions_match("memory_skill_retire", &derived);
    }

    #[test]
    fn skill_retire_tool_metadata_986() {
        assert_eq!(SkillRetireTool::name(), "memory_skill_retire");
        assert_eq!(SkillRetireTool::family(), "other");
    }

    #[test]
    fn skill_delete_parity_986() {
        let derived = derived_props_for::<SkillDeleteRequest>();
        assert_property_set_parity("memory_skill_delete", &derived);
        assert_descriptions_match("memory_skill_delete", &derived);
    }

    #[test]
    fn skill_delete_tool_metadata_986() {
        assert_eq!(SkillDeleteTool::name(), "memory_skill_delete");
        assert_eq!(SkillDeleteTool::family(), "other");
    }
}
