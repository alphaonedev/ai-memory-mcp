// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_rule_list` handler (issue #691).
//!
//! Read-only listing of the substrate's `governance_rules` table.
//! Accepts an optional `kind` filter and an optional `enabled_only`
//! flag; default returns every row sorted by id ASC.
//!
//! # MCP mutation is disabled
//!
//! Per issue #691 design revision 2026-05-13, MCP stdio cannot
//! mutate rules. Use the CLI (`ai-memory rules add --sign`) or the
//! HTTP admin endpoints (`POST /api/v1/governance/rules` with the
//! `X-AI-Memory-Operator-Signature` header).

use base64::Engine;
use serde_json::{Value, json};

use crate::governance::rules_store::{self, Rule};

/// Handler for `memory_rule_list`. Accepts:
///
/// ```json
/// {
///   "kind": "filesystem_write" (optional),
///   "enabled_only": true (optional, defaults to false)
/// }
/// ```
///
/// Returns:
///
/// ```json
/// {
///   "count": <n>,
///   "rules": [ { id, kind, matcher, severity, reason, ... }, ... ]
/// }
/// ```
pub fn handle_rule_list(conn: &rusqlite::Connection, arguments: &Value) -> Result<Value, String> {
    let kind_filter = arguments.get("kind").and_then(Value::as_str);
    let enabled_only = arguments
        .get("enabled_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // v0.7.0 #1041 (Agent-6 #4) — `enabled_only=true` previously
    // post-filtered the `list(conn)` result with `r.enabled` only.
    // That contract lied to the operator: with an operator pubkey
    // resolved, the enforcement engine silently drops every row
    // whose `attest_level != "operator_signed"` (via
    // `enforced_rule_passes`), but the MCP `memory_rule_list` tool
    // reported those rows as enabled regardless. An operator
    // diffing "what does memory_rule_list say is enabled" against
    // "what does the engine actually enforce" would see a
    // mismatch.
    //
    // Post-#1041 the `enabled_only=true` filter additionally
    // consults `enforced_rule_passes` so the response only carries
    // rows the engine would actually enforce. The pubkey lookup is
    // O(1) (`resolve_operator_pubkey` reads a process-wide
    // `OnceLock`) so the perf cost is negligible.
    let operator_pubkey = rules_store::resolve_operator_pubkey();
    let rules: Vec<Rule> = if let Some(kind) = kind_filter {
        if enabled_only {
            rules_store::list_enabled_by_kind(conn, kind)
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|r| rules_store::enforced_rule_passes(r, operator_pubkey.as_ref()))
                .collect()
        } else {
            // No "list_by_kind" helper today — we filter in-memory
            // from `list` to keep the store surface small. The
            // governance_rules table is operator-scale (typical
            // deployment <100 rows) so the scan is fine.
            rules_store::list(conn)
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|r| r.kind == kind)
                .collect()
        }
    } else if enabled_only {
        rules_store::list(conn)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|r| r.enabled && rules_store::enforced_rule_passes(r, operator_pubkey.as_ref()))
            .collect()
    } else {
        rules_store::list(conn).map_err(|e| e.to_string())?
    };

    let mut out = Vec::with_capacity(rules.len());
    for r in &rules {
        let sig_b64 = r
            .signature
            .as_ref()
            .map(|b| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b));
        out.push(json!({
            "id": r.id,
            "kind": r.kind,
            "matcher": r.matcher,
            "severity": r.severity,
            "reason": r.reason,
            "namespace": r.namespace,
            "created_by": r.created_by,
            "created_at": r.created_at,
            "enabled": r.enabled,
            "signature_b64": sig_b64,
            "attest_level": r.attest_level,
        }));
    }
    Ok(json!({
        "count": out.len(),
        "rules": out,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_rule_list ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_rule_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct RuleListRequest {
    /// Restrict to one AgentAction kind.
    #[serde(default)]
    pub kind: Option<String>,

    /// Skip disabled rules. Default false.
    #[serde(default)]
    pub enabled_only: Option<bool>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_rule_list`.
#[allow(dead_code)]
pub struct RuleListTool;

impl McpTool for RuleListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_RULE_LIST
    }
    fn description() -> &'static str {
        "List substrate-level agent-action rules. Read-only (#691)."
    }
    fn docs() -> &'static str {
        "#691: governance_rules read. Mutation operator-only (CLI/HTTP signed); MCP read-only by design 2026-05-13."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(RuleListRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_rule_list`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn rule_list_parity_986() {
        let derived = derived_props_for::<RuleListRequest>();
        assert_property_set_parity("memory_rule_list", &derived);
        assert_descriptions_match("memory_rule_list", &derived);
    }

    #[test]
    fn rule_list_tool_metadata_986() {
        assert_eq!(RuleListTool::name(), "memory_rule_list");
        assert_eq!(RuleListTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE governance_rules (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 matcher TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 namespace TEXT NOT NULL DEFAULT '_global',
                 created_by TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned'
             );",
        )
        .unwrap();
        conn
    }

    fn insert(conn: &rusqlite::Connection, id: &str, kind: &str, enabled: bool) {
        rules_store::insert(
            conn,
            &Rule {
                id: id.into(),
                kind: kind.into(),
                matcher: r#"{"k":"v"}"#.into(),
                severity: "refuse".into(),
                reason: "r".into(),
                namespace: "_global".into(),
                created_by: "test".into(),
                created_at: 0,
                enabled,
                signature: None,
                attest_level: "unsigned".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn empty_returns_zero() {
        let conn = fresh_conn();
        let r = handle_rule_list(&conn, &json!({})).unwrap();
        assert_eq!(r["count"], 0);
    }

    #[test]
    fn lists_all_rules_by_default() {
        let conn = fresh_conn();
        insert(&conn, "R1", "bash", true);
        insert(&conn, "R2", "filesystem_write", false);
        let r = handle_rule_list(&conn, &json!({})).unwrap();
        assert_eq!(r["count"], 2);
    }

    #[test]
    fn filters_by_kind() {
        let conn = fresh_conn();
        insert(&conn, "R1", "bash", true);
        insert(&conn, "R2", "filesystem_write", true);
        let r = handle_rule_list(&conn, &json!({"kind":"bash"})).unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["rules"][0]["id"], "R1");
    }

    #[test]
    fn enabled_only_skips_disabled() {
        // v0.7.0 #1041 — `enabled_only=true` now also drops rows
        // the engine's `enforced_rule_passes` would skip (unsigned
        // when pubkey resolved). Suppress pubkey resolution so the
        // unsigned R1 fixture surfaces regardless of dev-host
        // state.
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let conn = fresh_conn();
        insert(&conn, "R1", "bash", true);
        insert(&conn, "R2", "bash", false);
        let r = handle_rule_list(&conn, &json!({"enabled_only":true})).unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["rules"][0]["id"], "R1");
    }

    #[test]
    fn enabled_only_drops_unsigned_when_pubkey_resolved_1041() {
        // v0.7.0 #1041 (Agent-6 #4) — when an operator pubkey is
        // resolved, the engine's `enforced_rule_passes` drops every
        // row whose `attest_level != "operator_signed"`. Pre-#1041
        // the MCP `memory_rule_list` tool reported those rows as
        // enabled regardless — an operator UI lie. Post-#1041 the
        // `enabled_only=true` branch consults `enforced_rule_passes`
        // and returns the same set the engine would actually enforce.
        //
        // We install a deterministic test pubkey, insert one unsigned-
        // enabled row, and assert the response excludes it.
        use base64::Engine;
        use ed25519_dalek::SigningKey;

        // Lock the process-wide env state for the duration of the
        // test so a sibling test can't race the env var.
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _g = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        // SAFETY: serialised via ENV_LOCK above.
        unsafe { std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", &pubkey_b64) };

        let conn = fresh_conn();
        insert(&conn, "R-unsigned", "bash", true);
        let r = handle_rule_list(&conn, &json!({"enabled_only": true})).unwrap();
        let count = r["count"].as_i64().unwrap();

        // SAFETY: serialised via ENV_LOCK above.
        unsafe { std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY") };

        assert_eq!(
            count, 0,
            "#1041: enabled_only=true MUST drop unsigned-enabled rows when pubkey resolved; \
             pre-#1041 would report count=1 (operator UI lie)"
        );
    }

    #[test]
    fn kind_and_enabled_only_combined() {
        // Issue #819 — handle_rule_list internally uses
        // list_enabled_by_kind which filters by operator pubkey signature.
        // Suppress pubkey resolution so the unsigned R1/R3 fixtures
        // surface regardless of dev-host / CI-runner state.
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let conn = fresh_conn();
        insert(&conn, "R1", "bash", true);
        insert(&conn, "R2", "bash", false);
        insert(&conn, "R3", "filesystem_write", true);
        let r = handle_rule_list(&conn, &json!({"kind":"bash","enabled_only":true})).unwrap();
        assert_eq!(r["count"], 1);
        assert_eq!(r["rules"][0]["id"], "R1");
    }
}
