// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_notify` and `memory_inbox` handlers.

use crate::mcp::param_names;
use crate::models::ConfidenceSource;
use crate::models::{Memory, Tier};
use crate::{db, validate};
use serde_json::{Value, json};
pub fn handle_notify(
    conn: &rusqlite::Connection,
    params: &Value,
    resolved_ttl: &crate::config::ResolvedTtl,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let target = params["target_agent_id"]
        .as_str()
        .ok_or("target_agent_id is required")?;
    let title = params["title"].as_str().ok_or("title is required")?;
    let payload = params["payload"].as_str().ok_or("payload is required")?;
    // B4 (R2-LOW) — clamp instead of panic on out-of-range JSON; the
    // `.clamp(1, 10)` below enforces the semantic priority range, but
    // an i64 like `9_999_999_999` would have aborted the stdio MCP
    // server before the clamp ran.
    let priority = i32::try_from(params["priority"].as_i64().unwrap_or(5))
        .unwrap_or(i32::MAX)
        .clamp(1, 10);
    let tier_str = params["tier"].as_str().unwrap_or(Tier::Mid.as_str());
    let tier = Tier::from_str(tier_str).ok_or(format!("invalid tier: {tier_str}"))?;

    validate::validate_agent_id(target).map_err(|e| e.to_string())?;
    validate::validate_title(title).map_err(|e| e.to_string())?;
    validate::validate_content(payload).map_err(|e| e.to_string())?;

    let sender = crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;
    let namespace = super::agent::messages_namespace_for(target);

    let now = chrono::Utc::now();
    let expires_at = resolved_ttl
        .ttl_for_tier(&tier)
        .map(|s| (now + chrono::Duration::seconds(s)).to_rfc3339());

    let metadata = json!({
        "agent_id": sender.clone(),
        "recipient_agent_id": target,
        "message_kind": "notify",
    });

    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: namespace.clone(),
        title: title.to_string(),
        content: payload.to_string(),
        tags: vec!["_message".to_string()],
        priority,
        confidence: 1.0,
        source: "notify".to_string(),
        access_count: 0,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        last_accessed_at: None,
        expires_at,
        metadata,
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    let actual_id = db::insert(conn, &mem).map_err(|e| e.to_string())?;

    Ok(json!({
        "id": actual_id,
        "from": sender,
        "to": target,
        "namespace": namespace,
        "tier": mem.tier,
        "delivered_at": mem.created_at,
    }))
}

pub fn handle_inbox(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
    caller: Option<&str>,
) -> Result<Value, String> {
    // Caller identity is the default inbox owner — agents read their own
    // inbox unless an explicit agent_id is supplied.
    let explicit = params["agent_id"].as_str();
    // #1557 — in the multi-tenant posture (a resolved visibility caller is
    // present), the inbox owner is BOUND to the caller: a caller may only read
    // its own inbox. An explicit `agent_id` that disagrees is refused — parity
    // with the HTTP `get_inbox` 403, since inbox rows are scope=private
    // agent-to-agent messages. Without this bind, `resolve_agent_id` returns
    // the caller-supplied value verbatim, letting any caller read any agent's
    // private inbox. `caller == None` is the single-tenant trust-all posture and
    // preserves the legacy self-or-explicit resolution unchanged.
    let owner = match caller {
        Some(c) => {
            if let Some(requested) = explicit {
                if requested != c {
                    return Err(format!(
                        "agent_id mismatch: caller '{c}' may only read its own inbox"
                    ));
                }
            }
            c.to_string()
        }
        None => {
            crate::identity::resolve_agent_id(explicit, mcp_client).map_err(|e| e.to_string())?
        }
    };
    let unread_only = params["unread_only"].as_bool().unwrap_or(false);
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(50))
        .unwrap_or(usize::MAX)
        .min(500);
    let namespace = super::agent::messages_namespace_for(&owner);
    let items = db::list(
        conn,
        Some(&namespace),
        None,
        limit,
        0,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|e| e.to_string())?;
    let filtered: Vec<&Memory> = items
        .iter()
        .filter(|m| !unread_only || m.access_count == 0)
        .collect();
    let messages: Vec<Value> = filtered
        .iter()
        .map(|m| {
            let sender = m
                .metadata
                .get(param_names::AGENT_ID)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            json!({
                "id": m.id,
                "from": sender,
                "title": m.title,
                "payload": m.content,
                "priority": m.priority,
                "tier": m.tier,
                "created_at": m.created_at,
                "read": m.access_count > 0,
                "access_count": m.access_count,
            })
        })
        .collect();
    Ok(json!({
        "agent_id": owner,
        "namespace": namespace,
        "count": messages.len(),
        "unread_only": unread_only,
        "messages": messages,
    }))
}

// --- D1.5 (#986): per-tool McpTool impls for the 2 other-family notify tools ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_notify`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct NotifyRequest {
    /// Recipient agent_id.
    pub target_agent_id: String,

    /// Subject (<=200 chars).
    pub title: String,

    /// Body.
    pub payload: String,

    /// Default 5; clamped 1..=10.
    #[serde(default)]
    pub priority: Option<i64>,

    /// short=6h, mid=7d, long=no expiry.
    #[serde(default)]
    pub tier: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_notify`.
#[allow(dead_code)]
pub struct NotifyTool;

impl McpTool for NotifyTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_NOTIFY
    }
    fn description() -> &'static str {
        "Send a message from the caller to another agent's inbox."
    }
    fn docs() -> &'static str {
        "Send message to _messages/<target>. Sender = caller agent_id. Read via memory_inbox."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<NotifyRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_inbox`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct InboxRequest {
    /// Recipient; default caller.
    #[serde(default)]
    pub agent_id: Option<String>,

    /// access_count==0 only.
    #[serde(default)]
    pub unread_only: Option<bool>,

    /// Default 50, cap 500.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_inbox`.
#[allow(dead_code)]
pub struct InboxTool;

impl McpTool for InboxTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_INBOX
    }
    fn description() -> &'static str {
        "List messages sent to an agent via memory_notify."
    }
    fn docs() -> &'static str {
        "Read _messages/<agent_id>. access_count==0 is the unread marker."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<InboxRequest>()
    }
    fn family() -> &'static str {
        // Note: `memory_inbox` lives in `Family::Power` per
        // `src/profile.rs::Family::for_tool`, not the `other` family.
        // The legacy registry tags it Power. See D1.6 (#987) for the
        // collapse — the per-tool family() tag here is the new
        // source-of-truth.
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_notify` (Family::Other)
    //! and `memory_inbox` (Family::Power) — both handlers live in
    //! `src/mcp/tools/notify.rs` so the per-tool parity tests sit here
    //! together. Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn notify_parity_986() {
        let derived = derived_props_for::<NotifyRequest>();
        assert_property_set_parity("memory_notify", &derived);
        assert_descriptions_match("memory_notify", &derived);
    }

    #[test]
    fn notify_tool_metadata_986() {
        assert_eq!(NotifyTool::name(), "memory_notify");
        assert_eq!(NotifyTool::family(), "other");
    }

    #[test]
    fn inbox_parity_986() {
        let derived = derived_props_for::<InboxRequest>();
        assert_property_set_parity("memory_inbox", &derived);
        assert_descriptions_match("memory_inbox", &derived);
    }

    #[test]
    fn inbox_tool_metadata_986() {
        assert_eq!(InboxTool::name(), "memory_inbox");
        assert_eq!(InboxTool::family(), "power");
    }

    /// #1557 — seed one message into `owner`'s inbox namespace, sent by
    /// `sender`, so the owner-bind on `handle_inbox` can be exercised.
    fn seed_inbox_message(conn: &rusqlite::Connection, owner: &str, sender: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: super::super::agent::messages_namespace_for(owner),
            title: format!("msg from {sender}"),
            content: format!("private payload for {owner}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": sender, "scope": "private"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        };
        db::insert(conn, &mem).unwrap()
    }

    #[test]
    fn inbox_caller_cannot_read_other_agents_inbox_1557() {
        let (owner, attacker, sender) = ("alice", "bob", "carol");
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, owner, sender);
        // Attacker (resolved caller) explicitly asks for the owner's inbox →
        // refused, never returning the owner's private messages.
        let err =
            handle_inbox(&conn, &json!({"agent_id": owner}), None, Some(attacker)).unwrap_err();
        assert!(err.contains("may only read its own inbox"), "got: {err}");
    }

    #[test]
    fn inbox_caller_reads_own_inbox_1557() {
        let (owner, sender) = ("alice", "carol");
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, owner, sender);
        // Owner caller, explicit matching agent_id → sees the message.
        let explicit = handle_inbox(&conn, &json!({"agent_id": owner}), None, Some(owner)).unwrap();
        assert_eq!(explicit["count"].as_u64(), Some(1));
        assert_eq!(explicit["messages"][0]["from"].as_str(), Some(sender));
        // Owner caller, agent_id omitted → defaults to the caller's own inbox.
        let implied = handle_inbox(&conn, &json!({}), None, Some(owner)).unwrap();
        assert_eq!(implied["agent_id"].as_str(), Some(owner));
        assert_eq!(implied["count"].as_u64(), Some(1));
    }

    #[test]
    fn inbox_none_caller_is_trust_all_unchanged_1557() {
        let (owner, sender) = ("alice", "carol");
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, owner, sender);
        // Single-tenant trust-all (no resolved caller) preserves the legacy
        // self-or-explicit behavior — an explicit agent_id is honored.
        let resp = handle_inbox(&conn, &json!({"agent_id": owner}), None, None).unwrap();
        assert_eq!(
            resp["count"].as_u64(),
            Some(1),
            "None == trust-all (legacy)"
        );
    }
}

// --- v0.6.0.0 webhook subscriptions ---------------------------------------
