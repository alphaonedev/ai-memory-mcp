// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_notify` and `memory_inbox` handlers.

use crate::mcp::param_names;
use crate::models::ConfidenceSource;
use crate::models::field_names;
use crate::models::{Memory, Tier};
use crate::{db, validate};
use serde_json::{Value, json};
pub fn handle_notify(
    conn: &rusqlite::Connection,
    params: &Value,
    resolved_ttl: &crate::config::ResolvedTtl,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let target = params[param_names::TARGET_AGENT_ID]
        .as_str()
        .ok_or("target_agent_id is required")?;
    let title = params["title"]
        .as_str()
        .ok_or(crate::errors::msg::TITLE_REQUIRED)?;
    let payload = params["payload"].as_str().ok_or("payload is required")?;
    // B4 (R2-LOW) — clamp instead of panic on out-of-range JSON; an i64 like
    // `9_999_999_999` would have aborted the stdio MCP server before the clamp
    // ran. v1.0.0 batch-2: routed through the shared
    // `crate::models::normalize_priority` SSOT so the MCP, HTTP-sqlite and
    // HTTP-postgres surfaces cannot drift on this normalization (they had).
    // Behaviour is byte-identical to the inline expression this replaces.
    let priority = crate::models::normalize_priority(
        params["priority"]
            .as_i64()
            .unwrap_or(i64::from(crate::models::DEFAULT_PRIORITY)),
    );
    let tier_str = params["tier"].as_str().unwrap_or(Tier::Mid.as_str());
    let tier =
        Tier::from_str(tier_str).ok_or_else(|| crate::errors::msg::invalid("tier", tier_str))?;

    validate::validate_agent_id(target).map_err(|e| e.to_string())?;
    validate::validate_title(title).map_err(|e| e.to_string())?;
    validate::validate_content(payload).map_err(|e| e.to_string())?;

    let sender = crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;
    let namespace = super::agent::messages_namespace_for(target);

    let now = chrono::Utc::now();
    let expires_at = resolved_ttl
        .ttl_for_tier(&tier)
        .map(|s| (now + chrono::Duration::seconds(s)).to_rfc3339());

    let mut metadata = json!({
        "agent_id": sender.clone(),
        "recipient_agent_id": target,
        "message_kind": "notify",
    });
    // #2122 — covenant clause-1 why_trace path for `memory_notify`. The
    // notification `payload` is VERBATIM caller content, so the substrate
    // does NOT stamp its own rationale here (that would re-open the #2121
    // tenant-bypass class on this funnel); the CALLER supplies the
    // rationale via the optional `why_trace` param. Under
    // AI_MEMORY_REQUIRE_WHY_TRACE=1 a why_trace-less notify is refused by
    // the `db::insert` gate; default posture is unchanged (advisory).
    if let Some(wt) = params[param_names::WHY_TRACE].as_str()
        && !wt.trim().is_empty()
    {
        metadata[param_names::WHY_TRACE] = json!(wt);
    }

    let mem = Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from: None,
        valid_until: None,
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
        lifecycle_state: crate::models::LifecycleState::Open,
    };
    // #3358 — notify is a tenant-authored memory write and must consume the
    // sender's quota exactly like `memory_store`. Charge the destination
    // namespace to the authenticated sender (never the recipient), counting
    // one row plus the caller-controlled title/content/metadata bytes.
    let payload_bytes =
        crate::quotas::coordination_payload_bytes(&[&mem.title, &mem.content], &[&mem.metadata]);
    let quota_op = crate::quotas::QuotaOp::Memory {
        bytes: payload_bytes,
    };
    crate::quotas::check_and_record(conn, &sender, &mem.namespace, quota_op)
        .map_err(|e| e.to_string())?;

    let actual_id = match db::insert(conn, &mem) {
        Ok(id) => id,
        Err(e) => {
            // The quota increment commits before the insert. Restore it on
            // every downstream refusal/failure so only durable notifications
            // remain charged.
            if let Err(refund_err) =
                crate::quotas::refund_op(conn, &sender, &mem.namespace, quota_op)
            {
                crate::quotas::log_refund_op_failed(&sender, &refund_err);
            }
            return Err(e.to_string());
        }
    };

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
    handle_inbox_with_policy(conn, params, mcp_client, caller, true)
}

pub(crate) fn handle_inbox_with_policy(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
    caller: Option<&str>,
    single_tenant_trust_all: bool,
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
    // private inbox. #3356 makes that legacy trust-all branch an explicit,
    // default-off single-tenant opt-in. When the visibility caller is absent
    // because AI_MEMORY_AGENT_ID is unset, bind to the same process-derived
    // identity memory_notify stamps rather than disabling inbox access.
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
            if single_tenant_trust_all {
                crate::identity::resolve_agent_id(explicit, mcp_client)
                    .map_err(|e| e.to_string())?
            } else {
                let derived = crate::identity::resolve_agent_id(None, mcp_client)
                    .map_err(|e| e.to_string())?;
                if let Some(requested) = explicit
                    && requested != derived
                {
                    return Err(format!(
                        "agent_id mismatch: caller '{derived}' may only read its own inbox"
                    ));
                }
                derived
            }
        }
    };
    // #3374 — both were read with a silent fallback. `unread_only: "yes"` (a
    // string, the shape an LLM caller emits most often) read as `false`, so a
    // caller asking for its UNREAD messages got its ENTIRE inbox back — more
    // rows than it asked for, and no signal that the filter was ignored. And
    // `limit` was read `as_u64()`, for which any NEGATIVE is indistinguishable
    // from absent, so `limit: -5` silently became the 50-row default. Refuse
    // the wrong type; ABSENT still takes the documented default, and the 500
    // cap still applies.
    let unread_only =
        crate::mcp::param_guard::optional_bool(params, field_names::UNREAD_ONLY)?.unwrap_or(false);
    let limit = crate::mcp::param_guard::optional_non_negative_u64(params, param_names::LIMIT)?
        .map_or(50, |n| usize::try_from(n).unwrap_or(usize::MAX))
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
        None, // #1834 valid_at (no as-of)
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
                (field_names::CREATED_AT): m.created_at,
                "read": m.access_count > 0,
                (field_names::ACCESS_COUNT): m.access_count,
            })
        })
        .collect();
    Ok(json!({
        "agent_id": owner,
        "namespace": namespace,
        "count": messages.len(),
        (field_names::UNREAD_ONLY): unread_only,
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

    /// Covenant clause-1 rationale (#2122): why this notification is being
    /// sent. Required under AI_MEMORY_REQUIRE_WHY_TRACE=1 (the payload is
    /// caller content, so the substrate never stamps its own rationale).
    #[serde(default)]
    pub why_trace: Option<String>,
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
        // v0.9.0 P0-1 (#1869) — recall is pure by default, so
        // read-marking is EVENTUALLY consistent: recalling a message
        // appends a ledger row and the periodic fold (default 60 s;
        // gc-tick fallback) is what bumps access_count past 0. A
        // just-recalled message can list as unread for up to one fold
        // interval. Pinned by
        // `tests/recall_purity_p01.rs::fold_flips_inbox_unread_marker`.
        "Read _messages/<agent_id>. access_count==0 is the unread marker \
         (eventually consistent under pure recall: the periodic \
         recall-access fold, default 60s, read-marks recalled messages)."
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
    fn notify_charges_sender_rows_and_bytes_3358() {
        let _env = crate::identity::agent_id_env_unset_guard();
        let conn = db::open(std::path::Path::new(":memory:")).expect("open database");
        let ttl = crate::config::ResolvedTtl::default();
        let client = "quota-sender";
        let sender = crate::identity::resolve_agent_id(None, Some(client)).unwrap();
        let target = "ai:quota-recipient";
        let namespace = super::super::agent::messages_namespace_for(target);
        for index in 0..3 {
            let params = json!({
                "target_agent_id": target,
                "title": format!("quota accounted notify {index}"),
                "payload": "caller controlled payload",
            });
            handle_notify(&conn, &params, &ttl, Some(client)).expect("notify under quota");
        }

        let sender_status =
            crate::quotas::get_status(&conn, &sender, &namespace).expect("sender quota status");
        assert_eq!(sender_status.current_memories_today, 3);
        assert!(sender_status.current_storage_bytes > 0);
        let inbox_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
                [&namespace],
                |row| row.get(0),
            )
            .expect("count inbox rows");
        assert_eq!(inbox_rows, 3);
        let recipient_status =
            crate::quotas::peek_status(&conn, target, &namespace).expect("recipient quota status");
        assert_eq!(recipient_status.current_memories_today, 0);
        assert_eq!(recipient_status.current_storage_bytes, 0);
    }

    #[test]
    fn notify_refuses_sender_over_quota_without_writing_3358() {
        let _env = crate::identity::agent_id_env_unset_guard();
        let conn = db::open(std::path::Path::new(":memory:")).expect("open database");
        let ttl = crate::config::ResolvedTtl::default();
        let client = "quota-limited";
        let sender = crate::identity::resolve_agent_id(None, Some(client)).unwrap();
        let target = "ai:quota-target";
        let namespace = super::super::agent::messages_namespace_for(target);
        crate::quotas::get_status(&conn, &sender, &namespace).expect("seed quota row");
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 0
             WHERE agent_id = ?1 AND namespace = ?2",
            rusqlite::params![sender, namespace],
        )
        .expect("tighten sender quota");
        let params = json!({
            "target_agent_id": target,
            "title": "must be refused",
            "payload": "must not reach the inbox",
        });

        let err = handle_notify(&conn, &params, &ttl, Some(client))
            .expect_err("notify over quota must fail closed");

        assert!(err.contains("QUOTA_EXCEEDED"), "unexpected error: {err}");
        let inbox_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
                [&namespace],
                |row| row.get(0),
            )
            .expect("count inbox rows");
        assert_eq!(inbox_rows, 0, "an over-quota notify must not materialise");
        let status =
            crate::quotas::get_status(&conn, &sender, &namespace).expect("sender quota status");
        assert_eq!(status.current_memories_today, 0);
        assert_eq!(status.current_storage_bytes, 0);
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
            cid: None,
            valid_from: None,
            valid_until: None,
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
            lifecycle_state: crate::models::LifecycleState::Open,
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
        let err = handle_inbox_with_policy(
            &conn,
            &json!({"agent_id": owner}),
            None,
            Some(attacker),
            false,
        )
        .unwrap_err();
        assert!(err.contains("may only read its own inbox"), "got: {err}");
    }

    #[test]
    fn inbox_caller_reads_own_inbox_1557() {
        let (owner, sender) = ("alice", "carol");
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, owner, sender);
        // Owner caller, explicit matching agent_id → sees the message.
        let explicit =
            handle_inbox_with_policy(&conn, &json!({"agent_id": owner}), None, Some(owner), false)
                .unwrap();
        assert_eq!(explicit["count"].as_u64(), Some(1));
        assert_eq!(explicit["messages"][0]["from"].as_str(), Some(sender));
        // Owner caller, agent_id omitted → defaults to the caller's own inbox.
        let implied =
            handle_inbox_with_policy(&conn, &json!({}), None, Some(owner), false).unwrap();
        assert_eq!(implied["agent_id"].as_str(), Some(owner));
        assert_eq!(implied["count"].as_u64(), Some(1));
    }

    #[test]
    fn inbox_none_caller_cannot_select_foreign_inbox_by_default_3356() {
        let _env = crate::identity::agent_id_env_unset_guard();
        let client = "inbox-default-denied-3356";
        let derived = crate::identity::resolve_agent_id(None, Some(client)).unwrap();
        let foreign = "ai:foreign-inbox-owner";
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, foreign, "ai:sender");

        let error = handle_inbox_with_policy(
            &conn,
            &json!({"agent_id": foreign}),
            Some(client),
            None,
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            format!("agent_id mismatch: caller '{derived}' may only read its own inbox")
        );
    }

    #[test]
    fn inbox_none_caller_reads_derived_own_inbox_by_default_3356() {
        let _env = crate::identity::agent_id_env_unset_guard();
        let client = "inbox-default-allowed-3356";
        let owner = crate::identity::resolve_agent_id(None, Some(client)).unwrap();
        let sender = "ai:sender";
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, &owner, sender);

        let implied =
            handle_inbox_with_policy(&conn, &json!({}), Some(client), None, false).unwrap();
        assert_eq!(implied["agent_id"].as_str(), Some(owner.as_str()));
        assert_eq!(implied["count"].as_u64(), Some(1));

        let explicit = handle_inbox_with_policy(
            &conn,
            &json!({"agent_id": &owner}),
            Some(client),
            None,
            false,
        )
        .unwrap();
        assert_eq!(explicit["agent_id"].as_str(), Some(owner.as_str()));
        assert_eq!(explicit["count"].as_u64(), Some(1));
    }

    #[test]
    fn inbox_none_caller_allows_explicit_single_tenant_opt_in_3356() {
        let (owner, sender) = ("alice", "carol");
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        seed_inbox_message(&conn, owner, sender);
        let response =
            handle_inbox_with_policy(&conn, &json!({"agent_id": owner}), None, None, true).unwrap();
        assert_eq!(response["count"].as_u64(), Some(1));
        assert_eq!(response["agent_id"].as_str(), Some(owner));
    }
}

// --- v0.6.0.0 webhook subscriptions ---------------------------------------
