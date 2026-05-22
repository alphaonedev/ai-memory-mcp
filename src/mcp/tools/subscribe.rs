// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP subscription management handlers.

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impls for `memory_subscribe` and
// `memory_unsubscribe` (governance family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_subscribe`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SubscribeRequest {
    /// https URL (http only for loopback). SSRF guard rejects private IPs.
    pub url: String,

    /// Comma-list or *. Events: memory_store, memory_delete, memory_promote.
    #[serde(default)]
    pub events: Option<String>,

    /// HMAC secret. Omit for unsigned.
    #[serde(default)]
    pub secret: Option<String>,

    /// Exact namespace match.
    #[serde(default)]
    pub namespace_filter: Option<String>,

    /// agent_id filter.
    #[serde(default)]
    pub agent_filter: Option<String>,

    #[schemars(description = "#912 event-type subset.")]
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_subscribe`.
#[allow(dead_code)]
pub struct SubscribeTool;

impl McpTool for SubscribeTool {
    fn name() -> &'static str {
        "memory_subscribe"
    }
    fn description() -> &'static str {
        "Register a webhook subscription for memory events."
    }
    fn docs() -> &'static str {
        "Webhook subscription. HMAC-SHA256 signed via X-Ai-Memory-Signature when secret supplied. https required (http only for loopback). Secret stored hashed only."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(SubscribeRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "governance"
    }
}

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_unsubscribe`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct UnsubscribeRequest {
    pub id: String,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_unsubscribe`.
#[allow(dead_code)]
pub struct UnsubscribeTool;

impl McpTool for UnsubscribeTool {
    fn name() -> &'static str {
        "memory_unsubscribe"
    }
    fn description() -> &'static str {
        "Delete a subscription by id."
    }
    fn docs() -> &'static str {
        "Delete subscription. DLQ rows retained for audit."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(UnsubscribeRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "governance"
    }
}

pub(super) fn handle_subscribe(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let url = params["url"].as_str().ok_or("url is required")?;
    let events = params["events"].as_str().unwrap_or("*");
    let secret = params["secret"].as_str();
    let namespace_filter = params["namespace_filter"].as_str();
    let agent_filter = params["agent_filter"].as_str();
    let created_by =
        crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;

    // R3-S1.HMAC (v0.7.0 fix campaign 2026-05-13): refuse subscription
    // registration when neither a per-subscription `secret` nor a
    // server-wide `[hooks.subscription] hmac_secret` is configured.
    // Mirrors the HTTP subscribe handler — see
    // `crate::handlers::subscribe` for the rationale.
    if secret.is_none_or(str::is_empty) && crate::config::active_hooks_hmac_secret().is_none() {
        return Err(
            "HMAC secret required: configure per-subscription `hmac_secret` or \
             server-wide `[security] hmac_secret`. Pass `secret: <value>` in the \
             tool call, OR set [hooks.subscription] hmac_secret in the daemon \
             config. Unsigned subscription dispatch was disabled in v0.7.0 \
             (fix campaign R3-S1.HMAC, 2026-05-13)."
                .to_string(),
        );
    }

    // P5 (G9): optional structured per-event-type opt-in. Callers pass
    // `event_types: ["memory_store", "memory_link_created"]` to scope a
    // subscription to a narrow event subset. When omitted, the legacy
    // `events` (comma-separated / `*`) field governs — preserves
    // backward compatibility for pre-P5 subscribers.
    let event_types: Option<Vec<String>> = params["event_types"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    });

    // Require the caller to be a registered agent (#301 item 4).
    // MCP stdio is single-tenant per process, but the same tool set is
    // exposed on the HTTP daemon where a caller might not be attested.
    // Registration in `_agents` is cheap (single memory_agent_register
    // call) and provides an audit trail; refusing unregistered
    // subscribers closes the "any MCP client owns the webhook fleet"
    // hole flagged by the v0.6.0 security review.
    let registered = crate::db::list_agents(conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .any(|a| a.agent_id == created_by);
    if !registered {
        return Err(format!(
            "agent {created_by:?} is not registered; call memory_agent_register before memory_subscribe"
        ));
    }

    crate::subscriptions::validate_url(url).map_err(|e| e.to_string())?;

    let id = crate::subscriptions::insert(
        conn,
        &crate::subscriptions::NewSubscription {
            url,
            events,
            secret,
            namespace_filter,
            agent_filter,
            created_by: Some(&created_by),
            event_types: event_types.as_deref(),
        },
    )
    .map_err(|e| e.to_string())?;

    let mut response = json!({
        "id": id,
        "url": url,
        "events": events,
        "namespace_filter": namespace_filter,
        "agent_filter": agent_filter,
        "created_by": created_by,
    });
    if let Some(et) = &event_types {
        response["event_types"] = json!(et);
    }
    Ok(response)
}

pub(crate) fn handle_unsubscribe(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"].as_str().ok_or("id is required")?;
    // Cross-tenant authorization (#870, security-high, 2026-05-18):
    // scope the DELETE to the caller's resolved agent_id. Without this
    // any tenant could enumerate ids (via lucky guess or by exfiltrating
    // another tenant's list output) and remove the other tenant's
    // webhook fleet. The resolution chain matches `handle_subscribe`.
    let caller = crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;
    let removed =
        crate::subscriptions::delete(conn, id, Some(&caller)).map_err(|e| e.to_string())?;
    Ok(json!({"id": id, "removed": removed}))
}

pub(super) fn handle_list_subscriptions(
    conn: &rusqlite::Connection,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    // Cross-tenant authorization (#872, security-high, 2026-05-18):
    // only return subscriptions owned by the caller. Pre-fix this
    // returned every tenant's rows.
    let caller = crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;
    let subs = crate::subscriptions::list(conn, Some(&caller)).map_err(|e| e.to_string())?;
    Ok(json!({"count": subs.len(), "subscriptions": subs}))
}

/// v0.7 K7 — MCP handler for `memory_subscription_replay`. Thin
/// wrapper around [`crate::subscriptions::memory_subscription_replay`]
/// that exposes the operator/governance reliability tool over the
/// MCP wire. Family: `Power` (operator-scoped, not data-plane).
pub(super) fn handle_subscription_replay(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let subscription_id = params["subscription_id"]
        .as_str()
        .ok_or("subscription_id is required")?;
    let since = params["since"]
        .as_str()
        .ok_or("since is required (RFC3339)")?;
    crate::subscriptions::memory_subscription_replay(conn, subscription_id, since)
        .map_err(|e| e.to_string())
}

// --- D1.5 (#986): per-tool McpTool impls for the in-scope subscribe tools ---
//
// `memory_subscribe` + `memory_unsubscribe` belong to Family::Governance
// and are migrated by the sibling D1.4 (#985) sub-agent. Only the
// `list_subscriptions` (other) and `subscription_replay` (power) tools
// land here in D1.5 scope.
//
// #985/#986 integration: imports already brought in at the top of the
// file by the D1.4 governance commit (`McpTool`, `JsonSchema`,
// `Deserialize`). Duplicate `use` statements removed during cherry-pick
// integration.

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_list_subscriptions`.
/// The legacy schema is `properties: {}` — empty struct.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ListSubscriptionsRequest {}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_list_subscriptions`.
#[allow(dead_code)]
pub struct ListSubscriptionsTool;

impl McpTool for ListSubscriptionsTool {
    fn name() -> &'static str {
        "memory_list_subscriptions"
    }
    fn description() -> &'static str {
        "List active webhook subscriptions."
    }
    fn docs() -> &'static str {
        "List subscriptions. Secrets never returned."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(ListSubscriptionsRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "other"
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_subscription_replay`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SubscriptionReplayRequest {
    /// Subscription id.
    pub subscription_id: String,

    /// RFC3339 inclusive lower bound.
    pub since: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_subscription_replay`.
#[allow(dead_code)]
pub struct SubscriptionReplayTool;

impl McpTool for SubscriptionReplayTool {
    fn name() -> &'static str {
        "memory_subscription_replay"
    }
    fn description() -> &'static str {
        "Replay subscription_events since an RFC3339 timestamp."
    }
    fn docs() -> &'static str {
        "K7: replay events ordered by delivered_at asc."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(SubscriptionReplayRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for the in-scope subscribe tools.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn list_subscriptions_parity_986() {
        let derived = derived_props_for::<ListSubscriptionsRequest>();
        assert_property_set_parity("memory_list_subscriptions", &derived);
        assert_descriptions_match("memory_list_subscriptions", &derived);
    }

    #[test]
    fn list_subscriptions_tool_metadata_986() {
        assert_eq!(ListSubscriptionsTool::name(), "memory_list_subscriptions");
        assert_eq!(ListSubscriptionsTool::family(), "other");
    }

    #[test]
    fn subscription_replay_parity_986() {
        let derived = derived_props_for::<SubscriptionReplayRequest>();
        assert_property_set_parity("memory_subscription_replay", &derived);
        assert_descriptions_match("memory_subscription_replay", &derived);
    }

    #[test]
    fn subscription_replay_tool_metadata_986() {
        assert_eq!(SubscriptionReplayTool::name(), "memory_subscription_replay");
        assert_eq!(SubscriptionReplayTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_subscribe`,
    //! `handle_unsubscribe`, `handle_list_subscriptions`, and
    //! `handle_subscription_replay`.

    use super::*;
    use crate::storage as db;
    use serde_json::json;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn register_agent(conn: &rusqlite::Connection) -> String {
        // Resolve the agent_id the handler will pick (None override, None mcp_client)
        // so `subscribe`'s registry check finds the row.
        let agent_id = crate::identity::resolve_agent_id(None, None).unwrap();
        db::register_agent(conn, &agent_id, "test", &[]).expect("register");
        agent_id
    }

    // R3-S1.HMAC: no per-subscription secret AND no server-wide secret → refusal.
    #[test]
    fn no_secret_refuses_unsigned() {
        // Belt-and-braces: ensure no global secret is set.
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        let _ = register_agent(&conn);
        let err = handle_subscribe(
            &conn,
            &json!({"url": "https://example.com/hook", "events": "*"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("HMAC secret required"), "got: {err}");
    }

    // Per-subscription secret allowed → registration proceeds.
    #[test]
    fn per_subscription_secret_accepted() {
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        let _ = register_agent(&conn);
        let resp = handle_subscribe(
            &conn,
            &json!({
                "url": "https://example.com/hook",
                "events": "memory_store",
                "secret": "shared-secret-hex",
            }),
            None,
        )
        .expect("ok");
        assert!(resp["id"].is_string());
        assert_eq!(resp["url"].as_str(), Some("https://example.com/hook"));
        assert_eq!(resp["events"].as_str(), Some("memory_store"));
    }

    // event_types array — structured per-event-type opt-in echoed in response.
    #[test]
    fn event_types_array_propagated() {
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        let _ = register_agent(&conn);
        let resp = handle_subscribe(
            &conn,
            &json!({
                "url": "https://example.com/hook",
                "secret": "shared-secret-hex",
                "event_types": ["memory_store", "memory_link_created"],
            }),
            None,
        )
        .expect("ok");
        let arr = resp["event_types"].as_array().expect("array");
        assert_eq!(arr.len(), 2);
    }

    // Missing url → typed error.
    #[test]
    fn missing_url_errors() {
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        let _ = register_agent(&conn);
        let err = handle_subscribe(&conn, &json!({"secret": "s"}), None).unwrap_err();
        assert!(err.contains("url"), "got: {err}");
    }

    // Unregistered agent refused.
    #[test]
    fn unregistered_agent_refused() {
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        // NB: did not call register_agent
        let err = handle_subscribe(
            &conn,
            &json!({"url": "https://example.com/hook", "secret": "s"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("not registered"), "got: {err}");
    }

    // Invalid URL rejected by validate_url.
    #[test]
    fn invalid_url_rejected() {
        crate::config::set_active_hooks_hmac_secret(None);
        let conn = fresh_conn();
        let _ = register_agent(&conn);
        let err =
            handle_subscribe(&conn, &json!({"url": "not-a-url", "secret": "s"}), None).unwrap_err();
        assert!(!err.is_empty());
    }

    // handle_unsubscribe — unknown id returns removed: false (no error).
    #[test]
    fn unsubscribe_unknown_id_returns_false() {
        let conn = fresh_conn();
        let resp = handle_unsubscribe(
            &conn,
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
        )
        .expect("ok");
        assert_eq!(resp["removed"], false);
    }

    // handle_unsubscribe — missing id errors.
    #[test]
    fn unsubscribe_missing_id_errors() {
        let conn = fresh_conn();
        let err = handle_unsubscribe(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    // handle_list_subscriptions — empty DB returns count=0.
    #[test]
    fn list_subscriptions_empty() {
        let conn = fresh_conn();
        let resp = handle_list_subscriptions(&conn, None).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
    }

    // handle_subscription_replay — missing fields error.
    #[test]
    fn subscription_replay_missing_id_errors() {
        let conn = fresh_conn();
        let err = handle_subscription_replay(&conn, &json!({"since": "2026-01-01T00:00:00Z"}))
            .unwrap_err();
        assert!(err.contains("subscription_id"), "got: {err}");
    }

    #[test]
    fn subscription_replay_missing_since_errors() {
        let conn = fresh_conn();
        let err =
            handle_subscription_replay(&conn, &json!({"subscription_id": "sub-1"})).unwrap_err();
        assert!(err.contains("since"), "got: {err}");
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_subscribe` and
    //! `memory_unsubscribe`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_subscribe_parity_985() {
        let derived = derived_props_for::<SubscribeRequest>();
        assert_property_set_parity("memory_subscribe", &derived);
        assert_descriptions_match("memory_subscribe", &derived);
    }

    #[test]
    fn memory_subscribe_tool_metadata_985() {
        assert_eq!(SubscribeTool::name(), "memory_subscribe");
        assert_eq!(SubscribeTool::family(), "governance");
    }

    #[test]
    fn memory_unsubscribe_parity_985() {
        let derived = derived_props_for::<UnsubscribeRequest>();
        assert_property_set_parity("memory_unsubscribe", &derived);
        assert_descriptions_match("memory_unsubscribe", &derived);
    }

    #[test]
    fn memory_unsubscribe_tool_metadata_985() {
        assert_eq!(UnsubscribeTool::name(), "memory_unsubscribe");
        assert_eq!(UnsubscribeTool::family(), "governance");
    }
}
