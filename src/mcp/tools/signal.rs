// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_signal_*` MCP stdio tools. Thin
//! wrappers over the `crate::signals` sqlite free-functions that expose the
//! signed-signal coordination substrate to MCP callers. Mirrors the
//! `crate::actions` / `mcp::tools::action` split: the handlers hold a bare
//! `rusqlite::Connection` (not a SAL store), so they call the free-functions
//! directly. `handle_signal_send` additionally takes the dispatch context's
//! `active_keypair` so an outbound signal is Ed25519-signed in place via
//! [`crate::signals::sign_into`] when a signing keypair is available.

use crate::identity::keypair::AgentKeypair;
use crate::mcp::param_names;
use serde_json::{Value, json};

/// MCP handler for `memory_signal_send`. Builds a [`crate::models::Signal`]
/// from the request params, signs it in place when `keypair` is `Some` and
/// `can_sign()`, inserts it, and returns the created signal as JSON plus the
/// resulting attestation level (`self_signed` vs `unsigned`).
///
/// # Errors
/// Returns the stringified signing / `rusqlite` error on failure.
pub fn handle_signal_send(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let from_agent = params
        .get(param_names::FROM_AGENT)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let subject = params
        .get(param_names::SUBJECT)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let to_agent = params
        .get(param_names::TO_AGENT)
        .and_then(Value::as_str)
        .map(str::to_string);
    let in_reply_to = params
        .get(param_names::IN_REPLY_TO)
        .and_then(Value::as_str)
        .map(str::to_string);
    let correlation_id = params
        .get(param_names::CORRELATION_ID)
        .and_then(Value::as_str)
        .map(str::to_string);
    let body = params
        .get(param_names::BODY)
        .cloned()
        .unwrap_or(Value::Null);
    let signal_type = params
        .get(param_names::SIGNAL_TYPE)
        .and_then(Value::as_str)
        .and_then(crate::models::SignalType::from_str)
        .unwrap_or_default();
    let reference_ids = params
        .get(param_names::REFERENCE_IDS)
        .cloned()
        .unwrap_or_else(|| json!([]));

    let now = chrono::Utc::now().timestamp();
    let mut signal = crate::models::Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        from_agent,
        to_agent,
        subject,
        body,
        signal_type,
        in_reply_to,
        correlation_id,
        reference_ids,
        created_at: now,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: vec![],
        sender_pubkey: vec![],
    };

    let attest_level = match keypair {
        Some(kp) if kp.can_sign() => {
            crate::signals::sign_into(&mut signal, kp).map_err(|e| e.to_string())?;
            crate::models::AttestLevel::SelfSigned.as_str()
        }
        _ => crate::models::AttestLevel::Unsigned.as_str(),
    };

    crate::signals::insert(conn, &signal).map_err(|e| e.to_string())?;

    // #1714 — coordination observability: append a tamper-evident
    // `signed_events` row for the send so the Pillar-1 substrate has an
    // audit trail on the same chain the governance gate uses. Best-effort:
    // the signal already committed, so an audit-append failure (e.g. a rare
    // chain-sequence race) is logged loudly rather than failing the send.
    emit_signal_send_audit(conn, &signal);

    Ok(json!({
        (param_names::ID): signal.id,
        "attest_level": attest_level,
        "signal": serde_json::to_value(&signal).map_err(|e| e.to_string())?,
    }))
}

/// #1714 — emit the `coordination.signal_send` audit row. The payload hash
/// commits to the signal's identity (id / sender / recipient / subject /
/// type), so the chain row is bounded regardless of body size and lets an
/// auditor correlate it to the stored signal. Daemon-signed when an audit
/// signing key is installed (else `unsigned`), exactly like every other
/// production audit-row writer. Failures are logged, never propagated.
fn emit_signal_send_audit(conn: &rusqlite::Connection, signal: &crate::models::Signal) {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(signal.id.as_bytes());
    hasher.update([0x1F]);
    hasher.update(signal.from_agent.as_bytes());
    hasher.update([0x1F]);
    hasher.update(signal.to_agent.as_deref().unwrap_or("").as_bytes());
    hasher.update([0x1F]);
    hasher.update(signal.subject.as_bytes());
    hasher.update([0x1F]);
    hasher.update(signal.signal_type.as_str().as_bytes());
    let payload_hash = hasher.finalize().to_vec();
    let event = crate::signed_events::SignedEvent::with_daemon_signature(
        payload_hash,
        signal.from_agent.clone(),
        crate::signals::SIGNAL_SEND_EVENT_TYPE.to_string(),
        chrono::Utc::now().to_rfc3339(),
    );
    if let Err(e) = crate::signed_events::append_signed_event(conn, &event) {
        tracing::warn!(
            target: "ai_memory::coordination",
            signal_id = %signal.id,
            from_agent = %signal.from_agent,
            error = %e,
            "coordination.signal_send audit append failed (signal already committed)"
        );
    }
}

/// MCP handler for `memory_signal_read`. Fetches a signal by id, stamps
/// `read_at` (best-effort, idempotent), and returns the signal plus its
/// Ed25519 verification status. The `signal` field is `null` when no row
/// matches, mirroring how `memory_get` reports an absent row.
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_signal_read(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let found = crate::signals::get(conn, id).map_err(|e| e.to_string())?;
    match found {
        None => Ok(json!({ "signal": Value::Null })),
        Some(signal) => {
            let now = chrono::Utc::now().timestamp();
            // Best-effort read-stamp; a failure here must not mask the read.
            let _ = crate::signals::mark_read(conn, id, now);
            Ok(json!({
                "signal": serde_json::to_value(&signal).map_err(|e| e.to_string())?,
                "verified": crate::signals::verify(&signal),
            }))
        }
    }
}

/// MCP handler for `memory_signal_inbox`. Lists signals for a namespace,
/// optionally narrowed to a recipient (direct messages + namespace
/// broadcasts), newest-first, capped at `limit` (default 50).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_signal_inbox(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_agent = params
        .get(param_names::TO_AGENT)
        .and_then(Value::as_str)
        .map(str::to_string);
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let signals = crate::signals::list_inbox(conn, namespace, to_agent.as_deref(), limit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "signals": serde_json::to_value(&signals).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_signal_thread`. Lists every signal sharing a
/// `correlation_id`, oldest-first (thread order).
///
/// # Errors
/// Returns the stringified `rusqlite` error on query failure.
pub fn handle_signal_thread(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let correlation_id = params
        .get(param_names::CORRELATION_ID)
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signals = crate::signals::thread(conn, correlation_id).map_err(|e| e.to_string())?;
    Ok(json!({
        "signals": serde_json::to_value(&signals).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_signal_ack`. Stamps `acknowledged_at` on a signal
/// once via [`crate::signals::mark_acked`]. Returns `acknowledged: <bool>` —
/// `false` when the signal was already acked or no row matched.
///
/// # Errors
/// Returns the stringified `rusqlite` error on update failure.
pub fn handle_signal_ack(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let acknowledged = crate::signals::mark_acked(conn, id, now).map_err(|e| e.to_string())?;
    Ok(json!({ "acknowledged": acknowledged }))
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_signal_send`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SignalSendRequest {
    pub namespace: String,

    pub from_agent: String,

    pub subject: String,

    /// Recipient agent id. Omit for a namespace-wide broadcast.
    #[serde(default)]
    pub to_agent: Option<String>,

    #[serde(default)]
    pub body: Value,

    /// Signal kind (`authorize` / `notify` / `request` / `response` /
    /// `broadcast`). Defaults to `notify`.
    #[serde(default)]
    pub signal_type: Option<String>,

    /// Threads a `response` back onto its `request` signal id.
    #[serde(default)]
    pub in_reply_to: Option<String>,

    /// Correlation id grouping a thread of signals.
    #[serde(default)]
    pub correlation_id: Option<String>,

    /// JSON array of related signal / memory ids.
    #[serde(default)]
    pub reference_ids: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_signal_read`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SignalReadRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_signal_inbox`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SignalInboxRequest {
    pub namespace: String,

    /// Recipient agent id. When set, returns direct messages to this agent
    /// plus namespace broadcasts; when omitted, returns every signal in the
    /// namespace.
    #[serde(default)]
    pub to_agent: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_signal_thread`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SignalThreadRequest {
    pub correlation_id: String,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_signal_ack`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SignalAckRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_signal_send`.
#[allow(dead_code)]
pub struct SignalSendTool;

impl McpTool for SignalSendTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SIGNAL_SEND
    }
    fn description() -> &'static str {
        "Send a typed, optionally Ed25519-signed inter-agent signal (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): create a signal; self-signed when a signing keypair is available."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SignalSendRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_signal_read`.
#[allow(dead_code)]
pub struct SignalReadTool;

impl McpTool for SignalReadTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SIGNAL_READ
    }
    fn description() -> &'static str {
        "Read one signal by id, mark it read, and report verify status (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): fetch a signal, stamp read_at, and verify its Ed25519 signature."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SignalReadRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_signal_inbox`.
#[allow(dead_code)]
pub struct SignalInboxTool;

impl McpTool for SignalInboxTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SIGNAL_INBOX
    }
    fn description() -> &'static str {
        "List signals for a namespace/recipient — direct + broadcast (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): the recipient inbox — direct messages plus namespace broadcasts, newest-first."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SignalInboxRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_signal_thread`.
#[allow(dead_code)]
pub struct SignalThreadTool;

impl McpTool for SignalThreadTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SIGNAL_THREAD
    }
    fn description() -> &'static str {
        "List a signal correlation thread, oldest-first (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): return every signal sharing a correlation_id in thread order."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SignalThreadRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_signal_ack`.
#[allow(dead_code)]
pub struct SignalAckTool;

impl McpTool for SignalAckTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SIGNAL_ACK
    }
    fn description() -> &'static str {
        "Acknowledge a signal by id (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): stamp acknowledged_at on a signal; reports whether this call set it."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SignalAckRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_signal_*` tools.
    use super::*;

    #[test]
    fn signal_send_tool_metadata() {
        assert_eq!(SignalSendTool::name(), "memory_signal_send");
        assert_eq!(SignalSendTool::family(), "power");
        assert!(!SignalSendTool::description().is_empty());
        assert!(!SignalSendTool::docs().is_empty());
    }

    #[test]
    fn signal_read_tool_metadata() {
        assert_eq!(SignalReadTool::name(), "memory_signal_read");
        assert_eq!(SignalReadTool::family(), "power");
        assert!(!SignalReadTool::description().is_empty());
        assert!(!SignalReadTool::docs().is_empty());
    }

    #[test]
    fn signal_inbox_tool_metadata() {
        assert_eq!(SignalInboxTool::name(), "memory_signal_inbox");
        assert_eq!(SignalInboxTool::family(), "power");
        assert!(!SignalInboxTool::description().is_empty());
        assert!(!SignalInboxTool::docs().is_empty());
    }

    #[test]
    fn signal_thread_tool_metadata() {
        assert_eq!(SignalThreadTool::name(), "memory_signal_thread");
        assert_eq!(SignalThreadTool::family(), "power");
        assert!(!SignalThreadTool::description().is_empty());
        assert!(!SignalThreadTool::docs().is_empty());
    }

    #[test]
    fn signal_ack_tool_metadata() {
        assert_eq!(SignalAckTool::name(), "memory_signal_ack");
        assert_eq!(SignalAckTool::family(), "power");
        assert!(!SignalAckTool::description().is_empty());
        assert!(!SignalAckTool::docs().is_empty());
    }

    #[test]
    fn signal_send_schema_requires_core_fields() {
        let schema = SignalSendTool::input_schema();
        let obj = schema.as_object().expect("schema is an object");
        assert!(
            obj.contains_key("properties"),
            "schema must advertise properties"
        );
        let required = obj
            .get("required")
            .and_then(Value::as_array)
            .expect("required is an array");
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        for name in &["namespace", "from_agent", "subject"] {
            assert!(
                required_names.contains(name),
                "required must include {name}"
            );
        }
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    fn fresh() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn send_read_inbox_ack_roundtrips_over_mcp() {
        let conn = fresh();
        // Send with no keypair → unsigned.
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "agent-from",
                "to_agent": "agent-to",
                "subject": "hello",
                "body": {"k": "v"},
                "signal_type": "request",
                "correlation_id": "corr-1",
            }),
            None,
        )
        .expect("send ok");
        assert_eq!(sent["attest_level"].as_str(), Some("unsigned"));
        let id = sent[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        assert_eq!(sent["signal"]["signal_type"].as_str(), Some("request"));

        // Read marks it read + reports verify=false (unsigned).
        let read = handle_signal_read(&conn, &json!({ "id": id })).expect("read ok");
        assert_eq!(read["signal"]["subject"].as_str(), Some("hello"));
        assert_eq!(read["verified"].as_bool(), Some(false));
        assert!(
            read["signal"]["read_at"].is_null(),
            "read returns pre-stamp snapshot"
        );
        // A second read confirms the stamp landed on the row.
        let reread = handle_signal_read(&conn, &json!({ "id": id })).expect("read ok");
        assert!(reread["signal"]["read_at"].as_i64().is_some());

        // Inbox for the recipient finds it.
        let inbox = handle_signal_inbox(
            &conn,
            &json!({ "namespace": "_sig", "to_agent": "agent-to" }),
        )
        .expect("inbox ok");
        let arr = inbox["signals"].as_array().expect("signals array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Thread groups by correlation id.
        let thread =
            handle_signal_thread(&conn, &json!({ "correlation_id": "corr-1" })).expect("thread ok");
        assert_eq!(thread["signals"].as_array().expect("array").len(), 1);

        // Ack flips once, then is a no-op.
        let acked = handle_signal_ack(&conn, &json!({ "id": id })).expect("ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));
        let reacked = handle_signal_ack(&conn, &json!({ "id": id })).expect("ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));
    }

    #[test]
    fn read_absent_returns_null_signal() {
        let conn = fresh();
        let got = handle_signal_read(&conn, &json!({ "id": "missing" })).expect("read ok");
        assert!(got["signal"].is_null());
    }

    #[test]
    fn send_with_keypair_self_signs_and_verifies() {
        let conn = fresh();
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "ai:curator",
                "subject": "signed",
            }),
            Some(&kp),
        )
        .expect("send ok");
        assert_eq!(sent["attest_level"].as_str(), Some("self_signed"));
        let id = sent[param_names::ID].as_str().expect("id present");

        // The stored signal verifies.
        let read = handle_signal_read(&conn, &json!({ "id": id })).expect("read ok");
        assert_eq!(read["verified"].as_bool(), Some(true));
    }

    #[test]
    fn send_defaults_signal_type_to_notify() {
        let conn = fresh();
        let sent = handle_signal_send(
            &conn,
            &json!({ "namespace": "_sig", "from_agent": "a", "subject": "s" }),
            None,
        )
        .expect("send ok");
        assert_eq!(sent["signal"]["signal_type"].as_str(), Some("notify"));
        // Broadcast (no to_agent) round-trips with a null recipient.
        assert!(sent["signal"]["to_agent"].is_null());
        assert!(sent["signal"]["created_at"].as_i64().expect("created_at") > 0);
    }

    /// #1714 — a signal send appends a `coordination.signal_send` audit row
    /// to the `signed_events` chain (attributed to the sender), and the
    /// append-only chain still verifies after it. This is the coordination
    /// substrate's first tamper-evident observability record.
    #[test]
    fn send_emits_signed_events_audit_row_1714() {
        let conn = fresh();
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "ai:alice",
                "to_agent": "ai:bob",
                "subject": "coordinate",
            }),
            None,
        )
        .expect("send ok");
        assert!(sent[param_names::ID].as_str().is_some());

        // Exactly one coordination.signal_send row, attributed to the sender.
        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::signals::SIGNAL_SEND_EVENT_TYPE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "expected one coordination.signal_send audit row");
        assert_eq!(agent, "ai:alice", "audit row attributed to the sender");

        // The append-only chain verifies over the new row.
        let report = crate::signed_events::verify_audit_trail(&conn, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
        assert!(report.total_events >= 1);
    }
}
