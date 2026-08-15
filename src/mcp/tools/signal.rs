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

use crate::hooks::events::{SignalAck, SignalDelta};
use crate::identity::keypair::AgentKeypair;
use crate::mcp::param_names;
use serde_json::{Value, json};

/// v0.8.0 Pillar-1 (#1709 / #1729) — substrate-level decision returned by a
/// `pre_signal_send` hook callback. Mirrors [`crate::hooks::HookDecision`]:
/// `Allow` (proceed unchanged), `Modify` (rewrite the in-flight signal from
/// the returned [`SignalDelta`] before it is signed + persisted), `Deny`
/// (refuse the signal — no sign, no insert), or `AskUser`.
///
/// On this **synchronous** in-substrate path (the MCP stdio loop has no
/// tokio runtime — see `daemon_runtime::run`), `AskUser` is resolved
/// **fail-closed** to a refusal carrying the prompt as the reason; the
/// interactive operator-prompt resolution is the async wire-level
/// [`crate::hooks::HookChain`]'s concern (the broader MCP-dispatch hook
/// gap is tracked by #1714). This mirrors how [`ReflectHookDecision`] on
/// the same sync substrate path exposed only the control-flow-affecting
/// outcomes.
///
/// [`ReflectHookDecision`]: crate::storage::reflect::ReflectHookDecision
//
// `dead_code`-allowed like the sibling Pillar-1 surfaces (`SignalAckRequest`):
// the variants are constructed by hook-callback authors — the #1729 tests
// today and the daemon wire-chain bridge (#1714) tomorrow — not by the
// substrate handlers, which only match on them.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SignalHookDecision {
    /// Proceed with the (possibly already-modified) signal unchanged.
    Allow,
    /// Rewrite the in-flight signal's mutable fields from this delta
    /// before signing + insert.
    Modify(Box<SignalDelta>),
    /// Refuse the signal. `reason` surfaces to the caller; `code` is an
    /// HTTP-style integer for the API surface.
    Deny { reason: String, code: i32 },
    /// Pause for operator input. Resolved fail-closed to a refusal on the
    /// sync substrate path (see the enum docs).
    AskUser {
        prompt: String,
        options: Vec<String>,
        default: Option<String>,
    },
}

/// v0.8.0 Pillar-1 (#1709 / #1729) — optional in-substrate hook callbacks
/// fired by [`handle_signal_send_with_hooks`] / [`handle_signal_ack_with_hooks`].
/// Bundled so the handler signatures stay compact and future callbacks land
/// without churning callers. Both callbacks are `Option`; when `None` the
/// handlers behave identically to the unhooked thin entry points
/// [`handle_signal_send`] / [`handle_signal_ack`].
///
/// This is the sync-callback analogue of [`crate::storage::reflect::ReflectHooks`]:
/// the signal handlers are synchronous (`rusqlite::Connection`) and run on the
/// MCP stdio loop's `spawn_blocking` thread with no tokio runtime, so the
/// async wire-level [`crate::hooks::HookChain`] cannot be `.await`-ed here. The
/// daemon layer (where an async runtime exists) is responsible for bridging a
/// configured chain into these callbacks (#1714).
pub struct SignalHooks<'a> {
    /// Fired BEFORE the signal is signed + inserted. Receives the
    /// rewritable in-flight [`SignalDelta`]; returns a
    /// [`SignalHookDecision`] (`Deny`/`AskUser` refuse the send,
    /// `Modify` rewrites the delta).
    #[allow(clippy::type_complexity)]
    pub pre_signal_send: Option<Box<dyn Fn(&SignalDelta) -> SignalHookDecision + Send + Sync + 'a>>,
    /// Fired AFTER the ack stamp commits. Notify-class — receives a
    /// read-only [`SignalAck`] snapshot; the return value is ignored.
    #[allow(clippy::type_complexity)]
    pub post_signal_ack: Option<Box<dyn Fn(&SignalAck) + Send + Sync + 'a>>,
}

impl<'a> SignalHooks<'a> {
    /// Empty bundle — both callbacks `None`. Used by the thin
    /// [`handle_signal_send`] / [`handle_signal_ack`] entry points so
    /// existing callers stay byte-identical.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            pre_signal_send: None,
            post_signal_ack: None,
        }
    }
}

impl<'a> Default for SignalHooks<'a> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<'a> std::fmt::Debug for SignalHooks<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalHooks")
            .field(
                "pre_signal_send",
                &self.pre_signal_send.as_ref().map(|_| "<fn>"),
            )
            .field(
                "post_signal_ack",
                &self.post_signal_ack.as_ref().map(|_| "<fn>"),
            )
            .finish()
    }
}

/// MCP handler for `memory_signal_send`. Thin shim over
/// [`handle_signal_send_with_hooks`] with an empty hook bundle — preserves
/// the pre-#1729 signature so every existing caller (the `mcp::mod`
/// dispatch arm + tests) compiles unchanged.
///
/// # Errors
/// Returns the stringified signing / `rusqlite` error on failure.
pub fn handle_signal_send(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    handle_signal_send_with_hooks(conn, params, keypair, &SignalHooks::empty())
}

/// v0.8.0 Pillar-1 (#1709 / #1729) — variant of [`handle_signal_send`] that
/// fires the [`crate::hooks::HookEvent::PreSignalSend`] callback. Builds a
/// [`crate::models::Signal`] from the request params, fires `pre_signal_send`
/// (honoring `Allow`/`Modify`/`Deny`/`AskUser`) BEFORE signing, signs it in
/// place when `keypair` is `Some` and `can_sign()`, inserts it, and returns
/// the created signal as JSON plus the attestation level.
///
/// Firing before signing (not just before the insert) is deliberate: a
/// `Modify` rewrite must be reflected in the Ed25519-signed canonical bytes,
/// so the hook runs first and the *final* signal is what gets signed.
///
/// # Errors
/// Returns a stringified error on a `pre_signal_send` refusal
/// (`Deny`/`AskUser`) or on a signing / `rusqlite` failure.
pub fn handle_signal_send_with_hooks(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
    hooks: &SignalHooks<'_>,
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

    // v0.8.0 Pillar-1 (#1709 / #1729) — fire PreSignalSend BEFORE signing +
    // insert. A `Modify` rewrites the signal's mutable fields (so the final
    // bytes are what get signed); `Deny` / `AskUser` refuse the send (no
    // sign, no insert, no audit row). `from_agent` / `id` are provenance-
    // immutable and not exposed in the delta.
    if let Some(pre) = hooks.pre_signal_send.as_ref() {
        let delta = SignalDelta {
            namespace: signal.namespace.clone(),
            to_agent: signal.to_agent.clone(),
            subject: signal.subject.clone(),
            body: signal.body.clone(),
            signal_type: signal.signal_type,
            in_reply_to: signal.in_reply_to.clone(),
            correlation_id: signal.correlation_id.clone(),
            reference_ids: signal.reference_ids.clone(),
        };
        match pre(&delta) {
            SignalHookDecision::Allow => {}
            SignalHookDecision::Modify(d) => {
                signal.namespace = d.namespace;
                signal.to_agent = d.to_agent;
                signal.subject = d.subject;
                signal.body = d.body;
                signal.signal_type = d.signal_type;
                signal.in_reply_to = d.in_reply_to;
                signal.correlation_id = d.correlation_id;
                signal.reference_ids = d.reference_ids;
            }
            SignalHookDecision::Deny { reason, code } => {
                return Err(format!(
                    "signal refused by pre_signal_send hook (code {code}): {reason}"
                ));
            }
            SignalHookDecision::AskUser { prompt, .. } => {
                // Fail-closed on the sync substrate path (no operator-prompt
                // loop here); the wire-level HookChain resolves AskUser.
                return Err(format!(
                    "signal pending operator decision (pre_signal_send AskUser): {prompt}"
                ));
            }
        }
    }

    let attest_level = match keypair {
        Some(kp) if kp.can_sign() => {
            crate::signals::sign_into(&mut signal, kp).map_err(|e| e.to_string())?;
            crate::models::AttestLevel::SelfSigned.as_str()
        }
        _ => crate::models::AttestLevel::Unsigned.as_str(),
    };

    // #1807 — charge the sender's per-namespace storage quota for the signal
    // payload (storage_only; a signal carries no metadata object — the byte
    // cap IS the payload-size limit). Charged AFTER the PreSignalSend hook
    // (which may `Modify` the body) so the final bytes are accounted, and
    // BEFORE insert so an over-cap signal is never persisted. Unowned sends
    // (empty `from_agent`) are not charged. T-exempt precedent-copy; 5-agent
    // review (memory `4d3ea1c5`) deemed #1807 legitimate.
    if !signal.from_agent.is_empty() {
        let bytes = crate::quotas::coordination_payload_bytes(
            &[&signal.subject],
            &[&signal.body, &signal.reference_ids],
        );
        crate::quotas::check_and_record_storage_only(
            conn,
            &signal.from_agent,
            &signal.namespace,
            bytes,
        )
        .map_err(|e| e.to_string())?;
    }

    crate::signals::insert(conn, &signal).map_err(|e| e.to_string())?;

    // #1714 / #1722 — coordination observability: append a tamper-evident
    // `signed_events` row for the send so the Pillar-1 substrate has an
    // audit trail on the same chain the governance gate uses. Best-effort
    // via the shared `coordination_audit::emit` writer: the signal already
    // committed, so an append failure is logged loudly, never propagated.
    // The payload hash commits to the signal's identity (id / sender /
    // recipient / subject / type) so the chain row is bounded regardless of
    // body size and an auditor can correlate it to the stored signal.
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::SIGNAL_SEND,
        &signal.from_agent,
        &[
            &signal.id,
            &signal.from_agent,
            signal.to_agent.as_deref().unwrap_or(""),
            &signal.subject,
            signal.signal_type.as_str(),
        ],
    );

    Ok(json!({
        (param_names::ID): signal.id,
        "attest_level": attest_level,
        "signal": serde_json::to_value(&signal).map_err(|e| e.to_string())?,
    }))
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

/// MCP handler for `memory_signal_ack`. Thin shim over
/// [`handle_signal_ack_with_hooks`] with an empty hook bundle — preserves
/// the pre-#1729 signature so every existing caller compiles unchanged.
///
/// # Errors
/// Returns the stringified `rusqlite` error on update failure.
pub fn handle_signal_ack(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    handle_signal_ack_with_hooks(conn, params, &SignalHooks::empty())
}

/// v0.8.0 Pillar-1 (#1709 / #1729) — variant of [`handle_signal_ack`] that
/// fires the [`crate::hooks::HookEvent::PostSignalAck`] callback AFTER the
/// `acknowledged_at` stamp commits. **Notify-class**: the hook return value
/// is ignored (the ack has already landed). Stamps `acknowledged_at` once
/// via [`crate::signals::mark_acked`]; returns `acknowledged: <bool>` —
/// `false` when the signal was already acked or no row matched.
///
/// # Errors
/// Returns the stringified `rusqlite` error on update failure.
pub fn handle_signal_ack_with_hooks(
    conn: &rusqlite::Connection,
    params: &Value,
    hooks: &SignalHooks<'_>,
) -> Result<Value, String> {
    let id = params
        .get(param_names::ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let acknowledged = crate::signals::mark_acked(conn, id, now).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: append a `coordination.signal_ack`
    // audit row ONLY when this call actually flipped the ack (a no-op re-ack
    // must not write a row). The ack handler has no actor param, so resolve
    // the principal by loading the signal: the recipient (`to_agent`) is who
    // acks; fall back to "" for a broadcast (None) or an absent signal.
    // Best-effort: the ack already committed. The same load feeds the
    // #1729 PostSignalAck snapshot below.
    if acknowledged {
        let signal = crate::signals::get(conn, id).ok().flatten();
        let actor = signal
            .as_ref()
            .and_then(|s| s.to_agent.clone())
            .unwrap_or_default();
        crate::coordination_audit::emit(
            conn,
            crate::coordination_audit::SIGNAL_ACK,
            &actor,
            &[id, &actor, "ack"],
        );

        // v0.8.0 Pillar-1 (#1709 / #1729) — fire PostSignalAck post-commit
        // (notify-only). Skipped when the signal row could not be re-read.
        if let (Some(post), Some(s)) = (hooks.post_signal_ack.as_ref(), signal.as_ref()) {
            let ack = SignalAck {
                id: s.id.clone(),
                namespace: s.namespace.clone(),
                from_agent: s.from_agent.clone(),
                to_agent: s.to_agent.clone(),
                subject: s.subject.clone(),
                signal_type: s.signal_type,
                acknowledged_at: s.acknowledged_at.unwrap_or(now),
            };
            post(&ack);
        }
    }

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
                rusqlite::params![crate::coordination_audit::SIGNAL_SEND],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "expected one coordination.signal_send audit row");
        assert_eq!(agent, "ai:alice", "audit row attributed to the sender");

        // The append-only chain verifies over the new row.
        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
        assert!(report.total_events >= 1);
    }

    /// #1722 — a signal ack that actually flips `acknowledged` appends one
    /// `coordination.signal_ack` audit row attributed to the recipient
    /// (`to_agent`), and a no-op re-ack appends NO further row. The
    /// append-only chain stays intact across both.
    #[test]
    fn ack_emits_signed_events_audit_row_1722() {
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
        let id = sent[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        // First ack flips it → exactly one signal_ack row, attributed to the
        // recipient (the agent that acks).
        let acked = handle_signal_ack(&conn, &json!({ "id": id })).expect("ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::SIGNAL_ACK],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "expected one coordination.signal_ack audit row");
        assert_eq!(agent, "ai:bob", "ack row attributed to the recipient");

        // A no-op re-ack writes NO further signal_ack row.
        let reacked = handle_signal_ack(&conn, &json!({ "id": id })).expect("ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));
        let count2: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::SIGNAL_ACK],
                |r| r.get(0),
            )
            .expect("query audit row");
        assert_eq!(count2, 1, "a no-op re-ack must not write another audit row");

        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    // ---- #1729 Pillar-1 signal hooks ----------------------------------------

    fn send_params() -> Value {
        json!({
            "namespace": "_sig",
            "from_agent": "agent-from",
            "to_agent": "agent-to",
            "subject": "original-subject",
            "body": {"k": "v"},
            "signal_type": "request",
            "correlation_id": "corr-hook",
        })
    }

    #[test]
    fn pre_signal_send_deny_refuses_the_insert_1729() {
        let conn = fresh();
        let hooks = SignalHooks {
            pre_signal_send: Some(Box::new(|_d: &SignalDelta| SignalHookDecision::Deny {
                reason: "policy: no signals on _sig".to_string(),
                code: 403,
            })),
            post_signal_ack: None,
        };
        let err = handle_signal_send_with_hooks(&conn, &send_params(), None, &hooks)
            .expect_err("Deny must refuse the send");
        assert!(
            err.contains("refused by pre_signal_send hook"),
            "got: {err}"
        );
        // Nothing was persisted.
        let inbox = handle_signal_inbox(
            &conn,
            &json!({ "namespace": "_sig", "to_agent": "agent-to" }),
        )
        .expect("inbox ok");
        assert_eq!(
            inbox["signals"].as_array().expect("array").len(),
            0,
            "a denied signal must not be inserted"
        );
    }

    #[test]
    fn pre_signal_send_askuser_refuses_fail_closed_1729() {
        let conn = fresh();
        let hooks = SignalHooks {
            pre_signal_send: Some(Box::new(|_d: &SignalDelta| SignalHookDecision::AskUser {
                prompt: "approve this signal?".to_string(),
                options: vec!["yes".to_string(), "no".to_string()],
                default: None,
            })),
            post_signal_ack: None,
        };
        let err = handle_signal_send_with_hooks(&conn, &send_params(), None, &hooks)
            .expect_err("AskUser is fail-closed on the sync path");
        assert!(err.contains("pending operator decision"), "got: {err}");
    }

    #[test]
    fn pre_signal_send_modify_rewrites_field_and_persists_1729() {
        let conn = fresh();
        let hooks = SignalHooks {
            pre_signal_send: Some(Box::new(|d: &SignalDelta| {
                // Rewrite the subject; carry every other field through verbatim.
                let mut rewritten = d.clone();
                rewritten.subject = "rewritten-by-hook".to_string();
                SignalHookDecision::Modify(Box::new(rewritten))
            })),
            post_signal_ack: None,
        };
        let sent = handle_signal_send_with_hooks(&conn, &send_params(), None, &hooks)
            .expect("modified send ok");
        assert_eq!(
            sent["signal"]["subject"].as_str(),
            Some("rewritten-by-hook"),
            "the Modify rewrite must be reflected in the returned signal"
        );
        // The rewrite is durable — re-read the stored row.
        let id = sent[param_names::ID].as_str().expect("id").to_string();
        let read = handle_signal_read(&conn, &json!({ "id": id })).expect("read ok");
        assert_eq!(
            read["signal"]["subject"].as_str(),
            Some("rewritten-by-hook"),
            "the Modify rewrite must be persisted, not just echoed"
        );
    }

    #[test]
    fn post_signal_ack_fires_post_commit_1729() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let conn = fresh();
        // Send (no hooks) so there is a signal to ack.
        let sent = handle_signal_send(&conn, &send_params(), None).expect("send ok");
        let id = sent[param_names::ID].as_str().expect("id").to_string();

        let fired = AtomicUsize::new(0);
        let seen_subject = std::sync::Mutex::new(String::new());
        let hooks = SignalHooks {
            pre_signal_send: None,
            post_signal_ack: Some(Box::new(|ack: &SignalAck| {
                fired.fetch_add(1, Ordering::SeqCst);
                *seen_subject.lock().unwrap() = ack.subject.clone();
                assert!(
                    ack.acknowledged_at > 0,
                    "post hook sees the committed ack timestamp"
                );
            })),
        };
        let acked =
            handle_signal_ack_with_hooks(&conn, &json!({ "id": id }), &hooks).expect("ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "post_signal_ack fires once"
        );
        assert_eq!(*seen_subject.lock().unwrap(), "original-subject");

        // A no-op re-ack must NOT fire the post hook again (no state change).
        let reacked =
            handle_signal_ack_with_hooks(&conn, &json!({ "id": id }), &hooks).expect("re-ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "a no-op re-ack must not re-fire post_signal_ack"
        );
    }
}
