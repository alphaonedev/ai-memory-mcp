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
    // #2996 — `from_agent` is BOUND to the resolved MCP caller identity, NOT
    // taken from the caller-asserted body: the wire value is discarded exactly
    // as the HTTP handler (`handlers::coordination::send_signal`) discards its
    // body `from_agent`. Without this, `sign_into` signs with the process
    // keypair regardless of `from_agent`, so a co-located agent could forge any
    // authorship (`self_signed`, same daemon key) and even store spaces /
    // empty. The bound id is the signing keypair's own agent_id when a keypair
    // is present (so authorship matches the signature), else the durable
    // process identity; a shape check rejects control chars.
    let from_agent = match keypair {
        Some(kp) => kp.agent_id.clone(),
        None => crate::identity::resolve_agent_id(None, None)
            .map_err(|e| format!("resolve caller agent_id: {e}"))?,
    };
    crate::validate::validate_agent_id_shape(&from_agent).map_err(|e| e.to_string())?;
    let mut subject = params
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
    let mut body = params
        .get(param_names::BODY)
        .cloned()
        .unwrap_or(Value::Null);
    // Minor (A6-13) — reject an unknown `signal_type` value like the
    // `condition_type` fix (#3007), instead of silently coercing it to `notify`.
    // An ABSENT value still defaults.
    let signal_type = match params.get(param_names::SIGNAL_TYPE).and_then(Value::as_str) {
        Some(s) => crate::models::SignalType::from_str(s)
            .ok_or_else(|| format!("invalid signal_type: {s}"))?,
        None => crate::models::SignalType::default(),
    };
    let reference_ids = params
        .get(param_names::REFERENCE_IDS)
        .cloned()
        .unwrap_or_else(|| json!([]));

    // #2998 — validate namespace + bound the subject / body sizes. #2994 —
    // screen the caller-origin credential vectors (subject / body) before the
    // direct insert + federation EGRESS.
    crate::coordination_guard::require_namespace(&namespace)?;
    crate::coordination_guard::require_text(
        param_names::SUBJECT,
        &subject,
        crate::coordination_guard::MAX_TEXT_FIELD_BYTES,
    )?;
    crate::coordination_guard::require_payload_size(param_names::BODY, &body)?;
    crate::secret_screen::screen_text_field_for_caller(&mut subject).map_err(|r| r.to_string())?;
    crate::secret_screen::screen_json_field_for_caller(&mut body).map_err(|r| r.to_string())?;

    let now = chrono::Utc::now().timestamp();
    // #3011 — wire `signals.expires_at`: an optional `ttl_secs` marks the signal
    // caller-declared-ephemeral, so the gc pruner (`signals::prune_expired`) can
    // reap it. Validated + overflow-checked like the lease ttl.
    let expires_at = match params.get(param_names::TTL_SECS).and_then(Value::as_i64) {
        Some(ttl) => {
            crate::validate::validate_ttl_secs(Some(ttl)).map_err(|e| e.to_string())?;
            Some(
                now.checked_add(ttl)
                    .ok_or_else(|| crate::coordination_guard::TTL_SECS_OVERFLOW.to_string())?,
            )
        }
        None => None,
    };
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
        expires_at,
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
/// Returns `"id is required"` when the schema-required `id` is missing,
/// blank, or not a JSON string (#3365), or the stringified `rusqlite` error
/// on query failure.
pub fn handle_signal_read(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3365 (#3171 residue) — `id` is schema-REQUIRED; the `""` fallback
    // returned `{"signal": null}` for a malformed call, so a caller could not
    // tell a bad id from a deleted/expired signal. Refuse instead.
    let id = crate::mcp::param_guard::require_str(params, param_names::ID)?;
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
/// Returns `"namespace is required"` when the schema-required `namespace` is
/// missing/blank/non-string, `"invalid to_agent: .."` when the recipient
/// filter is present but is not a non-empty string (#3365), or the
/// stringified `rusqlite` error on query failure.
pub fn handle_signal_inbox(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3365 (#3171 residue) — `namespace` is schema-REQUIRED; the `""`
    // fallback answered `memory_signal_inbox {}` with an empty `signals` list,
    // which an agent reads as "no messages for me" and never retries.
    let namespace = crate::mcp::param_guard::require_str(params, param_names::NAMESPACE)?;
    // #3365 — a PRESENT-but-non-string `to_agent` DROPPED the recipient
    // predicate, so the inbox returned every OTHER agent's DIRECT signals
    // instead of only this recipient's directs plus namespace broadcasts: a
    // confidentiality leak produced by a wrong TYPE, not by any authz decision.
    // Refuse it; an ABSENT `to_agent` still means the whole namespace.
    let to_agent = crate::mcp::param_guard::optional_str(params, param_names::TO_AGENT)?;
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let signals =
        crate::signals::list_inbox(conn, namespace, to_agent, limit).map_err(|e| e.to_string())?;
    Ok(json!({
        "signals": serde_json::to_value(&signals).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_signal_thread`. Lists every signal sharing a
/// `correlation_id`, oldest-first (thread order).
///
/// # Errors
/// Returns `"correlation_id is required"` when the schema-required
/// `correlation_id` is missing/blank (#3171), or the stringified `rusqlite`
/// error on query failure.
pub fn handle_signal_thread(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    // #3171 — `correlation_id` is schema-REQUIRED. Pre-fix it was read with
    // `unwrap_or_default()`, so a malformed call threaded on `""` and got an
    // empty `signals` array back: a plausible "this thread has no messages"
    // answer to a question that was never actually asked. Refuse instead.
    let correlation_id = crate::mcp::param_guard::require_str(params, param_names::CORRELATION_ID)?;
    let signals = crate::signals::thread(conn, correlation_id).map_err(|e| e.to_string())?;
    Ok(json!({
        "signals": serde_json::to_value(&signals).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_signal_ack`. Thin shim over
/// [`handle_signal_ack_with_hooks`] with an empty hook bundle.
///
/// `mcp_client` is the dispatch context's client label, used ONLY to resolve
/// the caller identity the ack is authorized against (#3364); see
/// [`handle_signal_ack_with_hooks`].
///
/// # Errors
/// Returns the refusal string when the caller is not the signal's addressee
/// (#3364), or the stringified `rusqlite` error on update failure.
pub fn handle_signal_ack(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    handle_signal_ack_with_hooks(conn, params, mcp_client, &SignalHooks::empty())
}

/// v0.8.0 Pillar-1 (#1709 / #1729) — variant of [`handle_signal_ack`] that
/// fires the [`crate::hooks::HookEvent::PostSignalAck`] callback AFTER the
/// `acknowledged_at` stamp commits. **Notify-class**: the hook return value
/// is ignored (the ack has already landed). Stamps `acknowledged_at` once
/// via [`crate::signals::mark_acked`]; returns `acknowledged: <bool>` —
/// `false` when the signal was already acked or no row matched.
///
/// # Authorization (#3364)
/// Only the signal's ADDRESSEE may acknowledge it. The caller identity is
/// RESOLVED from the MCP session ([`crate::identity::resolve_agent_id`] —
/// `AI_MEMORY_AGENT_ID`, else the `clientInfo`-derived id, else the durable
/// host id), never taken from a body field: the same reason #2996 bound
/// `signal_send.from_agent` to the resolved identity instead of the wire
/// value. A namespace broadcast has no addressee and is refused outright
/// (see [`crate::signals::AckDenied`]).
///
/// # Errors
/// - `"id is required"` when the schema-required `id` is missing/blank/
///   non-string — the row must be identified before it can be authorized.
/// - The [`crate::signals::AckDenied`] refusal when the resolved caller is
///   not the addressee, or the signal is a broadcast.
/// - The stringified caller-resolution / `rusqlite` error on failure.
pub fn handle_signal_ack_with_hooks(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
    hooks: &SignalHooks<'_>,
) -> Result<Value, String> {
    // #3364 — the row has to be IDENTIFIED before it can be authorized, so the
    // `unwrap_or_default()` read (which acked `""`, i.e. nothing, and reported
    // a plausible `acknowledged: false`) becomes a refusal.
    let id = crate::mcp::param_guard::require_str(params, param_names::ID)?;
    // #3364 — resolve the CALLER. `SignalAckRequest` carries no `agent_id`
    // and must not grow one: a caller-asserted actor is exactly what an
    // impersonating agent would set. This mirrors #2996's bind of
    // `signal_send.from_agent`; it resolves through `resolve_agent_id` rather
    // than the signing keypair because an ack is not signed — the principal is
    // the MCP session, not the daemon key (binding to the key would make the
    // tool unusable by every agent except the key's own label).
    let caller = crate::identity::resolve_agent_id(None, mcp_client)
        .map_err(|e| format!("resolve caller agent_id: {e}"))?;
    crate::validate::validate_agent_id_shape(&caller).map_err(|e| e.to_string())?;

    // #3364 — load BEFORE any write: the ack is authorized against the STORED
    // addressee, and a refused ack must leave the row byte-identical. Pre-fix
    // the stamp landed first and the row was re-read only to name an actor in
    // the audit trail.
    let Some(signal) = crate::signals::get(conn, id).map_err(|e| e.to_string())? else {
        // No row: nothing to authorize and nothing to change. Unchanged
        // pre-#3364 shape — an absent id is not an authorization verdict, and
        // reporting one would leak which ids exist.
        return Ok(json!({ "acknowledged": false }));
    };
    crate::signals::authorize_ack(&signal, &caller).map_err(|e| e.to_string())?;

    let now = chrono::Utc::now().timestamp();
    let acknowledged = crate::signals::mark_acked(conn, id, now).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: append a `coordination.signal_ack`
    // audit row ONLY when this call actually flipped the ack (a no-op re-ack
    // must not write a row). #3364 — the row now names the RESOLVED CALLER.
    // Pre-fix it named the signal's `to_agent`, so a wrongful ack by bob was
    // recorded on the tamper-evident chain as alice's: the audit trail blamed
    // the victim. The caller is authorized as the addressee above, so the two
    // agree on the legitimate path — the difference is that the value is now
    // the acknowledging principal by construction, not by assumption.
    // Best-effort: the ack already committed.
    if acknowledged {
        crate::coordination_audit::emit(
            conn,
            crate::coordination_audit::SIGNAL_ACK,
            &caller,
            &[id, &caller, "ack"],
        );

        // v0.8.0 Pillar-1 (#1709 / #1729) — fire PostSignalAck post-commit
        // (notify-only). The snapshot comes from the pre-stamp row loaded
        // above; `acknowledged == true` means THIS call wrote the stamp, so
        // `now` IS the committed `acknowledged_at`.
        if let Some(post) = hooks.post_signal_ack.as_ref() {
            let ack = SignalAck {
                id: signal.id.clone(),
                namespace: signal.namespace.clone(),
                from_agent: signal.from_agent.clone(),
                to_agent: signal.to_agent.clone(),
                subject: signal.subject.clone(),
                signal_type: signal.signal_type,
                acknowledged_at: now,
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

    /// **IGNORED** (#3171 / #2996). Still schema-required for wire
    /// compatibility, but the value you send is DISCARDED: authorship is
    /// bound to the signing keypair's own `agent_id` (or the durable process
    /// identity when no keypair is loaded), because a caller-asserted
    /// `from_agent` combined with a shared daemon key would let a co-located
    /// agent forge `self_signed` authorship for anyone. Send your own id or a
    /// placeholder — either way the stored signal names the signer.
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

    // #3011 — wire `signals.expires_at`. The doc comment must NOT be a `///`
    // one: schemars turns a `#`-leading doc line into a JSON-Schema `title`
    // (not a `description`), and the wire trimmer strips `description` but not
    // property `title`, so a `///` here would leak a truncated fragment onto
    // the public tools/list surface. Use `#[schemars(description = ...)]` so a
    // clean description is emitted and then trimmed off the bare wire.
    #[schemars(description = "Optional retention TTL in seconds. When set, the \
                             signal expires at now + ttl_secs and the gc pruner \
                             reaps it once past.")]
    #[serde(default)]
    pub ttl_secs: Option<i64>,
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
        "List UNACKED signals for a namespace/recipient — direct + broadcast (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): the recipient inbox — direct messages plus namespace broadcasts, \
         newest-first. #3171: UNACKED ONLY (`acknowledged_at IS NULL`); an acked signal never \
         reappears here — read it back with memory_signal_thread or memory_signal_read."
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

    /// #3364 — the identity `handle_signal_ack` resolves for THIS process, so
    /// a test can address a signal to its own caller and exercise the ALLOWED
    /// path. Same shape as the `subscribe` handler tests' owner resolution.
    fn caller_id() -> String {
        crate::identity::resolve_agent_id(None, None).expect("resolve test caller identity")
    }

    #[test]
    fn send_read_inbox_ack_roundtrips_over_mcp() {
        let conn = fresh();
        // #3364 — address the signal to THIS caller so the ack at the end of
        // the roundtrip is the ALLOWED (addressee) path.
        let me = caller_id();
        // Send with no keypair → unsigned.
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "agent-from",
                "to_agent": me,
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
        let inbox = handle_signal_inbox(&conn, &json!({ "namespace": "_sig", "to_agent": me }))
            .expect("inbox ok");
        let arr = inbox["signals"].as_array().expect("signals array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Thread groups by correlation id.
        let thread =
            handle_signal_thread(&conn, &json!({ "correlation_id": "corr-1" })).expect("thread ok");
        assert_eq!(thread["signals"].as_array().expect("array").len(), 1);

        // Ack flips once, then is a no-op.
        let acked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));
        let reacked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));
    }

    /// Minor (A6-13) — an unknown `signal_type` is REJECTED, not coerced to
    /// `notify` (mirrors the #3007 `condition_type` fix).
    #[test]
    fn send_rejects_unknown_signal_type() {
        let conn = fresh();
        let err = handle_signal_send(
            &conn,
            &json!({ "namespace": "_sig", "from_agent": "a", "subject": "s", "signal_type": "bogus" }),
            None,
        )
        .expect_err("unknown signal_type must reject");
        assert!(err.contains("invalid signal_type"), "{err}");
    }

    /// #2996 — the caller-asserted `from_agent` is DISCARDED (mirrors the HTTP
    /// handler): with no keypair the authorship binds to the resolved process
    /// identity, so a co-located agent cannot forge another's authorship, and a
    /// spaces / empty / control-char `from_agent` can never be stored.
    #[test]
    fn send_discards_caller_asserted_from_agent_2996() {
        let conn = fresh();
        let sent = handle_signal_send(
            &conn,
            &json!({ "namespace": "_sig", "from_agent": "ai:IMPERSONATED-VICTIM", "subject": "s" }),
            None,
        )
        .expect("send ok");
        assert_ne!(
            sent["signal"]["from_agent"].as_str(),
            Some("ai:IMPERSONATED-VICTIM"),
            "the caller-asserted from_agent is discarded, never stored"
        );
        assert!(
            sent["signal"]["from_agent"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "authorship is bound to the resolved caller identity"
        );
    }

    /// #3011 — an optional `ttl_secs` sets `signals.expires_at = now + ttl` so
    /// the gc pruner can reap the caller-declared-ephemeral signal.
    #[test]
    fn send_ttl_secs_sets_expires_at_3011() {
        let conn = fresh();
        let sent = handle_signal_send(
            &conn,
            &json!({ "namespace": "_sig", "from_agent": "a", "subject": "s", "ttl_secs": 3600 }),
            None,
        )
        .expect("send ok");
        let expires_at = sent["signal"]["expires_at"]
            .as_i64()
            .expect("expires_at is set from ttl_secs");
        assert!(
            expires_at > chrono::Utc::now().timestamp(),
            "expires_at is in the future"
        );
        // A signal without ttl_secs has no expiry.
        let no_ttl = handle_signal_send(
            &conn,
            &json!({ "namespace": "_sig", "from_agent": "a", "subject": "s" }),
            None,
        )
        .expect("send ok");
        assert!(no_ttl["signal"]["expires_at"].is_null());
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
        // #2996 — authorship is BOUND to the signing keypair's agent_id, so the
        // audit row is attributed to the bound sender (`ai:alice`), NOT any
        // caller-asserted `from_agent` body value.
        let kp = crate::identity::keypair::generate("ai:alice").expect("generate");
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "ai:IMPERSONATED-VICTIM",
                "to_agent": "ai:bob",
                "subject": "coordinate",
            }),
            Some(&kp),
        )
        .expect("send ok");
        assert!(sent[param_names::ID].as_str().is_some());
        assert_eq!(
            sent["signal"]["from_agent"].as_str(),
            Some("ai:alice"),
            "from_agent is bound to the keypair, not the caller-asserted body value"
        );

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
    /// `coordination.signal_ack` audit row, and a no-op re-ack appends NO
    /// further row. The append-only chain stays intact across both.
    ///
    /// #3364 — the row is now attributed to the RESOLVED CALLER. Pre-fix it
    /// was attributed to the signal's `to_agent` on the assumption that the
    /// recipient is who acks; nothing enforced that, so the tamper-evident
    /// record named whoever the signal was addressed to, not whoever acked.
    #[test]
    fn ack_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let me = caller_id();
        let sent = handle_signal_send(
            &conn,
            &json!({
                "namespace": "_sig",
                "from_agent": "ai:alice",
                "to_agent": me,
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
        // resolved caller (the agent that actually acked).
        let acked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("ack ok");
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
        assert_eq!(
            agent, me,
            "#3364: the ack row names the RESOLVED CALLER, not the signal's to_agent"
        );

        // A no-op re-ack writes NO further signal_ack row.
        let reacked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("ack ok");
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
        // Send (no hooks) so there is a signal to ack. #3364 — address it to
        // THIS caller so the ack below takes the ALLOWED (addressee) path.
        let mut params = send_params();
        params[param_names::TO_AGENT] = Value::String(caller_id());
        let sent = handle_signal_send(&conn, &params, None).expect("send ok");
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
        let acked = handle_signal_ack_with_hooks(&conn, &json!({ "id": id }), None, &hooks)
            .expect("ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "post_signal_ack fires once"
        );
        assert_eq!(*seen_subject.lock().unwrap(), "original-subject");

        // A no-op re-ack must NOT fire the post hook again (no state change).
        let reacked = handle_signal_ack_with_hooks(&conn, &json!({ "id": id }), None, &hooks)
            .expect("re-ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "a no-op re-ack must not re-fire post_signal_ack"
        );
    }

    /// #3171 — schema-REQUIRED `correlation_id` is refused when
    /// missing/blank. Pre-fix an `unwrap_or_default()` read threaded on
    /// `""` and returned an empty `signals` array: a plausible "this
    /// thread has no messages" answer to a question never asked.
    #[test]
    fn signal_thread_refuses_missing_or_blank_correlation_id_3171() {
        let conn = fresh();
        for bad in [
            json!({}),
            json!({ "correlation_id": "" }),
            json!({ "correlation_id": "  " }),
            json!({ "correlation_id": 1 }),
        ] {
            let e = handle_signal_thread(&conn, &bad).expect_err("refused");
            assert_eq!(e, "correlation_id is required", "{bad}");
        }
        // CONTROL: a well-formed call still succeeds.
        let ok = handle_signal_thread(&conn, &json!({ "correlation_id": "corr-x" })).expect("ok");
        assert_eq!(ok["signals"].as_array().expect("array").len(), 0);
    }

    // ---- #3364 signal_ack authorization -----------------------------------

    /// Send one signal addressed to `to_agent`, returning its id.
    fn send_to(conn: &rusqlite::Connection, to_agent: Value) -> String {
        let sent = handle_signal_send(
            conn,
            &json!({
                "namespace": "_ack",
                "from_agent": "ai:sender",
                "to_agent": to_agent,
                "subject": "coordinate",
            }),
            None,
        )
        .expect("send ok");
        sent[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string()
    }

    /// THE regression, DENIED half (#3364). A signal addressed to somebody
    /// else must not be acknowledgeable by this caller.
    ///
    /// Pre-fix `handle_signal_ack` had no authorization at all: it stamped
    /// `acknowledged_at` for anyone who knew the id, and — because the handler
    /// carried no actor — attributed the `coordination.signal_ack` audit row
    /// to the signal's `to_agent`, i.e. the tamper-evident chain NAMED THE
    /// VICTIM as the acknowledger. Since `memory_signal_inbox` is
    /// UNACKED-ONLY (#3171), the wrongful ack also made the message disappear
    /// from its real addressee's inbox.
    ///
    /// Every assertion below FAILS against the unfixed handler: it returned
    /// `Ok({"acknowledged": true})`, wrote the stamp, and wrote an audit row.
    #[test]
    fn ack_refuses_a_caller_that_is_not_the_addressee_3364() {
        let conn = fresh();
        // Deterministic: no resolved caller identity can equal this literal.
        let victim = "ai:alice-not-this-caller";
        let id = send_to(&conn, json!(victim));

        let err = handle_signal_ack(&conn, &json!({ "id": id }), None)
            .expect_err("a non-addressee ack must be REFUSED, not answered");
        assert!(
            err.contains("is not the addressee of this signal"),
            "got: {err}"
        );
        assert!(
            !err.contains(victim),
            "the refusal must not disclose the addressee to a caller that may not ack: {err}"
        );

        // The signal is UNTOUCHED — a refused ack writes nothing.
        let stored = crate::signals::get(&conn, &id)
            .expect("get")
            .expect("row still present");
        assert_eq!(
            stored.acknowledged_at, None,
            "a refused ack must leave acknowledged_at unset"
        );

        // ...and no audit row was appended (no state change to observe).
        let acks: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::SIGNAL_ACK],
                |r| r.get(0),
            )
            .expect("query audit rows");
        assert_eq!(acks, 0, "a refused ack must not write an audit row");

        // The message is still in its real addressee's (unacked-only) inbox.
        let inbox = handle_signal_inbox(&conn, &json!({ "namespace": "_ack", "to_agent": victim }))
            .expect("inbox ok");
        assert_eq!(
            inbox["signals"].as_array().expect("array").len(),
            1,
            "a refused ack must not hide the message from its addressee"
        );
    }

    /// #3364 — a namespace BROADCAST has no addressee, and `acknowledged_at`
    /// is one column on the row, so one agent acking it would hide it from
    /// every other recipient's unacked-only inbox. Fail closed.
    #[test]
    fn ack_refuses_a_namespace_broadcast_3364() {
        let conn = fresh();
        for to_agent in [Value::Null, json!("   ")] {
            let id = send_to(&conn, to_agent.clone());
            let err = handle_signal_ack(&conn, &json!({ "id": id }), None)
                .expect_err("a broadcast ack must be REFUSED");
            assert!(
                err.contains("a namespace broadcast has no addressee"),
                "to_agent={to_agent}: {err}"
            );
            let stored = crate::signals::get(&conn, &id).expect("get").expect("row");
            assert_eq!(stored.acknowledged_at, None);
        }
    }

    /// THE regression, ALLOWED half (#3364). The addressee itself still acks
    /// exactly as before — the gate must not be satisfiable by refusing
    /// everything. Also pins the missing-id refusal and the untouched
    /// absent-row shape.
    #[test]
    fn ack_still_allows_the_addressee_3364() {
        let conn = fresh();
        let me = caller_id();
        let id = send_to(&conn, json!(me));

        let acked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("addressee ack ok");
        assert_eq!(acked["acknowledged"].as_bool(), Some(true));
        let stored = crate::signals::get(&conn, &id).expect("get").expect("row");
        assert!(stored.acknowledged_at.is_some(), "the stamp landed");

        // A re-ack by the same addressee is still the documented no-op.
        let reacked = handle_signal_ack(&conn, &json!({ "id": id }), None).expect("re-ack ok");
        assert_eq!(reacked["acknowledged"].as_bool(), Some(false));

        // The id must be identified before it can be authorized.
        for bad in [json!({}), json!({ "id": "" }), json!({ "id": 7 })] {
            let e = handle_signal_ack(&conn, &bad, None).expect_err("refused");
            assert_eq!(e, "id is required", "{bad}");
        }

        // An id naming no row is NOT an authorization verdict: reporting one
        // would leak which signal ids exist. Unchanged pre-#3364 shape.
        let absent =
            handle_signal_ack(&conn, &json!({ "id": "sig-nope" }), None).expect("absent is Ok");
        assert_eq!(absent["acknowledged"].as_bool(), Some(false));
    }
}
