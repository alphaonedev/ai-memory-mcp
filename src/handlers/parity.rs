// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP parity helpers shared across handler modules.
//!
//! `fanout_or_pending` — fan out a locally-committed memory to peers via
//! quorum store. Used by `create_memory`, `update_memory`, and the bulk
//! endpoints in `handlers::http`.
//!
//! `resolve_caller_agent_id` — the HTTP precedence chain for caller
//! `agent_id` resolution (body → query → header → anonymous fallback).
//! Used by every HTTP handler that needs an identified caller.
//!
//! `under_replicated_response` — v0.8.1 W3 / gap G12: the durable-but-
//! under-replicated write response. On a W-of-N quorum miss the local
//! row is already durably committed (ADR-0001, never rolled back), so
//! this returns **`202 Accepted`** carrying the replication state in the
//! body (`{quorum_met:false, acks, needed, reason, durability:"local"}`)
//! rather than the pre-v0.8.1 `503 Service Unavailable` that misreported
//! a locally-durable write as a service failure (issue #869 introduced
//! the shared 503 helper; W3 corrects its status semantics). Collapses
//! the ~30 inline payload sites into one typed helper.
//!
//! All three helpers were extracted from `src/handlers/mod.rs` as part
//! of the issue #650 file-architecture cleanup.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use super::transport::AppState;
use crate::federation::QuorumNotMetPayload;
use crate::models::Memory;
use crate::validate;

/// Build the canonical under-replication response for a write whose
/// LOCAL commit already succeeded but did not reach W-of-N quorum.
///
/// # v0.8.1 W3 / gap G12 — durability is NOT a 503 (5-agent vote 4d3ea1c5)
///
/// Pre-v0.8.1 this returned `503 Service Unavailable` + `Retry-After: 2`.
/// That was an API-semantics bug: per ADR-0001 the local row is durably
/// committed and never rolled back before the quorum fanout runs (every
/// call site of this helper is post-local-commit — verified by the W3
/// per-site audit), so a 503 misreported a **locally-durable write** as a
/// service failure. The fix decouples the HTTP status from the
/// replication outcome:
///
/// * the local write committed → **never 5xx**; this helper now returns
///   **`202 Accepted`** carrying the replication state in the body
///   (`quorum_met:false`, `acks`, `needed`, `reason`, `durability:"local"`).
/// * a genuine LOCAL write failure is reported by the caller BEFORE this
///   helper is reached (the local-commit error path), so it still surfaces
///   as the appropriate error status — this helper is only the
///   durable-but-under-replicated case.
///
/// The under-replicated write is enqueued to the federation push-DLQ and
/// driven to convergence by the sync daemon; the named operator alarm is
/// the `ai_memory_federation_push_dlq_depth` gauge + the #1544 edge WARN.
/// The explicit unreached-peer identity list is a tracked follow-up (the
/// `AckTracker` carries acks, not the full configured peer set); `acks` +
/// `needed` convey the replication gap honestly today.
///
/// The `quorum_met:false` marker is REQUIRED (never a bare success body):
/// for an authority-granting coordination write (an action claim) a caller
/// must never infer cluster-confirmed exclusivity from a 2xx alone
/// (split-brain guard — W3 coordination-semantics finding).
pub(crate) fn under_replicated_response(payload: &QuorumNotMetPayload) -> axum::response::Response {
    let body = json!({
        "quorum_met": false,
        "acks": payload.got,
        "needed": payload.needed,
        "reason": payload.reason,
        "durability": "local",
    });
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

/// Fan out a locally-committed memory to peers via quorum store. On full
/// quorum, returns `None` (caller returns its normal 2xx success). On a
/// quorum MISS, returns `Some(202_response)` carrying the replication
/// state — the local commit already landed (W3/G12: a durable write is
/// never reported as a 5xx). Network errors are logged and swallowed —
/// the local commit already landed and the sync-daemon catches stragglers.
pub(crate) async fn fanout_or_pending(
    app: &AppState,
    mem: &Memory,
) -> Option<axum::response::Response> {
    let fed = app.federation.as_ref().as_ref()?;
    match crate::federation::broadcast_store_quorum(fed, mem).await {
        Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
            Ok(_) => None,
            Err(err) => {
                // W3/G12 — the local row is durable; surface replication
                // state as 202 + body, never a 5xx.
                let payload = QuorumNotMetPayload::from_err(&err);
                Some(under_replicated_response(&payload))
            }
        },
        Err(e) => {
            tracing::warn!("fanout error (local committed): {e:?}");
            None
        }
    }
}

/// Helper — resolve the caller's `agent_id` using the HTTP precedence chain.
///
/// # SECURITY (v0.7.0 — header-first; body and query must match)
///
/// The `X-Agent-Id` request header is the AUTHORITATIVE identity slot.
/// The optional `body` and `query` slots are caller-controlled and so
/// cannot be trusted as precedence inputs; they are accepted as
/// REFINEMENTS that MUST agree with the header-resolved id. A mismatch
/// returns a `agent_id_body_header_mismatch` / `agent_id_query_header_mismatch`
/// error so handlers can map it to `403 Forbidden`.
///
/// Pre-v0.7.0 precedence was `body → query → header` (body wins),
/// which was the #874-class spoof vector that the v0.7.0 fix series
/// closed at every CALLER. The structural fix lives in
/// [`crate::identity::resolve_http_agent_id`]; this wrapper mirrors
/// the same posture for the additional `query` slot some handlers
/// accept (e.g. `GET /inbox?agent_id=...`).
///
/// Returns a 400-mapped string error on invalid input; a 403-mapped
/// string error tagged `agent_id_*_header_mismatch` on body/query
/// disagreement; synthesizes an anonymous `anonymous:req-…` id on
/// total miss (no body, no query, no header) so the upstream handler
/// can decide whether anonymous writes are allowed.
pub(crate) fn resolve_caller_agent_id(
    body: Option<&str>,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<String, String> {
    // 1. Header (or anonymous fallback) is authoritative. Delegate to
    //    the identity primitive so the body-match check there runs once.
    let header_val = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let resolved = crate::identity::resolve_http_agent_id(body, header_val)
        .map_err(|e| crate::errors::msg::invalid("agent_id", e))?;

    // 2. Query refinement — same posture as body: when non-empty it
    //    MUST match the authoritative resolved id. Validate first so a
    //    malformed query surfaces as the more informative validation
    //    error rather than as a mismatch.
    if let Some(claim) = query
        && !claim.is_empty()
    {
        validate::validate_agent_id(claim)
            .map_err(|e| crate::errors::msg::invalid("agent_id", e))?;
        if claim != resolved {
            return Err(format!(
                "agent_id_query_header_mismatch: query-supplied agent_id {claim:?} disagrees \
                 with authenticated header-resolved id {resolved:?}"
            ));
        }
    }

    Ok(resolved)
}

/// Build a [`crate::store::CallerContext`] from the request headers
/// (and optional body-supplied agent id) for handlers that dispatch
/// through the SAL trait.
///
/// v0.7.0 ship-hardening (2026-05-19): the SAL recall/get/list/search
/// surfaces apply the #910 scope=private visibility filter using the
/// `CallerContext`'s `effective_principal()`. Multiple handlers
/// (`recall`, `set_namespace_standard`, `power_consolidation`,
/// `links`, etc.) historically hardcoded the principal to `"ai:http"`
/// or `"daemon"` — guaranteeing a mismatch with every memory's
/// `metadata.agent_id` and causing the filter to drop the caller's
/// own data. This helper consolidates the canonical resolution path
/// so handlers can switch from the legacy hardcode with a one-line
/// change.
///
/// On a missing / invalid `X-Agent-Id` header the function synthesizes
/// `anonymous:req-<uuid8>` (mirrors the same fallback path as
/// `crate::identity::resolve_http_agent_id`), keeping anonymous writes
/// possible while still binding the write + the subsequent read to
/// the SAME synthesized principal within a request scope (NOT across
/// requests — clients that need cross-request visibility on
/// scope=private memories MUST set `X-Agent-Id` explicitly).
#[cfg(feature = "sal")]
pub(crate) fn http_caller_ctx(
    headers: &axum::http::HeaderMap,
    body_agent_id: Option<&str>,
) -> crate::store::CallerContext {
    let resolved = resolve_caller_agent_id(body_agent_id, headers, None).unwrap_or_else(|e| {
        // QC Obs #2 (2026-05-20): the prior shape silently fell back
        // to `"anonymous:invalid"` on resolve error, polluting audit
        // trails with a bogus principal. Log the failure as a WARN so
        // operators see the anomaly; the full Result-propagation
        // refactor (return `Result<CallerContext, Response>` so the
        // handler can map to a 4xx) is tracked as a v0.7.1 follow-up
        // since it requires touching every call site.
        tracing::warn!(
            target: "handlers::parity",
            error = %e,
            "http_caller_ctx: invalid X-Agent-Id / body.agent_id, falling back to anonymous:invalid"
        );
        crate::identity::sentinels::ANONYMOUS_INVALID.to_string()
    });
    crate::store::CallerContext::for_agent(resolved)
}

#[cfg(test)]
mod require_caller_owns_memory_tests {
    use super::*;
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use serde_json::json;

    fn mem_with(metadata: serde_json::Value) -> Memory {
        Memory {
            id: "test-id".to_string(),
            tier: Tier::Long,
            namespace: "test-ns".to_string(),
            title: "test".to_string(),
            content: "test".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-05-20T00:00:00Z".to_string(),
            updated_at: "2026-05-20T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
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
        }
    }

    #[test]
    fn owner_passes() {
        let mem = mem_with(json!({"agent_id": "alice"}));
        assert!(require_caller_owns_memory(&mem, "alice", false).is_none());
    }

    #[test]
    fn non_owner_blocked() {
        let mem = mem_with(json!({"agent_id": "alice"}));
        assert!(require_caller_owns_memory(&mem, "bob", false).is_some());
    }

    #[test]
    fn legacy_unowned_passes() {
        let mem = mem_with(json!({}));
        assert!(require_caller_owns_memory(&mem, "bob", false).is_none());
        let mem = mem_with(json!({"agent_id": ""}));
        assert!(require_caller_owns_memory(&mem, "bob", false).is_none());
    }

    #[test]
    fn daemon_passes() {
        let mem = mem_with(json!({"agent_id": "alice"}));
        assert!(require_caller_owns_memory(&mem, "daemon", false).is_none());
    }

    #[test]
    fn inbox_target_passes_when_allowed() {
        let mem = mem_with(json!({
            "agent_id": "alice",
            "target_agent_id": "bob",
        }));
        // allow_inbox = true (DELETE case): bob is the inbox target,
        // permitted to consume the message.
        assert!(require_caller_owns_memory(&mem, "bob", true).is_none());
    }

    #[test]
    fn inbox_target_blocked_when_disallowed() {
        let mem = mem_with(json!({
            "agent_id": "alice",
            "target_agent_id": "bob",
        }));
        // allow_inbox = false (UPDATE/PROMOTE case): bob may NOT
        // mutate alice's row even though he's the inbox target.
        assert!(require_caller_owns_memory(&mem, "bob", false).is_some());
    }

    #[test]
    fn inbox_target_mismatch_blocked() {
        let mem = mem_with(json!({
            "agent_id": "alice",
            "target_agent_id": "carol",
        }));
        // bob is neither owner nor inbox target.
        assert!(require_caller_owns_memory(&mem, "bob", true).is_some());
    }
}

/// #954 — DRY helper for the caller-vs-row-owner ownership gate that
/// guards mutating handlers (update, promote, delete, archive, restore,
/// link create / delete).
///
/// Returns `None` when the caller is permitted to mutate the row;
/// returns `Some(403 Forbidden response)` when ownership fails —
/// caller short-circuits with `return` on the `Some` branch.
///
/// **Carve-outs (preserved verbatim from the inline sites the helper
/// replaces):**
/// - `owner.is_empty()` → unowned/legacy row falls through to caller
///   (legacy-unowned carve-out used across the codebase).
/// - `caller == "daemon"` → daemon-origin path exempt; the audit
///   chain captures the daemon-origin write via signed_events.
/// - `allow_inbox && metadata.target_agent_id == caller` → the
///   sender-stamped inbox carve-out from the DELETE handler. Only
///   the recipient of an inbox message may delete it; passing
///   `allow_inbox = false` disables this carve-out for handlers
///   (update / promote) where the inbox target should NOT be able
///   to mutate someone else's row.
///
/// **Wire shape on rejection.** `403 Forbidden` with body
/// `{"error": "caller does not own this memory", "owner": "<owner>",
/// "caller": "<caller>"}` — matches the inline-site shape so test
/// expectations + audit grep patterns remain valid.
#[must_use]
pub fn require_caller_owns_memory(
    mem: &Memory,
    caller: &str,
    allow_inbox: bool,
) -> Option<axum::response::Response> {
    let owner = mem
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if owner.is_empty() || owner == caller || caller == crate::identity::sentinels::DAEMON_PRINCIPAL
    {
        return None;
    }
    if allow_inbox {
        let target = mem
            .metadata
            .get("target_agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !target.is_empty() && target == caller {
            return None;
        }
    }
    tracing::warn!(
        target: super::AUTHZ_TRACE_TARGET,
        "ownership-gate 403: caller {caller} != owner {owner} (id={})",
        mem.id
    );
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "caller does not own this memory",
                "owner": owner,
                "caller": caller,
            })),
        )
            .into_response(),
    )
}
