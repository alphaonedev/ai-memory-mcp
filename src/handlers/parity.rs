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
use crate::models::{Memory, Tier};
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

/// #2856 (federation data-integrity) — the consolidate-specific
/// under-replication response. Sibling of [`under_replicated_response`]
/// that ADDITIONALLY carries the created consolidated memory's `id` (and
/// the same `{id, consolidated, summary, content, memory}` fields the
/// success `201` body emits), so a caller whose consolidation committed
/// LOCALLY but did not reach quorum can DISCOVER the row it must reconcile.
///
/// **Why a distinct helper.** `consolidate` mints a NEW substrate-derived
/// memory attributed to the tenant consolidator, but the origin daemon
/// cannot produce that tenant's Ed25519 signature — so under the
/// v1.0.0-default strict `AI_MEMORY_FED_REQUIRE_WRITE_SIG` the receiver
/// refuses the unsigned honored-third-party relay and buckets it into
/// `skipped` inside its own 2xx. The origin then finalises a quorum MISS
/// and returns THIS 202. Pre-#2856 the bare [`under_replicated_response`]
/// omitted the `id`, so the caller saw a success-shaped 2xx with NO way to
/// tell WHAT was written-locally-but-not-replicated — the "success-shaped
/// while silently diverging" defect the North Star forbids. Emitting the
/// `id` + the `quorum_met:false` / `durability:"local"` state makes the
/// under-replication LOUD and RECONCILABLE (5-agent vote `4d3ea1c5`,
/// Option A). The `202`-not-`5xx` status is preserved (W3 / gap G12): the
/// local row IS durable.
///
/// True convergent replication of a tenant-attributed consolidation is a
/// separate authorship-model decision tracked as a follow-up; this helper
/// closes the silent-divergence + missing-`id` defect without changing the
/// receiver gate or the row's attribution.
pub(crate) fn under_replicated_consolidate_response(
    payload: &QuorumNotMetPayload,
    mem: &Memory,
    source_count: usize,
) -> axum::response::Response {
    use crate::models::field_names;
    let body = json!({
        "id": mem.id,
        (field_names::CONSOLIDATED): source_count,
        "summary": mem.content,
        // v0.7.0 L7-followup — mirror `content` + a nested `memory` dict so
        // the caller reads the same shape as the `201` success body.
        "content": mem.content,
        "memory": {
            "id": mem.id,
            "title": mem.title,
            "content": mem.content,
            "namespace": mem.namespace,
        },
        // Replication state — LOUD + honest (never a bare success body).
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

/// #1886 / #1911 — single SSOT for the create / bulk-create `expires_at`
/// resolution so every backend (SQLite + Postgres, single + bulk) derives
/// the row's expiry identically. Precedence mirrors the original sqlite
/// `create_memory` body:
///
/// 1. an explicit caller `expires_at` (RFC3339) wins verbatim;
/// 2. else a caller-supplied `ttl_secs` → `now + ttl_secs`;
/// 3. else the operator-configured tier default (`ResolvedTtl::ttl_for_tier`).
///
/// Returns `None` (an immortal row) when all three are absent — and,
/// v1.0.0 #2399, whenever `tier` is [`Tier::Long`], which SHORT-CIRCUITS the
/// whole ladder above.
///
/// # v1.0.0 #2399 — the long-tier gate
///
/// Pre-#2399 this helper was TIER-BLIND, so a fresh `POST /api/v1/memories`
/// (or a bulk row) carrying `tier=long` + an explicit `expires_at` / `ttl_secs`
/// produced a `long` row with a live expiry. EVERY other lane forces NULL for
/// long — the insert `ON CONFLICT` arms, both update funnels (#2331 FBL-01)
/// and the supersede funnel — and the GC reap predicate is TIER-BLIND
/// (`expires_at IS NOT NULL AND expires_at < now`), so the "permanent" row was
/// archived (or hard-deleted + crypto-erased under `archive_on_gc=false`) at
/// the caller's deadline while the same logical write via upsert survived
/// forever. The gate lives HERE as well as at the shared store funnel
/// ([`crate::models::Memory::effective_expires_at`]) so the projected
/// `Memory` — and therefore the create response echoed to the caller — never
/// carries a value the durable row will not have.
///
/// Pre-#1886 the Postgres single-create path bound `expires_at` from the
/// explicit field ONLY, silently dropping a validated `ttl_secs` — an
/// ephemeral `{"ttl_secs":3600}` write landed as an immortal row on a
/// postgres-backed daemon, a data-retention divergence versus sqlite.
/// Pre-#1911 the Postgres bulk path honoured `ttl_secs` but omitted the
/// tier-default fallback. Routing all four call sites through this helper
/// makes the divergence impossible by construction.
#[must_use]
pub fn resolve_create_expires_at(
    now: chrono::DateTime<chrono::Utc>,
    tier: &Tier,
    explicit: Option<String>,
    ttl_secs: Option<i64>,
    tier_default_secs: Option<i64>,
) -> Option<String> {
    // v1.0.0 #2399 — long is permanent on EVERY lane; see the doc comment.
    if matches!(tier, Tier::Long) {
        return None;
    }
    explicit.or_else(|| {
        ttl_secs
            .or(tier_default_secs)
            .map(|s| (now + chrono::Duration::seconds(s)).to_rfc3339())
    })
}

/// #3332 — project PostgreSQL SAL statistics into the documented HTTP
/// envelope. The count collections stay as the shared list structs, matching
/// SQLite's direct `Stats` serialization and the SDK/API contract.
#[cfg(feature = "sal-postgres")]
pub(super) fn postgres_stats_envelope(stats: &crate::models::Stats) -> serde_json::Value {
    use crate::models::field_names;

    json!({
        (field_names::TOTAL_MEMORIES): stats.total,
        // v1.0.0 #2334 (FBL-15) — additive expiry-axis fields
        // (live = the boot/export definition;
        // expired_pending_gc = the awaiting-GC remainder).
        "live": stats.live,
        "expired_pending_gc": stats.expired_pending_gc,
        "by_tier": stats.by_tier,
        (field_names::BY_NAMESPACE): stats.by_namespace,
        "expiring_soon": stats.expiring_soon,
        "links_count": stats.links_count,
        "db_size_bytes": stats.db_size_bytes,
        (field_names::STORAGE_BACKEND): "postgres",
    })
}

#[cfg(all(test, feature = "sal-postgres"))]
mod stats_envelope_parity_tests {
    use super::postgres_stats_envelope;
    use crate::models::{NamespaceCount, Stats, TierCount};

    #[test]
    fn postgres_count_collections_match_sqlite_list_shape_3332() {
        let stats = Stats {
            total: 7,
            live: 6,
            expired_pending_gc: 1,
            by_tier: vec![TierCount {
                tier: "mid".to_string(),
                count: 7,
            }],
            by_namespace: vec![NamespaceCount {
                namespace: "global".to_string(),
                count: 7,
            }],
            expiring_soon: 1,
            links_count: 2,
            db_size_bytes: 4096,
            dim_violations: 0,
            index_evictions_total: 0,
        };

        // The SQLite handler serializes this shared `Stats` value directly.
        let sqlite = serde_json::to_value(&stats).expect("serialize SQLite stats envelope");
        let postgres = postgres_stats_envelope(&stats);

        for field in ["by_tier", "by_namespace"] {
            assert!(
                postgres[field].is_array(),
                "PostgreSQL {field} must use the documented list shape: {postgres}"
            );
            assert_eq!(
                postgres[field], sqlite[field],
                "PostgreSQL and SQLite {field} values must serialize identically"
            );
        }
        assert_eq!(postgres["live"], 6);
        assert_eq!(postgres["expired_pending_gc"], 1);
        assert_eq!(postgres["storage_backend"], "postgres");
    }
}

#[cfg(test)]
mod resolve_create_expires_at_tests {
    use super::resolve_create_expires_at;
    use crate::models::Tier;
    use chrono::{Duration, TimeZone, Utc};

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn explicit_expires_at_wins_verbatim() {
        let out = resolve_create_expires_at(
            fixed_now(),
            &Tier::Short,
            Some("2030-01-01T00:00:00+00:00".to_string()),
            Some(3600),
            Some(60),
        );
        assert_eq!(out.as_deref(), Some("2030-01-01T00:00:00+00:00"));
    }

    #[test]
    fn ttl_secs_is_honoured_when_no_explicit_expiry_1886() {
        // #1886 regression: a caller-supplied `ttl_secs` MUST become an
        // expiry. Pre-fix the postgres single-create path returned `None`
        // here (immortal row).
        let out = resolve_create_expires_at(fixed_now(), &Tier::Short, None, Some(3600), None);
        let expected = (fixed_now() + Duration::seconds(3600)).to_rfc3339();
        assert_eq!(out.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn ttl_secs_takes_precedence_over_tier_default() {
        let out = resolve_create_expires_at(fixed_now(), &Tier::Short, None, Some(3600), Some(60));
        let expected = (fixed_now() + Duration::seconds(3600)).to_rfc3339();
        assert_eq!(out.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn tier_default_applies_when_no_explicit_or_ttl_1911() {
        // #1911 regression: with neither explicit expiry nor `ttl_secs`,
        // the configured tier default must still expire the row. Pre-fix
        // the postgres bulk path returned `None` (immortal row).
        let out = resolve_create_expires_at(fixed_now(), &Tier::Short, None, None, Some(21600));
        let expected = (fixed_now() + Duration::seconds(21600)).to_rfc3339();
        assert_eq!(out.as_deref(), Some(expected.as_str()));
    }

    /// v1.0.0 #2399 — the long-tier gate short-circuits EVERY rung of the
    /// precedence ladder: an explicit caller `expires_at`, a caller
    /// `ttl_secs`, and the operator-configured tier default all yield `None`
    /// so the fresh row is immortal, matching the upsert / update / supersede
    /// lanes. Without this a `tier=long` create was reaped by the tier-blind
    /// GC predicate at the caller's deadline.
    #[test]
    fn long_tier_forces_immortal_over_every_precedence_rung_2399() {
        assert_eq!(
            resolve_create_expires_at(
                fixed_now(),
                &Tier::Long,
                Some("2030-01-01T00:00:00+00:00".to_string()),
                Some(3600),
                Some(60),
            ),
            None,
            "explicit caller expires_at must not survive on a long row"
        );
        assert_eq!(
            resolve_create_expires_at(fixed_now(), &Tier::Long, None, Some(3600), None),
            None,
            "caller ttl_secs must not survive on a long row"
        );
        assert_eq!(
            resolve_create_expires_at(fixed_now(), &Tier::Long, None, None, Some(21600)),
            None,
            "an operator tier default must not survive on a long row"
        );
        // Non-long tiers keep the pre-#2399 ladder byte-for-byte.
        for tier in [Tier::Short, Tier::Mid] {
            assert_eq!(
                resolve_create_expires_at(
                    fixed_now(),
                    &tier,
                    Some("2030-01-01T00:00:00+00:00".to_string()),
                    None,
                    None,
                )
                .as_deref(),
                Some("2030-01-01T00:00:00+00:00"),
            );
        }
    }

    #[test]
    fn none_when_all_absent_stays_immortal() {
        assert_eq!(
            resolve_create_expires_at(fixed_now(), &Tier::Short, None, None, None),
            None
        );
    }
}

#[cfg(test)]
mod require_caller_owns_memory_tests {
    use super::*;
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use serde_json::json;

    fn mem_with(metadata: serde_json::Value) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
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
/// **Wire shape on rejection (#3426).** Two leak-resistant refusals,
/// chosen by whether the caller may READ the row at all:
/// - not visible to the caller (e.g. another agent's `private` row) →
///   [`hidden_row_refusal`]: `404` with `{"error": "not found"}`,
///   byte-identical to the read path's answer, so the write path is no
///   longer an existence oracle. This matches what the postgres branch
///   already returned (its handlers read through a visibility-scoped
///   `store.get`).
/// - visible but not owned (e.g. a `collective` row) →
///   [`owner_gate_refusal`]: `403` with
///   `{"error": "caller does not own this memory", "caller": "<caller>", "id": "<id>"}`.
///
/// Neither body names the owning agent id. Pre-#3426 the refusal carried
/// an `"owner"` field, disclosing WHO holds a row to a caller that is not
/// entitled to it; the owner is now emitted only to the server-side
/// `AUTHZ_TRACE_TARGET` log.
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
    // #3426 — the owner id stays SERVER-SIDE. Operators keep the full
    // `caller != owner` attribution in this structured AUTHZ trace line;
    // the refused caller gets a body that names neither.
    tracing::warn!(
        target: super::AUTHZ_TRACE_TARGET,
        "ownership-gate refusal: caller {caller} != owner {owner} (id={})",
        mem.id
    );
    // #3426 / #3339 — hide-on-write for a row the caller cannot READ.
    // Pre-fix the sqlite branch answered `403 + owner` for a private row
    // owned by someone else while `GET` answered `404`, so the write path
    // was an existence AND identity oracle for rows the caller may not
    // see. The postgres branch already masked these (its handlers fetch
    // through a visibility-scoped `store.get`, which yields `NotFound` →
    // 404), so this converges sqlite ONTO the standing postgres contract
    // rather than inventing a third behaviour. Denial-preserving: a row
    // refused before is still refused, only less informatively.
    if !crate::visibility::is_visible_to_caller(mem, caller) {
        return Some(hidden_row_refusal());
    }
    Some(owner_gate_refusal(
        crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY,
        Some(caller),
        RefusedResource::Memory,
        &mem.id,
    ))
}

/// #3426 — the single leak-resistant wire shape for EVERY cross-owner
/// authorization refusal on the HTTP surface.
///
/// The owning agent id is deliberately **not a parameter**: a refusal
/// built through this constructor is structurally incapable of naming
/// the owner, so a future gate cannot reintroduce the disclosure by
/// copying a neighbouring `json!` literal. The owner belongs in the
/// server-side `AUTHZ_TRACE_TARGET` warn line at the call site, never
/// on the wire.
///
/// `caller` and `id` are both values the refused caller SUPPLIED, so
/// echoing them discloses nothing it did not already know. `caller` is
/// `Option` because the postgres branch reaches this refusal through
/// `postgres_gate::store_err_to_response`, which maps a bare
/// [`crate::store::StoreError`] and has no caller principal in scope;
/// omitting the field is strictly less disclosure, never more.
///
/// **Wire shape.** `403 Forbidden` with body
/// `{"error": "<error>", "caller": "<caller>", "<key>": "<id>"}`, where
/// `<key>` is [`RefusedResource::wire_key`] and `"caller"` is present
/// only when known. The `error` string is byte-identical on both
/// backends: it is the same SSOT const the SAL adapters put in
/// `StoreError::PermissionDenied.reason`.
#[must_use]
pub fn owner_gate_refusal(
    error: &str,
    caller: Option<&str>,
    resource: RefusedResource,
    id: &str,
) -> axum::response::Response {
    let mut body = serde_json::Map::new();
    body.insert("error".to_string(), json!(error));
    if let Some(caller) = caller {
        body.insert("caller".to_string(), json!(caller));
    }
    body.insert(resource.wire_key().to_string(), json!(id));
    (StatusCode::FORBIDDEN, Json(serde_json::Value::Object(body))).into_response()
}

/// #3426 — which id an [`owner_gate_refusal`] echoes back, as a closed set
/// rather than a caller-supplied key string (rust-1.98 API-09).
///
/// The gate sites differ only in what the refused row is CALLED on the
/// wire — `id` for a memory the caller addressed directly, `source_id`
/// for the source row of a graph edge — and a closed enum keeps a future
/// site from inventing a key (`"owner"` included) by passing a literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusedResource {
    /// The memory the caller addressed directly, echoed as `id`.
    Memory,
    /// The source row of a link / graph traversal, echoed as `source_id`.
    SourceMemory,
}

impl RefusedResource {
    /// The JSON key this resource's id appears under in a refusal body.
    #[must_use]
    pub const fn wire_key(self) -> &'static str {
        match self {
            Self::Memory => "id",
            Self::SourceMemory => "source_id",
        }
    }
}

/// #3426 / #3339 — the hide-on-write refusal for a row the caller is not
/// entitled to READ, byte-identical to the `404` body the read path and
/// the postgres branch already return, so a non-owner cannot tell
/// "exists but not yours" from "does not exist".
#[must_use]
pub fn hidden_row_refusal() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
}
