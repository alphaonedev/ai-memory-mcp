// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation `/sync/since` GET endpoint (receive-side pull).
//!
//! Extracted from [`super::federation_receive`] under issue #650
//! (handler cap ≤1200 LOC). Handler body unchanged; only the module
//! surface moved. Wire compatibility preserved via
//! `pub use federation_sync_since::*` in [`super`].

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use crate::db;
use crate::federation::peer_attestation::{self, PeerAttestationConfig};
use crate::models::Memory;
use crate::validate;

use super::AppState;
use super::federation_receive::{SyncSinceQuery, extract_peer_id};
#[cfg(feature = "sal")]
use super::{StorageBackend, store_err_to_response};

pub async fn sync_since(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SyncSinceQuery>,
) -> impl IntoResponse {
    let state = app.db.clone();
    // Validate `since` parses as RFC 3339 BEFORE hitting the DB so a
    // garbage timestamp returns a clear 400 instead of a 200 with the
    // entire database (red-team #247).
    if let Some(ref s) = q.since
        && !s.is_empty()
        && chrono::DateTime::parse_from_rfc3339(s).is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid `since` parameter — expected RFC 3339 timestamp"
            })),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(500).min(10_000);

    // v0.7.0 #239 — per-peer namespace allowlist. Read the
    // `x-peer-id` header + the operator-configured attestation map
    // BEFORE the DB hit so the projection size cap (`limit`) is
    // applied against the post-filter row set. Default-deny on
    // missing peer-id / missing scope row unless the operator opts
    // in via `AI_MEMORY_FED_SYNC_TRUST_PEER=1` (legacy compat).
    let peer_header = extract_peer_id(&headers).map(str::to_string);
    let attest_cfg = PeerAttestationConfig::from_env();
    let trust_bypass = peer_attestation::sync_trust_peer_bypass();

    // v0.7.0 #948 — federation-pull visibility gate. Pre-#948 the
    // namespace allowlist was the ONLY filter, which meant rows in an
    // allowlisted namespace with `metadata.scope == "private"` and a
    // `metadata.agent_id` belonging to an agent that has NOT consented
    // to share with this peer were still projected. The fix resolves
    // a federation "caller" identity from the peer-attestation
    // headers and post-filters every projected row through the
    // canonical `crate::visibility::is_visible_to_caller` helper
    // (landed in commit 4d30dd638 / #951).
    //
    // Caller resolution ladder (federation contract):
    //   1. `X-Peer-Id` (the syncing peer's wire-attested identity —
    //      the same value that already drives `scope_for(...)` above).
    //   2. `X-Agent-Id` (the daemon principal of the syncing process,
    //      mirroring the side-effect write path at line ~169 below).
    //   3. Empty string ("") — opaque/unknown caller; the visibility
    //      helper denies every scope=private row to a "" caller that
    //      isn't the (also-empty) owner, which is the correct
    //      default-deny posture.
    let federation_caller: String = peer_header
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-agent-id")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("")
        .to_string();

    // v0.7.0 #978 — close the legacy-unauthored cross-tenant leak.
    // Pre-#978 a `has_ownership_signal` carve-out projected any row
    // that lacked BOTH `metadata.scope` AND `metadata.agent_id`
    // through unchanged, on the rationale that pre-v0.7-era rows had
    // no NHI-ownership signals to filter against. That carve-out was
    // the load-bearing reason every federated peer matching the
    // namespace allowlist could see legacy operator/CLI-seeded rows
    // — the same cross-tenant leak surface the visibility-gate
    // cluster (#940/#942/#944/#946/#947/#948/#956/#959/#960/#974/#976)
    // closed on every other handler in v0.7.0.
    //
    // The replacement predicate runs EVERY row through
    // `crate::visibility::is_visible_to_caller`, with one named
    // operator-explicit escape hatch:
    //
    //   `metadata.federation_share == true`  — the documented migration
    //   path for legacy rows the operator KNOWS should federate (the
    //   row text was written with broadcast intent; stamping the flag
    //   is an explicit consent signal).
    //
    // Legacy rows that lack the flag default to scope=private +
    // unowned in the canonical helper and get DENIED to non-owner
    // federation callers, restoring the visibility invariant. The
    // existing `AI_MEMORY_FED_SYNC_TRUST_PEER=1` full-dump escape
    // hatch (see `allow_all_legacy` below) remains intact for legacy
    // peers that demand the pre-#948 wire shape verbatim.
    fn federation_projectable(mem: &Memory, federation_caller: &str) -> bool {
        // Operator-explicit opt-in flag. The check is deliberately
        // strict — only the literal JSON `true` boolean passes.
        // String `"true"`, integer `1`, etc. do NOT.
        let opt_in = mem
            .metadata
            .get("federation_share")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if opt_in {
            return true;
        }
        crate::visibility::is_visible_to_caller(mem, federation_caller)
    }

    // Pre-resolved scope row: `Some(&PeerScope)` means filter by its
    // namespace allowlist; `None` + bypass means "legacy full dump";
    // `None` + no bypass means "default-deny → empty page".
    let scope = peer_header.as_deref().and_then(|p| attest_cfg.scope_for(p));
    let allow_all_legacy = scope.is_none() && trust_bypass;

    let visibility_ok = |mem: &Memory| -> bool {
        // The operator-explicit `AI_MEMORY_FED_SYNC_TRUST_PEER=1`
        // bypass (resolved into `allow_all_legacy` above) is the
        // documented full-dump posture for legacy peers. When it
        // fires, every row in an allowed namespace projects unchanged
        // — that's the contract operators rely on for v0.6 ↔ v0.7
        // peer rollouts, and it predates the #978 cross-tenant fix.
        // Skip the visibility predicate ONLY on that explicit-trust
        // path; default-deny posture stays default.
        if allow_all_legacy {
            return true;
        }
        federation_projectable(mem, &federation_caller)
    };
    if scope.is_none() && !trust_bypass {
        // Default-deny: short-circuit to an empty envelope with WARN
        // so an unauthorised peer cannot exfiltrate the DB. The
        // `excluded_for_scope` field is honest about the partial view.
        tracing::warn!(
            target: "federation::scope",
            peer = %peer_header.as_deref().unwrap_or(""),
            "sync_since: no scope allowlist for peer; refusing to return rows. \
             Set AI_MEMORY_FED_SYNC_TRUST_PEER=1 to opt out (legacy peers)."
        );
        return (
            StatusCode::OK,
            Json(json!({
                "count": 0,
                "limit": limit,
                "updated_since": q.since,
                "earliest_updated_at": serde_json::Value::Null,
                "latest_updated_at": serde_json::Value::Null,
                "memories": Vec::<Memory>::new(),
                "excluded_for_scope": 0,
                "excluded_for_scope_private": 0,
                "scope_status": "no_allowlist_default_deny",
            })),
        )
            .into_response();
    }

    // Helper closure: namespace test for the resolved scope.
    let allowed = |ns: &str| -> bool {
        if allow_all_legacy {
            return true;
        }
        match scope {
            Some(s) => s
                .allowed_namespaces
                .iter()
                .any(|p| crate::federation::peer_attestation::namespace_allowed_test_glob(p, ns)),
            None => false,
        }
    };

    // v0.7.0 Wave-3 Continuation 2 — dispatch through the SAL trait
    // when postgres-backed. Heterogeneous federation (sqlite ↔ postgres)
    // rides on this single code path so the wire shape is byte-blind
    // to the underlying store.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let mems = match app
            .store
            .list_memories_updated_since(q.since.as_deref(), limit)
            .await
        {
            Ok(v) => v,
            Err(e) => return store_err_to_response(e),
        };
        let total = mems.len();
        let ns_filtered: Vec<Memory> = mems.into_iter().filter(|m| allowed(&m.namespace)).collect();
        let after_ns = ns_filtered.len();
        let excluded = total.saturating_sub(after_ns);
        // #948 visibility post-filter (see `federation_caller`
        // resolution above): drop any scope=private row whose owner /
        // inbox-target does NOT match the federation caller. The
        // canonical helper centralises the predicate so future scope
        // semantics change once and land everywhere.
        let filtered: Vec<Memory> = ns_filtered.into_iter().filter(visibility_ok).collect();
        let excluded_for_scope_private = after_ns.saturating_sub(filtered.len());
        let earliest_updated_at = filtered.first().map(|m| m.updated_at.clone());
        let latest_updated_at = filtered.last().map(|m| m.updated_at.clone());
        return (
            StatusCode::OK,
            Json(json!({
                "count": filtered.len(),
                "limit": limit,
                "updated_since": q.since,
                "earliest_updated_at": earliest_updated_at,
                "latest_updated_at": latest_updated_at,
                "memories": filtered,
                "storage_backend": "postgres",
                "excluded_for_scope": excluded,
                "excluded_for_scope_private": excluded_for_scope_private,
                "scope_status": if allow_all_legacy { "legacy_bypass" } else { "scoped" },
            })),
        )
            .into_response();
    }

    let lock = state.lock().await;
    let mems = match db::memories_updated_since(&lock.0, q.since.as_deref(), limit) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("sync_since: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal server error"})),
            )
                .into_response();
        }
    };

    // v0.7.0 #239 — apply per-peer namespace scope filter. Rows
    // outside the operator-configured allowlist are EXCLUDED from
    // the response (callers see a partial view + an honest
    // `excluded_for_scope` count).
    let total = mems.len();
    let mems: Vec<Memory> = mems.into_iter().filter(|m| allowed(&m.namespace)).collect();
    let excluded = total.saturating_sub(mems.len());

    // v0.7.0 #948 — scope=private visibility post-filter. The
    // canonical `crate::visibility::is_visible_to_caller` helper
    // (commit 4d30dd638 / #951) enforces the NHI visibility contract:
    // a scope=private row is projected only when the resolved
    // federation caller is either the owner (`metadata.agent_id`) or
    // the inbox target (`metadata.target_agent_id`). Rows that flunk
    // this check are EXCLUDED from the response (separate from the
    // namespace-allowlist count so operators can tell the two
    // filtering modes apart).
    let after_ns = mems.len();
    let mems: Vec<Memory> = mems.into_iter().filter(visibility_ok).collect();
    let excluded_for_scope_private = after_ns.saturating_sub(mems.len());

    // Record the puller as a peer so subsequent incremental push/pull
    // pairs have a durable clock entry. Best-effort; don't fail the
    // response if the side-effect write fails.
    let header_agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok());
    if let (Some(peer), Ok(local_agent_id)) = (
        q.peer.as_deref(),
        crate::identity::resolve_http_agent_id(None, header_agent_id),
    ) && validate::validate_agent_id(peer).is_ok()
        && let Some(last) = mems.last()
        && let Err(e) = db::sync_state_observe(&lock.0, &local_agent_id, peer, &last.updated_at)
    {
        tracing::debug!("sync_since: sync_state_observe failed: {e}");
    }

    // S39 diagnostic echo (v0.6.2). The testbook scenario writes 6 rows
    // while peer-3 is suspended then queries `/sync/since?since=<ckpt>`
    // and expects the 6 back. When the count comes back 0, the scenario
    // can't tell whether:
    //   a) the server parsed `since` differently than expected,
    //   b) `limit` silently truncated, or
    //   c) the returned timestamps don't actually cover the expected range.
    // Echoing `updated_since` (what the server parsed, verbatim) plus
    // earliest / latest `updated_at` from the result set lets the
    // scenario pin the failure mode without changing any behavior. Fields
    // are additive — no existing caller assertion regresses.
    let earliest_updated_at = mems.first().map(|m| m.updated_at.clone());
    let latest_updated_at = mems.last().map(|m| m.updated_at.clone());

    (
        StatusCode::OK,
        Json(json!({
            "count": mems.len(),
            "limit": limit,
            "updated_since": q.since,
            "earliest_updated_at": earliest_updated_at,
            "latest_updated_at": latest_updated_at,
            "memories": mems,
            "excluded_for_scope": excluded,
            "excluded_for_scope_private": excluded_for_scope_private,
            "scope_status": if allow_all_legacy { "legacy_bypass" } else { "scoped" },
        })),
    )
        .into_response()
}
